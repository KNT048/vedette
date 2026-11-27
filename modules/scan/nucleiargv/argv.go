// Package nucleiargv builds and checks the only nuclei command line Vedette ever runs. It is a leaf:
// standard library only, no database and no core/exec, because the sensor binary links it, and both sides use the
// same code: core before it hands a job over, the worker in the scan container before nuclei starts (SYS-2). Like
// nmapargv, a job on the wire carries no argv, flag, path or URL: the worker builds the line from the
// job's fields with Build, then checks it with Validate.
//
// The worker's grammar is the last fence against a compromised core, so it is as narrow as nmapargv's. A job has
// a scope:
//   - ScopeLAN (the scan module): private IPv4 literals only (RFC 1918 or the RFC 6598 shared space 100.64/10,
//     core/localnet), 1..MaxTargets of them, no domain, no public address;
//   - ScopeOwnIP (exposure): exactly one target, a public IPv4 literal (localnet.Public), at OwnIPRate, with the
//     classes of K-6 excluded on top of the forbidden tags. Like nmapargv's external shape, the grammar alone cannot
//     tell the box's own IP from anyone's: the worker checks right before nuclei that the box leaves the Internet through
//     that address (core/egressip, the same fence as nmap's external shape), and refuses the job otherwise.
//
// An own_ip job has a depth: "" is the shape above (the KEV templates the pack marks own_ip); DepthFull is the deep scan of
// a target whose testing terms were accepted (exposure FULL-1): the same one public IPv4 and the same worker fence, at FullRate with
// FullConcurrency templates at a time (gentle: GentleFullRate with GentleFullConcurrency), up to MaxFullTemplates templates a run,
// and -etags of FullForbiddenTags: dos only with
// Disruptive, the extra tick of the terms. A LAN job has no depth.
//
// No domain in any scope: a name could resolve to loopback or the metadata address.
//
// The flags are those of the nuclei version pinned in the scan image; a new pinned version is checked against this
// list in the lab before it ships (docs/specs/sensor-protocol.md).
package nucleiargv

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/localnet"
)

// TemplatesDir is where the signed scan image keeps the safe template pack. Every template nuclei loads is
// one file under it, named on the command line (M2): never the whole directory.
const TemplatesDir = "/usr/share/vedette/nuclei-templates"

// ErrorLog is where nuclei writes its error log: the worker's stderr pipe, never a file.
const ErrorLog = "/dev/stderr"

// Limits of a job.
const (
	MaxTemplates  = 32
	MaxTargets    = 16
	MaxRate       = 20 // requests per second, the scan module's rate (INV-5)
	MinHostErrors = 2
	MaxHostErrors = 20
	// MaxOutput caps what one nuclei run may print (JSONL); more is discarded (sensor protocol §9). The only copy.
	MaxOutput = 4 << 20
)

// forbiddenTags are the template tags that may never run (INV-4, FORBID-2): the pack refuses them, and nuclei is told
// to exclude them as a second fence. One list for both; unexported so nobody can change it after fixedFlags read it. The one
// exception: dos runs in a full job with the extra tick of the terms, from the pack's disruptive set only.
var forbiddenTags = []string{"dos", "intrusive", "fuzz"}

// ForbiddenTags returns a copy of the tags that may never run.
func ForbiddenTags() []string { return slices.Clone(forbiddenTags) }

// The scopes of a job. "" is ScopeLAN: a job of a core that does not send the scope.
const (
	ScopeLAN   = "lan"
	ScopeOwnIP = "own_ip"
)

// OwnIPRate is the only rate of the own_ip scope (requests a second): one public address, the customer's own.
const OwnIPRate = 5

// ownIPForbiddenTags are the tags kept off the box's own public IP on top of
// forbiddenTags: nothing that tries a login or a credential, guesses, injects, runs a command or uploads. The real fence is the
// pack's per-template own_ip decision (pack.Template.OwnIP, made when the pack is built and checked again by the worker on the
// template file): a template of these tags is never marked own_ip. nuclei is told to exclude them as well (-etags of
// ownIPFlags); how nuclei 3.11.1 applies -etags to a template named with -t is not lab-checked, so nothing relies on it.
var ownIPForbiddenTags = []string{"default-login", "brute-force", "sqli", "time-based-sqli", "xss", "injection", "code-injection",
	"argument-injection", "ssti", "file-upload", "rce", "authenticated", "login"}

// OwnIPForbiddenTags returns a copy of the tags an own_ip job never runs, forbiddenTags included.
func OwnIPForbiddenTags() []string { return append(slices.Clone(forbiddenTags), ownIPForbiddenTags...) }

// DepthFull is the depth of an own_ip job of a target whose testing terms were accepted.
const DepthFull = "full"

// The full shape. nuclei's own defaults are -rl 150 -c 25 -bs 25 (docs.projectdiscovery.io/tools/nuclei/running, Rate
// Limits), sized for many hosts from a big machine; a full job has one host (so -bs 1) behind the customer's own uplink and runs on a
// small 4-core box next to core: 20 requests a second (the scan module's ceiling, MaxRate) with 10 templates in flight, so a target
// that answers within half a second keeps the rate busy. To be measured on such a box.
const (
	FullRate         = 20
	FullConcurrency  = 10
	MaxFullTemplates = 200 // per run: 200 ids of at most 100 bytes keep the jobs reply under sensorlink's 64 KiB, and its lines under the limit of nucleiout.LinesPerTemplate
)

// The gentle speed of a deep scan (a target's deep-scan settings): a full job at GentleFullRate with GentleFullConcurrency templates in
// flight, a fifth of the normal rate. The job's own rate says which: a worker that does not know the gentle shape refuses the rate
// (fail closed). The template step's bounds stretch by TimeScale.
const (
	GentleFullRate        = 4
	GentleFullConcurrency = 2
)

// TimeScale is how many times longer the templates of a full job take at rate than at FullRate: 1 at FullRate, FullRate /
// GentleFullRate at the gentle rate, 0 for a rate that is no full rate.
func TimeScale(rate int) int {
	switch rate {
	case FullRate:
		return 1
	case GentleFullRate:
		return FullRate / GentleFullRate
	}
	return 0
}

// HostErrors is the -mhe of an own_ip job of the shape of depth and rate: nuclei gives a port up only after two whole waves of the
// templates the shape keeps in flight time out with no answer in between, never fewer than DefaultHostErrors. In nuclei 3.11.1
// (pkg/protocols/common/hosterrorscache) the count is per host:port, only HTTP requests feed it (timeouts, refused or reset
// connections), one answer resets it, and a permanent error gives the port up at once whatever -mhe says: connection refused, or
// (fastdialer) a run whose first connection to the port failed ("port closed or filtered"). A full job keeps FullConcurrency
// templates in flight, so one burst of a slow port (an HTTPS admin page under load) can time out all of them together: 3 dropped
// such a port at its first burst. 20 waits for a second silent wave, still inside the 2..20 every released worker accepts (nuclei's
// own default is 30, sized for -c 25). The gentle shape (2 in flight) gets 4, an own_ip job without depth (1 in flight) keeps 3.
// A LAN job's -mhe is the scan module's unresponsive_after setting, not this.
func HostErrors(depth string, rate int) int {
	inFlight := 1
	if depth == DepthFull {
		inFlight = FullConcurrency
		if rate == GentleFullRate {
			inFlight = GentleFullConcurrency
		}
	}
	return min(max(2*inFlight, DefaultHostErrors), MaxHostErrors)
}

// DefaultHostErrors is the -mhe of a job that runs one template at a time (the scan module's default unresponsive_after).
const DefaultHostErrors = 3

// disruptiveTags are the tags of the disruptive checks: only a full job with the extra tick of the terms runs them.
// brute-force and default-login try passwords, authenticated logs in with a user name and password of the template's own, dos may
// stop the service.
var disruptiveTags = []string{"dos", "brute-force", "default-login", "authenticated"}

// DisruptiveTags returns a copy of the tags of the disruptive checks.
func DisruptiveTags() []string { return slices.Clone(disruptiveTags) }

// FullForbiddenTags is the -etags of a full job: without the tick forbiddenTags and the disruptive tags (a second fence behind the
// pack's sets); with it forbiddenTags without dos (intrusive and fuzz write, delete or change state: never, at any depth).
func FullForbiddenTags(disruptive bool) []string {
	if disruptive {
		return slices.DeleteFunc(slices.Clone(forbiddenTags), func(t string) bool { return t == "dos" })
	}
	out := slices.Clone(forbiddenTags)
	for _, t := range disruptiveTags {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// fixedFlags is the part of every line that never changes:
//
//	-jsonl -silent -nc   one JSON object per line on stdout, nothing else
//	-duc                 no update check (no request to GitHub from the scan container)
//	-ni                  no interactsh: out-of-band hosts are outside every scope
//	-ms                  one line per template and target also when nothing matched, with the error (INV-6)
//	-dr                  no redirect is followed: a device cannot send nuclei elsewhere
//	-nh                  no httpx probing of the targets: only the ports core named
//	-etags <ForbiddenTags>
//	-pt http,tcp,ssl     only these protocols run (an allow-list): no dns or whois (they would ask public
//	                     resolvers about the target), no javascript, websocket, headless, code or file templates
//	-elog /dev/stderr    nuclei's own error log (one JSON object per failed request, with input, address, kind) on
//	                     stderr: the worker counts network timeouts per target from it, so core learns that a device
//	                     stopped answering after it had answered some templates (INV-6)
//	-c 1 -bs 1           one template and one target at a time, so -rl is the whole load on a device
//	-timeout 10 -retries 1
var fixedFlags = []string{
	"-jsonl", "-silent", "-nc",
	"-duc", "-ni", "-ms", "-dr", "-nh",
	"-etags", strings.Join(forbiddenTags, ","),
	"-pt", "http,tcp,ssl",
	"-elog", ErrorLog,
	"-c", "1", "-bs", "1",
	"-timeout", "10", "-retries", "1",
}

// ownIPFlags are fixedFlags with the -etags of the own_ip scope (OwnIPForbiddenTags): the same length, so the two shapes differ
// only there, and Validate tells them apart by it.
var ownIPFlags = func() []string {
	f := slices.Clone(fixedFlags)
	f[slices.Index(f, "-etags")+1] = strings.Join(OwnIPForbiddenTags(), ",")
	return f
}()

// fullFlags are fixedFlags with the -etags of a full job (FullForbiddenTags), -c FullConcurrency, and two more:
//
//	-or -ot   no request and response pair and no encoded template in a finding's line (nuclei 3.11.1 -omit-raw, -omit-template):
//	          up to MaxFullTemplates templates on one page could otherwise print its body once per match, past MaxOutput; a full
//	          result keeps the template id, name, severity and port, never the evidence
//
// fullDisruptiveFlags are those of a full job with the tick; the gentle ones have -c GentleFullConcurrency instead.
var (
	fullFlags, fullDisruptiveFlags             = fullFlagsOf(false, FullConcurrency), fullFlagsOf(true, FullConcurrency)
	gentleFullFlags, gentleFullDisruptiveFlags = fullFlagsOf(false, GentleFullConcurrency), fullFlagsOf(true, GentleFullConcurrency)
)

func fullFlagsOf(disruptive bool, concurrency int) []string {
	f := slices.Clone(fixedFlags)
	f[slices.Index(f, "-etags")+1] = strings.Join(FullForbiddenTags(disruptive), ",")
	f[slices.Index(f, "-c")+1] = strconv.Itoa(concurrency)
	return append(f, "-or", "-ot")
}

// flagsOf is the fixed part of a job's line; nil for a scope or depth that does not exist, or a combination that may not be
// (a depth outside own_ip, the tick without the depth). A full job at GentleFullRate has the gentle flags.
func flagsOf(scope, depth string, disruptive bool, rate int) []string {
	gentle := depth == DepthFull && rate == GentleFullRate
	switch {
	case gentle && scope == ScopeOwnIP && disruptive:
		return gentleFullDisruptiveFlags
	case gentle && scope == ScopeOwnIP:
		return gentleFullFlags
	case depth == "" && disruptive:
		return nil
	case depth == "" && (scope == "" || scope == ScopeLAN):
		return fixedFlags
	case depth == "" && scope == ScopeOwnIP:
		return ownIPFlags
	case depth == DepthFull && scope == ScopeOwnIP && disruptive:
		return fullDisruptiveFlags
	case depth == DepthFull && scope == ScopeOwnIP:
		return fullFlags
	}
	return nil
}

// Job is what a nuclei run is made of. On the wire a job names template ids; the worker turns them into the paths of
// its verified index before it builds the line (M2), so Templates here are paths.
type Job struct {
	Templates     []string // template files relative to TemplatesDir, from the verified index, 1..MaxTemplates
	Targets       []Target // 1..MaxTargets
	Rate          int      // requests per second, 1..MaxRate
	MaxHostErrors int      // nuclei stops sending to a target after this many errors in a row (INV-6), 2..20
	Scope         string   // ScopeLAN ("" too) or ScopeOwnIP
	Depth         string   // "" or DepthFull (own_ip only): 1..MaxFullTemplates templates at FullRate
	Disruptive    bool     // a full job with the extra tick of the terms: dos is not excluded
}

// Target is one place nuclei sends requests to: a host and a port, with the scheme of the HTTP templates, or no
// scheme for the network ones.
type Target struct {
	Host   string // canonical private IPv4 address
	Port   int
	Scheme string // "http", "https" or "" (host:port)
}

// Input is the -u value of the target: scheme://host:port, or host:port without a scheme.
func (t Target) Input() string {
	hp := t.Host + ":" + strconv.Itoa(t.Port)
	if t.Scheme == "" {
		return hp
	}
	return t.Scheme + "://" + hp
}

var pathRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*\.yaml$`)

// ValidTemplatePath says whether p can name a template file of the pack: a relative .yaml path of plain segments.
func ValidTemplatePath(p string) bool {
	return len(p) <= 200 && pathRE.MatchString(p) && !strings.Contains(p, "..")
}

// validHost accepts only a canonical private IPv4 literal (RFC 1918 or RFC 6598, localnet.Addr) that is not the
// network or broadcast address of a /24: the same fence as nmapargv. No domain (it could resolve to loopback or the
// metadata address), no public IP, and never the Alibaba Cloud metadata address 100.100.100.200, which lies in 100.64/10
// (nuclei keeps up to 4 KB of an answer as evidence, which can reach an AI provider). nmap may still probe it.
func validHost(h string) bool {
	a, err := netip.ParseAddr(h)
	if err != nil || a.String() != h || !localnet.Addr(a) || a == metadataV4 {
		return false
	}
	last := a.As4()[3]
	return last != 0 && last != 255
}

// metadataV4 is the cloud metadata endpoint inside the local networks (core/netguard lists it too; this leaf may not import it).
var metadataV4 = netip.AddrFrom4([4]byte{100, 100, 100, 200})

// validPublic accepts only a canonical public IPv4 literal (localnet.Public: not private, shared, loopback, link-local,
// documentation, multicast or reserved): the target of the own_ip scope.
func validPublic(h string) bool {
	a, err := netip.ParseAddr(h)
	return err == nil && a.Is4() && a.String() == h && localnet.Public(a)
}

// valid checks a target of a scope: a private address for ScopeLAN, a public one for ScopeOwnIP.
func (t Target) valid(scope string) bool {
	hostOK := validHost(t.Host)
	if scope == ScopeOwnIP {
		hostOK = validPublic(t.Host)
	}
	return hostOK && t.Port >= 1 && t.Port <= 65535 && (t.Scheme == "" || t.Scheme == "http" || t.Scheme == "https")
}

// Build builds the nuclei command line of a job: the fixed flags of its scope, -rl, -mhe, one -t per template file, then one
// -u per target. It refuses a job outside the limits above; an own_ip job takes exactly one public target at OwnIPRate, a full one
// at FullRate (or GentleFullRate, with the gentle flags) with up to MaxFullTemplates templates.
func Build(j Job) ([]string, error) {
	flags := flagsOf(j.Scope, j.Depth, j.Disruptive, j.Rate)
	if flags == nil {
		return nil, fmt.Errorf("nucleiargv: scope %.20q with depth %.20q (disruptive %t) is not a shape of a job", j.Scope, j.Depth, j.Disruptive)
	}
	rate, most := OwnIPRate, MaxTemplates
	if j.Depth == DepthFull {
		rate, most = FullRate, MaxFullTemplates
		if j.Rate == GentleFullRate {
			rate = GentleFullRate
		}
	}
	if j.Scope == ScopeOwnIP && (len(j.Targets) != 1 || j.Rate != rate) {
		return nil, fmt.Errorf("nucleiargv: an own_ip run of depth %.20q takes exactly one target at %d requests a second, got %d at %d", j.Depth, rate, len(j.Targets), j.Rate)
	}
	if len(j.Templates) == 0 || len(j.Templates) > most {
		return nil, fmt.Errorf("nucleiargv: a run needs 1 to %d templates, got %d", most, len(j.Templates))
	}
	for i, p := range j.Templates {
		if !ValidTemplatePath(p) || slices.Contains(j.Templates[:i], p) {
			return nil, fmt.Errorf("nucleiargv: template %q is not a valid path or is repeated", p)
		}
	}
	if len(j.Targets) == 0 || len(j.Targets) > MaxTargets {
		return nil, fmt.Errorf("nucleiargv: a run needs 1 to %d targets, got %d", MaxTargets, len(j.Targets))
	}
	for i, t := range j.Targets {
		if !t.valid(j.Scope) || slices.Contains(j.Targets[:i], t) {
			return nil, fmt.Errorf("nucleiargv: target %q is not valid or repeated", t.Input())
		}
	}
	if j.Rate < 1 || j.Rate > MaxRate {
		return nil, fmt.Errorf("nucleiargv: rate %d is outside 1..%d", j.Rate, MaxRate)
	}
	if j.MaxHostErrors < MinHostErrors || j.MaxHostErrors > MaxHostErrors {
		return nil, fmt.Errorf("nucleiargv: max host errors %d is outside %d..%d", j.MaxHostErrors, MinHostErrors, MaxHostErrors)
	}
	args := slices.Clone(flags)
	args = append(args, "-rl", strconv.Itoa(j.Rate), "-mhe", strconv.Itoa(j.MaxHostErrors))
	for _, p := range j.Templates {
		args = append(args, "-t", TemplatesDir+"/"+p)
	}
	for _, t := range j.Targets {
		args = append(args, "-u", t.Input())
	}
	return args, nil
}

// Validate re-checks a whole argv before the process starts, independently of how it was made (SYS-2): it must be
// exactly what Build makes from some job Build accepts.
func Validate(args []string) error {
	j, err := parse(args)
	if err != nil {
		return err
	}
	again, err := Build(j)
	if err != nil {
		return err
	}
	if !slices.Equal(again, args) {
		return errors.New("nucleiargv: argv is not in the one allowed shape")
	}
	return nil
}

// parse reads the job back from an argv of Build's shape; the fixed flags say the scope.
func parse(args []string) (Job, error) {
	var j Job
	prefix := func(f []string) bool { return len(args) >= len(f)+8 && slices.Equal(args[:len(f)], f) }
	var n int
	switch {
	case prefix(fixedFlags):
		j.Scope, n = ScopeLAN, len(fixedFlags)
	case prefix(ownIPFlags):
		j.Scope, n = ScopeOwnIP, len(ownIPFlags)
	case prefix(fullFlags):
		j.Scope, j.Depth, n = ScopeOwnIP, DepthFull, len(fullFlags)
	case prefix(fullDisruptiveFlags):
		j.Scope, j.Depth, j.Disruptive, n = ScopeOwnIP, DepthFull, true, len(fullDisruptiveFlags)
	case prefix(gentleFullFlags):
		j.Scope, j.Depth, n = ScopeOwnIP, DepthFull, len(gentleFullFlags)
	case prefix(gentleFullDisruptiveFlags):
		j.Scope, j.Depth, j.Disruptive, n = ScopeOwnIP, DepthFull, true, len(gentleFullDisruptiveFlags)
	default:
		return Job{}, errors.New("nucleiargv: the fixed flags are not the allowed ones")
	}
	rest := args[n:]
	if rest[0] != "-rl" || rest[2] != "-mhe" {
		return Job{}, errors.New("nucleiargv: -rl and -mhe must follow the fixed flags")
	}
	var ok bool
	if j.Rate, ok = atoi(rest[1]); !ok {
		return Job{}, fmt.Errorf("nucleiargv: rate %q is not a number", rest[1])
	}
	if j.MaxHostErrors, ok = atoi(rest[3]); !ok {
		return Job{}, fmt.Errorf("nucleiargv: max host errors %q is not a number", rest[3])
	}
	pairs := rest[4:]
	if len(pairs)%2 != 0 {
		return Job{}, errors.New("nucleiargv: every -t and -u needs a value")
	}
	i := 0
	for ; i < len(pairs) && pairs[i] == "-t"; i += 2 {
		p, ok := strings.CutPrefix(pairs[i+1], TemplatesDir+"/")
		if !ok {
			return Job{}, fmt.Errorf("nucleiargv: template %q is outside %s", pairs[i+1], TemplatesDir)
		}
		j.Templates = append(j.Templates, p)
	}
	for ; i < len(pairs); i += 2 {
		if pairs[i] != "-u" {
			return Job{}, fmt.Errorf("nucleiargv: %q where -u was expected", pairs[i])
		}
		t, ok := parseInput(pairs[i+1], j.Scope)
		if !ok {
			return Job{}, fmt.Errorf("nucleiargv: target %q is not scheme://host:port or host:port", pairs[i+1])
		}
		j.Targets = append(j.Targets, t)
	}
	return j, nil
}

// parseInput is the inverse of Target.Input for canonical inputs of a scope.
func parseInput(in, scope string) (Target, bool) {
	var t Target
	hp := in
	if scheme, rest, ok := strings.Cut(in, "://"); ok {
		t.Scheme, hp = scheme, rest
	}
	i := strings.LastIndexByte(hp, ':')
	if i < 0 {
		return Target{}, false
	}
	port, ok := atoi(hp[i+1:])
	if !ok {
		return Target{}, false
	}
	t.Host, t.Port = hp[:i], port
	if !t.valid(scope) || t.Input() != in {
		return Target{}, false
	}
	return t, true
}

// atoi accepts only plain decimal digits (no sign, no spaces, no leading zero), up to 5 digits.
func atoi(s string) (int, bool) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

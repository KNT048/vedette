// Package nucleiargv builds and checks the only nuclei command line Vedette ever runs (D-125 (2)). It is a leaf:
// standard library only, no database and no core/exec, because the sensor binary links it, and both sides use the
// same code: core before it hands a job over, the worker in the scan container before nuclei starts (SYS-2). Like
// nmapargv, a job on the wire carries no argv, flag, path or URL (D-111 (3)): the worker builds the line from the
// job's fields with Build, then checks it with Validate.
//
// The worker's grammar is the last fence against a compromised core (D-113 (3)), so it is as narrow as nmapargv's. A job has
// a scope (D-520):
//   - ScopeLAN (the scan module): private IPv4 literals only (RFC 1918 or the RFC 6598 shared space 100.64/10,
//     core/localnet, D-461), 1..MaxTargets of them, no domain, no public address;
//   - ScopeOwnIP (exposure, D-561): exactly one target, a public IPv4 literal (localnet.Public), at OwnIPRate, with the
//     classes of K-6 (D-559) excluded on top of the forbidden tags. Like nmapargv's external shape, the grammar alone cannot
//     tell the box's own IP from anyone's: the worker checks right before nuclei that the box leaves the Internet through
//     that address (core/egressip, the same fence as nmap's external shape), and refuses the job otherwise.
//
// No domain in any scope: a name could resolve to loopback or the metadata address.
//
// The flags are those of the nuclei version pinned in the scan image; a new pinned version is checked against this
// list in the lab before it ships (docs/specs/sensor-protocol.md, D-116 (5)).
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

// TemplatesDir is where the signed scan image keeps the safe template pack (D-125 (4)). Every template nuclei loads is
// one file under it, named on the command line (M2): never the whole directory.
const TemplatesDir = "/usr/share/vedette/nuclei-templates"

// ErrorLog is where nuclei writes its error log: the worker's stderr pipe, never a file.
const ErrorLog = "/dev/stderr"

// Limits of a job (D-125 (1)).
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
// to exclude them as a second fence. One list for both; unexported so nobody can change it after fixedFlags read it.
var forbiddenTags = []string{"dos", "intrusive", "fuzz"}

// ForbiddenTags returns a copy of the tags that may never run.
func ForbiddenTags() []string { return slices.Clone(forbiddenTags) }

// The scopes of a job (D-520). "" is ScopeLAN: a job of a core that does not send the scope.
const (
	ScopeLAN   = "lan"
	ScopeOwnIP = "own_ip"
)

// OwnIPRate is the only rate of the own_ip scope (requests a second, D-561): one public address, the customer's own.
const OwnIPRate = 5

// ownIPForbiddenTags are the classes D-559 K-6 keeps off the box's own public IP on top of forbiddenTags: nothing that tries a
// login or a credential, guesses, injects or uploads. Core and the worker leave a template that carries one out of an own_ip
// job; nuclei is told to exclude them as well (-etags of ownIPFlags), the second fence.
var ownIPForbiddenTags = []string{"default-login", "brute-force", "sqli", "xss", "injection", "file-upload"}

// OwnIPForbiddenTags returns a copy of the tags an own_ip job never runs, forbiddenTags included.
func OwnIPForbiddenTags() []string { return append(slices.Clone(forbiddenTags), ownIPForbiddenTags...) }

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
//	                     stopped answering after it had answered some templates (INV-6, D-165)
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

// flagsOf is the fixed part of a scope's line; nil for a scope that does not exist.
func flagsOf(scope string) []string {
	switch scope {
	case "", ScopeLAN:
		return fixedFlags
	case ScopeOwnIP:
		return ownIPFlags
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

// validHost accepts only a canonical private IPv4 literal (RFC 1918 or RFC 6598, localnet.Addr, D-461) that is not the
// network or broadcast address of a /24: the same fence as nmapargv. No domain (it could resolve to loopback or the
// metadata address), no public IP, and never the Alibaba Cloud metadata address 100.100.100.200, which lies in 100.64/10
// (nuclei keeps up to 4 KB of an answer as evidence, which can reach an AI provider; D-461 (5)). nmap may still probe it.
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
// -u per target. It refuses a job outside the limits above; an own_ip job takes exactly one public target at OwnIPRate.
func Build(j Job) ([]string, error) {
	flags := flagsOf(j.Scope)
	if flags == nil {
		return nil, fmt.Errorf("nucleiargv: scope %.20q is not lan or own_ip", j.Scope)
	}
	if j.Scope == ScopeOwnIP && (len(j.Targets) != 1 || j.Rate != OwnIPRate) {
		return nil, fmt.Errorf("nucleiargv: an own_ip run takes exactly one target at %d requests a second, got %d at %d", OwnIPRate, len(j.Targets), j.Rate)
	}
	if len(j.Templates) == 0 || len(j.Templates) > MaxTemplates {
		return nil, fmt.Errorf("nucleiargv: a run needs 1 to %d templates, got %d", MaxTemplates, len(j.Templates))
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
	n := len(fixedFlags)
	var j Job
	switch {
	case len(args) < n+8:
		return Job{}, errors.New("nucleiargv: the fixed flags are not the allowed ones")
	case slices.Equal(args[:n], fixedFlags):
		j.Scope = ScopeLAN
	case slices.Equal(args[:n], ownIPFlags):
		j.Scope = ScopeOwnIP
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

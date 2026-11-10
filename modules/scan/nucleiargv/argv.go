// Package nucleiargv builds and checks the only nuclei command line Vedette ever runs (D-125 (2)). It is a leaf:
// standard library only, no database and no core/exec, because the sensor binary links it, and both sides use the
// same code: core before it hands a job over, the worker in the scan container before nuclei starts (SYS-2). Like
// nmapargv, a job on the wire carries no argv, flag, path or URL (D-111 (3)): the worker builds the line from the
// job's fields with Build, then checks it with Validate.
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
)

// TemplatesDir is where the signed scan image keeps the safe template pack (D-125 (4)). Nuclei reads templates
// from nowhere else.
const TemplatesDir = "/usr/share/vedette/nuclei-templates"

// Limits of a job (D-125 (1)).
const (
	MaxTemplates  = 32
	MaxTargets    = 16
	MaxRate       = 20 // requests per second, the scan module's rate (INV-5)
	MinHostErrors = 2
	MaxHostErrors = 20
	// MaxOutput caps what one nuclei run may print (JSONL); more is discarded (sensor protocol §9).
	MaxOutput = 4 << 20
)

// fixedFlags is the part of every line that never changes:
//
//	-t TemplatesDir        only the signed pack baked into the image
//	-jsonl -silent -nc     one JSON object per line on stdout, nothing else
//	-duc                   no update check (no request to GitHub from the scan container)
//	-ni                    no interactsh: out-of-band hosts are outside every scope, and templates that need them are skipped
//	-ms                    one line per template and target also when nothing matched, with the error, for the
//	                       non-response count of INV-6
//	-etags dos,intrusive,fuzz, -ept headless,code,file
//	                       a second fence behind the pack builder (INV-4): no such template runs even if one slipped in
//	-c 1 -bs 1             one template and one target at a time, so -rl is the whole load on a device
//	-timeout 10 -retries 1 a slow device gets one more try, not a storm
var fixedFlags = []string{
	"-t", TemplatesDir,
	"-jsonl", "-silent", "-nc",
	"-duc", "-ni", "-ms",
	"-etags", "dos,intrusive,fuzz",
	"-ept", "headless,code,file",
	"-c", "1", "-bs", "1",
	"-timeout", "10", "-retries", "1",
}

// Job is what a nuclei run is made of: the fields of a job on the sensor link (D-125 (1)).
type Job struct {
	Templates     []string // template ids of the pack, 1..MaxTemplates
	Targets       []Target // 1..MaxTargets
	Rate          int      // requests per second, 1..MaxRate
	MaxHostErrors int      // nuclei stops sending to a target after this many errors in a row (INV-6), 2..20
}

// Target is one place nuclei sends requests to: a host and a port, with the scheme of the HTTP templates, or no
// scheme for the network ones.
type Target struct {
	Host   string // canonical IPv4 address or lower-case domain name
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

var (
	templateRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	labelRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tldRE      = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidTemplate says whether id can be a template id on the line: no comma (the list separator), no leading dash.
func ValidTemplate(id string) bool { return templateRE.MatchString(id) && !strings.Contains(id, "..") }

// validHost accepts a canonical unicast IPv4 address that can belong to a device (not loopback, unspecified,
// link-local, multicast or broadcast), or a lower-case domain name of at least two labels whose last label starts
// with a letter. Whether the host is in scope is core's question (D-113 (3)); this is the grammar.
func validHost(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Is4() && a.String() == h && a.IsGlobalUnicast()
	}
	if len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 || !tldRE.MatchString(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	return true
}

func (t Target) valid() bool {
	return validHost(t.Host) && t.Port >= 1 && t.Port <= 65535 && (t.Scheme == "" || t.Scheme == "http" || t.Scheme == "https")
}

// Build builds the nuclei command line of a job: the fixed flags, -rl, -mhe, -id with the template ids, then one -u per
// target. It refuses a job outside the limits above.
func Build(j Job) ([]string, error) {
	if len(j.Templates) == 0 || len(j.Templates) > MaxTemplates {
		return nil, fmt.Errorf("nucleiargv: a run needs 1 to %d templates, got %d", MaxTemplates, len(j.Templates))
	}
	for i, id := range j.Templates {
		if !ValidTemplate(id) || slices.Contains(j.Templates[:i], id) {
			return nil, fmt.Errorf("nucleiargv: template id %q is not valid or repeated", id)
		}
	}
	if len(j.Targets) == 0 || len(j.Targets) > MaxTargets {
		return nil, fmt.Errorf("nucleiargv: a run needs 1 to %d targets, got %d", MaxTargets, len(j.Targets))
	}
	for i, t := range j.Targets {
		if !t.valid() || slices.Contains(j.Targets[:i], t) {
			return nil, fmt.Errorf("nucleiargv: target %q is not valid or repeated", t.Input())
		}
	}
	if j.Rate < 1 || j.Rate > MaxRate {
		return nil, fmt.Errorf("nucleiargv: rate %d is outside 1..%d", j.Rate, MaxRate)
	}
	if j.MaxHostErrors < MinHostErrors || j.MaxHostErrors > MaxHostErrors {
		return nil, fmt.Errorf("nucleiargv: max host errors %d is outside %d..%d", j.MaxHostErrors, MinHostErrors, MaxHostErrors)
	}
	args := slices.Clone(fixedFlags)
	args = append(args, "-rl", strconv.Itoa(j.Rate), "-mhe", strconv.Itoa(j.MaxHostErrors), "-id", strings.Join(j.Templates, ","))
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

// parse reads the job back from an argv of Build's shape.
func parse(args []string) (Job, error) {
	n := len(fixedFlags)
	if len(args) < n+8 || !slices.Equal(args[:n], fixedFlags) {
		return Job{}, errors.New("nucleiargv: the fixed flags are not the allowed ones")
	}
	rest := args[n:]
	if rest[0] != "-rl" || rest[2] != "-mhe" || rest[4] != "-id" {
		return Job{}, errors.New("nucleiargv: -rl, -mhe and -id must follow the fixed flags")
	}
	var j Job
	var ok bool
	if j.Rate, ok = atoi(rest[1]); !ok {
		return Job{}, fmt.Errorf("nucleiargv: rate %q is not a number", rest[1])
	}
	if j.MaxHostErrors, ok = atoi(rest[3]); !ok {
		return Job{}, fmt.Errorf("nucleiargv: max host errors %q is not a number", rest[3])
	}
	j.Templates = strings.Split(rest[5], ",")
	pairs := rest[6:]
	if len(pairs)%2 != 0 {
		return Job{}, errors.New("nucleiargv: every target needs -u and a value")
	}
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i] != "-u" {
			return Job{}, fmt.Errorf("nucleiargv: %q where -u was expected", pairs[i])
		}
		t, ok := parseInput(pairs[i+1])
		if !ok {
			return Job{}, fmt.Errorf("nucleiargv: target %q is not scheme://host:port or host:port", pairs[i+1])
		}
		j.Targets = append(j.Targets, t)
	}
	return j, nil
}

// parseInput is the inverse of Target.Input for canonical inputs.
func parseInput(in string) (Target, bool) {
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
	if !t.valid() || t.Input() != in {
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

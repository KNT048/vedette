// Package nucleiout reads what the worker's nuclei run printed (-jsonl -ms) into results core can trust (
// INV-8, INV-10). The output came from a process that talked to devices an attacker may control, through a worker that
// may be compromised (SYS-6), so the parser fails closed: one line it cannot read without doubt throws the whole run
// away; it never returns a result for a template or a target (host and port) the job did not ask for; and evidence is
// capped, valid UTF-8, without control, format or separator characters, so it can be stored and shown as plain text.
//
// Unknown fields are ignored on purpose: nuclei adds fields between versions, and core reads only the few it needs.
// Repeated keys and keys that differ only by case are refused (internal/jsonstrict), because encoding/json would pick
// one of them silently. Standard library plus internal/jsonstrict and nucleiargv, so the sensor binary may link it too.
package nucleiout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// Limits (sensor protocol §9); the output cap is nucleiargv.MaxOutput.
const (
	MaxLines = 1024 // 32 templates x 16 targets is 512 lines with -ms; twice that is suspicious
	// LinesPerTemplate sizes the line limit of a run with many templates (a full run, up to 200 templates on one target):
	// MaxLines or this many lines a template, whichever is more. The assumption, from nuclei v3.11.1's -ms (one failure line per
	// template and target that matched nothing) and its JSONL writer (one line per matcher name, and per request of a template with
	// several, that matched): a template prints one line when nothing matched and one per match otherwise; tech-detect prints one per
	// product it recognised (tens), a payload template at most 64. 200 templates x 40 is 8000; the 4 MiB output cap (about 500 bytes
	// the shortest line with -or -ot) would stop a run near there anyway. Lab check deferred.
	LinesPerTemplate = 40
	MaxRequest       = 2048 // bytes of request kept as evidence (S-SCAN-3)
	MaxResponse      = 4096 // bytes of response kept as evidence
	MaxError         = 256  // bytes of nuclei's error text
)

// cutMark ends a text that was cut at its cap.
const cutMark = " …(cut)"

// Result is one line of the run: one template on one target.
type Result struct {
	Template string // template id, one of the job's
	Target   string // host:port, one of the job's targets
	Matched  bool   // the template's matchers matched: the flaw is there (INV-8)
	Request  string // cleaned and capped
	Response string // cleaned and capped
	Error    string // cleaned and capped; non-empty when the target did not answer properly (INV-6)
	// MatcherName is the name of the matcher that matched, cleaned and capped at MaxMatcherName (a technologies template
	// such as tech-detect names the product it found there; core keeps only a name that is a product tag of the pack).
	MatcherName string
}

// MaxMatcherName caps a matcher name.
const MaxMatcherName = 64

// line is the part of nuclei's JSON line core reads.
type line struct {
	TemplateID    string `json:"template-id"`
	Host          string `json:"host"`
	Port          string `json:"port"`
	MatcherStatus *bool  `json:"matcher-status"`
	Request       string `json:"request"`
	Response      string `json:"response"`
	Error         string `json:"error"`
	MatcherName   string `json:"matcher-name"`
}

// Skipped says what Read left out: Lines lines of the job's templates whose JSON is valid but
// that cannot be a result of the job: about a host:port the job did not name, a target that cannot be read, no matcher-status, a
// match with an error. Matched counts the ones that said matched; MatchedTemplates are their templates (every one, all of the
// job's): such a template never reads "no match reported", its result is inconclusive (InconclusiveNote). Templates are the first
// MaxSkippedTemplates distinct templates of the skipped lines and MoreTemplates how many more there were; Template, Host and Port
// are the first line's (Host is "(unreadable)" when its target could not be read; each checked and clipped, safe to log and store).
type Skipped struct {
	Lines, Matched   int
	MatchedTemplates []string
	Templates        []string
	MoreTemplates    int
	Template, Host   string
	Port             string
}

// InconclusiveNote is the note of a template a skipped line said matched (review r2 M3): no finding, never "no match".
const InconclusiveNote = "nuclei reported a match it could not tie to this address; check by hand"

// OverCapNote is the note of a template without a result when more templates had skipped lines than Skipped names (review r2 L5).
const OverCapNote = " [not run (over the cap of 20 templates per run)]"

// MaxSkippedHost caps the host of a skipped line as it is logged and stored; MaxSkippedTemplates the templates Skipped names.
const (
	MaxSkippedHost      = 64
	MaxSkippedTemplates = 20
)

// unreadable is the Host of a skipped line whose target could not be read: never the raw text.
const unreadable = "(unreadable)"

// clusterName is the Template of Skipped when its first line was a cluster's skip line (it names no template of the job).
const clusterName = "(a cluster of templates)"

// Note is the text the probe log and the core log carry for the skipped lines; "" when nothing was skipped. It goes after the
// request text of a probe row (AppendNote), so it never hides what was sent.
func (s Skipped) Note() string {
	if s.Lines == 0 {
		return ""
	}
	m := ""
	if s.Matched > 0 {
		m = fmt.Sprintf(", %d said matched", s.Matched)
	}
	return fmt.Sprintf(" [not counted: %d nuclei line(s) that could not be a result of this check (another address, an unreadable target, no match status, or a match with an error)%s; first: %s on %s:%s]", s.Lines, m, s.Template, s.Host, s.Port)
}

// AppendNote puts note after request within limit characters: the note is cut, never the request (review r1 L7).
func AppendNote(request, note string, limit int) string {
	room := limit - utf8.RuneCountInString(request)
	if room <= 0 || note == "" {
		return request
	}
	if r := []rune(note); len(r) > room {
		note = string(r[:room])
	}
	return request + note
}

// clusterID is the id nuclei 3.11.1 gives a cluster of templates that send the same request: "cluster-" and a SHA-256 in hex.
var clusterID = regexp.MustCompile(`^cluster-[0-9a-f]{64}$`)

// errSkip marks a line Read skips: valid JSON of one of the job's templates that cannot be a result of the job.
var errSkip = errors.New("a line that cannot be a result of the job")

// Parse reads a whole run (Read) and returns its results only.
func Parse(out []byte, templates, targets []string) ([]Result, error) {
	res, _, err := Read(out, templates, targets)
	return res, err
}

// Read reads a whole run. templates are the job's template ids and targets its host:port pairs. Output over the cap, a line that
// is not valid JSON (or is ambiguous) and a line for a template outside the job throw the run away; any other line that cannot be a
// result of the job is skipped and counted in Skipped.
func Read(out []byte, templates, targets []string) ([]Result, Skipped, error) {
	var skip Skipped
	if len(out) > nucleiargv.MaxOutput {
		return nil, skip, fmt.Errorf("nucleiout: output of %d bytes is over the %d cap", len(out), nucleiargv.MaxOutput)
	}
	limit := max(MaxLines, LinesPerTemplate*len(templates)) // a full run of 200 templates: 8000
	var res []Result
	over := map[string]bool{} // templates of skipped lines past MaxSkippedTemplates
	for i, raw := range bytes.Split(out, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		if len(res)+skip.Lines == limit {
			return nil, skip, fmt.Errorf("nucleiout: more than %d lines", limit)
		}
		r, err := parseLine(raw, templates, targets)
		if errors.Is(err, errSkip) {
			if skip.Lines == 0 {
				skip.Template, skip.Host, skip.Port = r.Template, unreadable, ""
				if r.Template == "" { // a cluster's skip line: name the cluster in the note and the log, never an empty template
					skip.Template = clusterName
				}
				if h, p, ok := strings.Cut(r.Target, ":"); ok {
					skip.Host, skip.Port = h, p
				}
			}
			skip.Lines++
			if r.Matched {
				skip.Matched++
				if !slices.Contains(skip.MatchedTemplates, r.Template) {
					skip.MatchedTemplates = append(skip.MatchedTemplates, r.Template) // one of the job's: bounded by it
				}
			}
			switch {
			case r.Template == "": // a cluster's skip line names no template of the job
			case slices.Contains(skip.Templates, r.Template):
			case len(skip.Templates) < MaxSkippedTemplates:
				skip.Templates = append(skip.Templates, r.Template)
			case !over[r.Template]:
				over[r.Template] = true
				skip.MoreTemplates++
			}
			continue
		}
		if err != nil {
			return nil, skip, fmt.Errorf("nucleiout: line %d: %w", i+1, err)
		}
		res = append(res, r)
	}
	return res, skip, nil
}

// parseLine reads one line. A line Read skips returns errSkip with only Template, Target (the foreign host:port, or "" when it
// could not be read; its host a plain name or address of at most MaxSkippedHost characters) and Matched set.
func parseLine(raw []byte, templates, targets []string) (Result, error) {
	if raw[0] != '{' {
		return Result{}, errors.New("not a JSON object")
	}
	if why := jsonstrict.Ambiguous(raw); why != "" {
		return Result{}, fmt.Errorf("ambiguous JSON: %s", why)
	}
	var l line
	if err := json.Unmarshal(raw, &l); err != nil {
		return Result{}, fmt.Errorf("not the expected JSON: %w", err)
	}
	if clusterID.MatchString(l.TemplateID) {
		// nuclei merges the job's templates that send the same request into a cluster; when it gives a host up as unresponsive it
		// prints one skip line per cluster under the cluster's id. Not a result of any template: skipped and counted, never named
		// as a template. A cluster line that is anything else (a match, no error) cannot be read without doubt.
		if l.MatcherStatus == nil || *l.MatcherStatus || l.Error == "" {
			return Result{}, errors.New("a cluster line that is not a skipped host")
		}
		return Result{Target: targetOf(l.Host, l.Port)}, errSkip
	}
	if !slices.Contains(templates, l.TemplateID) {
		return Result{}, errors.New("a template the job did not ask for")
	}
	// From here the line is valid JSON of one of the job's templates: what cannot be a result of the job is skipped and counted
	// (review r1 M6), never a reason to throw the run away.
	target := targetOf(l.Host, l.Port)
	matched := l.MatcherStatus != nil && *l.MatcherStatus
	if target == "" || l.MatcherStatus == nil || !slices.Contains(targets, target) || (matched && l.Error != "") {
		return Result{Template: l.TemplateID, Target: target, Matched: matched}, errSkip
	}
	return Result{
		Template: l.TemplateID, Target: target, Matched: *l.MatcherStatus,
		Request: Clean(l.Request, MaxRequest), Response: Clean(l.Response, MaxResponse), Error: Clean(l.Error, MaxError),
		MatcherName: Clean(l.MatcherName, MaxMatcherName),
	}, nil
}

// targetOf is the host:port a line is about. The pinned nuclei v3.11.1 writes "host" as the bare address with "port"
// apart (and "url" beside them), for http and tcp templates alike; its "host was skipped as it was found unresponsive"
// line has no port and keeps the input ("http://host:port") in "host" (lab VM, 2026-11-12, testdata/matched.jsonl).
// The older shapes ("host:port", a URL) still read through hostOf; when "port" is given too, the two must agree.
func targetOf(host, port string) string {
	if strings.Contains(host, ":") {
		t := hostOf(host)
		if port != "" && !strings.HasSuffix(t, ":"+port) {
			return ""
		}
		return t
	}
	// the bare shape: an IPv4 address in its canonical form (jobs name nothing else) and a strict decimal port, each checked
	// on its own so that text in either cannot make up the other (a "port" of "80/x" or "//10.0.0.5:80" is refused)
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return ""
	}
	if a, err := netip.ParseAddr(host); err != nil || !a.Is4() || a.String() != host {
		return ""
	}
	return host + ":" + port
}

// hostOf takes host:port out of nuclei's host field, which is "host:port" or "scheme://host[:port][/...]"; an http or
// https URL without a port gets the scheme's default port. User info, IPv6 brackets, another scheme, a bare host and
// anything else unusual give "", which no job names.
func hostOf(s string) string {
	scheme, rest, hasScheme := strings.Cut(s, "://")
	if !hasScheme {
		rest, scheme = s, ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || strings.ContainsAny(rest, "@[]") {
		return ""
	}
	host, port, hasPort := strings.Cut(rest, ":")
	if !plainHost(host) {
		return ""
	}
	switch {
	case hasPort:
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host == "" {
			return ""
		}
	case scheme == "http":
		port = "80"
	case scheme == "https":
		port = "443"
	default:
		return ""
	}
	if hasScheme && scheme != "http" && scheme != "https" {
		return ""
	}
	return host + ":" + port
}

// plainHost: an address or a DNS name of letters, digits, dots and hyphens, at most MaxSkippedHost characters. A job names only
// IPv4 addresses; a name can only be a skipped line's (a redirect elsewhere), which is logged and stored, so it must be plain.
func plainHost(h string) bool {
	if h == "" || len(h) > MaxSkippedHost {
		return false
	}
	for _, c := range []byte(h) {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// unsafeRune is a character evidence may not hold: anything of the categories Cc (controls), Cf (format: bidi
// controls, zero-width characters, the BOM, the soft hyphen, tag characters), Zl and Zp (line and paragraph
// separators), and the replacement character; newline and tab are kept.
func unsafeRune(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError || (r >= 0xe0000 && r <= 0xe007f) // the whole tag block, unassigned ones too
}

// Clean makes untrusted text safe to store and show as plain text: valid UTF-8, \r\n as \n, no unsafe characters,
// at most limit bytes cut on a character boundary and marked.
func Clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + cutMark
}

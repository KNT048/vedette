// Package nucleiout reads what the worker's nuclei run printed (-jsonl -ms) into results core can trust (D-125 (2),
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
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// Limits (sensor protocol §9, D-125 (1)); the output cap is nucleiargv.MaxOutput.
const (
	MaxLines = 1024 // 32 templates x 16 targets is 512 lines with -ms; twice that is suspicious
	// LinesPerTemplate sizes the line limit of a run with many templates (D-527: a full run, up to 200 templates on one target):
	// MaxLines or this many lines a template, whichever is more. The assumption, from nuclei v3.11.1's -ms (one failure line per
	// template and target that matched nothing) and its JSONL writer (one line per matcher name, and per request of a template with
	// several, that matched): a template prints one line when nothing matched and one per match otherwise; tech-detect prints one per
	// product it recognised (tens), a payload template at most 64. 200 templates x 40 is 8000; the 4 MiB output cap (about 500 bytes
	// the shortest line with -or -ot) would stop a run near there anyway. Lab check deferred (.ai/deferred/feat-full-4-nuclei.md).
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
	// MatcherName is the name of the matcher that matched, cleaned and capped at MaxMatcherName (D-527: a technologies template
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

// Parse reads a whole run. templates are the job's template ids and targets its host:port pairs; anything outside
// them is an error.
func Parse(out []byte, templates, targets []string) ([]Result, error) {
	if len(out) > nucleiargv.MaxOutput {
		return nil, fmt.Errorf("nucleiout: output of %d bytes is over the %d cap", len(out), nucleiargv.MaxOutput)
	}
	limit := max(MaxLines, LinesPerTemplate*len(templates)) // a full run of 200 templates (D-527): 8000
	var res []Result
	for i, raw := range bytes.Split(out, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		if len(res) == limit {
			return nil, fmt.Errorf("nucleiout: more than %d lines", limit)
		}
		r, err := parseLine(raw, templates, targets)
		if err != nil {
			return nil, fmt.Errorf("nucleiout: line %d: %w", i+1, err)
		}
		res = append(res, r)
	}
	return res, nil
}

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
	if !slices.Contains(templates, l.TemplateID) {
		return Result{}, errors.New("a template the job did not ask for")
	}
	target := targetOf(l.Host, l.Port)
	if target == "" || !slices.Contains(targets, target) {
		return Result{}, errors.New("a target the job did not name")
	}
	if l.MatcherStatus == nil {
		return Result{}, errors.New("no matcher-status")
	}
	if *l.MatcherStatus && l.Error != "" {
		return Result{}, errors.New("a match with an error")
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

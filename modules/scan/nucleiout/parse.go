// Package nucleiout reads what the worker's nuclei run printed (-jsonl -ms) into results core can trust (D-125 (2),
// INV-8, INV-10). The output came from a process that talked to devices an attacker may control, through a worker that
// may be compromised (SYS-6), so the parser fails closed: one line it cannot read without doubt throws the whole run
// away; it never returns a result for a template or a host the job did not ask for; and evidence is capped, valid
// UTF-8, without control or bidirectional-override characters, so it can be stored and shown as plain text.
//
// Unknown fields are ignored on purpose: nuclei adds fields between versions, and core reads only the few it needs.
// Repeated keys and keys that differ only by case are refused (internal/jsonstrict), because encoding/json would pick
// one of them silently. Standard library plus internal/jsonstrict, so the sensor binary may link it too.
package nucleiout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// Limits (sensor protocol §9, D-125 (1)).
const (
	MaxOutput   = 4 << 20 // bytes of JSONL in one run
	MaxLines    = 1024    // 32 templates x 16 targets is 512 lines with -ms; twice that is suspicious
	MaxRequest  = 2048    // bytes of request kept as evidence (S-SCAN-3)
	MaxResponse = 4096    // bytes of response kept as evidence
	MaxError    = 256     // bytes of nuclei's error text
)

// cutMark ends a text that was cut at its cap.
const cutMark = " …(cut)"

// Result is one line of the run: one template on one target.
type Result struct {
	Template string // template id, one of the job's
	Host     string // one of the job's hosts
	Matched  bool   // the template's matchers matched: the flaw is there (INV-8)
	Request  string // cleaned and capped
	Response string // cleaned and capped
	Error    string // cleaned and capped; non-empty when the target did not answer properly (INV-6)
}

// line is the part of nuclei's JSON line core reads.
type line struct {
	TemplateID    string `json:"template-id"`
	Host          string `json:"host"`
	MatcherStatus *bool  `json:"matcher-status"`
	Request       string `json:"request"`
	Response      string `json:"response"`
	Error         string `json:"error"`
}

// Parse reads a whole run. templates and hosts are those of the job; anything outside them is an error.
func Parse(out []byte, templates, hosts []string) ([]Result, error) {
	if len(out) > MaxOutput {
		return nil, fmt.Errorf("nucleiout: output of %d bytes is over the %d cap", len(out), MaxOutput)
	}
	var res []Result
	for i, raw := range bytes.Split(out, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		if len(res) == MaxLines {
			return nil, fmt.Errorf("nucleiout: more than %d lines", MaxLines)
		}
		r, err := parseLine(raw, templates, hosts)
		if err != nil {
			return nil, fmt.Errorf("nucleiout: line %d: %w", i+1, err)
		}
		res = append(res, r)
	}
	return res, nil
}

func parseLine(raw []byte, templates, hosts []string) (Result, error) {
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
	host := hostOf(l.Host)
	if host == "" || !slices.Contains(hosts, host) {
		return Result{}, errors.New("a host the job did not name")
	}
	if l.MatcherStatus == nil {
		return Result{}, errors.New("no matcher-status")
	}
	if *l.MatcherStatus && l.Error != "" {
		return Result{}, errors.New("a match with an error")
	}
	return Result{
		Template: l.TemplateID, Host: host, Matched: *l.MatcherStatus,
		Request: Clean(l.Request, MaxRequest), Response: Clean(l.Response, MaxResponse), Error: Clean(l.Error, MaxError),
	}, nil
}

// hostOf takes the host name out of nuclei's host field, which is "host", "host:port" or "scheme://host:port/...".
// User info, IPv6 brackets and anything else unusual give "", which no job names.
func hostOf(s string) string {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.ContainsAny(s, "@[]") {
		return ""
	}
	if h, port, ok := strings.Cut(s, ":"); ok {
		if port == "" || strings.Trim(port, "0123456789") != "" {
			return ""
		}
		s = h
	}
	return s
}

// unsafeRune is a character evidence may not hold: control characters other than newline and tab, and the
// bidirectional controls that can make text read differently from what it is.
func unsafeRune(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == utf8.RuneError
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

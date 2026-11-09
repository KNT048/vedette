package response

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// The steps that must not change anything (D-95): the check before and the read-back. The rules here are generic: no command of a
// vendor is named in code (D-58); the lists of commands a template may not contain are data (data/cli-ban.json).

// cliBan is data/cli-ban.json: patterns of command lines a template may not contain.
type cliBan struct {
	Everywhere    []string `json:"everywhere"`
	ReadOnlySteps []string `json:"read_only_steps"`
}

type banRules struct{ everywhere, readOnly []*regexp.Regexp }

var banData = sync.OnceValues(func() (banRules, error) {
	b, err := dataFiles.ReadFile("data/cli-ban.json")
	if err != nil {
		return banRules{}, fmt.Errorf("response: read cli-ban.json: %w", err)
	}
	var f cliBan
	if err := json.Unmarshal(b, &f); err != nil {
		return banRules{}, fmt.Errorf("response: parse cli-ban.json: %w", err)
	}
	var r banRules
	if r.everywhere, err = compileBan(f.Everywhere); err != nil {
		return banRules{}, err
	}
	if r.readOnly, err = compileBan(f.ReadOnlySteps); err != nil {
		return banRules{}, err
	}
	if len(r.everywhere) == 0 || len(r.readOnly) == 0 {
		return banRules{}, fmt.Errorf("response: cli-ban.json has an empty list")
	}
	return r, nil
})

// compileBan turns the patterns into anchored expressions: a line (lowercased, spaces collapsed) is refused when it starts with the
// pattern, at a word end; * matches any text.
func compileBan(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		p = strings.Join(strings.Fields(strings.ToLower(p)), " ")
		if p == "" {
			return nil, fmt.Errorf("response: cli-ban.json has an empty pattern")
		}
		re, err := regexp.Compile(`^` + strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, `.*`) + `(\s|$)`)
		if err != nil {
			return nil, fmt.Errorf("response: cli-ban.json pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// cliLines splits a command template into its lines: trimmed, spaces collapsed, lowercased, empty lines dropped.
func cliLines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.Join(strings.Fields(strings.ToLower(l)), " "); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func banHit(lines []string, res []*regexp.Regexp) string {
	for _, l := range lines {
		for _, re := range res {
			if re.MatchString(l) {
				return l
			}
		}
	}
	return ""
}

// stepSet is the four templates of one action.
type stepSet struct{ run, rollback, verify, pre Tpl }

// cliProblem checks the command lines of an action. custom: the lines of a customer's action (run and rollback too, spec 9.3); a
// built-in action is reviewed data, so only its check before and read-back are checked. The check before and the read-back may not
// contain a change command, and may share no line with the run or the rollback, except a first line that is the same in both (a
// pager or terminal setup line). "" when acceptable.
func cliProblem(s stepSet, custom bool) string {
	ban, err := banData()
	if err != nil {
		return "The list of refused commands could not be read, so no command was accepted."
	}
	for _, st := range []struct {
		what     string
		t        Tpl
		readOnly bool
		write    bool
	}{{"Action", s.run, false, true}, {"Rollback", s.rollback, false, true}, {"Read-back", s.verify, true, false}, {"Check before", s.pre, true, false}} {
		lines := cliLines(st.t.CLI)
		if len(lines) == 0 || (st.write && !custom) {
			continue
		}
		if l := banHit(lines, ban.everywhere); l != "" {
			return st.what + `: the command "` + oneLine(l, 60) + `" is not allowed in a template.`
		}
		if st.readOnly {
			if l := banHit(lines, ban.readOnly); l != "" {
				return st.what + `: the command "` + oneLine(l, 60) + `" can change the device. This step may only read.`
			}
		}
	}
	written := map[string]bool{}
	var firsts []string
	for _, w := range []Tpl{s.run, s.rollback} {
		if ls := cliLines(w.CLI); len(ls) > 0 {
			firsts = append(firsts, ls[0])
			for _, l := range ls {
				written[l] = true
			}
		}
	}
	for _, st := range []struct {
		what string
		t    Tpl
	}{{"Read-back", s.verify}, {"Check before", s.pre}} {
		for i, l := range cliLines(st.t.CLI) {
			if i == 0 && slicesContains(firsts, l) {
				continue
			}
			if written[l] {
				return st.what + `: the line "` + oneLine(l, 60) + `" is also a line of the action or its rollback. This step may only read.`
			}
		}
	}
	return ""
}

func slicesContains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// readBackProblem checks the read-back: it runs after the action and after the undo and must not change anything, so an API call
// is a GET without a body (spec 1.6, 9.1 (3)). "" when acceptable or empty.
func readBackProblem(t Tpl) string {
	if t.Empty() {
		return ""
	}
	if (t.Method != "" && t.Method != "GET") || strings.TrimSpace(t.Body) != "" {
		return "Read-back: an API call can only be a GET without a body. It must not change anything."
	}
	return ""
}

// ---- reading what the device printed (D-95 (2), amended 2026-11-10) ----

var ansiRE = regexp.MustCompile(`\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[@-Z\\-_])`)

// normalizeOutput makes device output comparable: ANSI escape sequences, carriage returns and other control characters are
// removed, runs of spaces and tabs become one space, and output that is JSON is compacted. Matching stays case-sensitive.
// It is pure: the executor (13b-6) calls it on the output it reads and then drops the output.
func normalizeOutput(s string) string {
	s = ansiRE.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case unicode.IsControl(r), r == 0x2028, r == 0x2029:
			return -1
		}
		return r
	}, s)
	out := collapseSpaces(s)
	if t := strings.TrimSpace(out); t != "" && (t[0] == '{' || t[0] == '[') && json.Valid([]byte(t)) {
		var c bytes.Buffer
		if err := json.Compact(&c, []byte(t)); err == nil {
			return c.String()
		}
	}
	return out
}

// containsText reports whether the normalised output holds the text: the text is normalised like the output (spaces collapsed),
// the comparison is a case-sensitive substring.
func containsText(normalized, text string) bool {
	return strings.Contains(normalized, collapseSpaces(text))
}

func collapseSpaces(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !space {
				b.WriteRune(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// precheckVerdict reads the output of a check before. It returns "" when the action may go ahead, otherwise the reason it is refused.
// Output that holds a refusal text refuses; output that lacks the required text (precheck_expect) refuses; output with nothing in
// it (after normalising) refuses: a silent device is not an all-clear (fail closed).
func precheckVerdict(output string, refuse []string, expect string) string {
	n := normalizeOutput(output)
	if strings.TrimSpace(n) == "" {
		return "the check before printed nothing"
	}
	for _, r := range refuse {
		if containsText(n, r) {
			return r
		}
	}
	if expect != "" && !containsText(n, expect) {
		return "the output does not contain: " + expect
	}
	return ""
}

// readBackHolds is the read-back judgement of D-95 (2): after the action the output must contain expect, after the undo it must not.
func readBackHolds(output, expect string, afterUndo bool) bool {
	return containsText(normalizeOutput(output), expect) != afterUndo
}

package response

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"

	"github.com/knt048/vedette/core/conn/cliban"
)

// The steps that must not change anything (D-95): the check before and the read-back. The rules here are generic: no command of a
// vendor is named in code (D-58); the lists of commands a template may not contain are data (core/conn/cliban/cli-ban.json).

// The lists of refused commands are data and live in one place, core/conn/cliban (data: cli-ban.json), which the writer reads too.
type banRules = cliban.Rules

func banData() (banRules, error) { return cliban.Load() }

// cliLines splits a command template into its lines: trimmed, spaces collapsed, lowercased, empty lines dropped.
func cliLines(s string) []string { return cliban.Lines(s) }

func banHit(lines []string, res []*regexp.Regexp) string { return cliban.Hit(lines, res) }

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
		if l := banHit(lines, ban.Everywhere); l != "" {
			return st.what + `: the command "` + oneLine(l, 60) + `" is not allowed in a template.`
		}
		if st.readOnly {
			if l := banHit(lines, ban.ReadOnly); l != "" {
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
	if strings.Contains(normalized, collapseSpaces(text)) {
		return true
	}
	// JSON output was compacted (no whitespace outside strings), so a text written the way a device pretty-prints ("mode": "trunk") is
	// compacted the same way before it is looked for, or a refusal text could never match and an expect would always fail (D-95 (1c)).
	return looksJSON(normalized) && strings.Contains(normalized, normalizePattern(text, true))
}

// looksJSON reports whether normalised output is a JSON document (normalizeOutput compacted it).
func looksJSON(normalized string) bool {
	t := strings.TrimSpace(normalized)
	return t != "" && (t[0] == '{' || t[0] == '[') && json.Valid([]byte(t))
}

// normalizePattern puts a refusal or expect text in the form of the output it is compared with. For JSON output it drops the whitespace
// outside double-quoted strings, as json.Compact does to the output; otherwise it collapses runs of spaces. A custom action for an HTTP or
// MCP connection is saved in this form (checkCatalog), so what an admin reads is what is compared.
func normalizePattern(text string, jsonOutput bool) string {
	if !jsonOutput {
		return collapseSpaces(text)
	}
	var b strings.Builder
	inStr, esc := false, false
	for _, r := range text {
		switch {
		case inStr:
			b.WriteRune(r)
			switch {
			case esc:
				esc = false
			case r == '\\':
				esc = true
			case r == '"':
				inStr = false
			}
		case r == '"':
			inStr = true
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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

// Package cliban is the list of command lines that a step which must only read may not hold, and that no template may hold at all
// (D-58, D-95: the list is data, cli-ban.json, never Go literals). It has one copy, here; modules/response reads it when a template is saved
// and when a read step is about to go out, and core/conn/write reads it as the last gate before a read step is typed into a device. The GUI
// mock carries a copy that a test keeps equal.
package cliban

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed cli-ban.json
var data []byte

// JSON is the embedded file, for the test that keeps the GUI mock copy equal.
func JSON() []byte { return data }

type file struct {
	Everywhere    []string `json:"everywhere"`
	ReadOnlySteps []string `json:"read_only_steps"`
}

// Rules are the compiled lists: Everywhere may appear in no step, ReadOnly may not appear in a step that must only read.
type Rules struct{ Everywhere, ReadOnly []*regexp.Regexp }

// Load compiles the embedded lists once.
var Load = sync.OnceValues(func() (Rules, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return Rules{}, fmt.Errorf("cliban: parse cli-ban.json: %w", err)
	}
	var r Rules
	var err error
	if r.Everywhere, err = Compile(f.Everywhere); err != nil {
		return Rules{}, err
	}
	if r.ReadOnly, err = Compile(f.ReadOnlySteps); err != nil {
		return Rules{}, err
	}
	if len(r.Everywhere) == 0 || len(r.ReadOnly) == 0 {
		return Rules{}, fmt.Errorf("cliban: cli-ban.json has an empty list")
	}
	return r, nil
})

// Compile turns patterns into anchored expressions: a line (lowercased, spaces collapsed) is refused when it starts with the pattern, at a
// word end; * matches any text.
func Compile(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		p = strings.Join(strings.Fields(strings.ToLower(p)), " ")
		if p == "" {
			return nil, fmt.Errorf("cliban: cli-ban.json has an empty pattern")
		}
		re, err := regexp.Compile(`^` + strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, `.*`) + `(\s|$)`)
		if err != nil {
			return nil, fmt.Errorf("cliban: cli-ban.json pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Lines splits a command text into its lines: trimmed, spaces collapsed, lowercased, empty lines dropped.
func Lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.Join(strings.Fields(strings.ToLower(l)), " "); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Hit returns the first line (already through Lines) that a rule refuses, or "".
func Hit(lines []string, res []*regexp.Regexp) string {
	for _, l := range lines {
		for _, re := range res {
			if re.MatchString(l) {
				return l
			}
		}
	}
	return ""
}

// ReadOnlyProblem is "" when the lines may be typed in a step that must only read, otherwise the line that may not.
func ReadOnlyProblem(lines []string) (string, error) {
	r, err := Load()
	if err != nil {
		return "", err
	}
	norm := Lines(strings.Join(lines, "\n"))
	if l := Hit(norm, r.Everywhere); l != "" {
		return l, nil
	}
	return Hit(norm, r.ReadOnly), nil
}

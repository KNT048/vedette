package write

import (
	_ "embed"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/knt048/vedette/core/conn/cliban"
)

// leave.json is the line that leaves configuration mode after a refused SSH line, per way of entering it (D-358). It is data, like
// cli-ban.json (D-58): the core knows connection kinds, not vendors.
//
//go:embed leave.json
var leaveData []byte

type leaveRule struct {
	enter []*regexp.Regexp
	leave string
}

var leaveRules = sync.OnceValues(func() ([]leaveRule, error) {
	var f struct {
		Rules []struct {
			Enter []string `json:"enter"`
			Leave string   `json:"leave"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(leaveData, &f); err != nil {
		return nil, err
	}
	out := make([]leaveRule, 0, len(f.Rules))
	for _, r := range f.Rules {
		re, err := cliban.Compile(r.Enter)
		if err != nil {
			return nil, err
		}
		l := strings.TrimSpace(r.Leave)
		if len(re) == 0 || l == "" || strings.ContainsFunc(l, unicode.IsControl) || strings.ContainsAny(l, shellChars) {
			return nil, errors.New("write: leave.json has a rule without an enter pattern or with a leave line that is not one plain line")
		}
		out = append(out, leaveRule{enter: re, leave: l})
	}
	return out, nil
})

// leaveLine is the line to type after the lines sent were accepted and the next one was refused: the rule of the nearest line that
// entered configuration mode, or "" (nothing is typed; the session just closes). A file that does not load gives "" too: the
// behaviour before D-358, and TestLeaveRulesLoad keeps it from shipping.
func leaveLine(sent []string) string {
	rules, err := leaveRules()
	if err != nil {
		return ""
	}
	lines := cliban.Lines(strings.Join(sent, "\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		for _, r := range rules {
			if cliban.Hit(lines[i:i+1], r.enter) != "" {
				return r.leave
			}
		}
	}
	return ""
}

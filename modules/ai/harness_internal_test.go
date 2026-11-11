package ai

import (
	"context"
	"strings"
	"testing"
)

// When two fields hit different blocking hooks, the field that comes first in key order decides which one is reported.
func TestAfterHooksReportTheFirstFieldInKeyOrder(t *testing.T) {
	t.Parallel()
	r := runner(t, nil,
		CustomHook{ID: "a", Name: "A", When: AfterAI, Match: HookMatch{MatchKeywords, "alpha"}, Action: ActionBlock, Message: "A hit.", Enabled: true},
		CustomHook{ID: "b", Name: "B", When: AfterAI, Match: HookMatch{MatchKeywords, "beta"}, Action: ActionBlock, Message: "B hit.", Enabled: true})
	for range 100 {
		res, err := afterHooks(context.Background(), r, true, `{"f6":"beta","f1":"alpha","f2":"beta","f3":"x","f4":"y","f5":"z"}`)
		if err != nil || res.Outcome != OutcomeBlocked || res.Text != "A hit." || len(res.Hits) != 1 || strings.Contains(res.Hits[0].Name, "B") {
			t.Fatalf("%+v %v", res, err)
		}
	}
}

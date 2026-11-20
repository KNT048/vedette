package run

import (
	"testing"

	"github.com/knt048/vedette/core/selfcheck"
)

func TestSelfcheckHasEveryRunsRule(t *testing.T) {
	got := map[string]bool{}
	for _, inv := range selfcheck.Registered() {
		got[inv.Name] = true
	}
	for _, inv := range Invariants {
		if !got[inv.Name] {
			t.Errorf("%s is not in the self-check", inv.Name)
		}
	}
}

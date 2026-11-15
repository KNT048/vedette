package mitigation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

// W-1 (D-548): when the device's own agent reported the version, "How to check it yourself" does not ask for it (no About screen),
// says the agent reports the new version by itself and the finding closes by itself. A version from a scan keeps the old steps.
func TestGenericRecheck_D548_AgentVersionIsNotAskedFor(t *testing.T) {
	row := func(agent bool) findings.Row {
		var r findings.Row
		doc := `{"basis":"version","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z","agent":` + map[bool]string{true: "true", false: "false"}[agent] + `},
			"asset":{"id":"a","name":"WIN-LAB","hostname":"WIN-LAB","ip":"192.168.18.128","kind":"server","display":"Windows"},
			"kev":{"display":"Windows","vendor":"Microsoft","product":"Windows","has_template":false}}`
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	got := strings.Join(genericRecheck(row(true)).Steps, " ")
	if strings.Contains(got, "About screen") || !strings.Contains(got, "the agent on WIN-LAB reports the installed version of Windows") || !strings.Contains(got, "closes this finding by itself") {
		t.Fatalf("agent: %s", got)
	}
	if got := strings.Join(genericRecheck(row(false)).Steps, " "); !strings.Contains(got, "About screen") {
		t.Fatalf("scan: %s", got)
	}
}

// N52-2: a product-only match on a row the agent reported with its version does not ask to look the version up either: the agent gave it,
// and the comparison with NVD's data is what failed. A product match on a typed row keeps "Check which version".
func TestGenericRecheck_N52_AgentRowProductMatchDoesNotAskForTheVersion(t *testing.T) {
	row := func(agentRow bool) findings.Row {
		var r findings.Row
		doc := `{"basis":"product","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z","agent_row":` + map[bool]string{true: "true", false: "false"}[agentRow] + `},
			"asset":{"id":"a","name":"byn","hostname":"byn","ip":"192.168.18.181","kind":"server","display":"OpenSSL"},
			"kev":{"display":"OpenSSL","vendor":"OpenSSL","product":"OpenSSL","has_template":false}}`
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	got := strings.Join(genericRecheck(row(true)).Steps, " ")
	if strings.Contains(got, "About screen") || !strings.Contains(got, "Nothing to look up on byn: its agent reports the installed version of OpenSSL") {
		t.Fatalf("agent row: %s", got)
	}
	if got := strings.Join(genericRecheck(row(false)).Steps, " "); !strings.Contains(got, "About screen") {
		t.Fatalf("typed row: %s", got)
	}
}

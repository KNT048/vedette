package mitigation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

// When no agent of this box reports the device now (the check the finding page uses), the steps say the version is
// the one an agent last reported and never that an agent reports it or will report the new one by itself: for an agent's detection,
// for a product match on an agent's row, and for a known version an agent gave. A device an agent reports keeps the old words, and a
// finding no agent gave the version of asks nothing.
func TestGenericRecheck_NoAgentReportsTheDeviceNow(t *testing.T) {
	t.Parallel()
	row := func(doc string) findings.Row {
		var r findings.Row
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	const asset = `"asset":{"id":"a-srv25","name":"Windows Server 2025 host","hostname":"srv25","ip":"192.168.10.40","kind":"server","display":"Windows Server 2025"},
		"kev":{"display":"Microsoft Windows","vendor":"Microsoft","product":"Windows","has_template":false}`
	detection := row(`{"id":"f-1","basis":"version","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z","agent":true},` + asset + `}`)
	productRow := row(`{"id":"f-2","basis":"product","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z","agent_row":true},` + asset + `}`)
	known := row(`{"id":"f-3","basis":"version","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z"},` + asset + `}`)
	known.Known = &findings.KnownVersion{Software: "Windows Server 2025", Version: "10.0.26100.1742", Source: findings.VersionByAgent}
	scanned := row(`{"id":"f-4","basis":"version","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z"},` + asset + `}`)
	scanned.Known = &findings.KnownVersion{Software: "Windows Server 2025", Version: "10.0.26100.1742", Source: findings.VersionByScan}

	reports := map[string]bool{}
	p := &Provider{agents: func(_ context.Context, id string) bool { return reports[id] }}
	for name, r := range map[string]findings.Row{"detection": detection, "product match on an agent row": productRow, "known version from an agent": known} {
		if !p.agentGone(t.Context(), r) {
			t.Fatalf("%s: no agent reports the device, but the check says one does", name)
		}
		got := strings.Join(genericRecheck(r, true).Steps, " ")
		if !strings.Contains(got, "an agent last reported") || strings.Contains(got, "agent on Windows Server 2025 host reports") ||
			strings.Contains(got, "its agent reports") || strings.Contains(got, "usually within two hours") || strings.Contains(got, "About screen") {
			t.Errorf("%s, no agent now: %s", name, got)
		}
		if got := strings.Join(genericRecheck(r, false).Steps, " "); strings.Contains(got, "last reported") {
			t.Errorf("%s, an agent reports it: %s", name, got)
		}
	}
	if p.agentGone(t.Context(), scanned) || (&Provider{}).agentGone(t.Context(), detection) {
		t.Fatal("a scanned version, or no agent check set, says nothing about an agent")
	}
	reports["a-srv25"] = true
	if p.agentGone(t.Context(), detection) {
		t.Fatal("an agent reports the device")
	}
}

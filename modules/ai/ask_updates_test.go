package ai_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// G9 (J4, kien): "list CVE of ip 192.168.10.77 and list application affect (need upgrade)". The model names the device by its IP and
// gets, in ONE call, one action per update with the CVE count and the worst severity, the agent's version called detected (never
// "needs confirming"), and the recommended updates.
func TestAskDeviceUpdates_G9_OneCallByIP(t *testing.T) {
	a := newAskAPI(t)
	cves := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("CVE-2026-%04d", 1000+i))
		}
		return out
	}
	a.data.updates = map[string]ai.DeviceUpdates{"a-ws07": {Open: 41, PlanRan: true,
		Exploited: []ai.UpdateRow{{Action: "Upgrade Mozilla Firefox from 115.0 to 128.1 or later", Software: "Mozilla Firefox", Version: "115.0", Fixed: "128.1", CVEs: cves(38), Worst: "critical", Ransomware: 2, Detected: 38}},
		NoUpdate:  []ai.UpdateRow{{Action: "No update is named that fixes these: follow the vendor's advice for Microsoft Office", Software: "Microsoft Office", CVEs: cves(3), Worst: "high", Suspected: 3}},
		Planned:   []ai.UpdateRow{{Action: "Upgrade 7-Zip from 23.01 to 24.07 or later", Software: "7-Zip", CVEs: cves(2), Worst: "high", Likely: 1}}}}
	a.fake.play(turn{calls: []provider.ToolCall{call("device_updates", `{"device":"192.168.10.77"}`)}}, turn{text: "Upgrade Firefox first."})
	got := a.ask("list CVE of ip 192.168.10.77 and list application affect (need upgrade)", 200, "")
	res := toolResults(a.fake.askRequests()[1])
	if len(res) != 1 || res[0].IsError {
		t.Fatalf("result %+v", res)
	}
	body := res[0].Content[strings.Index(res[0].Content, "{") : strings.LastIndex(res[0].Content, "}")+1]
	var out struct {
		Found       bool             `json:"found"`
		Device      map[string]any   `json:"device"`
		Open        int              `json:"open_exploited_findings"`
		Exploited   []map[string]any `json:"exploited"`
		NoUpdate    []map[string]any `json:"no_named_update"`
		Recommended []map[string]any `json:"recommended"`
		StatusWords string           `json:"status_words"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if !out.Found || out.Device["asset_id"] != "a-ws07" || out.Open != 41 || len(out.Exploited) != 1 || len(out.NoUpdate) != 1 || len(out.Recommended) != 1 {
		t.Fatalf("answer %s", body)
	}
	x := out.Exploited[0]
	if x["action"] != "Upgrade Mozilla Firefox from 115.0 to 128.1 or later" || x["cves"] != float64(38) || x["worst"] != "critical" || x["ransomware"] != float64(2) {
		t.Fatalf("exploited row %v", x)
	}
	if x["status"] != "detected" || out.NoUpdate[0]["status"] != "suspected" || !strings.Contains(out.StatusWords, "do not say it needs confirming") {
		t.Fatalf("the agent's version is detected, a guess suspected: %v %v", x, out.NoUpdate[0])
	}
	if out.Recommended[0]["likely_exploited_soon"] != float64(1) || out.Recommended[0]["status"] != nil {
		t.Fatalf("recommended %v", out.Recommended[0])
	}
	if c := list(got["tool_calls"]); len(c) != 1 {
		t.Fatalf("one call answers it: %v", c)
	}
	if rows := list(got["table"].(map[string]any)["rows"]); len(rows) != 3 || !strings.Contains(fmt.Sprint(rows[0]), "Mozilla Firefox") || !strings.Contains(fmt.Sprint(rows[2]), "recommended") {
		t.Fatalf("table %v", got["table"])
	}
}

// The device is found by its name too; two names that both match ask for the asset_id; an unknown IP says so.
func TestAskDeviceUpdates_G9_FindsTheDevice(t *testing.T) {
	for _, c := range []struct{ arg, want string }{
		{`{"device":"ws-07"}`, `"asset_id":"a-ws07"`},
		{`{"device":"a-nas"}`, `"asset_id":"a-nas"`},
		{`{"device":"S"}`, `"candidates"`},
		{`{"device":"10.9.9.9"}`, `"found":false`},
	} {
		a := newAskAPI(t)
		a.fake.play(turn{calls: []provider.ToolCall{call("device_updates", c.arg)}}, turn{text: "Done."})
		a.ask("What should I upgrade?", 200, "")
		if res := toolResults(a.fake.askRequests()[1]); len(res) != 1 || !strings.Contains(res[0].Content, c.want) {
			t.Errorf("%s: %+v", c.arg, res)
		}
	}
}

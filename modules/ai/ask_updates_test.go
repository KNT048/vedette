package ai_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// A real question: "list CVE of ip 192.168.10.77 and list application affect (need upgrade)". The model names the device by its IP and
// gets, in ONE call, one action per update with the CVE count and the worst severity, the agent's version called detected (never
// "needs confirming"), and the recommended updates.
func TestAskDeviceUpdates_OneCallByIP(t *testing.T) {
	a := newAskAPI(t)
	cves := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("CVE-2026-%04d", 1000+i))
		}
		return out
	}
	a.data.updates = map[string]ai.DeviceUpdates{"a-ws07": {Open: 41,
		Exploited: []ai.UpdateRow{{Action: "Upgrade Mozilla Firefox from 115.0 to 128.1 or later", Software: "Mozilla Firefox", Version: "115.0", Fixed: "128.1", CVEs: cves(38), Worst: "critical", Detected: 38}},
		NoUpdate:  []ai.UpdateRow{{Action: "No update is named that fixes these: follow the vendor's advice for Microsoft Office", Software: "Microsoft Office", CVEs: cves(3), Worst: "high", Suspected: 3}},
		Planned: []ai.UpdateRow{{Action: "Upgrade 7-Zip from 23.01 to 24.07 or later", Software: "7-Zip", CVEs: cves(2), Worst: "high"},
			// Microsoft's newest update is newer than every fix NVD names: the count is a floor, in the plan's words
			{Action: "Install the latest cumulative update for Windows Server 2025 (from build 26100.33650 to 26100.33822 or later)", Software: "Windows Server 2025",
				CVEs: cves(5), Worst: "critical"},
			// Microsoft's newest update with none of its CVEs analysed yet: named, no count
			{Action: "Install the latest cumulative update for Windows Server 2022 (from build 20348.85761 to 20348.85870 or later; KB5131090)", Software: "Windows Server 2022"}}}}
	a.fake.play(turn{calls: []provider.ToolCall{call("device_updates", `{"device":"192.168.10.77"}`)}}, turn{text: "Upgrade Firefox first."})
	got := a.ask("list CVE of ip 192.168.10.77 and list application affect (need upgrade)", 200, "")
	res := toolResults(a.fake.askRequests()[1])
	if len(res) != 1 || res[0].IsError {
		t.Fatalf("result %+v", res)
	}
	body := res[0].Content[strings.Index(res[0].Content, "{") : strings.LastIndex(res[0].Content, "}")+1]
	var out struct {
		Found       bool           `json:"found"`
		Device      map[string]any `json:"device"`
		Open        int            `json:"open_exploited_findings"`
		Exploited   []string       `json:"exploited"`
		NoUpdate    []string       `json:"no_named_update"`
		Recommended []string       `json:"recommended"`
		StatusWords string         `json:"status_words"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if !out.Found || out.Device["asset_id"] != "a-ws07" || out.Open != 41 || len(out.Exploited) != 1 || len(out.NoUpdate) != 1 || len(out.Recommended) != 3 {
		t.Fatalf("answer %s", body)
	}
	if x := out.Exploited[0]; x != "Upgrade Mozilla Firefox from 115.0 to 128.1 or later; 38 CVEs, worst critical, detected" {
		t.Fatalf("exploited row %q", x)
	}
	if !strings.HasSuffix(out.NoUpdate[0], ", suspected") || !strings.Contains(out.StatusWords, "do not say it needs confirming") {
		t.Fatalf("the agent's version is detected, a guess suspected: %v", out.NoUpdate)
	}
	if out.Recommended[0] != "Upgrade 7-Zip from 23.01 to 24.07 or later; 2 CVEs, worst high" {
		t.Fatalf("recommended %q", out.Recommended[0])
	}
	if out.Recommended[1] != "Install the latest cumulative update for Windows Server 2025 (from build 26100.33650 to 26100.33822 or later); 5 CVEs, worst critical" {
		t.Fatalf("recommended Windows update %q", out.Recommended[1])
	}
	if out.Recommended[2] != "Install the latest cumulative update for Windows Server 2022 (from build 20348.85761 to 20348.85870 or later; KB5131090); NVD lists no CVE of it for this release yet" {
		t.Fatalf("recommended update with no CVE analysed %q", out.Recommended[2])
	}
	if c := list(got["tool_calls"]); len(c) != 1 {
		t.Fatalf("one call answers it: %v", c)
	}
	if rows := list(got["table"].(map[string]any)["rows"]); len(rows) != 5 || !strings.Contains(fmt.Sprint(rows[0]), "Mozilla Firefox") || !strings.Contains(fmt.Sprint(rows[2]), "recommended") {
		t.Fatalf("table %v", got["table"])
	}
	// the table's CVE cell says what the line says: never "0 CVEs" for an update NVD lists no CVE for
	if cells := fmt.Sprint(list(got["table"].(map[string]any)["rows"])); regexp.MustCompile(`\b0 CVEs`).MatchString(cells) ||
		!strings.Contains(cells, "NVD lists no CVE of it for this release yet") || !strings.Contains(cells, "5 CVEs") {
		t.Fatalf("table cells %s", cells)
	}
}

// The device is found by its name too; two names that both match ask for the asset_id; an unknown IP says so.
func TestAskDeviceUpdates_FindsTheDevice(t *testing.T) {
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

// Review r2 M of #935: through the real loop (12 KB of tool results a question, the input budget that stops tool turns, the sized
// usage a provider reports), a PC with 40 applications to upgrade and 12 recommended updates is read to the end: the model follows
// the note's offset, every one of the 40 updates reaches it, and no call is refused for the tool limit.
func TestAskDeviceUpdates_FortyUpdatesThroughTheLoop(t *testing.T) {
	a := newAskAPI(t)
	a.fake.sizedUsage = true
	apps := []string{"Mozilla Firefox", "Google Chrome", "Microsoft Edge", "Adobe Acrobat Reader DC", "7-Zip", "Notepad++", "VLC media player", "Zoom Workplace", "Microsoft Teams", "Python 3.11"}
	var ex, rec []ai.UpdateRow
	for i := range 40 {
		ex = append(ex, ai.UpdateRow{Action: fmt.Sprintf("Upgrade %s (%d) from 24.%d.1 to 25.%d.3 or later", apps[i%len(apps)], i, i, i), CVEs: make([]string, 1+i%9), Worst: []string{"critical", "high"}[i%2], Detected: 1 + i%9})
	}
	for i := range 12 {
		rec = append(rec, ai.UpdateRow{Action: fmt.Sprintf("Upgrade %s (%d) from 1.%d to 2.%d or later", apps[i%len(apps)], i, i, i), CVEs: make([]string, 3), Worst: "high"})
	}
	a.data.updates = map[string]ai.DeviceUpdates{"a-ws07": {Open: 200, Exploited: ex, Planned: rec}}
	next := regexp.MustCompile(`part \\"exploited\\" and offset (\d+)`)
	seen := map[string]bool{}
	calls, refused := 0, 0
	a.fake.mu.Lock()
	a.fake.script = func(_ context.Context, _ ai.Profile, req provider.Request) (provider.Response, error) {
		usage := provider.Usage{InputTokens: requestTokens(req), OutputTokens: 40}
		args := `{"device":"192.168.10.77"}`
		if res := toolResults(req); len(res) > 0 {
			c := res[0].Content
			if strings.Contains(c, "tool limit") {
				refused++
			}
			body := c[strings.Index(c, "{") : strings.LastIndex(c, "}")+1]
			var out struct {
				Exploited []string `json:"exploited"`
			}
			if err := json.Unmarshal([]byte(body), &out); err == nil {
				for _, r := range out.Exploited {
					seen[r] = true
				}
			}
			m := next.FindStringSubmatch(c)
			if m == nil {
				return provider.Response{Text: "Upgrade Firefox first.", Usage: usage, Stop: provider.StopEnd}, nil
			}
			args = `{"device":"a-ws07","part":"exploited","offset":` + m[1] + `}`
		}
		calls++
		return provider.Response{ToolCalls: []provider.ToolCall{{ID: fmt.Sprintf("c%d", calls), Name: "device_updates", Arguments: json.RawMessage(args)}}, Usage: usage, Stop: provider.StopToolUse}, nil
	}
	a.fake.mu.Unlock()
	a.ask("list CVE of ip 192.168.10.77 and list application affect (need upgrade)", 200, "")
	if len(seen) != 40 || refused != 0 || calls > 3 {
		t.Fatalf("read %d of 40 updates in %d calls, %d refused", len(seen), calls, refused)
	}
	t.Logf("40 updates in %d calls", calls)
}

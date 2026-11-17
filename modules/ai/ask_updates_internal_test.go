package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// updatesBox is a Data and an Updates with the devices and the updates of one test.
type updatesBox struct {
	assets  []AssetRow
	updates map[string]DeviceUpdates
}

func (b updatesBox) Assets(context.Context) ([]AssetRow, error)     { return b.assets, nil }
func (b updatesBox) Findings(context.Context) ([]FindingRow, error) { return nil, nil }
func (b updatesBox) Finding(context.Context, string) (FindingRow, bool, error) {
	return FindingRow{}, false, nil
}
func (b updatesBox) IOC(context.Context, string, string) (IOCFact, bool, error) {
	return IOCFact{}, false, nil
}
func (b updatesBox) DeviceUpdates(_ context.Context, id string) (DeviceUpdates, bool, error) {
	u, ok := b.updates[id]
	return u, ok, nil
}

type updatesAnswer struct {
	Found       bool             `json:"found"`
	Device      map[string]any   `json:"device"`
	Note        string           `json:"note"`
	Total       int              `json:"exploited_updates_total"`
	RecTotal    int              `json:"recommended_total"`
	PlanNote    string           `json:"recommended_note"`
	Exploited   []map[string]any `json:"exploited"`
	NoUpdate    []map[string]any `json:"no_named_update"`
	Recommended []map[string]any `json:"recommended"`
	Candidates  []map[string]any `json:"candidates"`
}

func callUpdates(t *testing.T, b updatesBox, args string) (updatesAnswer, error) {
	t.Helper()
	a, err := parseArgs(json.RawMessage(args), deviceUpdatesArgs, "device")
	if err != nil {
		return updatesAnswer{}, err
	}
	out, err := (&Service{}).toolDeviceUpdates(t.Context(), b, b, a)
	if err != nil {
		return updatesAnswer{}, err
	}
	if len(out.Text) > askResultBytes {
		t.Fatalf("%d bytes, over the cap", len(out.Text))
	}
	var ans updatesAnswer
	if err := json.Unmarshal([]byte(out.Text), &ans); err != nil {
		t.Fatalf("%v: %s", err, out.Text)
	}
	return ans, nil
}

func manyUpdates(n int, what string) []UpdateRow {
	var out []UpdateRow
	for i := range n {
		out = append(out, UpdateRow{Action: fmt.Sprintf("Upgrade %s application number %02d with a long product name from 1.0.%d to 2.0.%d or later", what, i, i, i),
			CVEs: []string{fmt.Sprintf("CVE-2026-%04d", 1000+i), fmt.Sprintf("CVE-2026-%04d", 2000+i)}, Worst: "high", Detected: 2})
	}
	return out
}

// Review r1 M3 of #935: the owner's PC with 30 applications to upgrade. The first answer fits 4 KB (the recommended rows go first, then
// the exploited ones down to a few), says how many there are and where the next call starts, and following the notes reads every
// update to the end in a few calls, never through get_finding.
func TestDeviceUpdates_G9_EveryRowIsReadableByPaging(t *testing.T) {
	b := updatesBox{assets: []AssetRow{{ID: "a-pc", Name: "PC-134", IP: "192.168.18.134"}},
		updates: map[string]DeviceUpdates{"a-pc": {Open: 60, Exploited: manyUpdates(30, "exploited"), Planned: manyUpdates(12, "recommended"), PlanRan: true, PlanCompared: true}}}
	ans, err := callUpdates(t, b, `{"device":"192.168.18.134"}`)
	if err != nil || !ans.Found || ans.Total != 30 || ans.RecTotal != 12 {
		t.Fatalf("%+v %v", ans, err)
	}
	if len(ans.Exploited) == 0 || len(ans.Recommended) > len(ans.Exploited) || len(ans.Exploited) > askRowsDefault {
		t.Fatalf("cut order: %d exploited, %d recommended", len(ans.Exploited), len(ans.Recommended))
	}
	if !strings.Contains(ans.Note, fmt.Sprintf(`"30 (showing %d)"`, len(ans.Exploited))) || !strings.Contains(ans.Note, fmt.Sprintf(`part "exploited" and offset %d`, len(ans.Exploited))) {
		t.Fatalf("note %q", ans.Note)
	}
	seen := map[string]bool{}
	for _, r := range ans.Exploited {
		seen[r["action"].(string)] = true
	}
	calls := 1
	for offset := len(ans.Exploited); offset < 30; calls++ {
		page, err := callUpdates(t, b, fmt.Sprintf(`{"device":"a-pc","part":"exploited","offset":%d}`, offset))
		if err != nil || len(page.Exploited) == 0 || len(page.Recommended) != 0 {
			t.Fatalf("offset %d: %+v %v", offset, page, err)
		}
		for _, r := range page.Exploited {
			seen[r["action"].(string)] = true
		}
		offset += len(page.Exploited)
		if offset >= 30 && !strings.Contains(page.Note, "the last ones") {
			t.Fatalf("last page note %q", page.Note)
		}
	}
	if len(seen) != 30 || calls > 4 {
		t.Fatalf("read %d of 30 updates in %d calls", len(seen), calls)
	}
	if _, err := callUpdates(t, b, `{"device":"a-pc","offset":10}`); err == nil || !strings.Contains(err.Error(), "offset needs part") {
		t.Fatalf("offset without part: %v", err)
	}
}

// Review r1 M2, L4 of #935: an IP matches only that IP, never a name that contains it; an exact name beside names that contain it is
// not picked; an empty device is refused at the edge.
func TestDeviceUpdates_G9_DeviceIsNeverGuessed(t *testing.T) {
	b := updatesBox{assets: []AssetRow{{ID: "a-100", Name: "192.168.1.100", IP: "192.168.1.100"}, {ID: "a-rogue", Name: "ws-07", IP: "192.168.1.50"},
		{ID: "a-pc", Name: "WS-07.corp.local", IP: "192.168.1.7"}, {ID: "a-lldp", Name: ""}},
		updates: map[string]DeviceUpdates{"a-100": {}, "a-rogue": {}, "a-pc": {}, "a-lldp": {}}}
	if ans, err := callUpdates(t, b, `{"device":"192.168.1.10"}`); err != nil || ans.Found || len(ans.Candidates) != 0 {
		t.Fatalf("an IP no device has: %+v %v", ans, err)
	}
	if ans, err := callUpdates(t, b, `{"device":"192.168.1.100"}`); err != nil || !ans.Found || ans.Device["asset_id"] != "a-100" {
		t.Fatalf("by IP: %+v %v", ans, err)
	}
	ans, err := callUpdates(t, b, `{"device":"ws-07"}`)
	if err != nil || ans.Found || len(ans.Candidates) != 2 || ans.Candidates[0]["asset_id"] != "a-rogue" {
		t.Fatalf("exact name beside a longer one: %+v %v", ans, err)
	}
	if ans, err := callUpdates(t, b, `{"device":"corp.local"}`); err != nil || !ans.Found || ans.Device["asset_id"] != "a-pc" {
		t.Fatalf("one name contains it: %+v %v", ans, err)
	}
	for _, empty := range []string{`{"device":""}`, `{"device":"   "}`} {
		if _, err := callUpdates(t, b, empty); err == nil {
			t.Fatalf("%s was not refused", empty)
		}
	}
}

// Review r1 M1, M4, L1 of #935: an agent's version Vedette could not compare is "reported" (not "inside the range"); an empty
// recommended list says why when the device was not compared or the feeds are off, never a bare 0.
func TestDeviceUpdates_G9_WordsForWhatIsNotProved(t *testing.T) {
	b := updatesBox{assets: []AssetRow{{ID: "a-1", Name: "nas", IP: "10.0.0.1"}, {ID: "a-2", Name: "cam", IP: "10.0.0.2"}},
		updates: map[string]DeviceUpdates{
			"a-1": {Open: 1, NoUpdate: []UpdateRow{{Action: "No update is named that fixes these: follow the vendor's advice for Photo Station", CVEs: []string{"CVE-2022-27593"}, Reported: 1}}, PlanRan: true},
			"a-2": {PlanOff: true}}}
	ans, err := callUpdates(t, b, `{"device":"10.0.0.1"}`)
	if err != nil || len(ans.NoUpdate) != 1 || ans.NoUpdate[0]["status"] != "reported" || !strings.Contains(ans.PlanNote, "not compared") {
		t.Fatalf("%+v %v", ans, err)
	}
	if !strings.Contains(statusWords, "reported = the agent reported the installed version but Vedette could not compare it") {
		t.Fatal(statusWords)
	}
	if ans, _ := callUpdates(t, b, `{"device":"cam"}`); !strings.Contains(ans.PlanNote, "feeds module is off") {
		t.Fatalf("feeds off: %+v", ans)
	}
}

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

type testAnswer struct {
	Found       bool             `json:"found"`
	Device      map[string]any   `json:"device"`
	Note        string           `json:"note"`
	StatusWords string           `json:"status_words"`
	Total       int              `json:"exploited_updates_total"`
	RecTotal    int              `json:"recommended_total"`
	PlanNote    string           `json:"recommended_note"`
	Exploited   []string         `json:"exploited"`
	NoUpdate    []string         `json:"no_named_update"`
	Recommended []string         `json:"recommended"`
	Candidates  []map[string]any `json:"candidates"`
}

func callUpdates(t *testing.T, b updatesBox, args string) (testAnswer, error) {
	t.Helper()
	a, err := parseArgs(json.RawMessage(args), deviceUpdatesArgs, "device")
	if err != nil {
		return testAnswer{}, err
	}
	out, err := (&Service{}).toolDeviceUpdates(t.Context(), b, b, a)
	if err != nil {
		return testAnswer{}, err
	}
	if len(out.Text) > askResultBytes {
		t.Fatalf("%d bytes, over the cap", len(out.Text))
	}
	var ans testAnswer
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

// Review r2 L4 of #935: a first call that cannot hold every row keeps a few of each list (the recommended rows go first, then those with
// no named update, then the exploited ones), says the totals and where the next page starts; a page has one list, without the status
// words and the device's details (they came with the first call), and pages read to the end.
func TestDeviceUpdates_FirstCallKeepsEachListAndPagesAreLean(t *testing.T) {
	b := updatesBox{assets: []AssetRow{{ID: "a-pc", Name: "PC-134", IP: "192.168.18.134"}},
		updates: map[string]DeviceUpdates{"a-pc": {Open: 200, Exploited: manyUpdates(60, "exploited"), NoUpdate: manyUpdates(10, "unnamed"), Planned: manyUpdates(20, "recommended")}}}
	ans, err := callUpdates(t, b, `{"device":"192.168.18.134"}`)
	if err != nil || !ans.Found || ans.Total != 60 || ans.RecTotal != 20 || ans.StatusWords == "" || ans.Device["name"] != "PC-134" {
		t.Fatalf("%+v %v", ans, err)
	}
	if len(ans.Recommended) != 3 || len(ans.NoUpdate) != 3 || len(ans.Exploited) <= 5 {
		t.Fatalf("floors: %d exploited, %d no named update, %d recommended", len(ans.Exploited), len(ans.NoUpdate), len(ans.Recommended))
	}
	if !strings.Contains(ans.Note, fmt.Sprintf(`"60 (showing %d)"`, len(ans.Exploited))) || !strings.Contains(ans.Note, fmt.Sprintf(`part "exploited" and offset %d`, len(ans.Exploited))) {
		t.Fatalf("note %q", ans.Note)
	}
	read := len(ans.Exploited)
	for read < 60 {
		page, err := callUpdates(t, b, fmt.Sprintf(`{"device":"a-pc","part":"exploited","offset":%d}`, read))
		if err != nil || len(page.Exploited) == 0 || len(page.Recommended) != 0 || page.StatusWords != "" || page.Device["name"] != nil {
			t.Fatalf("offset %d: %+v %v", read, page, err)
		}
		if !strings.HasPrefix(page.Exploited[0], fmt.Sprintf("Upgrade exploited application number %02d ", read)) {
			t.Fatalf("offset %d starts at %q", read, page.Exploited[0])
		}
		read += len(page.Exploited)
	}
	if _, err := callUpdates(t, b, `{"device":"a-pc","offset":10}`); err == nil || !strings.Contains(err.Error(), "offset needs part") {
		t.Fatalf("offset without part: %v", err)
	}
}

// Review r1 M2, L4 of #935: an IP matches only that IP, never a name that contains it; an exact name beside names that contain it is
// not picked; an empty device is refused at the edge.
func TestDeviceUpdates_DeviceIsNeverGuessed(t *testing.T) {
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
	if ans, err := callUpdates(t, b, `{"device":"corp.local"}`); err != nil || !ans.Found || ans.Device["asset_id"] != "a-pc" || !strings.Contains(ans.Note, "only one whose name contains it") {
		t.Fatalf("one name contains it, said to be partial (review r2 L2): %+v %v", ans, err)
	}
	if ans, _ := callUpdates(t, b, `{"device":"192.168.1.100"}`); strings.Contains(ans.Note, "contains it") {
		t.Fatalf("an exact match is not partial: %q", ans.Note)
	}
	for _, empty := range []string{`{"device":""}`, `{"device":"   "}`} {
		if _, err := callUpdates(t, b, empty); err == nil {
			t.Fatalf("%s was not refused", empty)
		}
	}
}

// Review r1 M1, M4, L1 of #935: an agent's version Vedette could not compare is "reported" (not "inside the range"); an empty
// recommended list says why when the device was not compared or the feeds are off, never a bare 0.
func TestDeviceUpdates_WordsForWhatIsNotProved(t *testing.T) {
	b := updatesBox{assets: []AssetRow{{ID: "a-1", Name: "nas", IP: "10.0.0.1"}, {ID: "a-2", Name: "cam", IP: "10.0.0.2"}},
		updates: map[string]DeviceUpdates{
			"a-1": {Open: 1, NoUpdate: []UpdateRow{{Action: "No update is named that fixes these: follow the vendor's advice for Photo Station", CVEs: []string{"CVE-2022-27593"}, Detected: 1}}},
			"a-2": {PlanOff: true}}}
	ans, err := callUpdates(t, b, `{"device":"10.0.0.1"}`)
	if err != nil || len(ans.NoUpdate) != 1 || !strings.HasSuffix(ans.NoUpdate[0], "; 1 CVE, detected") {
		t.Fatalf("%+v %v", ans, err)
	}
	if !strings.Contains(statusWords, "detected = the device's own agent or another trusted source reported the installed version") {
		t.Fatal(statusWords)
	}
	if ans, _ := callUpdates(t, b, `{"device":"cam"}`); !strings.Contains(ans.PlanNote, "feeds module is off") {
		t.Fatalf("feeds off: %+v", ans)
	}
}

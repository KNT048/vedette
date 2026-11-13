package reports

import (
	"strings"
	"testing"
)

func fixRow(id, asset, device, product, status string) FindingRow {
	return FindingRow{ID: id, CVE: "CVE-2026-" + id, AssetID: asset, Device: device, Product: product, Status: status, Severity: "critical"}
}

// One upgrade that closes three findings is one line, naming the fixed release (the highest of the three) and the device.
func TestTopRisksOneUpgradeIsOneLineWithTheFixedVersion(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "a1", "FortiGate-HQ", "FortiGate (FortiOS)", "confirmed"), fixRow("2", "a1", "FortiGate-HQ", "FortiGate (FortiOS)", "confirmed"),
		fixRow("3", "a1", "FortiGate-HQ", "FortiGate (FortiOS)", "confirmed")}
	fx := map[string]Fix{"1": {Kind: "fixed", Version: "7.4.1", Fixed: "7.4.2"}, "2": {Kind: "fixed", Version: "7.4.1", Fixed: "7.4.10"}, "3": {Kind: "fixed", Version: "7.4.1", Fixed: "7.4.3"}}
	got, kinds := topRisks(open, fx)
	want := "Upgrade FortiGate (FortiOS) on FortiGate-HQ from 7.4.1 to 7.4.10 or later — fixes 3 exploited vulnerabilities"
	if len(got) != 1 || got[0].Action != want || kinds[0] != "fix" {
		t.Fatalf("got %+v %v, want action %q", got, kinds, want)
	}
}

// The same release on several devices is one line; a device with no fixed release is its own line with the honest fallback.
func TestTopRisksMergeDevicesAndFallBackHonestly(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "a1", "fw-1", "Apache", "confirmed"), fixRow("2", "a2", "fw-2", "Apache", "confirmed"), fixRow("3", "a3", "fw-3", "Apache", "confirmed"),
		fixRow("4", "a4", "old-box", "Apache", "confirmed"), fixRow("5", "a5", "mystery", "Apache", "suspected")}
	fx := map[string]Fix{"1": {Kind: "fixed", Version: "2.4.50", Fixed: "2.4.52"}, "2": {Kind: "fixed", Version: "2.4.49", Fixed: "2.4.52"}, "3": {Kind: "fixed", Version: "2.4.1", Fixed: "2.4.52"}}
	got, _ := topRisks(open, fx)
	if len(got) != 3 {
		t.Fatalf("risks = %+v", got)
	}
	var texts []string
	for _, r := range got {
		texts = append(texts, r.Action)
	}
	all := strings.Join(texts, "\n")
	for _, w := range []string{"Upgrade Apache to 2.4.52 or later on fw-1 and 2 more — fixes 3 exploited vulnerabilities",
		"Update Apache on old-box, or apply the vendor's temporary fix: a scan confirmed it", "Check the version of Apache on mystery"} {
		if !strings.Contains(all, w) {
			t.Errorf("missing %q in\n%s", w, all)
		}
	}
	if got[0].Devices != 3 {
		t.Errorf("merged line names %d devices", got[0].Devices)
	}
}

func TestVerLessComparesNumbers(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ a, b string }{{"7.4.2", "7.4.10"}, {"2.4.9", "2.4.52"}, {"1.0", "1.0.1"}} {
		if !verLess(c.a, c.b) || verLess(c.b, c.a) {
			t.Errorf("%s should be older than %s", c.a, c.b)
		}
	}
}

func TestHappenedCountsAndNamesWhatMatters(t *testing.T) {
	t.Parallel()
	in := []Incident{
		{Kind: "bad_connection", Severity: "medium", Title: "pc-1 reached a known-bad address", LastSeen: day0(1)},
		{Kind: "failed_logins", Severity: "medium", Title: "5 failed logins from 45.1.2.3 on web in 10 minutes", LastSeen: day0(2)},
		{Kind: "login_accepted", Severity: "high", Title: "A login from 45.1.2.3 was ACCEPTED after failed attempts on web", LastSeen: day0(1)},
		{Kind: "trap", Severity: "high", Title: "Someone touched the SSH trap", LastSeen: day0(3)},
		{Kind: "trap", Severity: "high", Title: "old", LastSeen: day0(30)}, // not this week
	}
	h := buildHappened(in, t0.Add(-7*day), t0)
	if h.Traps != 1 || h.FailedLogins != 1 || h.AcceptedLogins != 1 || h.BadConnections != 1 || len(h.Top) != 3 || h.Top[0].Kind != "login_accepted" || h.Top[1].Kind != "trap" {
		t.Fatalf("happened = %+v", h)
	}
	if want := "This week: 1 login ACCEPTED after failed attempts, 1 honeypot touch, 1 failed-login attack, 1 connection to a known-bad address."; h.Summary != want {
		t.Fatalf("summary = %q", h.Summary)
	}
	if e := buildHappened(nil, t0.Add(-7*day), t0); e.Summary != "No incidents this week." || e.Top == nil {
		t.Fatalf("empty = %+v", e)
	}
}

// The email leads with the actions and the incident line; the page says the same sentences (one rendered example).
func TestDigestLeadsWithActionsAndIncidents(t *testing.T) {
	t.Parallel()
	in := sampleInput()
	in.fixes = map[string]Fix{"f1": {Kind: "fixed", Version: "10.0.1", Fixed: "10.0.4"}}
	in.incidentsOn = true
	in.incidents = []Incident{{Kind: "trap", Severity: "high", Title: "Someone touched the SSH trap", Count: 2, LastSeen: day0(1)}}
	r := buildWeekly(in)
	m := digest(r)
	if m.Action != r.Actions[0].Text || !strings.HasPrefix(m.Action, "Upgrade Microsoft Windows on pc-old from 10.0.1 to 10.0.4 or later — fixes 1 exploited vulnerability") {
		t.Fatalf("action = %q", m.Action)
	}
	if !strings.HasPrefix(m.What, "This week: 1 honeypot touch.\nSomeone touched the SSH trap\n") || r.Happened == nil || r.Sources[3].ID != "incidents" {
		t.Fatalf("what = %q", m.What)
	}
	t.Logf("PAGE top risk: %s\nPAGE happened: %s\nEMAIL title: %s\nEMAIL what:\n%s\nEMAIL first: %s\nEMAIL items: %q", r.TopRisks[0].Action, r.Happened.Summary, m.Title, m.What, m.Action, m.Items)
}

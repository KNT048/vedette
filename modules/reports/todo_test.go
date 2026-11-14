package reports

import (
	"slices"
	"strings"
	"testing"
)

func fixRow(id, asset, device, product, status string) FindingRow {
	return FindingRow{ID: id, CVE: "CVE-2026-" + id, AssetID: asset, Device: device, Product: product, Status: status, Severity: "critical"}
}

// One upgrade that closes three findings is one line, naming the release the box chose (it is outside every range) and the device.
func TestTopRisksOneUpgradeIsOneLineWithTheFixedVersion(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "a1", "FortiGate-HQ", "FortiGate (FortiOS)", "confirmed"), fixRow("2", "a1", "FortiGate-HQ", "FortiGate (FortiOS)", "confirmed"),
		fixRow("3", "a1", "FortiGate-HQ", "FortiGate (FortiOS)", "confirmed")}
	fx := map[string]Fix{}
	for _, id := range []string{"1", "2", "3"} {
		fx[id] = Fix{Kind: "fixed", Version: "7.4.1", Fixed: "7.4.3", Closed: true}
	}
	got, kinds := topRisks(open, fx)
	want := "Upgrade FortiGate (FortiOS) on FortiGate-HQ from 7.4.1 to 7.4.3 or later — fixes 3 exploited vulnerabilities"
	if len(got) != 1 || got[0].Action != want || kinds[0] != "fix" {
		t.Fatalf("got %+v %v, want action %q", got, kinds, want)
	}
	fx["3"] = Fix{Kind: "fixed", Version: "7.4.1", Fixed: "7.4.3"} // not closed by it: the line says so
	if got, _ := topRisks(open, fx); !strings.HasSuffix(got[0].Action, "— fixes 2 of 3 exploited vulnerabilities") {
		t.Fatalf("action = %q", got[0].Action)
	}
}

// A distribution caveat travels with the release (review M1); no single release in the ranges is the plain advisory fallback.
func TestTopRisksCarryTheDistroCaveatAndTheNoReleaseFallback(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "a1", "web", "OpenSSH", "confirmed"), fixRow("2", "a2", "gw", "FortiGate", "confirmed")}
	fx := map[string]Fix{"1": {Kind: "fixed", Version: "8.9p1", Fixed: "9.3p2", Distro: "Ubuntu", Closed: true}, "2": {Kind: "none", Version: "7.4.1", Closed: true}}
	got, _ := topRisks(open, fx)
	if want := "Upgrade OpenSSH on web from 8.9p1 to 9.3p2 or later — fixes 1 exploited vulnerability (if you installed it from Ubuntu's packages, install its security updates instead)"; got[1].Action != want {
		t.Fatalf("action = %q", got[1].Action)
	}
	if want := "NVD names no single release that fixes all 1 exploited vulnerability of FortiGate on gw: check the vendor advisory"; got[0].Action != want {
		t.Fatalf("action = %q", got[0].Action)
	}
}

// Ranking is by product, as D-485: a product with the most exploited CVEs across devices takes one slot even when its devices need
// different steps (review M3); the sentence is the biggest step and says how many more devices need another.
func TestTopRisksRankByProductAcrossDevices(t *testing.T) {
	t.Parallel()
	var open []FindingRow
	fx := map[string]Fix{}
	for i, dev := range []string{"d1", "d2", "d3", "d4"} {
		for k := range 2 { // 8 findings on Apache over four devices
			id := dev + string(rune('a'+k))
			open = append(open, fixRow(id, dev, dev, "Apache", "confirmed"))
			if i < 3 {
				fx[id] = Fix{Kind: "fixed", Version: "2.4." + dev[1:], Fixed: "2.4.52", Closed: true}
			}
		}
	}
	open = append(open, fixRow("z1", "z", "zz", "Zebra", "confirmed"), fixRow("z2", "z", "zz", "Zebra", "confirmed"), fixRow("z3", "z", "zz", "Zebra", "suspected"))
	got, _ := topRisks(open, fx)
	if len(got) != 2 || got[0].Product != "Apache" || got[0].Open != 8 || got[0].Devices != 4 {
		t.Fatalf("risks = %+v", got)
	}
	if want := "Upgrade Apache to 2.4.52 or later on d1 and 2 more — fixes 6 exploited vulnerabilities; 1 more device needs another step"; got[0].Action != want {
		t.Fatalf("action = %q, want %q", got[0].Action, want)
	}
}

func TestHappenedNamesWhatMatters(t *testing.T) {
	t.Parallel()
	h := buildHappened(IncidentWeek{Traps: 1, FailedLogins: 1, AcceptedLogins: 1, BadConnections: 600,
		Top: []Incident{{Kind: "login_accepted", Severity: "high", Title: "A login from 45.1.2.3 was ACCEPTED after 6 failed attempts on web", LastSeen: day0(1)}}})
	if want := "This week: 1 login ACCEPTED after failed attempts, 1 honeypot touch, 1 failed-login attack, 600 connections to known-bad addresses."; h.Summary != want || len(h.Top) != 1 {
		t.Fatalf("happened = %+v", h)
	}
	if e := buildHappened(IncidentWeek{}); e.Summary != "No incidents this week." || e.Top == nil {
		t.Fatalf("empty = %+v", e)
	}
}

// The email leads with the actions and the incident line; the page says the same sentences (one rendered example).
func TestDigestLeadsWithActionsAndIncidents(t *testing.T) {
	t.Parallel()
	in := sampleInput()
	in.fixes = map[string]Fix{"f1": {Kind: "fixed", Version: "10.0.1", Fixed: "10.0.4", Closed: true}}
	in.incidentsOn = true
	in.week = IncidentWeek{Traps: 1, Top: []Incident{{Kind: "trap", Severity: "high", Title: "Someone touched the SSH trap", LastSeen: day0(1)}}}
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

// The release is asked for every open finding of the devices the page names, not only those of the named products: one phone's CVEs
// carry several CISA product names and one release must clear them all (review round 2).
func TestWeeklyAsksTheFixesOfWholeDevices(t *testing.T) {
	t.Parallel()
	in := sampleInput()
	var asked []string
	in.fixesFor = func(fs []Finding) map[string]Fix {
		for _, f := range fs {
			asked = append(asked, f.ID)
		}
		return map[string]Fix{"f1": {Kind: "fixed", Group: "s1", Version: "10.0.1", Fixed: "10.0.4", Closed: true}}
	}
	in.findings = append(in.findings, Finding{ID: "f9", AssetID: "a2", CVE: "CVE-2026-0009", Status: "confirmed", Severity: "low", FirstSeen: day0(20)}) // another product, same device
	buildWeekly(in)
	if !slices.Contains(asked, "f9") || !slices.Contains(asked, "f1") {
		t.Fatalf("asked %v", asked)
	}
}

// One phone whose CVEs carry three CISA names is one line with all of its findings, and ranks as one product (review round 3, M-a).
func TestTopRisksMergeTheCISANamesOfOneSoftware(t *testing.T) {
	t.Parallel()
	g := func(id, product string) (FindingRow, Fix) {
		return fixRow(id, "ph", "iPhone-CEO", product, "confirmed"), Fix{Kind: "fixed", Group: "s-ios", Version: "18.2", Fixed: "26.7.1", Closed: true}
	}
	var open []FindingRow
	fx := map[string]Fix{}
	for _, c := range [][2]string{{"1", "Apple devices (iPhone, iPad, Mac)"}, {"2", "Apple devices (iPhone, iPad, Mac)"}, {"3", "Apple iOS and iPadOS"}, {"4", "Apple iOS, iPadOS, and macOS"}} {
		r, f := g(c[0], c[1])
		open, fx[c[0]] = append(open, r), f
	}
	open = append(open, fixRow("w1", "pc", "pc-1", "Microsoft Windows", "confirmed"))
	got, _ := topRisks(open, fx)
	if len(got) != 2 {
		t.Fatalf("risks = %+v", got)
	}
	if want := "Upgrade Apple devices (iPhone, iPad, Mac) on iPhone-CEO from 18.2 to 26.7.1 or later — fixes 4 exploited vulnerabilities"; got[0].Action != want || got[0].Open != 4 {
		t.Fatalf("action = %q open %d", got[0].Action, got[0].Open)
	}
	t.Logf("PAGE 1 top risks:\n1. %s\n2. %s", got[0].Action, got[1].Action)
}

// The same firewall with a finding no software row covers is not "1 more device", and the line that names a release leads on a tie
// (review round 3, M-b); two software rows on one device are one device.
func TestTopRisksCountDevicesOnceAndPreferTheNamedRelease(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "fw", "fw-1", "FortiGate", "confirmed"), fixRow("2", "fw", "fw-1", "FortiGate", "confirmed")}
	fx := map[string]Fix{"1": {Kind: "fixed", Group: "s1", Version: "7.2.5", Fixed: "7.4.11", Closed: true}}
	got, _ := topRisks(open, fx)
	if want := "Upgrade FortiGate on fw-1 from 7.2.5 to 7.4.11 or later — fixes 1 exploited vulnerability"; got[0].Action != want {
		t.Fatalf("action = %q", got[0].Action)
	}
	fx["2"] = Fix{Kind: "fixed", Group: "s2", Version: "7.0.1", Fixed: "7.0.9", Closed: true} // a second software row, same device
	if got, _ := topRisks(open, fx); strings.Contains(got[0].Action, "more device") || got[0].Devices != 1 {
		t.Fatalf("action = %q, devices %d", got[0].Action, got[0].Devices)
	}
}

// A product added by hand with no device is named after the product: the step names it once (W5-2), and next to a real device
// it is "the copy added by hand".
func TestTopRisksNameAHandAddedProductOnce(t *testing.T) {
	t.Parallel()
	byHand := fixRow("1", "a1", "Cisco BroadWorks (no device)", "Cisco BroadWorks", "open")
	byHand.noDevice = true
	got, _ := topRisks([]FindingRow{byHand}, nil)
	if want := "Check the version of Cisco BroadWorks (added by hand, no device) to confirm or rule out 1 suspected finding"; got[0].Action != want {
		t.Fatalf("action = %q", got[0].Action)
	}
	got, _ = topRisks([]FindingRow{byHand, fixRow("2", "a2", "bw-srv", "Cisco BroadWorks", "open")}, nil)
	if want := "Check the version of Cisco BroadWorks on bw-srv and the copy added by hand to confirm or rule out 2 suspected findings"; got[0].Action != want {
		t.Fatalf("action = %q", got[0].Action)
	}
}

// D-546 (review r1 M2): a Windows release Microsoft no longer updates is told to take a feature update, not a build it cannot get;
// a fix that needs Extended Security Updates says so.
func TestTopRisksWindowsFeatureUpdateAndESU(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "a1", "pc-01", "Windows 11 22H2", "suspected"), fixRow("2", "a2", "pc-02", "Windows 10 22H2", "suspected")}
	fx := map[string]Fix{"1": {Kind: "feature_update", Version: "10.0.22621.6060", Fixed: "Windows 11 23H2", Closed: true},
		"2": {Kind: "esu", Version: "10.0.19045.6456", Fixed: "10.0.19045.6575", Closed: true}}
	got, _ := topRisks(open, fx)
	want := map[string]string{
		"Windows 11 22H2": "Move Windows 11 22H2 on pc-01 to a Windows release Microsoft still services (a feature update): it gets no more monthly updates, and NVD names the fix only for Windows 11 23H2 — fixes 1 exploited vulnerability",
		"Windows 10 22H2": "Install the Extended Security Update 10.0.19045.6575 or later on Windows 10 22H2 on pc-02, or move it to a Windows release Microsoft still services — fixes 1 exploited vulnerability",
	}
	for _, r := range got {
		if r.Action != want[r.Product] {
			t.Errorf("%s: %q", r.Product, r.Action)
		}
	}
	if len(got) != 2 {
		t.Fatalf("risks = %+v", got)
	}
}

// D-546 (review r2 MEDIUM-1): devices that need an Extended Security Update, another ESU build, or have no fix data are separate steps:
// the first device's fix never speaks for the others, and the step is a "fix", not a "verify".
func TestTopRisksWindowsStepsAreNotMerged(t *testing.T) {
	t.Parallel()
	open := []FindingRow{fixRow("1", "a1", "pc-01", "Windows 10 22H2", "suspected"), fixRow("2", "a2", "pc-02", "Windows 10 22H2", "suspected"),
		fixRow("3", "a3", "pc-03", "Windows 10 22H2", "suspected"), fixRow("4", "a4", "pc-11", "Windows 11 22H2", "suspected"),
		fixRow("5", "a5", "pc-12", "Windows 11 22H2", "suspected")}
	fx := map[string]Fix{"1": {Kind: "esu", Version: "10.0.19045.6456", Fixed: "10.0.19045.6575", Closed: true},
		"2": {Kind: "esu", Version: "10.0.19045.6456", Fixed: "10.0.19045.6693", Closed: true},
		"4": {Kind: "feature_update", Version: "10.0.22621.6060", Fixed: "Windows 11 23H2", Closed: true}}
	got, kinds := topRisks(open, fx)
	if len(got) != 2 {
		t.Fatalf("risks = %+v", got)
	}
	for i, r := range got {
		if kinds[i] != "fix" {
			t.Errorf("%s: kind %s", r.Product, kinds[i])
		}
		switch r.Product {
		case "Windows 10 22H2":
			if !strings.HasPrefix(r.Action, "Install the Extended Security Update 10.0.19045.") || !strings.Contains(r.Action, " on pc-0") ||
				strings.Contains(r.Action, "and 2 more") || !strings.HasSuffix(r.Action, "; 2 more devices need another step") {
				t.Errorf("esu line: %q", r.Action)
			}
		case "Windows 11 22H2":
			if !strings.HasPrefix(r.Action, "Move Windows 11 22H2 on pc-11 to") || strings.Contains(r.Action, "pc-12 to") ||
				!strings.HasSuffix(r.Action, "; 1 more device needs another step") {
				t.Errorf("feature update line: %q", r.Action)
			}
		}
	}
}

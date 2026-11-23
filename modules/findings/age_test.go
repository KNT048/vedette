package findings

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// S-TIER-4: a KEV CVE published more than 12 months ago keeps every match that compared a version
// (agent, SNMP or LLDP, a person's entry, a banner) with its usual label; only a product-only match (no version compared) is
// dropped. A recent CVE and one with no known published day keep today's rules.
// nameOnly is a want of no finding because only the product name matched (MatchResult.NameOnly).
const nameOnly Basis = "name-only"

func TestMatchAsset_OldKEVDropsOnlyProductOnly(t *testing.T) {
	t.Parallel()
	old, recent := t0.AddDate(-2, 0, 0), t0.AddDate(0, -1, 0)
	ranged := func(pub time.Time) []Vuln {
		v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
		v.Published, v.DateAdded = pub, pub
		return []Vuln{v}
	}
	productOnly := func(pub time.Time) []Vuln { v := qnapVuln(); v.Published, v.DateAdded = pub, pub; return []Vuln{v} }
	agent := func(ver string) Asset { a := nas(ver); a.Software[0].Source = "agent"; return a }
	for name, tc := range map[string]struct {
		a       Asset
		vulns   []Vuln
		want    Basis // "" = no finding
		agentEv bool
	}{
		"old, product only":              {nas("6.1.1"), productOnly(old), "", false},
		"old, banner version inside":     {nas("6.1.1"), ranged(old), BasisVersion, false},
		"old, agent version inside":      {agent("6.1.1"), ranged(old), BasisVersion, true},
		"old, banner version outside":    {nas("6.2.0"), ranged(old), "", false},
		"recent, product only":           {nas("6.1.1"), productOnly(recent), nameOnly, false},
		"recent, banner version":         {nas("6.1.1"), ranged(recent), BasisVersion, false},
		"unknown day, product only":      {nas("6.1.1"), productOnly(time.Time{}), nameOnly, false},
		"product only, just inside year": {nas("6.1.1"), productOnly(t0.Add(-AgeLimit + time.Hour)), nameOnly, false},
		"product only, just over a year": {nas("6.1.1"), productOnly(t0.Add(-AgeLimit - time.Hour)), "", false},
		// review r1 #1 of #803: a safe scan template checks it, so the finding stays for the scan to confirm or clear it
		"old, product only, scan template": {nas("6.1.1"), func() []Vuln { v := productOnly(old); v[0].HasTemplate = true; return v }(), BasisProduct, false},
		// review r1 #3: NVD lists every version as affected, so no version could change it: it stays
		"old, every version, no version given": {nas(""), func() []Vuln {
			v := qnapVuln(Affected{CPE: qnapCPE})
			v.Published, v.DateAdded = old, old
			return []Vuln{v}
		}(), BasisProduct, false},
		// review r2 R of #803: KEV news is never hidden: an old CVE CISA added today is recent
		"old published, added today, product only": {nas("6.1.1"), func() []Vuln { v := productOnly(old); v[0].DateAdded = t0; return v }(), nameOnly, false},
		"old published, unknown date added":        {nas("6.1.1"), func() []Vuln { v := productOnly(old); v[0].DateAdded = time.Time{}; return v }(), nameOnly, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(tc.a, tc.vulns, nil, t0)
			if tc.want == nameOnly { // not aged, but no finding on the product name alone either
				if len(res.New) != 0 || len(res.Aged) != 0 || len(res.NameOnly) != 1 {
					t.Fatalf("%+v; want only NameOnly", res)
				}
				return
			}
			if tc.want == "" {
				if len(res.New) != 0 {
					t.Fatalf("new = %+v; want none", res.New)
				}
				return
			}
			if len(res.New) != 1 || res.New[0].Basis != tc.want || res.New[0].Evidence.Agent != tc.agentEv {
				t.Fatalf("new = %+v; want basis %s, agent %v", res.New, tc.want, tc.agentEv)
			}
		})
	}
	// the product-only old match is in Aged with the sentence that closes a finding of it
	res := MatchAsset(nas("6.1.1"), productOnly(old), map[string]bool{"CVE-2022-27593": true}, t0)
	if len(res.Existing) != 0 || len(res.Aged) != 1 || !strings.HasPrefix(res.Aged[0].Evidence.Summary, AgedNote+": CVE-2022-27593 was published on 9 Nov 2024 and added to CISA's list on 9 Nov 2024") {
		t.Fatalf("existing %+v, aged %+v", res.Existing, res.Aged)
	}
	// a version would decide an old CVE too, so the "add the version" item still counts it
	if res := MatchAsset(nas(""), ranged(old), nil, t0); len(res.NeedVersion) != 1 || len(res.New) != 0 {
		t.Fatalf("old CVE, no version: %+v", res)
	}
}

// The age rule measured on the real fixtures: the KEV entries and NVD ranges of the golden set, the Juniper set and the
// Office set, with each CVE's real published day (testdata/kev-published.json), on the devices the golden tests use. Each
// device starts with the flood the old matcher left (a finding for every KEV CVE of its products) and is matched again:
// the counts are the open findings the age rule closes, by basis: only product-only ones, so a FortiGate 6.2.0 read
// from a banner keeps its old exploited CVEs (CVE-2018-13379 class).
func TestGolden_WhatTheAgeRuleCloses(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/kev-published.json")
	if err != nil {
		t.Fatal(err)
	}
	var pf struct {
		Published map[string]string `json:"published"`
	}
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatal(err)
	}
	dated := func(vs []Vuln) []Vuln {
		for i := range vs {
			if d, err := time.Parse(time.DateOnly, pf.Published[vs[i].CVE]); err == nil {
				vs[i].Published = d
			}
		}
		return vs
	}
	golden := dated(goldenVulns(t))
	junos := dated(loadGolden(t, "testdata/kev-nvd-junos-n23.json"))
	ex4200SNMP := labEX4200()
	ex4200SNMP.SNMPOS = ex4200SNMP.StatedOS
	devices := []struct {
		name  string
		a     Asset
		vulns []Vuln
	}{
		{"iPhone 16.0.3 (typed)", Asset{ID: "a", Name: "phone", Software: []Software{iPhone(golden, "16.0.3")}}, golden},
		{"FortiGate 7.2.5 (banner)", Asset{ID: "a", Name: "fw", Software: []Software{fortiGate(golden, "7.2.5")}}, golden},
		{"FortiGate 6.2.0 (banner)", Asset{ID: "a", Name: "fw", Software: []Software{fortiGate(golden, "6.2.0")}}, golden},
		{"Office 2016 (typed)", Asset{ID: "a", Name: "pc", Software: []Software{office(golden, "2016")}}, golden},
		{"NetScaler 13.1-49.13 (banner)", Asset{ID: "a", Name: "adc", Software: []Software{netScaler(golden, "13.1-49.13")}}, golden},
		{"EX4200 JUNOS 15.1R7.9 (LLDP)", labEX4200(), junos},
		{"EX4200 JUNOS 15.1R7.9 (SNMP)", ex4200SNMP, junos},
		{"Ubuntu 26.04.1 server (agent)", Asset{ID: "a", Name: "byn", OS: "Ubuntu 26.04.1 LTS", AgentOS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}, golden},
	}
	var totP, totV, totN, totKept, totOpen int
	for _, d := range devices {
		flood := map[string]bool{}
		for _, v := range d.vulns {
			for _, sw := range deviceSoftware(d.a) {
				if keyedTo(sw, v) {
					flood[v.CVE] = true
				}
			}
		}
		undated := slices.Clone(d.vulns)
		for i := range undated {
			undated[i].Published = time.Time{}
		}
		before := MatchAsset(d.a, undated, flood, t0) // the matcher without the age rule (no published day)
		after := MatchAsset(d.a, d.vulns, flood, t0)
		var p, v, n int
		for _, x := range after.Aged {
			if !flood[x.CVE] {
				continue
			}
			if x.Basis == BasisProduct {
				p++
			} else {
				v++
			}
		}
		for _, x := range after.NameOnly { // The product-only ones the age rule does not take (recent, or an agent row)
			if flood[x.CVE] {
				n++
			}
		}
		open := len(before.Existing) + len(before.NameOnly) // the open findings the old matcher left (the name-only rule makes those no finding)
		t.Logf("%-32s open before %3d (product %3d), closed by the age rule: product %3d, version %3d; by the name-only rule %3d; kept %3d",
			d.name, open, countBasis(before.Existing, BasisProduct)+len(before.NameOnly), p, v, n, len(after.Existing))
		if open != len(after.Existing)+p+v+n {
			t.Errorf("%s: %d before, %d kept + %d closed", d.name, open, len(after.Existing), p+v+n)
		}
		totP, totV, totN, totKept, totOpen = totP+p, totV+v, totN+n, totKept+len(after.Existing), totOpen+open
	}
	t.Logf("all devices: %d open findings before; the age rule closes %d product-only and %d version ones, the name-only rule %d more; %d stay", totOpen, totP, totV, totN, totKept)
	// pinned: a change of the rule or the data shows here. Only product-only findings close (the first build, which also
	// closed banner and typed versions, closed 12 + 68 and kept 27: too strict for unpatched gear). The
	// product-only findings the age rule left (recent entries) close too; only version evidence stays.
	if totOpen != 107 || totP != 12 || totV != 0 || totN != 3 || totKept != 92 {
		t.Errorf("before %d, closed product %d, version %d, name-only %d, kept %d; want 107, 12, 0, 3, 92", totOpen, totP, totV, totN, totKept)
	}
}

func countBasis(ms []Match, b Basis) int {
	n := 0
	for _, m := range ms {
		if m.Basis == b {
			n++
		}
	}
	return n
}

// Review r1 #5 / r2 #4 of #803: "I have this" never re-adds, from a version-less row, a CVE the age rule dropped on another row
// of the same product (it would be created, with an alert, and closed in the same write).
func TestHaveScope_DoesNotReaddAgedCVE(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a-declared", Name: "QNAP", Software: []Software{
		{ID: "s-1", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "6.1.1", KevKeys: []string{"qnap|photo station"}},
		{ID: "s-2", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", KevKeys: []string{"qnap|photo station"}},
	}}
	v := qnapVuln()
	v.DateAdded = t0
	m := MatchResult{
		Aged:        []Match{{CVE: v.CVE, SoftwareID: "s-1", Basis: BasisProduct}},
		NeedVersion: []VersionNeeded{{SoftwareID: "s-2", Software: "Photo Station", CVEs: []string{v.CVE}}},
	}
	got := haveScope(a, []Vuln{v}, m, map[string]Have{a.ID: {Key: "qnap|photo station", Since: t0.AddDate(0, 0, -7)}}, nil, t0)
	if len(got.New) != 0 || len(got.Existing) != 0 || len(got.Aged) != 1 {
		t.Fatalf("new %+v, existing %+v, aged %+v", got.New, got.Existing, got.Aged)
	}
}

// Review r1 M1 of #909: a kernel CVE whose NVD list names only Ubuntu releases (CVE-2021-3493, NVD's real rows) names the device's own
// OS on an Ubuntu 20.04 host: the agent's kernel row is evidence and the finding stays past 12 months (no distro verdict here). On a
// Debian 13 host NVD names another distribution, so it ages out.
func TestMatchAsset_904_OwnOSIsNotAnotherProduct(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2021-3493", Vendor: "Linux", Product: "Kernel", Published: t0.AddDate(-5, 0, 0), DateAdded: t0.AddDate(-4, 0, 0), Affected: []Affected{
		{CPE: "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:lts:*:*:*", Range: VersionRange{EndIncl: "18.04"}},
		{CPE: "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:lts:*:*:*", Range: VersionRange{StartIncl: "18.04.1", EndIncl: "20.04"}},
		{CPE: "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:-:*:*:*", Range: VersionRange{EndIncl: "20.10"}}}}
	host := func(os, ver string) Asset {
		return Asset{ID: "a-1", Name: "host", OS: os, AgentOS: os, Software: []Software{{ID: "s-k", Display: "Linux Kernel", Vendor: "Linux", Product: "Kernel",
			Version: ver, KevKeys: []string{"linux|kernel"}, Source: "agent"}}}
	}
	// The agent's kernel row is no version evidence either way, so the old entry ages out on every host
	r := MatchAsset(host("Ubuntu 20.04.6 LTS", "5.4.0"), []Vuln{v}, nil, t0)
	if len(r.Aged) != 1 || len(r.New)+len(r.NameOnly) != 0 || confirmedMatch(r.Aged[0]) {
		t.Errorf("Ubuntu 20.04: %+v", r)
	}
	if r := MatchAsset(host("Debian GNU/Linux 13 (trixie)", "6.12.57"), []Vuln{v}, nil, t0); len(r.Aged) != 1 || len(r.New) != 0 {
		t.Errorf("Debian 13: %+v", r)
	}
	// review r2 M1: a distribution the OS check does not read may be the one NVD names (Mint 20 runs Ubuntu 20.04's kernel): never aged
	for _, os := range []string{"Linux Mint 20.3", "Pop!_OS 20.04 LTS", "Ubuntu", ""} {
		if r := MatchAsset(host(os, "5.4.0-42-generic"), []Vuln{v}, nil, t0); len(r.Aged) != 1 || len(r.New)+len(r.NameOnly) != 0 {
			t.Errorf("%q: %+v", os, r)
		}
	}
}

// Review r1 M2 of #909: when neither match is confirmed (NVD lists only other products), the agent's row still wins the tie whatever
// the order of the rows: an old entry ages on the agent's row (closeAged then closes the stored agent finding), and a recent one keeps
// agent_row (the page does not ask for the version).
func TestMatchAsset_904_AgentRowWinsAnUnconfirmedTie(t *testing.T) {
	t.Parallel()
	agent := Software{ID: "s-agent", Display: "Microsoft Exchange Server 2019", Vendor: "Microsoft", Product: "Exchange Server", Version: "15.2.1118.7",
		KevKeys: []string{"microsoft|exchange server"}, Source: "agent"}
	banner := Software{ID: "s-nmap", Display: "Exchange", Vendor: "Microsoft", Product: "Exchange Server", Version: "15.2", KevKeys: []string{"microsoft|exchange server"}, Source: "nmap"}
	v := Vuln{CVE: "CVE-2021-26855", Vendor: "Microsoft", Product: "Exchange Server", Affected: []Affected{{CPE: "cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*"}}}
	old, recent := v, v
	old.Published, old.DateAdded = t0.AddDate(-5, 0, 0), t0.AddDate(-5, 0, 0)
	recent.Published, recent.DateAdded = t0.AddDate(0, -1, 0), t0.AddDate(0, -1, 0)
	for name, rows := range map[string][]Software{"agent first": {agent, banner}, "banner first": {banner, agent}} {
		a := Asset{ID: "a-1", Name: "mail01", AgentOS: "Microsoft Windows Server 2019", Software: rows}
		if m := MatchAsset(a, []Vuln{old}, map[string]bool{v.CVE: true}, t0); len(m.Aged) != 1 || m.Aged[0].SoftwareID != "s-agent" || m.Aged[0].others == "" {
			t.Errorf("%s, old: %+v", name, m)
		}
		if m := MatchAsset(a, []Vuln{recent}, nil, t0); len(m.NameOnly) != 1 || m.NameOnly[0].SoftwareID != "s-agent" || !m.NameOnly[0].Evidence.AgentRow {
			t.Errorf("%s, recent: %+v", name, m)
		}
	}
}

// Old KEV drops only product-only matches WITHOUT agent evidence: a product match on a row
// the device's agent reported (Evidence.AgentRow: the agent gave the installed version, Vedette could not compare it) is never
// dropped or closed for its age; a finding the age rule closed before this fix reopens at the next match, with the neutral note.
func TestContract_AgentRowNeverAges(t *testing.T) {
	t.Parallel()
	srv := Asset{ID: "a-1", Name: "WINLAB01", OS: "Microsoft Windows Server 2025 Datacenter", AgentOS: "Microsoft Windows Server 2025 Datacenter",
		Software: []Software{{ID: "s-win", Display: "Windows Server 2025", Vendor: "Microsoft", Product: "Windows", Version: "10.0.26100.1742",
			CPE: "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100.1742:*:*:*:*:*:x64:*", KevKeys: []string{"microsoft|windows"}, Source: "agent"}}}
	v := Vuln{CVE: "CVE-2024-43573", Vendor: "Microsoft", Product: "Windows", Published: t0.AddDate(-2, 0, 0), DateAdded: t0.AddDate(-2, 0, 0)} // no version Vedette can compare
	m := MatchAsset(srv, []Vuln{v}, nil, t0)
	// The agent row is no version evidence, so the old entry ages out like any product-only match
	if len(m.Aged) != 1 || len(m.New)+len(m.NameOnly) != 0 || m.Aged[0].Basis != BasisProduct || !m.Aged[0].Evidence.AgentRow {
		t.Fatalf("an agent row kept, or a name-only finding: %+v", m)
	}
}

// Review r2 #1 of #804: the agent's row keeps an old KEV CVE whatever the order of the device's rows: an nmap row of the same product
// that sorts first and cannot be compared either must not win the tie and send the pair to Aged. And a finding stored with the agent
// row's evidence is never closed for its age when only the banner row matches later (the closeAged guard).
func TestContract_AgentRowWinsTheTieInBothOrders(t *testing.T) {
	t.Parallel()
	agent := Software{ID: "s-agent", Display: "Microsoft Exchange Server 2019", Vendor: "Microsoft", Product: "Exchange Server", Version: "15.2.792.3",
		KevKeys: []string{"microsoft|exchange server"}, Source: "agent"}
	banner := Software{ID: "s-nmap", Display: "Exchange", Vendor: "Microsoft", Product: "Exchange Server", Version: "15.2", KevKeys: []string{"microsoft|exchange server"}, Source: "nmap"}
	// ProxyLogon as a test box holds it: a safe scan template checks it, and NVD's cumulative-update rows do not compare with the build
	v := Vuln{CVE: "CVE-2021-26855", Vendor: "Microsoft", Product: "Exchange Server", Published: t0.AddDate(-5, 0, 0), DateAdded: t0.AddDate(-5, 0, 0), Ransomware: true, HasTemplate: true,
		Affected: []Affected{{CPE: "cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_8:*:*:*:*:*:*"}}}
	for name, rows := range map[string][]Software{"agent first": {agent, banner}, "banner first": {banner, agent}} {
		m := MatchAsset(Asset{ID: "a-1", Name: "mail01", AgentOS: "Microsoft Windows Server 2019", Software: rows}, []Vuln{v}, nil, t0)
		if len(m.Aged)+len(m.NameOnly) != 0 || len(m.New) != 1 || !m.New[0].Evidence.AgentRow || m.New[0].SoftwareID != "s-agent" { // review r1 H1 of #939
			t.Errorf("%s: %+v", name, m)
		}
	}
}

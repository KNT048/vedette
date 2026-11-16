package findings

import (
	"database/sql"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// D-615 as amended by D-616 (S-TIER-4): a KEV CVE published more than 12 months ago keeps every match that compared a version
// (agent, SNMP or LLDP, a person's entry, a banner) with its usual label; only a product-only match (no version compared) is
// dropped. A recent CVE and one with no known published day keep today's rules.
func TestMatchAsset_D615_OldKEVDropsOnlyProductOnly(t *testing.T) {
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
		"recent, product only":           {nas("6.1.1"), productOnly(recent), BasisProduct, false},
		"recent, banner version":         {nas("6.1.1"), ranged(recent), BasisVersion, false},
		"unknown day, product only":      {nas("6.1.1"), productOnly(time.Time{}), BasisProduct, false},
		"product only, just inside year": {nas("6.1.1"), productOnly(t0.Add(-AgeLimit + time.Hour)), BasisProduct, false},
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
		"old published, added today, product only": {nas("6.1.1"), func() []Vuln { v := productOnly(old); v[0].DateAdded = t0; return v }(), BasisProduct, false},
		"old published, unknown date added":        {nas("6.1.1"), func() []Vuln { v := productOnly(old); v[0].DateAdded = time.Time{}; return v }(), BasisProduct, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(tc.a, tc.vulns, nil, t0)
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

// D-615, D-616, S-TIER-4: an open product-only finding of an old KEV CVE closes with the reason in its history (never deleted,
// no alert: notify ignores not_relevant), and reopens when a version can be compared and is affected. A finding a scan
// confirmed, or one a person reopened, never closes for its age.
func TestContract_D615_AgedFindingClosesAndReopens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := qnapVuln() // no NVD ranges: a product-only match
	upsert := func(a Asset, pub time.Time) {
		t.Helper()
		e.advance(time.Minute)
		x := v
		x.Published, x.DateAdded = pub, pub
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, []Vuln{x}); err != nil {
			t.Fatal(err)
		}
	}
	load := func() Record {
		t.Helper()
		r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	upsert(nas("6.1.1"), time.Time{}) // before nvd-kev stored the day: counts as recent, a product finding (no NVD ranges)
	e.pub.take()
	upsert(nas("6.1.1"), t0.AddDate(-3, 0, 0)) // the day arrives: old, product only
	r := load()
	if r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonNotAffectedVersion || !strings.HasPrefix(r.ResolutionNote, AgedNote) {
		t.Fatalf("not closed for its age: %+v", r.Finding)
	}
	if last := r.History[len(r.History)-1]; last.User != SystemUser || !strings.HasPrefix(last.Note, AgedNote) {
		t.Fatalf("history %+v", r.History)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: r.ID, From: StatusSuspected, To: StatusNotRelevant, Reason: ReasonNotAffectedVersion}) {
		t.Fatalf("events = %+v", ev)
	}
	upsert(nas("6.1.1"), t0.AddDate(-3, 0, 0)) // said once
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved' AND detail LIKE '%D-615%'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	v = qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}) // NVD's ranges arrive: 6.1.1 is inside
	upsert(nas("6.1.1"), t0.AddDate(-3, 0, 0))
	if r = load(); r.Status != StatusSuspected || r.ResolutionNote != "" {
		t.Fatalf("not reopened: %+v", r.Finding)
	}
	if last := r.History[len(r.History)-1]; last.Action != "matches_again" || !strings.Contains(last.Note, "older than 12 months and matched by the product name only") {
		t.Fatalf("reopen row %+v", last)
	}

	v = qnapVuln()

	// review r1 #2 of #803: a version finding whose match falls back to product-only (NVD's ranges gone in one pull) is not closed
	w := newEnv(t)
	inRange := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	if _, err := w.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{inRange}); err != nil {
		t.Fatal(err)
	}
	gone := qnapVuln()
	gone.Published, gone.DateAdded = t0.AddDate(-3, 0, 0), t0.AddDate(-3, 0, 0)
	if _, err := w.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{gone}); err != nil {
		t.Fatal(err)
	}
	if r, _ := loadByPair(t.Context(), w.db.Reader(), "a-1", "CVE-2022-27593"); r.Status != StatusSuspected || r.Basis != BasisVersion {
		t.Fatalf("version finding closed for its age: %+v", r.Finding)
	}

	// a scan-confirmed finding stays open whatever its age
	s := newEnv(t)
	if _, err := s.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", Evidence{Template: "CVE-2022-27593", CheckedAt: t0}); err != nil {
		t.Fatal(err)
	}
	old := v
	old.Published, old.DateAdded = t0.AddDate(-3, 0, 0), t0.AddDate(-3, 0, 0)
	if _, err := s.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{old}); err != nil {
		t.Fatal(err)
	}
	if r, _ := loadByPair(t.Context(), s.db.Reader(), "a-1", "CVE-2022-27593"); r.Status != StatusConfirmed {
		t.Fatalf("scan finding closed: %+v", r.Finding)
	}

	// a person who reopened it decided: never closed for its age again, and its history says why it is no longer matched
	p := newEnv(t)
	if _, err := p.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{old}); err != nil {
		t.Fatal(err)
	}
	pr, _ := loadByPair(t.Context(), p.db.Reader(), "a-1", "CVE-2022-27593")
	if _, err := p.svc.SetStatus(t.Context(), pr.ID, ActionReopen, "", "kim@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{old}); err != nil {
		t.Fatal(err)
	}
	pr, _ = loadByPair(t.Context(), p.db.Reader(), "a-1", "CVE-2022-27593")
	if last := pr.History[len(pr.History)-1]; pr.Status != StatusSuspected || last.Action != "no_longer_matches" || !strings.Contains(last.Note, "This finding stays open") {
		t.Fatalf("person's reopen not kept: %+v, history %+v", pr.Finding, pr.History)
	}
}

// D-616, D-617: GET /findings/plan (S-TIER-1, S-TIER-2) answers before the plan job's first run: no item, compared false, and the
// state of each tier feed, so the page says what is missing instead of "no update to plan"; "plan" is never a finding id.
func TestPlan_HonestStateBeforeTheMatcher(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	c, b := e.call("GET", "/findings/plan", "viewer", "")
	if c != 200 || b["compared"] != false || len(b["items"].([]any)) != 0 {
		t.Fatalf("%d %v", c, b)
	}
	if d := b["data"].(map[string]any); d["epss"] != "off" || d["recent"] != "off" || d["epss_date"] != nil {
		t.Fatalf("data %v", d)
	}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "loading", EPSSDate: t0}
	c, b = e.call("GET", "/findings/plan?tier=likely&asset=a-1", "viewer", "")
	if d := b["data"].(map[string]any); c != 200 || d["epss"] != "ready" || d["recent"] != "loading" || d["epss_date"] != "2026-11-09" || d["recent_since"] != nil {
		t.Fatalf("%d %v", c, b)
	}
	e.gate.Set("feeds", false) // modules.md: the data is missing because the module is off, and its tables are not read
	c, b = e.call("GET", "/findings/plan", "viewer", "")
	if d := b["data"].(map[string]any); c != 200 || d["epss"] != "module_off" || d["recent"] != "module_off" || d["epss_date"] != nil {
		t.Fatalf("feeds module off: %d %v", c, b)
	}
	if c, _ = e.call("GET", "/findings/plan?tier=bogus", "viewer", ""); c != 400 {
		t.Fatalf("bad tier: %d", c)
	}
}

// D-615 measured on the real fixtures: the KEV entries and NVD ranges of the golden set, the N23 Juniper set and the N22
// Office set, with each CVE's real published day (testdata/kev-published.json), on the devices the golden tests use. Each
// device starts with the flood the old matcher left (a finding for every KEV CVE of its products) and is matched again:
// the counts are the open findings the age rule closes, by basis: only product-only ones (D-616), so a FortiGate 6.2.0 read
// from a banner keeps its old exploited CVEs (CVE-2018-13379 class).
func TestGolden_D615_WhatTheAgeRuleCloses(t *testing.T) {
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
	ex4200SNMP := walk1EX4200()
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
		{"EX4200 JUNOS 15.1R7.9 (LLDP)", walk1EX4200(), junos},
		{"EX4200 JUNOS 15.1R7.9 (SNMP)", ex4200SNMP, junos},
		{"Ubuntu 26.04.1 server (agent)", Asset{ID: "a", Name: "byn", OS: "Ubuntu 26.04.1 LTS", AgentOS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}, golden},
	}
	var totP, totV, totKept, totOpen int
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
		var p, v int
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
		t.Logf("%-32s open before %3d (product %3d), closed by the age rule: product %3d, version %3d; kept %3d",
			d.name, len(before.Existing), countBasis(before.Existing, BasisProduct), p, v, len(after.Existing))
		if len(before.Existing) != len(after.Existing)+p+v {
			t.Errorf("%s: %d before, %d kept + %d closed", d.name, len(before.Existing), len(after.Existing), p+v)
		}
		totP, totV, totKept, totOpen = totP+p, totV+v, totKept+len(after.Existing), totOpen+len(before.Existing)
	}
	t.Logf("all devices: %d open findings before; the age rule closes %d product-only and %d version ones; %d stay", totOpen, totP, totV, totKept)
	// pinned: a change of the rule or the data shows here. D-616: only product-only findings close (the first build, which also
	// closed banner and typed versions, closed 12 + 68 and kept 27; supervisor 2026-11-15: too strict for unpatched gear).
	if totOpen != 107 || totP != 12 || totV != 0 || totKept != 95 {
		t.Errorf("before %d, closed product %d, version %d, kept %d; want 107, 12, 0, 95", totOpen, totP, totV, totKept)
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

// Review r2 #4 of #803 (round-1 #7): the hourly reconcile closes what the age rule drops and counts it, so a pull that only
// filled the published days (no ranges changed, no rematch event) still closes within the hour.
func TestReconcile_D615_CountsAgedClosures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed() // a product finding: the sample entry has no NVD ranges
	e.feeds.vulns[0].Published, e.feeds.vulns[0].DateAdded = t0.AddDate(-4, 0, 0), t0.AddDate(-4, 0, 0)
	res, err := e.svc.Reconcile(t.Context())
	if err != nil || res.Aged != 1 {
		t.Fatalf("reconcile %+v %v", res, err)
	}
	if r, _ := e.svc.Get(t.Context(), id); r.Status != StatusNotRelevant {
		t.Fatalf("status %s", r.Status)
	}
}

// Review r1 #5 / r2 #4 of #803: "I have this" never re-adds, from a version-less row, a CVE the age rule dropped on another row
// of the same product (it would be created, with an alert, and closed in the same write).
func TestHaveScope_D615_DoesNotReaddAgedCVE(t *testing.T) {
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

// N100 n54 (D-615, D-616 as told to kien: old KEV drops only product-only matches WITHOUT agent evidence): a product match on a row
// the device's agent reported (Evidence.AgentRow, D-612: the agent gave the installed version, Vedette could not compare it) is never
// dropped or closed for its age; a finding the age rule closed before this fix reopens at the next match, with the neutral note.
func TestContract_D615_AgentRowNeverAges(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	srv := Asset{ID: "a-1", Name: "WINLAB01", OS: "Microsoft Windows Server 2025 Datacenter", AgentOS: "Microsoft Windows Server 2025 Datacenter",
		Software: []Software{{ID: "s-win", Display: "Windows Server 2025", Vendor: "Microsoft", Product: "Windows", Version: "10.0.26100.1742",
			CPE: "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100.1742:*:*:*:*:*:x64:*", KevKeys: []string{"microsoft|windows"}, Source: "agent"}}}
	v := Vuln{CVE: "CVE-2024-43573", Vendor: "Microsoft", Product: "Windows", Published: t0.AddDate(-2, 0, 0), DateAdded: t0.AddDate(-2, 0, 0)} // no version Vedette can compare
	m := MatchAsset(srv, []Vuln{v}, nil, t0)
	if len(m.Aged) != 0 || len(m.New) != 1 || m.New[0].Basis != BasisProduct || !m.New[0].Evidence.AgentRow {
		t.Fatalf("an agent row aged out: %+v", m)
	}
	if _, err := e.svc.UpsertFromMatch(t.Context(), srv, []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", v.CVE)
	if err != nil || r.Status != StatusSuspected {
		t.Fatalf("not open past 12 months: %+v %v", r.Finding, err)
	}
	// what the bug left on the box: the same finding closed for its age
	f, h, ok := r.AutoResolve(agedSummary(v), t0)
	if !ok {
		t.Fatal("could not close")
	}
	r.Finding = f
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		if err := updateRecord(t.Context(), tx, r); err != nil {
			return err
		}
		return insertHistory(t.Context(), tx, r.ID, h)
	}); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Minute)
	if _, err := e.svc.UpsertFromMatch(t.Context(), srv, []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	r, _ = loadByPair(t.Context(), e.db.Reader(), "a-1", v.CVE)
	if last := r.History[len(r.History)-1]; r.Status != StatusSuspected || last.Action != "matches_again" {
		t.Fatalf("not reopened: %+v, history %+v", r.Finding, r.History)
	}
}

// Review r2 #1 of #804: the agent's row keeps an old KEV CVE whatever the order of the device's rows: an nmap row of the same product
// that sorts first and cannot be compared either must not win the tie and send the pair to Aged. And a finding stored with the agent
// row's evidence is never closed for its age when only the banner row matches later (the closeAged guard).
func TestContract_D615_AgentRowWinsTheTieInBothOrders(t *testing.T) {
	t.Parallel()
	agent := Software{ID: "s-agent", Display: "Microsoft Exchange Server 2019", Vendor: "Microsoft", Product: "Exchange Server", Version: "15.2.1118.7",
		KevKeys: []string{"microsoft|exchange server"}, Source: "agent"}
	banner := Software{ID: "s-nmap", Display: "Exchange", Vendor: "Microsoft", Product: "Exchange Server", Version: "15.2", KevKeys: []string{"microsoft|exchange server"}, Source: "nmap"}
	v := Vuln{CVE: "CVE-2021-26855", Vendor: "Microsoft", Product: "Exchange Server", Published: t0.AddDate(-5, 0, 0), DateAdded: t0.AddDate(-5, 0, 0)} // no comparable range
	for name, rows := range map[string][]Software{"agent first": {agent, banner}, "banner first": {banner, agent}} {
		m := MatchAsset(Asset{ID: "a-1", Name: "mail01", AgentOS: "Microsoft Windows Server 2019", Software: rows}, []Vuln{v}, nil, t0)
		if len(m.Aged) != 0 || len(m.New) != 1 || !m.New[0].Evidence.AgentRow || m.New[0].SoftwareID != "s-agent" {
			t.Errorf("%s: %+v", name, m)
		}
	}
	e := newEnv(t)
	dev := Asset{ID: "a-1", Name: "mail01", AgentOS: "Microsoft Windows Server 2019", Software: []Software{banner, agent}}
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	dev.Software = []Software{banner} // the agent stops reporting the row; only the banner, product-only, matches now
	e.advance(time.Minute)
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	if r, _ := loadByPair(t.Context(), e.db.Reader(), "a-1", v.CVE); r.Status != StatusSuspected || r.Evidence == nil || !r.Evidence.AgentRow {
		t.Fatalf("an agent-evidence finding closed for its age: %+v", r.Finding)
	}
}

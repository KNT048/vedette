package findings

import (
	"testing"
)

// oldBuildWorld is one desktop (pc-01) running Acme Desk 3.7.6 and five CVEs whose only rows are the exact build 3.0.4 a third party
// tested (no range, no fix, not the vendor's record): CVE-2019-90101 says nothing more anywhere; the record of CVE-2026-90102 gives a
// solution and that of CVE-2026-90105 a workaround; CVE-2026-90103 has a reference tagged as the vendor's advisory; CVE-2021-90104 is
// on an exploited list. checker false leaves the box without a door to the CVE records.
func oldBuildWorld(t *testing.T, checker bool) *env {
	t.Helper()
	e := newEnv(t)
	tested := func(cve string) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Published: uncNew, Affected: []Affected{
			{CPE: "cpe:2.3:*:acme:acme_desk:3.0.4:*:*:*:*:*:*:*", AffectedOnly: true}, // the third party's record row beside NVD's copy
			{CPE: "cpe:2.3:a:acme:acme_desk:3.0.4:*:*:*:*:*:*:*"}}}
	}
	e.feeds.vulns = []Vuln{tested("CVE-2019-90101"), tested("CVE-2026-90102"), tested("CVE-2026-90103"), tested("CVE-2021-90104"),
		tested("CVE-2026-90105")}
	e.feeds.unlisted = map[string]bool{"CVE-2019-90101": true, "CVE-2026-90102": true, "CVE-2026-90103": true, "CVE-2026-90105": true}
	pc := Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{{ID: "s-desk", Display: "Acme Desk",
		Vendor: "Acme", Product: "Acme Desk", Version: "3.7.6", Source: "agent", KevKeys: []string{"acme|acme desk"}}}}
	e.inv.assets = map[string]AssetView{"pc-01": {ID: "pc-01", Name: "pc-01", Hostname: ptr("pc-01"), IP: "192.0.2.71", Kind: "workstation", Approved: true}}
	e.inv.match = map[string]Asset{"pc-01": pc}
	if checker {
		lab := RefLink{URL: "https://lab.example.com/advisories/acme-desk", Tags: []string{"Third Party Advisory"}}
		poc := RefLink{URL: "https://exploits.example.com/acme-desk", Tags: []string{"exploit"}}
		e.svc.SetChecker(&fakeChecker{records: map[string]CVERecordText{
			"CVE-2019-90101": {Description: "Acme Desk 3.0.4 contains a flaw.", Refs: []RefLink{lab, poc}},
			"CVE-2026-90102": {Description: "Acme Desk 3.0.4 contains a flaw.", Solution: "Upgrade to 3.5.0 or later.", Refs: []RefLink{lab}},
			"CVE-2026-90103": {Description: "Acme Desk 3.0.4 contains a flaw.", Refs: []RefLink{lab,
				{URL: "https://acme.example.com/security/2026-01", Tags: []string{"Vendor Advisory"}}}},
			"CVE-2021-90104": {Description: "Acme Desk 3.0.4 contains a flaw.", Refs: []RefLink{lab, poc}},
			"CVE-2026-90105": {Description: "Acme Desk 3.0.4 contains a flaw.", Workaround: "Turn off the preview pane.", Refs: []RefLink{lab}},
		}})
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e
}

// A CVE a third party reported for an older build it tested (every row an exact build older than the installed release), on no
// exploited list, whose record gives no fix, no workaround and no vendor reference, is listed apart as reported only for an older
// build, with the builds tested and the year of the report: it stays possible (nothing closes, no finding), and the counts give the
// main possible number and this group's number separately, on the list, on Home and on the device badge. A record that says anything
// more (a solution, a workaround, the vendor's advisory) or an exploited CVE stays in the main list.
func TestOlderBuild_AThirdPartysOldTestedBuildIsCountedApart(t *testing.T) {
	t.Parallel()
	e := oldBuildWorld(t, true)
	list, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*OlderBuild{}
	for _, r := range list.Items {
		got[r.CVE] = r.OlderBuild
	}
	if len(got) != 5 {
		t.Fatalf("possible rows %v, want the five CVEs listed (the group is shown, never hidden)", got)
	}
	if ob := got["CVE-2019-90101"]; ob == nil || len(ob.Tested) != 1 || ob.Tested[0] != "3.0.4" || ob.Year != 2019 {
		t.Errorf("CVE-2019-90101: older build %+v, want tested [3.0.4] in 2019", ob)
	}
	for _, cve := range []string{"CVE-2026-90102", "CVE-2026-90103", "CVE-2021-90104", "CVE-2026-90105"} {
		if ob := got[cve]; ob != nil {
			t.Errorf("%s: older build %+v, want it in the main possible list", cve, ob)
		}
	}
	c := list.Counts
	if c.Possible != 4 || c.OlderBuild != 1 {
		t.Errorf("counts possible %d, older build %d; want 4 and 1", c.Possible, c.OlderBuild)
	}
	sum := 0
	for _, n := range c.Causes {
		sum += n
	}
	if sum != c.Possible {
		t.Errorf("causes add up to %d, want the main possible number %d", sum, c.Possible)
	}

	o, err := NewFindingHandlers(e.svc, e.inv, e.feeds, nil).Overview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if o.Possible.Possible != 4 || o.Possible.OlderBuild != 1 {
		t.Errorf("Home possible %d, older build %d; want 4 and 1", o.Possible.Possible, o.Possible.OlderBuild)
	}
	dc, err := e.svc.deviceCounts(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := dc["pc-01"]; d == nil || d.Possible != 4 {
		t.Errorf("device counts %+v, want the badge to count the 4 main possible CVEs", d)
	}

	// it never closes anything: the question stays open and no finding is made
	var open, findings int
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM fnd_question WHERE cve = 'CVE-2019-90101' AND answer IS NULL`).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM fnd_finding WHERE cve = 'CVE-2019-90101'`).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if open != 1 || findings != 0 {
		t.Errorf("CVE-2019-90101: %d open questions, %d findings; want 1 and 0", open, findings)
	}
}

// Without the CVE record the box cannot say the vendor gave nothing: every row stays in the main list.
func TestOlderBuild_NoRecordNoGroup(t *testing.T) {
	t.Parallel()
	e := oldBuildWorld(t, false)
	list, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if list.Counts.Possible != 5 || list.Counts.OlderBuild != 0 {
		t.Errorf("counts %+v, want 5 possible and none apart", list.Counts)
	}
	for _, r := range list.Items {
		if r.OlderBuild != nil {
			t.Errorf("%s: older build %+v without the record", r.CVE, r.OlderBuild)
		}
	}
}

// The builds a row reads: every row an exact build the installed release is later than, each build once ("1.8.0 update401" keeps
// its update); a range, a build not older, a truncated list or an unreadable row reads none.
func TestOlderBuild_TestedBuilds(t *testing.T) {
	t.Parallel()
	full := make([]string, undecidedRows)
	for i := range full {
		full[i] = "cpe:2.3:a:acme:acme_desk:1.0.0:*:*:*:*:*:*:*"
	}
	cases := []struct {
		name string
		rows []string
		ver  string
		want []string
	}{
		{"one build, two writers", []string{"cpe:2.3:*:acme:acme_desk:3.0.4:*:*:*:*:*:*:*", "cpe:2.3:a:acme:acme_desk:3.0.4:*:*:*:*:*:*:*"}, "3.7.6", []string{"3.0.4"}},
		{"two builds", []string{"cpe:2.3:a:acme:acme_desk:2.5.0:*:*:*:*:*:*:*", "cpe:2.3:a:acme:acme_desk:3.0.4:*:*:*:*:*:*:*"}, "3.7.6", []string{"2.5.0", "3.0.4"}},
		{"an update part", []string{"cpe:2.3:a:acme:acme_desk:1.8.0:update401:*:*:*:*:*:*"}, "1.9.2", []string{"1.8.0 update401"}},
		{"a build not older", []string{"cpe:2.3:a:acme:acme_desk:3.0.4:*:*:*:*:*:*:*", "cpe:2.3:a:acme:acme_desk:3.9.0:*:*:*:*:*:*:*"}, "3.7.6", nil},
		{"the same build", []string{"cpe:2.3:a:acme:acme_desk:3.7.6:*:*:*:*:*:*:*"}, "3.7.6", nil},
		{"a range", []string{"cpe:2.3:a:acme:acme_desk:*:*:*:*:*:*:*:* [3.0.0, 3.1.0)"}, "3.7.6", nil},
		{"no version", []string{"cpe:2.3:a:acme:acme_desk:3.0.4:*:*:*:*:*:*:*"}, "", nil},
		{"not a CPE", []string{"acme desk 3.0.4"}, "3.7.6", nil},
		{"a full list may be cut", full, "3.7.6", nil},
	}
	for _, c := range cases {
		got := testedBuilds(c.rows, c.ver)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %v, want %v", c.name, got, c.want)
			}
		}
	}
}

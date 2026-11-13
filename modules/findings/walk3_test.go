package findings

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
)

// walk3VMware is the Windows device of customer walk 3 (W3-7): VMware Tools 13.0.10 as the agent maps it (pkgmap
// "vmware tools" → VMware|Tools).
func walk3VMware() Asset {
	return Asset{ID: "a-win", Name: "win11", OS: "Microsoft Windows 11 Pro", Software: []Software{
		{ID: "s-tools", Display: "VMware Tools", Vendor: "VMware", Product: "Tools", Version: "13.0.10", KevKeys: []string{"vmware|tools"}},
	}}
}

var walk3Multi = []string{"CVE-2020-3950", "CVE-2020-4006", "CVE-2022-22960"} // CISA "VMware | Multiple Products"

// openProductFindings gives the device the old open findings of cves the way the matcher made them before D-500: suspected,
// basis product, high.
func openProductFindings(t *testing.T, e *env, a Asset, vulns []Vuln, cves []string) {
	t.Helper()
	guess := make([]Vuln, 0, len(cves))
	for _, v := range vulns {
		if slices.Contains(cves, v.CVE) {
			v.Affected = []Affected{{CPE: "cpe:2.3:a:" + strings.ToLower(v.Vendor) + ":*:*:*:*:*:*:*:*:*"}} // may be anything: product
			guess = append(guess, v)
		}
	}
	if res, err := e.svc.UpsertFromMatch(t.Context(), a, guess); err != nil || len(res.Created) != len(cves) {
		t.Fatalf("setup: %+v %v", res, err)
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET severity = 'high' WHERE asset_id = ?`, a.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// W3-7, D-505: VMware Tools 13.0.10 gets nothing from the three "VMware Multiple Products" entries, whose real NVD lists
// name Fusion, Horizon Client, Remote Console, Identity Manager, Workspace ONE Access, Cloud Foundation… but not Tools,
// while NVD names "vmware:tools" in the Tools entry CVE-2023-20867 (which 13.0.10 is outside). The old open product
// findings close by themselves (not_relevant, system), and a later NVD entry naming Tools would reopen them.
func TestGolden_VMwareToolsMultipleProducts(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	dev := walk3VMware()
	if r := MatchAsset(dev, vulns, nil, t0); len(r.New) != 0 || len(r.NeedVersion) != 0 {
		t.Fatalf("VMware Tools 13.0.10: %+v", r)
	}
	have := map[string]bool{}
	for _, c := range walk3Multi {
		have[c] = true
	}
	r := MatchAsset(dev, vulns, have, t0)
	var closed []string
	for _, m := range r.NotAffected {
		closed = append(closed, m.CVE)
		if !strings.Contains(m.Evidence.Summary, "not VMware Tools") || !strings.Contains(m.Evidence.Summary, "several VMware products") {
			t.Errorf("%s: %q", m.CVE, m.Evidence.Summary)
		}
	}
	if slices.Sort(closed); !slices.Equal(closed, walk3Multi) || len(r.Existing) != 0 {
		t.Fatalf("proved %v, kept %+v; want %v proved", closed, r.Existing, walk3Multi)
	}
	if want := "Not affected: CISA lists CVE-2020-3950 for several VMware products, and NVD names other ones (fusion, horizon client, remote console), not VMware Tools. Vedette closed this by itself and reopens it if a later match says the device is affected."; !slices.ContainsFunc(r.NotAffected, func(m Match) bool { return m.Evidence.Summary == want }) {
		t.Errorf("no sentence %q in %+v", want, r.NotAffected)
	}

	e := newEnv(t)
	openProductFindings(t, e, dev, vulns, walk3Multi)
	e.pub.take()
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev, vulns); err != nil {
		t.Fatal(err)
	}
	for _, c := range walk3Multi {
		f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, c)
		if err != nil {
			t.Fatal(err)
		}
		if f.Status != StatusNotRelevant || f.ResolvedBy != SystemUser || f.ResolutionReason != ReasonNotAffectedVersion || !strings.Contains(f.ResolutionNote, "not VMware Tools") {
			t.Errorf("%s still open: %+v", c, f.Finding)
		}
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved'`); n != len(walk3Multi) {
		t.Errorf("auto_resolved rows %d", n)
	}
	if ev := e.pub.take(); len(ev) != len(walk3Multi) || ev[0].Name != EventStatusChanged {
		t.Errorf("events %+v", ev)
	}
}

// D-505: when NVD has never named the software by its own identity (no single-product entry of it with NVD data), a
// "Multiple Products" entry listing other products gives no finding but proves nothing: the old finding stays open (a
// person decides), says once that it no longer matches, and takes the product severity (medium, W3-3).
func TestMultipleProducts_NotNamedNeverCloses(t *testing.T) {
	t.Parallel()
	var vulns []Vuln
	for _, v := range goldenVulns(t) {
		if slices.Contains(walk3Multi, v.CVE) {
			vulns = append(vulns, v) // without CVE-2023-20867: nothing tells how NVD names VMware Tools
		}
	}
	dev := walk3VMware()
	if r := MatchAsset(dev, vulns, map[string]bool{walk3Multi[0]: true}, t0); len(r.New)+len(r.Existing)+len(r.NotAffected)+len(r.NeedVersion) != 0 {
		t.Fatalf("%+v", r)
	}
	e := newEnv(t)
	openProductFindings(t, e, dev, vulns, walk3Multi)
	for range 2 { // the second pass changes nothing
		if _, err := e.svc.UpsertFromMatch(t.Context(), dev, vulns); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range walk3Multi {
		f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, c)
		if err != nil {
			t.Fatal(err)
		}
		if f.Status != StatusSuspected || f.Severity != SeverityMedium || f.History[len(f.History)-1].Action != "no_longer_matches" {
			t.Errorf("%s: %+v, last history %+v", c, f.Finding, f.History[len(f.History)-1])
		}
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.regraded'`); n != len(walk3Multi) {
		t.Errorf("regraded rows %d, want one per finding", n)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.no_longer_matches'`); n != len(walk3Multi) {
		t.Errorf("no_longer_matches rows %d, want one per finding", n)
	}
}

// W3-8: the box (Ubuntu 26.04, software from the host's dpkg, D-470) is judged by its OS like an agent host: CVE-2021-3493
// lists only Ubuntu releases before 20.10, so it gives no finding and the old product finding closes. Without an OS (the
// cause on the N100) the same kernel stays a product finding.
func TestGolden_BoxOSRulesOutOverlayFS(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	const cve = "CVE-2021-3493"
	box := Asset{ID: "a-box", Name: "boxkien", OS: "Ubuntu 26.04", Software: []Software{agentPkg("Linux", "Kernel", "7.0.0")}}
	r := MatchAsset(box, vulns, map[string]bool{cve: true}, t0)
	if slices.ContainsFunc(append(r.New, r.Existing...), func(m Match) bool { return m.CVE == cve }) {
		t.Fatalf("%s on Ubuntu 26.04: %+v", cve, r)
	}
	if !slices.ContainsFunc(r.NotAffected, func(m Match) bool { return m.CVE == cve && strings.Contains(m.Evidence.Summary, "(Ubuntu 26.04)") }) {
		t.Fatalf("%s not proved: %+v", cve, r.NotAffected)
	}
	box.OS = ""
	if r := MatchAsset(box, vulns, nil, t0); !slices.ContainsFunc(r.New, func(m Match) bool { return m.CVE == cve && m.Basis == BasisProduct }) {
		t.Fatalf("without an OS: %+v", r.New)
	}
}

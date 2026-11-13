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
// name Fusion, Horizon Client, Remote Console, Identity Manager, Workspace ONE Access, Cloud Foundation… but not Tools.
// That proves nothing (NVD's list for such an entry can lag the vendor's advisory, review H1 of #671), so the old open
// findings stay open for a person: they take the product severity (medium) once and say, once, which products NVD lists.
func TestGolden_VMwareToolsMultipleProducts(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	dev := walk3VMware()
	if r := MatchAsset(dev, vulns, nil, t0); len(r.New) != 0 || len(r.NeedVersion) != 0 || len(r.Unlisted) != 0 {
		t.Fatalf("VMware Tools 13.0.10: %+v", r)
	}
	have := map[string]bool{}
	for _, c := range walk3Multi {
		have[c] = true
	}
	r := MatchAsset(dev, vulns, have, t0)
	var unlisted []string
	for _, m := range r.Unlisted {
		unlisted = append(unlisted, m.CVE)
	}
	if slices.Sort(unlisted); !slices.Equal(unlisted, walk3Multi) || len(r.Existing)+len(r.NotAffected) != 0 {
		t.Fatalf("unlisted %v, kept %+v, proved %+v; want %v unlisted, nothing proved", unlisted, r.Existing, r.NotAffected, walk3Multi)
	}
	const want = "NVD lists fusion, horizon client, remote console for CVE-2020-3950, not VMware Tools; check the vendor advisory and close it if it does not apply."

	e := newEnv(t)
	openProductFindings(t, e, dev, vulns, walk3Multi)
	// The N100 already said "no longer matches" in the generic words (no NVD data at the time): the reason is said once more.
	var noNVD []Vuln
	for _, v := range vulns {
		if slices.Contains(walk3Multi, v.CVE) {
			v.Affected = nil
		}
		noNVD = append(noNVD, v)
	}
	e.pub.take()
	for _, vs := range [][]Vuln{noNVD, vulns, vulns} {
		res, err := e.svc.UpsertFromMatch(t.Context(), dev, vs)
		if err != nil || len(res.Created) != 0 {
			t.Fatalf("%+v %v", res, err)
		}
	}
	for _, c := range walk3Multi {
		f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, c)
		if err != nil {
			t.Fatal(err)
		}
		last := f.History[len(f.History)-1]
		if f.Status != StatusSuspected || f.Severity != SeverityMedium || last.Action != "no_longer_matches" || !strings.Contains(last.Note, "not VMware Tools; check the vendor advisory") {
			t.Errorf("%s: %+v, last history %+v", c, f.Finding, last)
		}
		if c == "CVE-2020-3950" && last.Note != want {
			t.Errorf("note %q, want %q", last.Note, want)
		}
	}
	for action, n := range map[string]int{"findings.regraded": 3, "findings.no_longer_matches": 6, "findings.auto_resolved": 0} {
		if got := e.count(`SELECT count(*) FROM core_audit WHERE action = '` + action + `'`); got != n {
			t.Errorf("%s rows %d, want %d", action, got, n)
		}
	}
	if ev := e.pub.take(); len(ev) != 0 {
		t.Errorf("events %+v", ev)
	}
}

// D-505, review L4 of #671: a "Multiple Products" entry with an NVD entry Vedette cannot tie to a product (vendor or
// product ANY, or not a CPE) may be about the software: a product finding (medium), never a proof, never "unlisted".
func TestMultipleProducts_UnreadableEntryIsNoProof(t *testing.T) {
	t.Parallel()
	tools := Vuln{CVE: "CVE-2023-20867", Vendor: "VMware", Product: "Tools", Affected: []Affected{{CPE: "cpe:2.3:a:vmware:tools:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "10.3.0", EndExcl: "12.2.5"}}}}
	for _, odd := range []string{"cpe:2.3:a:vmware:*:*:*:*:*:*:*:*:*", "not a cpe"} {
		multi := Vuln{CVE: "CVE-2020-3950", Vendor: "VMware", Product: "Multiple Products", Affected: []Affected{
			{CPE: "cpe:2.3:a:vmware:fusion:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "11.0.0", EndExcl: "11.5.2"}}, {CPE: odd}}}
		r := MatchAsset(walk3VMware(), []Vuln{tools, multi}, map[string]bool{multi.CVE: true}, t0)
		if len(r.NotAffected)+len(r.Unlisted) != 0 || len(r.Existing) != 1 || r.Existing[0].Basis != BasisProduct || r.Existing[0].Severity != SeverityMedium {
			t.Errorf("%q: %+v", odd, r)
		}
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

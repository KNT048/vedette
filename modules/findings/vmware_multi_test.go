package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// vmwareToolsPC is a Windows test device: VMware Tools 13.0.10 as the agent maps it (the product catalogue
// "vmware tools" → VMware|Tools).
func vmwareToolsPC() Asset {
	return Asset{ID: "a-win", Name: "win11", OS: "Microsoft Windows 11 Pro", Software: []Software{
		{ID: "s-tools", Display: "VMware Tools", Vendor: "VMware", Product: "Tools", Version: "13.0.10", KevKeys: []string{"vmware|tools"}},
	}}
}

var vmwareMultiCVEs = []string{"CVE-2020-3950", "CVE-2020-4006", "CVE-2022-22960"}

// Only when NVD names none of the device's software of the vendor. A device that also has Fusion, which NVD names
// for CVE-2020-3950 and whose version is outside its range, keeps the earlier behaviour: Tools is unlisted, nothing retires.
func TestMultipleProducts_RetiresOnlyWhenNoSoftwareIsNamed(t *testing.T) {
	t.Parallel()
	dev := vmwareToolsPC()
	dev.Software = append(dev.Software, Software{ID: "s-fusion", Display: "VMware Fusion", Vendor: "VMware", Product: "Fusion", Version: "12.0.0", KevKeys: []string{"vmware|fusion"}})
	multi := Vuln{CVE: "CVE-2020-3950", Vendor: "VMware", Product: "Multiple Products", DateAdded: t0.AddDate(-5, 0, 0), Affected: []Affected{
		{CPE: "cpe:2.3:a:vmware:fusion:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "11.0.0", EndExcl: "11.5.2"}}}}
	r := MatchAsset(dev, []Vuln{multi}, map[string]bool{multi.CVE: true}, t0)
	if len(r.Unlisted) != 1 || len(r.Retired)+len(r.NotAffected)+len(r.Existing) != 0 {
		t.Fatalf("%+v", r)
	}
	multi.DateAdded = time.Time{} // a date Vedette could not read is never settled
	if r := MatchAsset(vmwareToolsPC(), []Vuln{multi}, map[string]bool{multi.CVE: true}, t0); len(r.Unlisted) != 1 || len(r.Retired) != 0 {
		t.Fatalf("no date: %+v", r)
	}
}

// A "Multiple Products" entry with an NVD entry Vedette cannot tie to a product (vendor or
// product ANY, or not a CPE) may be about the software: a product finding (medium), never a proof, never "unlisted".
func TestMultipleProducts_UnreadableEntryIsNoProof(t *testing.T) {
	t.Parallel()
	tools := Vuln{CVE: "CVE-2023-20867", Vendor: "VMware", Product: "Tools", Affected: []Affected{{CPE: "cpe:2.3:a:vmware:tools:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "10.3.0", EndExcl: "12.2.5"}}}}
	for _, odd := range []string{"cpe:2.3:a:vmware:*:*:*:*:*:*:*:*:*", "not a cpe"} {
		multi := Vuln{CVE: "CVE-2020-3950", Vendor: "VMware", Product: "Multiple Products", Affected: []Affected{
			{CPE: "cpe:2.3:a:vmware:fusion:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "11.0.0", EndExcl: "11.5.2"}}, {CPE: odd}}}
		r := MatchAsset(vmwareToolsPC(), []Vuln{tools, multi}, map[string]bool{multi.CVE: true}, t0)
		if len(r.NotAffected)+len(r.Unlisted)+len(r.Existing) != 0 || len(r.NameOnly) != 1 || r.NameOnly[0].Basis != BasisProduct || r.NameOnly[0].Severity != SeverityMedium { // No finding, no proof
			t.Errorf("%q: %+v", odd, r)
		}
	}
}

// The box (Ubuntu 26.04, software from the host's dpkg) is judged by its OS like an agent host: CVE-2021-3493
// lists only Ubuntu releases before 20.10, so it gives no finding and the old product finding closes. Without an OS (the
// cause on a test box) the same kernel stays a product finding.
func TestGolden_BoxOSRulesOutOverlayFS(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	const cve = "CVE-2021-3493"
	box := Asset{ID: "a-box", Name: "boxanna", OS: "Ubuntu 26.04", Software: []Software{agentPkg("Linux", "Kernel", "7.0.0")}}
	r := MatchAsset(box, vulns, map[string]bool{cve: true}, t0)
	if slices.ContainsFunc(append(r.New, r.Existing...), func(m Match) bool { return m.CVE == cve }) {
		t.Fatalf("%s on Ubuntu 26.04: %+v", cve, r)
	}
	if !slices.ContainsFunc(r.NotAffected, func(m Match) bool { return m.CVE == cve && strings.Contains(m.Evidence.Summary, "(Ubuntu 26.04)") }) {
		t.Fatalf("%s not proved: %+v", cve, r.NotAffected)
	}
	box.OS = ""
	if r := MatchAsset(box, vulns, nil, t0); !slices.ContainsFunc(r.NameOnly, func(m Match) bool { return m.CVE == cve && m.Basis == BasisProduct }) { // No finding
		t.Fatalf("without an OS: %+v", r.NameOnly)
	}
}

// VMware Tools 13.0.10 gets nothing from the three "VMware Multiple Products" entries, whose real NVD
// lists name Fusion, Horizon Client, Remote Console, Identity Manager, Workspace ONE Access, Cloud Foundation… but not
// Tools. The entries are years old in KEV, so NVD's list is settled: the old open product findings the retired
// vendor-wide rule made close by themselves at the first reconcile pass. A "Multiple Products" entry added 100 days ago
// keeps its finding (open, medium, the note); a version finding and one a person reopened are never closed.
func TestGolden_VMwareToolsMultipleProducts(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	dev := vmwareToolsPC()
	if r := MatchAsset(dev, vulns, nil, t0); len(r.New) != 0 || len(r.NeedVersion)+len(r.Unlisted)+len(r.Retired) != 0 {
		t.Fatalf("VMware Tools 13.0.10: %+v", r)
	}
	// Three more entries with the real NVD list of CVE-2020-3950 (ids made up): one CISA added 100 days ago, one whose
	// finding is basis version, one a person closed and reopened.
	const recent, version, reopened = "CVE-2026-0001", "CVE-2021-0002", "CVE-2021-0003"
	idx := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == vmwareMultiCVEs[0] })
	for _, x := range []struct {
		cve   string
		added time.Time
	}{{recent, t0.Add(-100 * 24 * time.Hour)}, {version, vulns[idx].DateAdded}, {reopened, vulns[idx].DateAdded}} {
		v := vulns[idx]
		v.CVE, v.DateAdded = x.cve, x.added
		vulns = append(vulns, v)
	}
	all := append(slices.Clone(vmwareMultiCVEs), recent, version, reopened)
	have := map[string]bool{}
	for _, c := range all {
		have[c] = true
	}
	r := MatchAsset(dev, vulns, have, t0)
	var unlisted, retired []string
	for _, m := range r.Unlisted {
		unlisted = append(unlisted, m.CVE)
	}
	for _, m := range r.Retired {
		retired = append(retired, m.CVE)
	}
	slices.Sort(unlisted)
	if slices.Sort(retired); len(unlisted) != len(all) || !slices.Equal(retired, []string{"CVE-2020-3950", "CVE-2020-4006", version, reopened, "CVE-2022-22960"}) ||
		len(r.Existing)+len(r.NotAffected) != 0 {
		t.Fatalf("unlisted %v, retired %v, kept %+v, proved %+v", unlisted, retired, r.Existing, r.NotAffected)
	}

}

package findings

import "testing"

// A device's own statement of its ESXi release (version 8.0 and the update its build names, written by a scan as the row
// cpe:/o:vmware:esxi:8.0:update_3) is compared with the releases NVD lists for an exploited ESXi flaw: the release NVD lists is
// affected, another update of the same version is not, and a row with no CPE (a build the table does not know) is never a finding.
func TestMatchAsset_EsxiStatedByTheDevice(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2025-22224", Vendor: "VMware", Product: "ESXi", DateAdded: winDay("2025-03-04"), Published: winDay("2025-03-04"),
		Affected: []Affected{
			{CPE: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*"},
			{CPE: "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"},
		}}
	row := func(cpe, ver string) Software {
		return Software{ID: "s-esxi", Display: "VMware ESXi", Vendor: "vmware", Product: "esxi", Version: ver, CPE: cpe, Source: "nmap", KevKeys: []string{"vmware|esxi"}}
	}
	affected := func(s Software) bool {
		a := Asset{ID: "a", Name: "host", OS: "VMware ESXi 8.0 Update 3 (build 24022510)", Software: []Software{s}}
		res := MatchAsset(a, []Vuln{v}, nil, t0)
		return len(res.New)+len(res.Existing) == 1
	}
	if !affected(row("cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", "8.0")) {
		t.Error("8.0 update_3 is listed by NVD: it is affected")
	}
	if affected(row("cpe:2.3:o:vmware:esxi:8.0:update_3b:*:*:*:*:*:*", "8.0")) {
		t.Error("8.0 update_3b is not a listed update: no finding")
	}
	if affected(row("cpe:2.3:o:vmware:esxi:8.0:update_1:*:*:*:*:*:*", "8.0")) {
		t.Error("8.0 update_1 is not a listed update: no finding")
	}
}

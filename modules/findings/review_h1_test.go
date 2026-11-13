package findings

import "testing"

// Review H1: the version schemes of PAN-OS (hotfix "-hN"), Junos (service release "RxSy") and Ivanti (R-release
// "RxY.z") are read and ordered.
func TestCompareVersions_VendorReleaseSchemes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"10.2.9-h1", "10.2.9", 1}, {"10.2.9-h1", "10.2.9-h2", -1}, {"10.2.9-h12", "10.2.9-h2", 1}, {"10.2.9-h1", "10.2.10", -1},
		{"22.4R2-S1", "22.4R2", 1}, {"22.4R2-S1", "22.4R2-S2", -1}, {"22.4R2-S9", "22.4R3", -1}, {"22.4R3", "22.4R2-S1", 1},
		{"22.7R2.4", "22.7R2.3", 1}, {"22.7R2.4", "22.7R2", 1}, {"22.7R2.4", "22.7R3", -1}, {"22.7R2.4", "22.7R2.4", 0},
	} {
		got, ok := CompareVersions(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d %v, want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
}

func device(vendor, product, version string) Asset {
	return Asset{ID: "a-1", Name: "fw01", Software: []Software{{ID: "s-1", Display: product, Vendor: vendor, Product: product, Version: version, KevKeys: []string{KevKey(vendor, product)}}}}
}

// Review H1 and L4, golden cases: an exact NVD entry with a hotfix, service release or R-release decides by version;
// another hotfix of the same release is not affected; a range decides those versions too; a version Vedette cannot
// read (Cisco IOS) is a product finding at medium, never "add the version".
func TestMatchAsset_VendorReleaseSchemes(t *testing.T) {
	t.Parallel()
	pan := Vuln{CVE: "CVE-2024-3400", Vendor: "Palo Alto Networks", Product: "PAN-OS", Ransomware: true, Affected: []Affected{
		{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.2.9:h1:*:*:*:*:*:*"},
		{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "10.2.0", EndExcl: "10.2.9"}},
	}}
	junos := Vuln{CVE: "CVE-2023-36845", Vendor: "Juniper", Product: "Junos OS", Affected: []Affected{
		{CPE: "cpe:2.3:o:juniper:junos:22.4:r2-s1:*:*:*:*:*:*"},
	}}
	ivanti := Vuln{CVE: "CVE-2025-0282", Vendor: "Ivanti", Product: "Connect Secure", Affected: []Affected{
		{CPE: "cpe:2.3:a:ivanti:connect_secure:22.7:r2.4:*:*:*:*:*:*"},
	}}
	cisco := Vuln{CVE: "CVE-2018-0171", Vendor: "Cisco", Product: "IOS", Affected: []Affected{
		{CPE: "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "15.9"}},
	}}
	for _, tc := range []struct {
		name string
		a    Asset
		v    Vuln
		want Basis // "" = no finding
		sev  Severity
	}{
		{"PAN-OS hotfix h1 listed", device("Palo Alto Networks", "PAN-OS", "10.2.9-h1"), pan, BasisVersion, SeverityCritical},
		{"PAN-OS hotfix h2 not listed", device("Palo Alto Networks", "PAN-OS", "10.2.9-h2"), pan, "", ""},
		{"PAN-OS older release in the range", device("Palo Alto Networks", "PAN-OS", "10.2.8-h3"), pan, BasisVersion, SeverityCritical},
		{"Junos service release listed", device("Juniper", "Junos OS", "22.4R2-S1"), junos, BasisVersion, SeverityHigh},
		{"Junos other service release", device("Juniper", "Junos OS", "22.4R2-S2"), junos, "", ""},
		{"Ivanti R-release listed (L4)", device("Ivanti", "Connect Secure", "22.7R2.4"), ivanti, BasisVersion, SeverityHigh},
		{"Ivanti later R-release", device("Ivanti", "Connect Secure", "22.7R2.5"), ivanti, "", ""},
		{"Cisco IOS unreadable version", device("Cisco", "IOS", "15.2(4)M3"), cisco, BasisProduct, SeverityMedium},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(tc.a, []Vuln{tc.v}, nil, t0)
			if len(res.NeedVersion) != 0 {
				t.Fatalf("sent to add the version: %+v", res.NeedVersion)
			}
			got, sev := Basis(""), Severity("")
			if len(res.New) == 1 {
				got, sev = res.New[0].Basis, res.New[0].Severity
			}
			if got != tc.want || sev != tc.sev {
				t.Fatalf("basis %q severity %q, want %q %q", got, sev, tc.want, tc.sev)
			}
		})
	}
}

// Review M1: an Ubuntu point release is its year.month release; an entry that lists only another distribution's
// releases says nothing about the device.
func TestMatchAsset_OSReleasesOnlyRuleOutTheirOwnDistribution(t *testing.T) {
	t.Parallel()
	kernel := func(cpes ...string) Vuln {
		v := Vuln{CVE: "CVE-2021-3493", Vendor: "Linux", Product: "Kernel"}
		for _, c := range cpes {
			v.Affected = append(v.Affected, Affected{CPE: c})
		}
		return v
	}
	box := func(os string) Asset {
		a := device("Linux", "Kernel", "5.4.0")
		a.OS = os
		return a
	}
	ubuntu2004 := kernel("cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*")
	if r := MatchAsset(box("Ubuntu 20.04.6 LTS"), []Vuln{ubuntu2004}, nil, t0); len(r.New) == 0 {
		t.Error("Ubuntu 20.04.6 is 20.04: ruled out")
	}
	if r := MatchAsset(box("Ubuntu 22.04.4 LTS"), []Vuln{ubuntu2004}, nil, t0); len(r.New) != 0 {
		t.Errorf("Ubuntu 22.04 is not listed: %+v", r.New)
	}
	debianOnly := kernel("cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*")
	if r := MatchAsset(box("Ubuntu 22.04.4 LTS"), []Vuln{debianOnly}, nil, t0); len(r.New) == 0 {
		t.Error("an entry for Debian only ruled out an Ubuntu device")
	}
}

// Review M2: NVD renamed products (apple:mac_os_x before apple:macos); a Mac is named by both, so a "Multiple
// Products" entry listing the old name is not taken for "another product".
func TestMatchAsset_RenamedProductAlias(t *testing.T) {
	t.Parallel()
	mac := device("Apple", "macOS", "10.15.2")
	mac.Software[0].KevKeys = []string{"apple|macos", "apple|multiple products"}
	own := Vuln{CVE: "CVE-2023-41990", Vendor: "Apple", Product: "macOS", Affected: []Affected{{CPE: "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "13.6"}}}}
	multi := Vuln{CVE: "CVE-2020-9934", Vendor: "Apple", Product: "Multiple Products", Affected: []Affected{{CPE: "cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.15.4"}}}}
	r := MatchAsset(mac, []Vuln{own, multi}, nil, t0)
	got := map[string]Basis{}
	for _, m := range r.New {
		got[m.CVE] = m.Basis
	}
	if got["CVE-2020-9934"] != BasisVersion || got["CVE-2023-41990"] != BasisVersion {
		t.Fatalf("matches %v", got)
	}
}

package findings

import (
	"slices"
	"testing"
)

// NVD's configurations of the CVEs a test box's "Could not be checked" list showed for software NVD names only at older exact
// versions (public NVD data, services.nvd.nist.gov 2026-11-17; every entry vulnerable, in OR nodes, no "running on" platform).
func newerListedVulns() []Vuln {
	cpes := func(cve, vendor, product string, cs ...string) Vuln {
		v := uncVuln(cve, vendor, product, uncNew)
		for _, c := range cs {
			v.Affected = append(v.Affected, Affected{CPE: c, VendorCNA: true})
		}
		return v
	}
	webkit := cpes("CVE-2023-41993", "Apple", "Multiple Products",
		"cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*", "cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:graalvm:20.3.13:*:*:*:enterprise:*:*:*", "cpe:2.3:a:oracle:graalvm:21.3.9:*:*:*:enterprise:*:*:*",
		"cpe:2.3:a:oracle:jdk:1.8.0:update401:*:*:*:*:*:*", "cpe:2.3:a:oracle:jre:1.8.0:update401:*:*:*:*:*:*",
		"cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:*")
	webkit.Affected = append(webkit.Affected,
		Affected{CPE: "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "14.0"}},
		Affected{CPE: `cpe:2.3:a:webkitgtk:webkitgtk\+:*:*:*:*:*:*:*:*`, Range: VersionRange{EndExcl: "2.42.2"}})
	mscomctl := cpes("CVE-2012-1856", "Microsoft", "Office",
		"cpe:2.3:a:microsoft:commerce_server:2009:*:*:*:*:*:*:*", "cpe:2.3:a:microsoft:office:2010:sp1:x86:*:*:*:*:*",
		"cpe:2.3:a:microsoft:sql_server:2000:sp4:*:*:*:*:*:*", "cpe:2.3:a:microsoft:sql_server:2000:sp4:analysis_services:*:*:*:*:*",
		"cpe:2.3:a:microsoft:sql_server:2005:sp4:*:*:*:*:*:*", "cpe:2.3:a:microsoft:sql_server:2008:r2_sp2:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:sql_server:2008:sp3:*:*:*:*:*:*", "cpe:2.3:a:microsoft:visual_basic:6.0:*:*:*:*:*:*:*")
	java2016 := cpes("CVE-2016-3427", "Oracle", "Java SE and JRockit",
		"cpe:2.3:a:oracle:jdk:1.6.0:update113:*:*:*:*:*:*", "cpe:2.3:a:oracle:jdk:1.7.0:update99:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:jdk:1.8.0:update77:*:*:*:*:*:*", "cpe:2.3:a:oracle:jre:1.6.0:update113:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:jre:1.7.0:update99:*:*:*:*:*:*", "cpe:2.3:a:oracle:jre:1.8.0:update77:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:jrockit:r28.3.9:*:*:*:*:*:*:*")
	java2010 := cpes("CVE-2010-0840", "Oracle", "Java Runtime Environment (JRE)",
		"cpe:2.3:a:oracle:jre:1.4.2_25:*:*:*:*:*:*:*", "cpe:2.3:a:oracle:jre:1.5.0:update23:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:jre:1.6.0:update18:*:*:*:*:*:*", "cpe:2.3:o:canonical:ubuntu_linux:9.10:*:*:*:*:*:*:*")
	java2013 := cpes("CVE-2013-0422", "Oracle", "Java Runtime Environment (JRE)",
		"cpe:2.3:a:oracle:jdk:1.7.0:-:*:*:*:*:*:*", "cpe:2.3:a:oracle:jre:1.7.0:update10:*:*:*:*:*:*")
	libvpx := cpes("CVE-2023-5217", "Google", "Chromium libvpx",
		"cpe:2.3:a:microsoft:edge:116.0.1938.98:*:*:*:*:*:*:*", "cpe:2.3:a:microsoft:edge:117.0.2045.47:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:edge_chromium:116.0.5845.229:*:*:*:*:*:*:*", "cpe:2.3:a:microsoft:edge_chromium:117.0.5938.132:*:*:*:*:*:*:*")
	libvpx.Affected = append(libvpx.Affected, Affected{CPE: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "117.0.5938.132"}})
	return []Vuln{webkit, mscomctl, java2016, java2010, java2013, libvpx}
}

// newerListedOutcome is what the matcher says about each CVE for a device with only row s: "unchecked <reason>", "finding",
// "need" or "-" (nothing: not a candidate).
func newerListedOutcome(t *testing.T, s Software, vulns []Vuln) map[string]string {
	t.Helper()
	res := MatchAsset(Asset{ID: "a", Name: "pc", OS: "Microsoft Windows 11 Pro", AgentOS: "Microsoft Windows 11 Pro", Software: []Software{s}}, vulns, nil, uncNow)
	out := map[string]string{}
	for _, v := range vulns {
		out[v.CVE] = "-"
	}
	for _, u := range res.Unchecked {
		out[u.CVE] = "unchecked " + string(u.Reason)
	}
	for _, n := range res.NeedVersion {
		for _, c := range n.CVEs {
			out[c] = "need"
		}
	}
	for _, m := range slices.Concat(res.New, res.Existing) {
		out[m.CVE] = "finding"
	}
	return out
}

// A test box's DESKTOP-55UKKFV, 2026-11-17: Java 8 Update 491, SQL Server 2022's RsFx Driver and Edge 157 were "could not be checked" for
// CVEs NVD lists only at older exact versions (Java "1.8.0 update401", SQL Server 2000 to 2008, Edge 116 and 117). NVD's list does
// not name them: not a candidate, and no verdict either (no finding, nothing "not affected"). The same CVEs stay on the list for a
// version NVD lists, or an older one (an exact list is often the last affected update: Oracle's "8u77 and earlier").
func TestUnchecked_NewerThanListed_LabBuild(t *testing.T) {
	t.Parallel()
	vulns := newerListedVulns()
	java := func(ver string) Software {
		return Software{ID: "s-java", Display: "Java 8 Update", Vendor: "Oracle", Product: "Java SE", Version: ver, Source: "agent", KevKeys: []string{"oracle|java se"}}
	}
	rsfx := func(ver string) Software {
		return Software{ID: "s-rsfx", Display: "Microsoft SQL Server RsFx Driver", Vendor: "Microsoft", Product: "SQL Server", Version: ver, Source: "agent",
			KevKeys: []string{"microsoft|sql server"}}
	}
	const listed = "unchecked " + string(UncheckedNoNVDVersions)
	for _, tc := range []struct {
		name string
		row  Software
		want map[string]string
	}{
		{"Java 8 Update 491", java("8.0.4910.10"), map[string]string{"CVE-2023-41993": "-", "CVE-2016-3427": "-", "CVE-2010-0840": "-", "CVE-2013-0422": "-"}},
		{"Java 8 Update 401", java("8.0.4010.7"), map[string]string{"CVE-2023-41993": listed, "CVE-2016-3427": "-", "CVE-2010-0840": "-"}},
		{"Java 8 Update 391", java("8.0.3910.13"), map[string]string{"CVE-2023-41993": listed}},
		// 8u60 is older than NVD's 8u77, 7u99's line is older than 8: as numbers "8.0.600" is after "1.8.0", which says nothing
		{"Java 8 Update 60", java("8.0.600.27"), map[string]string{"CVE-2016-3427": listed, "CVE-2023-41993": listed, "CVE-2010-0840": "-", "CVE-2013-0422": "-"}},
		{"Java 1.8.0_491", java("1.8.0_491"), map[string]string{"CVE-2023-41993": "-", "CVE-2016-3427": "-"}},
		{"SQL Server 2022 RsFx Driver", rsfx("16.0.1000.6"), map[string]string{"CVE-2012-1856": "-"}},
		{"SQL Server 2008 R2", rsfx("10.50.6000.34"), map[string]string{"CVE-2012-1856": listed}}, // its major is listed: which service pack is not known
		{"Edge 157", edgeRow("157.0.4341.60"), map[string]string{"CVE-2023-5217": "-"}},
		{"Edge 117.0.2045.47", edgeRow("117.0.2045.47"), map[string]string{"CVE-2023-5217": listed}}, // a version NVD lists
		{"Edge 110", edgeRow("110.0.1587.41"), map[string]string{"CVE-2023-5217": listed}},
	} {
		got := newerListedOutcome(t, tc.row, vulns)
		for cve, w := range tc.want {
			if got[cve] != w {
				t.Errorf("%s, %s: %q, want %q", tc.name, cve, got[cve], w)
			}
		}
	}
}

// Review r1 H1 of #970: NVD names many products by their release line ("esxi:8.0" with the update in the CPE, "solaris:11") while
// the computer reports the whole number. Those versions are inside the listed release, not after it: every row stays listed (NVD's
// public configurations of the KEV entries, from a test box's copy; Java 11 on a synthetic entry, no KEV entry lists jre:11.0).
func TestUnchecked_NewerThanListed_ReleaseLines(t *testing.T) {
	t.Parallel()
	cpes := func(cve, vendor, product string, cs ...string) Vuln {
		v := uncVuln(cve, vendor, product, uncNew)
		for _, c := range cs {
			v.Affected = append(v.Affected, Affected{CPE: c})
		}
		return v
	}
	row := func(vendor, product, ver string) Software {
		return Software{ID: "s", Display: vendor + " " + product, Vendor: vendor, Product: product, Version: ver, Source: "agent"}
	}
	for _, tc := range []struct {
		name string
		row  Software
		v    Vuln
	}{
		{"ESXi 8.0.3", row("VMware", "ESXi", "8.0.3"), cpes("CVE-2025-22224", "VMware", "ESXi and Workstation",
			"cpe:2.3:o:vmware:esxi:7.0:-:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:7.0:update_3r:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*",
			"cpe:2.3:o:vmware:esxi:8.0:c:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:8.0:update_3b:*:*:*:*:*:*",
			"cpe:2.3:o:vmware:esxi:8.0:update_3c:*:*:*:*:*:*")},
		{"vCenter 6.7.0.44000", row("VMware", "vCenter Server", "6.7.0.44000"), cpes("CVE-2020-3952", "VMware", "vCenter Server",
			"cpe:2.3:a:vmware:vcenter_server:6.7:-:*:*:*:*:*:*")},
		{"Solaris 11.4", row("Oracle", "Solaris", "11.4"), cpes("CVE-2019-3010", "Oracle", "Solaris", "cpe:2.3:o:oracle:solaris:11:*:*:*:*:*:*:*")},
		{"OpenSMTPD 6.6.1p1", row("OpenBSD", "OpenSMTPD", "6.6.1p1"), cpes("CVE-2020-7247", "OpenBSD", "OpenSMTPD",
			"cpe:2.3:a:openbsd:opensmtpd:6.6:*:*:*:*:*:*:*")},
		{"Internet Explorer 11.0.26100.1", row("Microsoft", "Internet Explorer", "11.0.26100.1"), cpes("CVE-2021-26411", "Microsoft", "Internet Explorer",
			"cpe:2.3:a:microsoft:edge:-:*:*:*:*:*:*:*", "cpe:2.3:a:microsoft:internet_explorer:11:-:*:*:*:*:*:*", "cpe:2.3:a:microsoft:internet_explorer:9:*:*:*:*:*:*:*")},
		{"ColdFusion 2018.0.0.310739", row("Adobe", "ColdFusion", "2018.0.0.310739"), cpes("CVE-2018-15961", "Adobe", "ColdFusion",
			"cpe:2.3:a:adobe:coldfusion:11.0:-:*:*:*:*:*:*", "cpe:2.3:a:adobe:coldfusion:11.0:update14:*:*:*:*:*:*", "cpe:2.3:a:adobe:coldfusion:2016:-:*:*:*:*:*:*",
			"cpe:2.3:a:adobe:coldfusion:2016:update6:*:*:*:*:*:*", "cpe:2.3:a:adobe:coldfusion:2018:-:*:*:*:*:*:*")},
		{"Citrix ADC 13.0.47.22", row("Citrix", "Application Delivery Controller Firmware", "13.0.47.22"), cpes("CVE-2019-19781", "Citrix",
			"Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance",
			"cpe:2.3:o:citrix:application_delivery_controller_firmware:12.1:*:*:*:*:*:*:*", "cpe:2.3:o:citrix:application_delivery_controller_firmware:13.0:*:*:*:*:*:*:*")},
		{"Java 11.0.22", Software{ID: "s", Display: "Java SE Development Kit 11", Vendor: "Oracle", Product: "Java SE", Version: "11.0.22", Source: "agent"},
			cpes("CVE-2026-0101", "Oracle", "JavaFX", "cpe:2.3:a:oracle:jre:11.0:*:*:*:*:*:*:*", "cpe:2.3:a:oracle:jdk:11.0:*:*:*:*:*:*:*")},
	} {
		res := MatchAsset(Asset{ID: "a", Name: "a", Software: []Software{tc.row}}, []Vuln{tc.v}, nil, uncNow)
		if len(res.New) != 0 || len(res.NotAffected) != 0 || len(res.Unchecked) != 1 || res.Unchecked[0].CVE != tc.v.CVE {
			t.Errorf("%s / %s: want listed, got unchecked %+v, new %+v", tc.name, tc.v.CVE, res.Unchecked, res.New)
		}
	}
}

// The class, on a row CISA's key reaches (the "No that proves nothing" branch) and one only NVD's list names: NVD names the row only
// at exact versions, all older than its own → no row. One entry the row is not later than (the same version, a newer one, "-" with no
// version of the product beside it, a version that does not read, a range, every version) keeps the row as before.
func TestUnchecked_NewerThanListed_Class(t *testing.T) {
	t.Parallel()
	exact := func(vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:a:acme:widget:" + v + ":*:*:*:*:*:*:*", VendorCNA: true})
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		aff   []Affected
		ver   string
		keyed bool
		want  bool // listed
	}{
		{"older only, keyed", exact("1.0", "1.1"), "2.0", true, false},
		{"older only, NVD's list", exact("1.0", "1.1"), "2.0", false, false},
		{"one newer, NVD's list", exact("1.0", "3.0"), "2.0", false, true},
		{"one equal, NVD's list", exact("1.0", "2.0"), "2.0", false, true},
		// NA ("-") beside a version of the same product is about no version (CPE name matching: DISJOINT), so it does not keep the row
		{"older and NA, keyed", exact("1.0", "-"), "2.0", true, false},
		{"older and NA, NVD's list", exact("1.0", "-"), "2.0", false, false},
		// NA alone may be a product whose release is in its name: it keeps the row
		{"NA only, keyed", exact("-"), "2.0", true, true},
		{"NA only, NVD's list", exact("-"), "2.0", false, true},
		{"a version that does not read, keyed", exact("1.0"), "2.0(1)M3", true, true},
		{"a version that does not read, NVD's list", exact("1.0"), "2.0(1)M3", false, true},
		{"a patch of the listed release, keyed", exact("8.9"), "8.9p1", true, true},
		{"a patch of the listed release, NVD's list", exact("8.9"), "8.9p1", false, true},
	} {
		s := Software{ID: "w", Display: "Acme Widget", Vendor: "Acme", Product: "Widget", Version: tc.ver, Source: "agent"}
		if tc.keyed {
			s.KevKeys = []string{"acme|widget"}
		}
		res := MatchAsset(Asset{ID: "a", Name: "a", Software: []Software{s}}, []Vuln{uncVuln("CVE-2026-0100", "Acme", "Widget", uncNew, tc.aff...)}, nil, uncNow)
		if len(res.New) != 0 || len(res.NotAffected) != 0 {
			t.Errorf("%s: a verdict %+v", tc.name, res)
		}
		if got := len(res.Unchecked) == 1; got != tc.want {
			t.Errorf("%s: listed %v, want %v (%+v)", tc.name, got, tc.want, res.Unchecked)
		}
	}
	// a range or every version is never "only older exact versions": the matcher's other rules decide those rows
	every := Affected{CPE: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}
	ranged := Affected{CPE: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.5", EndIncl: "1.9"}}
	for name, own := range map[string][]Affected{"none": nil, "every version": append(exact("1.0"), every), "a range": append(exact("1.0"), ranged)} {
		if newerThanListed(own, "2.0") {
			t.Errorf("%s: newer than listed", name)
		}
	}
	if !newerThanListed(exact("1.0", "1.1"), "2.0") || newerThanListed(exact("1.0"), "") || newerThanListed(exact("1.0"), "0.0") {
		t.Error("newerThanListed: older exact versions, or no version")
	}
}

// laterThan only says "later" when certain, in the scheme the vendor writes the version.
func TestLaterThan(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cpe, ver string
		want     bool
	}{
		{"cpe:2.3:a:acme:widget:9.0:*:*:*:*:*:*:*", "9.1", true},
		{"cpe:2.3:a:acme:widget:9.0:*:*:*:*:*:*:*", "9.0", false},
		{"cpe:2.3:a:acme:widget:9.0:*:*:*:*:*:*:*", "8.5", false},
		{"cpe:2.3:a:acme:widget:9.0:beta1:*:*:*:*:*:*", "9.1", true}, // an update NVD pins is a step inside 9.0
		{"cpe:2.3:a:acme:widget:9.0:beta1:*:*:*:*:*:*", "9.0", false},
		// review r1 H1 of #970: NVD names a release line by its first numbers; a version inside it is not after it
		{"cpe:2.3:a:acme:widget:9.0:*:*:*:*:*:*:*", "9.0.1", false},
		{"cpe:2.3:a:acme:widget:8.0:*:*:*:*:*:*:*", "9.0.1", true},
		{"cpe:2.3:a:acme:widget:8.0.1:*:*:*:*:*:*:*", "8", false},
		{"cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", "8.0.3", false},
		{"cpe:2.3:o:vmware:esxi:7.0:update1:*:*:*:*:*:*", "7.0.1", false},
		{"cpe:2.3:o:vmware:esxi:7.0:-:*:*:*:*:*:*", "8.0.3", true},
		{"cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*", "8.0.3 build-24022510", false},
		{"cpe:2.3:a:vmware:vcenter_server:6.7:-:*:*:*:*:*:*", "6.7.0.44000", false},
		{"cpe:2.3:a:vmware:vcenter_server:7.0:c:*:*:*:*:*:*", "8.0.1", true},
		{"cpe:2.3:a:vmware:vcenter_server:7.0:c:*:*:*:*:*:*", "7.0.3", false},
		{"cpe:2.3:o:oracle:solaris:11:*:*:*:*:*:*:*", "11.4", false},
		{"cpe:2.3:a:openbsd:opensmtpd:6.6:*:*:*:*:*:*:*", "6.6.1p1", false},
		{"cpe:2.3:a:openbsd:opensmtpd:6.6:*:*:*:*:*:*:*", "6.7.1p1", true}, // a patch suffix is a step inside 6.7.1
		{"cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*", "9.6p1", false},
		{"cpe:2.3:a:openbsd:openssh:9.5:p1:*:*:*:*:*:*", "9.6p1", true},
		// exact older releases with an update or build qualifier: the release numbers each side starts with decide
		{"cpe:2.3:o:vmware:esxi:6.5:update1:*:*:*:*:*:*", "8.0.3", true},
		{"cpe:2.3:o:vmware:esxi:7.0:update_3c:*:*:*:*:*:*", "8.0.3", true},
		{"cpe:2.3:o:vmware:esxi:4.0:1:*:*:*:*:*:*", "8.0.3", true},
		{"cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", "8.0.3 build-24022510", false},
		{"cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", "7.0.3", false},
		{"cpe:2.3:a:synology:diskstation_manager:4.3-3810:*:*:*:*:*:*:*", "7.2.1-69057-5", true},
		{"cpe:2.3:a:synology:diskstation_manager:6.2:*:*:*:*:*:*:*", "7.2.1-69057-5", true},
		{"cpe:2.3:a:synology:diskstation_manager:7.2.1-69057:*:*:*:*:*:*:*", "7.2.1-69057-5", false}, // the same release
		{"cpe:2.3:a:synology:diskstation_manager:7.2.2-72806:*:*:*:*:*:*:*", "7.2.1-69057-5", false},
		{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "2:0.9", false},   // an epoch is not a release number
		{"cpe:2.3:a:acme:widget:6.0:*:*:*:*:*:*:*", "v7.2.13", false}, // a version that does not start with one
		{"cpe:2.3:a:microsoft:internet_explorer:11:-:*:*:*:*:*:*", "11.0.26100.1", false},
		{"cpe:2.3:a:adobe:coldfusion:2021:update5:*:*:*:*:*:*", "2021.0.05.330109", false},
		{"cpe:2.3:a:adobe:coldfusion:2018:-:*:*:*:*:*:*", "2021.0.05.330109", false}, // a release named by its year
		{"cpe:2.3:o:citrix:application_delivery_controller_firmware:13.0:*:*:*:*:*:*:*", "13.0.47.22", false},
		{"cpe:2.3:a:oracle:openjdk:8:*:*:*:*:*:*:*", "8.0.4910.10", false},
		{"cpe:2.3:a:oracle:jre:11.0:*:*:*:*:*:*:*", "11.0.22", false},
		// review r1 L3: a typed year against a year-named product
		{"cpe:2.3:a:microsoft:exchange_server:2016:-:*:*:*:*:*:*", "2019", false},
		{"cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_14:*:*:*:*:*:*", "2019", false},
		{"cpe:2.3:a:acme:widget:9.0:p2:*:*:*:*:*:*", "9.0", false},
		{"cpe:2.3:a:acme:widget:15.2\\(4\\)m3:*:*:*:*:*:*:*", "16.0", true},
		{"cpe:2.3:a:acme:widget:15.2\\(4\\)m3:*:*:*:*:*:*:*", "15.2.7", false},
		{"cpe:2.3:a:acme:widget:2016:*:*:*:*:*:*:*", "16.0.1", false}, // two schemes (schemeClash)
		{"cpe:2.3:a:microsoft:edge:117.0.2045.47:*:*:*:*:*:*:*", "157.0.4341.60", true},
		// SQL Server: NVD's release names against a build's major
		{"cpe:2.3:a:microsoft:sql_server:2008:sp3:*:*:*:*:*:*", "16.0.1000.6", true},
		{"cpe:2.3:a:microsoft:sql_server:2008:r2_sp2:*:*:*:*:*:*", "10.50.6000.34", false},
		{"cpe:2.3:a:microsoft:sql_server:2016:*:*:*:*:*:*:*", "12.0.6024.0", false},
		{"cpe:2.3:a:microsoft:sql_server:2008:sp3:*:*:*:*:*:*", "2022", true},
		{"cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*", "2017", false},
		{"cpe:2.3:a:microsoft:office:2010:sp1:*:*:*:*:*:*", "16.0.17928.20114", false}, // Office editions share majors
		{"cpe:2.3:o:juniper:junos:15.1:r7:*:*:*:*:*:*", "21.4R3", false},
		// Java SE before 9: line and update, never "8.0" against "1.8.0" as numbers
		{"cpe:2.3:a:oracle:jre:1.8.0:update401:*:*:*:*:*:*", "8.0.4910.10", true},
		{"cpe:2.3:a:oracle:jdk:1.8.0:update_401:*:*:*:*:*:*", "8.0.4910.10", true},
		{"cpe:2.3:a:oracle:jre:1.8.0:update401:*:*:*:*:*:*", "8.0.4010.7", false},
		{"cpe:2.3:a:oracle:jre:1.8.0:update77:*:*:*:*:*:*", "8.0.600.27", false},
		{"cpe:2.3:a:oracle:jre:1.7.0:update99:*:*:*:*:*:*", "8.0.600.27", true},
		{"cpe:2.3:a:oracle:jdk:1.7.0:-:*:*:*:*:*:*", "7.0.10", true}, // Java 7 Update 1 after the release itself
		{"cpe:2.3:a:oracle:jre:1.6.0:update32_b31:*:*:*:*:*:*", "6.0.450", true},
		{"cpe:2.3:a:oracle:jre:1.4.2_25:*:*:*:*:*:*:*", "1.8.0_491", true},
		{"cpe:2.3:a:oracle:jre:1.8.0:*:*:*:*:*:*:*", "8.0.4910.10", false}, // every update of Java 8
		{"cpe:2.3:a:oracle:jre:1.8.0:*:*:*:*:*:*:*", "21.0.7", true},       // a later line than every update of Java 8
		{"cpe:2.3:a:oracle:jdk:1.8:update_111:*:*:*:*:*:*", "21.0.7", true},
		{"cpe:2.3:a:oracle:jdk:1.8:update_111:*:*:*:*:*:*", "8.0.1110.14", false},
		{"cpe:2.3:a:oracle:jdk:1.8:update_111:*:*:*:*:*:*", "8.0.1120.15", true},
		{"cpe:2.3:a:oracle:jre:1.6:update_131:*:*:*:*:*:*", "21.0.7", true},
		{"cpe:2.3:a:oracle:jre:1.9.0:*:*:*:*:*:*:*", "21.0.7", true}, // Java 9
		{"cpe:2.3:a:oracle:jre:1.9.0:*:*:*:*:*:*:*", "9.0.4", false},
		{"cpe:2.3:a:oracle:jre:1.8.0:update401:*:*:*:*:*:*", "17.0.10", true},
		{"cpe:2.3:a:oracle:jre:1.8.0:update401:*:*:*:*:*:*", "1.8.0.4910", false}, // not a way Java writes its version
		{"cpe:2.3:a:oracle:jdk:11.0.22:*:*:*:*:*:*:*", "8.0.4910.10", false},
		{"cpe:2.3:a:oracle:jdk:11.0.22:*:*:*:*:*:*:*", "11.0.23", true},
	} {
		c, err := ParseCPE(tc.cpe)
		if err != nil {
			t.Fatal(err)
		}
		lit, _ := c.Version.Literal()
		if got := laterThan(c, lit, tc.ver); got != tc.want {
			t.Errorf("%s vs %q: %v, want %v", tc.cpe, tc.ver, got, tc.want)
		}
	}
}

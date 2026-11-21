package findings

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// The class "a vendor's own rows or a distribution's word decide, not NVD's generic ranges": for each ecosystem, devices whose finding
// only the vendor's notation (read in the product's version scheme) or the distribution's fixed package can decide, with what a
// person checking the vendor's advisory would expect. The count is the cases the matcher gets right, per ecosystem; a wrong case is
// logged. It reruns like any test. Measured on 34 cases: 34 right with this matcher. The matcher before vendor rows, Oracle's trains
// and distribution-only CVEs were read got 20 right (ESXi 8/12, NetScaler 3/5, Junos 1/3, kernel 2/3, running kernel 1/3,
// distribution 1/2, Java 4/6), measured with this file and the Software.Guess field added to the older matcher.

// ecoCase is one device and one CVE: want says the device is affected; fix is the fix the finding must name ("" when not affected or
// when any fix will do).
type ecoCase struct {
	eco  string
	a    Asset
	v    Vuln
	want bool
	fix  string
}

func schemedRows(t testing.TB, scheme, product string, spans ...[3]string) []SchemedRange {
	t.Helper()
	s, ok := versionscheme.Lookup(scheme)
	if !ok {
		t.Fatalf("no scheme %s", scheme)
	}
	var out []SchemedRange
	for _, x := range spans {
		sp, ok := s.Span(x[0], x[1], x[2])
		if !ok {
			t.Fatalf("%s: span %v does not read", scheme, x)
		}
		out = append(out, SchemedRange{Product: product, Scheme: s, Span: sp, Origin: RangeCNA}) // a CVE record's rows
	}
	return out
}

// esxiStated is an ESXi host as the active sensor writes its own statement (vmware-version): the release its build names, with the
// build in the line's name and the CPE of its update.
func esxiStated(name, version, update, build string) Asset {
	rel := "ESXi " + version
	if update != "-" {
		rel += " Update " + strings.TrimPrefix(update, "update_")
	}
	display := "VMware " + rel + " (build " + build + ")"
	return Asset{ID: name, Name: name, OS: display, Software: []Software{{ID: "s-" + name, Display: display, Vendor: "vmware", Product: "esxi",
		Version: version, CPE: "cpe:2.3:o:vmware:esxi:" + version + ":" + update + ":*:*:*:*:*:*", Source: "nmap", KevKeys: []string{"vmware|esxi"}}}}
}

// esxiGuess is the row the active sensor writes for a build esxi-builds.json does not list: the host's version, no CPE, marked a guess.
func esxiGuess(version, build string) Asset {
	d := "VMware ESXi " + version + " (build " + build + ")"
	return Asset{ID: "guess-" + build, Name: "esx-new", OS: d, Software: []Software{{ID: "s-guess", Display: d, Vendor: "vmware", Product: "esxi",
		Version: version, Source: "nmap", Guess: true}}}
}

func ecosystemCases(t *testing.T) []ecoCase {
	t.Helper()
	esxiKey := productid.Key("VMware", "ESXi")
	listed := esxi22225(t) // NVD lists 8.0 update_2 and update_3 exactly; VMware states U3d, U2d, 7.0 U3s
	noU3 := esxiWithoutU3d(t)
	// VMSA-2025-0013: an ESXi CVE on no list, before NVD analyses it: only VMware's rows.
	offList := Vuln{CVE: "CVE-2025-41236", NVDAnswered: true, Origin: RangeCNA,
		Schemed: schemedRows(t, "vmware-esxi", esxiKey, [3]string{"8.0", "ESXi80U3f-24784735", ""},
			[3]string{"8.0", "ESXi80U2e-24789317", ""}, [3]string{"7.0", "ESXi70U3w-24784741", ""})}
	nsKey := productid.Key("Citrix", "NetScaler")
	// CVE-2025-5777: Citrix states the fixed build of each line; its record rows are the only ranges the list entry has.
	ns := Vuln{CVE: "CVE-2025-5777", Vendor: "Citrix", Product: "NetScaler ADC and Gateway", DateAdded: winDay("2025-07-10"), Published: winDay("2025-06-17"),
		NVDAnswered: true, RangesFrom: RangesCVEOrg, Origin: RangeCNA,
		Schemed: schemedRows(t, "citrix-netscaler", nsKey, [3]string{"14.1", "14.1-43.56", ""}, [3]string{"13.1", "13.1-58.32", ""},
			[3]string{"13.1 FIPS", "13.1-37.235 FIPS", ""})}
	// The same CVE as a record that writes the FIPS build without its word, and no plain 13.1 row.
	nsFIPSUnsaid := ns
	nsFIPSUnsaid.CVE = "CVE-2025-6543"
	nsFIPSUnsaid.Schemed = schemedRows(t, "citrix-netscaler", nsKey, [3]string{"14.1", "14.1-47.46", ""}, [3]string{"13.1", "13.1-37.236", ""})
	nsRow := func(version string) Asset {
		return Asset{ID: "ns-" + version, Name: "adc", Software: []Software{{ID: "s-ns", Display: "Citrix NetScaler", Vendor: "Citrix", Product: "NetScaler",
			Version: version, Source: "snmp", KevKeys: []string{"citrix|netscaler adc and gateway"}}}}
	}
	kKey := productid.Key("Linux", "Kernel")
	// A kernel CVE on no list: kernel.org states the first fixed release of each stable branch.
	kernel := Vuln{CVE: "CVE-2025-38352", NVDAnswered: true, Origin: RangeCNA,
		Schemed: schemedRows(t, "linux-kernel", kKey, [3]string{"6.1", "6.1.149", ""}, [3]string{"6.6", "6.6.103", ""})}
	kRow := func(id, version, os string, packaged bool) Asset {
		s := Software{ID: "s-k", Display: "Linux kernel", Vendor: "Linux", Product: "Kernel", Version: version, Source: "agent"}
		if packaged {
			s.Packaged, s.PkgVersion, s.PkgSource = true, version+"-45.45", "linux-signed"
		}
		return Asset{ID: id, Name: id, OS: os, AgentOS: os, Software: []Software{s}}
	}
	// A CVE Ubuntu fixed in openssh before NVD names the upstream product (no NVD rows yet), on no list.
	distro := Vuln{CVE: "CVE-2026-20001", NVDAnswered: true, Distro: []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "openssh", Status: "fixed", Fixed: "1:10.2p1-2ubuntu3.9"}}}
	sshRow := func(id, pkg string) Asset {
		os := "Ubuntu 26.04.1 LTS"
		return Asset{ID: id, Name: id, OS: os, AgentOS: os, Software: []Software{{ID: "s-ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH",
			Version: "10.2p1", Source: "agent", Packaged: true, PkgVersion: pkg, PkgSource: "openssh"}}}
	}
	// Java SE: Oracle's critical patch update lists the newest affected release of each supported train ("17.0.11", "21.0.3");
	// every older release of those trains is affected too.
	java := Vuln{CVE: "CVE-2024-21147", Vendor: "Oracle", Product: "Java SE", DateAdded: winDay("2024-08-01"), Published: winDay("2024-07-16"), NVDAnswered: true,
		Affected: []Affected{{CPE: "cpe:2.3:a:oracle:jdk:17.0.11:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:a:oracle:jdk:21.0.3:*:*:*:*:*:*:*"},
			{CPE: "cpe:2.3:a:oracle:jre:1.8.0:update411:*:*:*:*:*:*"}}}
	jRow := func(version string) Asset {
		return Asset{ID: "j-" + version, Name: "pc", Software: []Software{{ID: "s-java", Display: "Java", Vendor: "Oracle", Product: "Java SE", Version: version,
			Source: "agent", KevKeys: []string{"oracle|java se"}}}}
	}
	// A kernel CVE Ubuntu fixed in its linux package: the running kernel is the line's version; an older kernel still installed is a
	// reading of the same line and keeps the finding (its package is named), as the leading scanners do.
	kfix := Vuln{CVE: "CVE-2026-53266", NVDAnswered: true, Distro: []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "linux", Status: "fixed", Fixed: "7.0.0-31.31"}}}
	kernelDev := func(id string, pkgs ...string) Asset {
		os := "Ubuntu 26.04.1 LTS"
		a := Asset{ID: id, Name: id, OS: os, AgentOS: os}
		for _, p := range pkgs { // the first is the running kernel (the line's effective reading)
			a.Software = append(a.Software, Software{ID: "s-kernel", Display: "Linux kernel", Vendor: "Linux", Product: "Kernel", Version: "7.0.0", Source: "agent",
				Packaged: true, PkgVersion: p, PkgSource: "linux-signed"})
		}
		return a
	}
	jKey := productid.Key("Juniper", "Junos OS")
	// A Junos CVE on the list before NVD analyses it: Juniper's record states the fixed release of each line.
	junos := Vuln{CVE: "CVE-2025-21590", Vendor: "Juniper", Product: "Junos OS", DateAdded: winDay("2025-03-13"), Published: winDay("2025-03-12"), NVDAnswered: true,
		RangesFrom: RangesCVEOrg, Origin: RangeCNA,
		Schemed: schemedRows(t, "juniper-junos", jKey, [3]string{"0", "21.2R3-S9", ""}, [3]string{"21.4", "21.4R3-S10", ""},
			[3]string{"22.2", "22.2R3-S6", ""})}
	jDev := func(ver string) Asset {
		os := "JUNOS " + ver
		return Asset{ID: "jx-" + ver, Name: "Juniper Networks SRX300", OS: os, SNMPOS: os, SNMPOSAt: t0, Model: "SRX300"}
	}
	return []ecoCase{
		{"juniper-junos", jDev("21.4R3-S5.4"), junos, true, "21.4R3-S10"},
		{"juniper-junos", jDev("22.2R3-S6"), junos, false, ""},
		{"juniper-junos", jDev("20.4R3-S9"), junos, true, "21.2R3-S9"},
		{"vmware-esxi", esxiStated("u2", "8.0", "update_2", "22380479"), listed, true, "8.0 U2d (build 24585300)"},
		{"vmware-esxi", esxiStated("u2d", "8.0", "update_2d", "24585300"), listed, false, ""},
		{"vmware-esxi", esxiStated("u3", "8.0", "update_3", "24022510"), listed, true, "8.0 U3d (build 24585383)"},
		{"vmware-esxi", esxiStated("u3b", "8.0", "update_3b", "24280767"), listed, true, "8.0 U3d (build 24585383)"},
		{"vmware-esxi", esxiStated("u3d", "8.0", "update_3d", "24585383"), listed, false, ""},
		{"vmware-esxi", esxiStated("u3-no-row", "8.0", "update_3", "24022510"), noU3, true, ""}, // VMware silent on U3, NVD lists it
		{"vmware-esxi", esxiGuess("8.0.3", "24100000"), listed, false, ""},                      // a build the table does not list: a guess, never matched
		{"vmware-esxi", esxiGuess("8.0.3", "24100000"), offList, false, ""},
		{"vmware-esxi", esxiStated("7u3q", "7.0", "update_3q", "23794027"), listed, true, "7.0 U3s (build 24585291)"},
		{"vmware-esxi", esxiStated("7u3s", "7.0", "update_3s", "24585291"), listed, false, ""},
		{"vmware-esxi", esxiStated("off-u3d", "8.0", "update_3d", "24585383"), offList, true, "8.0 U3f (build 24784735)"},
		{"vmware-esxi", esxiStated("off-u2d", "8.0", "update_2d", "24585300"), offList, true, "8.0 U2e (build 24789317)"},
		{"citrix-netscaler", nsRow("13.1-49.13"), ns, true, "13.1-58.32"},
		{"citrix-netscaler", nsRow("14.1-12.30"), ns, true, "14.1-43.56"},
		{"citrix-netscaler", nsRow("14.1-43.56"), ns, false, ""},
		{"citrix-netscaler", nsRow("13.1-37.235 FIPS"), ns, false, ""},
		{"citrix-netscaler", nsRow("13.1-37.38"), nsFIPSUnsaid, false, ""}, // the row's 37.x build is FIPS's: never the fix of a plain 13.1 host
		{"linux-kernel", kRow("appliance-old", "6.1.140", "Linux", false), kernel, true, "6.1.149"},
		{"linux-kernel", kRow("appliance-new", "6.6.110", "Linux", false), kernel, false, ""},
		{"linux-kernel", kRow("ubuntu-kernel", "6.8.0", "Ubuntu 26.04.1 LTS", true), kernel, false, ""}, // a distribution's kernel: never read upstream
		{"distribution", sshRow("ssh-old", "1:10.2p1-2ubuntu3.8"), distro, true, "1:10.2p1-2ubuntu3.9"},
		{"distribution", sshRow("ssh-new", "1:10.2p1-2ubuntu3.9"), distro, false, ""},
		{"running kernel", kernelDev("k-running-old", "7.0.0-22.22"), kfix, true, "7.0.0-31.31"},
		{"running kernel", kernelDev("k-running-new", "7.0.0-31.31"), kfix, false, ""},
		{"running kernel", kernelDev("k-old-installed", "7.0.0-31.31", "7.0.0-22.22"), kfix, true, ""},
		{"java", jRow("17.0.10"), java, true, ""},
		{"java", jRow("17.0.11"), java, true, ""},
		{"java", jRow("17.0.12"), java, false, ""},
		{"java", jRow("1.8.0_401"), java, true, ""},
		{"java", jRow("1.8.0_421"), java, false, ""},
		{"java", jRow("11.0.20"), java, false, ""}, // a train Oracle does not list here
	}
}

func TestCount_VendorRowsAndDistributionFixes(t *testing.T) {
	t.Parallel()
	right, total := map[string]int{}, map[string]int{}
	findingsBy := map[string]int{}
	for _, c := range ecosystemCases(t) {
		total[c.eco]++
		res := MatchAsset(c.a, []Vuln{c.v}, nil, t0)
		var got *Match
		for _, m := range res.New {
			if m.CVE == c.v.CVE {
				got = &m
			}
		}
		fix := ""
		if got != nil {
			findingsBy[c.eco]++
			lines := deviceLines(c.a)
			if l, ok := lines[storedLine(got.SoftwareID)]; ok {
				fix = FixOf(c.a, l.sw, c.v).Version
			}
		}
		switch {
		case (got != nil) != c.want:
			t.Logf("%s on %s: finding %v, want %v", c.v.CVE, c.a.ID, got != nil, c.want)
		case c.want && c.fix != "" && fix != c.fix:
			t.Logf("%s on %s: fix %q, want %q", c.v.CVE, c.a.ID, fix, c.fix)
		default:
			right[c.eco]++
		}
	}
	ecos := slices.Sorted(func(yield func(string) bool) {
		for e := range total {
			if !yield(e) {
				return
			}
		}
	})
	sum, all := 0, 0
	for _, e := range ecos {
		t.Logf("%-17s right %d of %d (findings %d)", e, right[e], total[e], findingsBy[e])
		sum, all = sum+right[e], all+total[e]
	}
	t.Logf("all ecosystems: right %d of %d", sum, all)
	if sum != all {
		t.Errorf("%d of %d cases wrong", all-sum, all)
	}
}

// esxiWithoutU3d is CVE-2025-22225 with VMware's U3d row left out: VMware states fixes for 8.0 U2 and 7.0 U3 only, NVD lists
// 8.0 update_3 as affected.
func esxiWithoutU3d(t testing.TB) Vuln {
	t.Helper()
	v := esxi22225(t)
	v.Schemed = slices.DeleteFunc(slices.Clone(v.Schemed), func(r SchemedRange) bool { return r.Span.End != nil && r.Span.End.Train == "8.0 U3" })
	return v
}

// On a disagreement the affected side wins: the vendor's rows silent on the host's own train (8.0 U3) never close what NVD lists as
// affected, so an open finding of an exploited CVE stays open; a vendor's "not affected" counts only for a release past the fixed
// release of its own train.
func TestVendorRows_SilentOnTheTrainNeverCloseWhatNVDLists(t *testing.T) {
	t.Parallel()
	v := esxiWithoutU3d(t)
	if len(v.Schemed) != 2 {
		t.Fatalf("rows %d, want U2d and 7.0 U3s", len(v.Schemed))
	}
	host := esxiStated("u3", "8.0", "update_3", "24022510")
	res := MatchAsset(host, []Vuln{v}, map[string]bool{v.CVE: true}, t0)
	if len(res.Existing) != 1 || len(res.NotAffected) != 0 {
		t.Fatalf("existing %+v, not affected %+v: the finding must stay", res.Existing, res.NotAffected)
	}
	if res := MatchAsset(esxiStated("u2d", "8.0", "update_2d", "24585300"), []Vuln{v}, map[string]bool{v.CVE: true}, t0); len(res.NotAffected) != 1 {
		t.Fatalf("U2d, past its own train's fix: %+v", res)
	}
}

// A device whose train has no fixed release of its own is told the nearest fix is in a later train, never "for this release train".
func TestVendorRows_FixInALaterTrainIsSaidSo(t *testing.T) {
	t.Parallel()
	v := esxi22225(t)
	host := esxiStated("u1", "8.0", "update_1", "21495797")
	res := MatchAsset(host, []Vuln{v}, nil, t0)
	if len(res.New) != 1 {
		t.Fatalf("8.0 U1: %+v", res)
	}
	if s := res.New[0].Evidence.Summary; strings.Contains(s, "for this release train") || !strings.Contains(s, "in release train 8.0 U2") {
		t.Errorf("evidence %q", s)
	}
}

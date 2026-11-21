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
// logged. It reruns like any test; before the match pass read vendor rows and distribution-only CVEs, it was the "before" column of
// the pull request.

// ecoCase is one device and one CVE: want says the device is affected; fix is the fix the finding must name ("" when not affected or
// when any fix will do).
type ecoCase struct {
	eco  string
	a    Asset
	v    Vuln
	want bool
	fix  string
}

func schemedRows(t testing.TB, scheme, product, origin string, spans ...[3]string) []SchemedRange {
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
		out = append(out, SchemedRange{Product: product, Scheme: s, Span: sp, Origin: origin})
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

func ecosystemCases(t *testing.T) []ecoCase {
	t.Helper()
	esxiKey := productid.Key("VMware", "ESXi")
	listed := esxi22225(t) // NVD lists 8.0 update_2 and update_3 exactly; VMware states U3d, U2d, 7.0 U3s
	// VMSA-2025-0013: an ESXi CVE on no list, before NVD analyses it: only VMware's rows.
	offList := Vuln{CVE: "CVE-2025-41236", NVDAnswered: true, Origin: RangeCNA,
		Schemed: schemedRows(t, "vmware-esxi", esxiKey, RangeCNA, [3]string{"8.0", "ESXi80U3f-24784735", ""},
			[3]string{"8.0", "ESXi80U2e-24789317", ""}, [3]string{"7.0", "ESXi70U3w-24784741", ""})}
	nsKey := productid.Key("Citrix", "NetScaler")
	// CVE-2025-5777: Citrix states the fixed build of each line; its record rows are the only ranges the list entry has.
	ns := Vuln{CVE: "CVE-2025-5777", Vendor: "Citrix", Product: "NetScaler ADC and Gateway", DateAdded: winDay("2025-07-10"), Published: winDay("2025-06-17"),
		NVDAnswered: true, RangesFrom: RangesCVEOrg, Origin: RangeCNA,
		Schemed: schemedRows(t, "citrix-netscaler", nsKey, RangeCNA, [3]string{"14.1", "14.1-43.56", ""}, [3]string{"13.1", "13.1-58.32", ""},
			[3]string{"13.1 FIPS", "13.1-37.235 FIPS", ""})}
	nsRow := func(version string) Asset {
		return Asset{ID: "ns-" + version, Name: "adc", Software: []Software{{ID: "s-ns", Display: "Citrix NetScaler", Vendor: "Citrix", Product: "NetScaler",
			Version: version, Source: "snmp", KevKeys: []string{"citrix|netscaler adc and gateway"}}}}
	}
	kKey := productid.Key("Linux", "Kernel")
	// A kernel CVE on no list: kernel.org states the first fixed release of each stable branch.
	kernel := Vuln{CVE: "CVE-2025-38352", NVDAnswered: true, Origin: RangeCNA,
		Schemed: schemedRows(t, "linux-kernel", kKey, RangeCNA, [3]string{"6.1", "6.1.149", ""}, [3]string{"6.6", "6.6.103", ""})}
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
	return []ecoCase{
		{"vmware-esxi", esxiStated("u2", "8.0", "update_2", "22380479"), listed, true, "8.0 U2d (build 24585300)"},
		{"vmware-esxi", esxiStated("u2d", "8.0", "update_2d", "24585300"), listed, false, ""},
		{"vmware-esxi", esxiStated("u3", "8.0", "update_3", "24022510"), listed, true, "8.0 U3d (build 24585383)"},
		{"vmware-esxi", esxiStated("u3b", "8.0", "update_3b", "24280767"), listed, true, "8.0 U3d (build 24585383)"},
		{"vmware-esxi", esxiStated("u3d", "8.0", "update_3d", "24585383"), listed, false, ""},
		{"vmware-esxi", esxiStated("7u3q", "7.0", "update_3q", "23794027"), listed, true, "7.0 U3s (build 24585291)"},
		{"vmware-esxi", esxiStated("7u3s", "7.0", "update_3s", "24585291"), listed, false, ""},
		{"vmware-esxi", esxiStated("off-u3d", "8.0", "update_3d", "24585383"), offList, true, "8.0 U3f (build 24784735)"},
		{"vmware-esxi", esxiStated("off-u2d", "8.0", "update_2d", "24585300"), offList, true, "8.0 U2e (build 24789317)"},
		{"citrix-netscaler", nsRow("13.1-49.13"), ns, true, "13.1-58.32"},
		{"citrix-netscaler", nsRow("14.1-12.30"), ns, true, "14.1-43.56"},
		{"citrix-netscaler", nsRow("14.1-43.56"), ns, false, ""},
		{"citrix-netscaler", nsRow("13.1-37.235 FIPS"), ns, false, ""},
		{"linux-kernel", kRow("appliance-old", "6.1.140", "Linux", false), kernel, true, "6.1.149"},
		{"linux-kernel", kRow("appliance-new", "6.6.110", "Linux", false), kernel, false, ""},
		{"linux-kernel", kRow("ubuntu-kernel", "6.8.0", "Ubuntu 26.04.1 LTS", true), kernel, false, ""}, // a distribution's kernel: never read upstream
		{"distribution", sshRow("ssh-old", "1:10.2p1-2ubuntu3.8"), distro, true, "1:10.2p1-2ubuntu3.9"},
		{"distribution", sshRow("ssh-new", "1:10.2p1-2ubuntu3.9"), distro, false, ""},
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

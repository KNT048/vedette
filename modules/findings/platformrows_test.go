package findings

import (
	"strings"
	"testing"
)

// Platform-limited rows of a list that is not complete: a CVE record's rows read beside NVD's, or a CNA's partial list. Every row of the
// line's own product names a system (CPE target_sw, or the record's platforms as target_sw), the vendor's own CNA wrote them and the
// device's own agent states another system: the CVE does not apply to the line, whatever the record leaves unsaid about versions.
// A third party's record counts only when NVD's own rows agree. Anything unmapped, unknown or overlapping keeps it possible.
// Synthetic product: the rule reads the vocabulary of target_sw and the device's platform, never the product.
func TestPlatformRows_DisjointSystemsDecideNotAffected(t *testing.T) {
	t.Parallel()
	const app = "cpe:2.3:*:example:meeting_app:*:*:*:*:*:"
	row := func(sys, end string) Affected {
		return Affected{CPE: app + sys + ":*:*", Range: VersionRange{EndExcl: end}, AffectedOnly: true, VendorCNA: true}
	}
	// later is a row of a later train than the line's version: outside it proves nothing on a list that is not complete
	later := func(sys string) Affected {
		return Affected{CPE: app + sys + ":*:*", Range: VersionRange{StartIncl: "8.0", EndExcl: "8.5"}, AffectedOnly: true, VendorCNA: true}
	}
	// NVD names another product of the vendor only: the record's rows beside it are the only ones naming the line
	other := Affected{CPE: "cpe:2.3:a:example:meeting_sdk:*:*:*:*:*:android:*:*", Range: VersionRange{EndExcl: "7.0.4"}}
	beside := func(rows ...Affected) Vuln {
		return Vuln{CVE: "CVE-2099-7301", NVDAnswered: true, Published: uncNew, Affected: append([]Affected{other}, rows...)}
	}
	partial := func(rows ...Affected) Vuln {
		for i := range rows {
			rows[i].AffectedOnly = false
		}
		return Vuln{CVE: "CVE-2099-7302", NVDAnswered: true, Published: uncNew, RangesFrom: RangesCVEOrgPartial, Origin: RangeCNA, Affected: rows}
	}
	line := Software{ID: "z", Display: "Example Meeting App", Vendor: "Example", Product: "Meeting App", Version: "7.1.9", Source: "agent"}
	on := func(os string, s Software) Asset {
		return Asset{ID: "pc", Name: "pc-01", OS: os, AgentOS: os, Software: []Software{s}}
	}
	const windows, ubuntu, mac = "Microsoft Windows 11 Pro", "Ubuntu 24.04.1 LTS", "macOS 15.2"
	listed := beside(row("android", "7.0.4"), row("iphone_os", "7.0.3"))
	listed.Vendor, listed.Product = "Example", "Meeting App"
	tested := row("linux", "8.0.3") // a third party's record: the system it demonstrated the flaw on
	tested.VendorCNA = false
	thirdBeside := func(nvd Affected) Vuln {
		r := row("android", "7.0.4")
		r.VendorCNA = false
		return Vuln{CVE: "CVE-2099-7305", NVDAnswered: true, Published: uncNew, Affected: []Affected{nvd, r}}
	}
	nvdAny := Affected{CPE: "cpe:2.3:a:example:meeting_sdk:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "7.0.4"}}
	nvdOwn := Affected{CPE: "cpe:2.3:a:example:meeting_sdk:*:*:*:*:*:windows:*:*", Range: VersionRange{EndExcl: "7.0.4"}}
	scanned := line
	scanned.Source = "nmap"
	for _, tc := range []struct {
		name   string
		a      Asset
		v      Vuln
		closes bool
	}{
		{"rows for two mobile systems beside NVD, on Windows", on(windows, line), beside(row("android", "7.0.4"), row("iphone_os", "7.0.3")), true},
		{"a partial record for one mobile system, on Windows", on(windows, line), partial(row("android", "7.2.1")), true},
		{"a mobile system on a Linux distribution", on(ubuntu, line), partial(row("android", "7.2.1")), true},
		{"a desktop system on another desktop system", on(ubuntu, line), partial(later("windows")), true},
		{"one row for the device's own system", on(windows, line), partial(row("android", "7.2.1"), later("windows")), false},
		{"Linux on a Linux distribution", on(ubuntu, line), partial(later("linux")), false},
		{"iPhone and iPad apps run on macOS", on(mac, line), partial(later("iphone_os")), false},
		{"a row for every system beside a mobile one", on(windows, line), partial(row("android", "7.2.1"), later("*")), false},
		{"a row for the build of no named system", on(windows, line), partial(row("android", "7.2.1"), later("-")), false},
		{"a host application, not a system", on(windows, line), partial(later("wordpress")), false},
		{"the device's system is not known", on("", line), partial(row("android", "7.2.1")), false},
		{"a system outside the vocabulary", on("VMware ESXi 8.0 Update 3", line), partial(later("linux")), false},
		{"a row a scan saw: a container may run it", on(windows, scanned), partial(row("android", "7.2.1")), false},
		{"a third party's record names the system it tested on", on(windows, line), partial(tested), false},
		{"a third party's record NVD's own rows agree with", on(windows, line), thirdBeside(other), true},
		{"a third party's record, NVD names every system", on(windows, line), thirdBeside(nvdAny), false},
		{"a third party's record, NVD names the device's system", on(windows, line), thirdBeside(nvdOwn), false},
		{"an exploited CVE closes only by a person", on(windows, line), listed, false},
	} {
		have := map[string]bool{tc.v.CVE: true}
		res := MatchAsset(tc.a, []Vuln{tc.v}, have, uncNow)
		closed := len(res.NotAffected) == 1 && len(res.New)+len(res.Existing)+len(res.Unchecked)+len(res.NameOnly) == 0
		if closed != tc.closes {
			t.Errorf("%s: closed %v, want %v (not affected %+v, existing %+v, unchecked %+v)", tc.name, closed, tc.closes, res.NotAffected, res.Existing, res.Unchecked)
			continue
		}
		if closed && !strings.Contains(res.NotAffected[0].Evidence.Summary, "the device runs "+tc.a.AgentOS) {
			t.Errorf("%s: the evidence does not name the device's system: %q", tc.name, res.NotAffected[0].Evidence.Summary)
		}
	}
}

// A complete list and NVD's own rows rule a line out by a system the same way: never by one whose builds may run on the device's
// (an iPhone or iPad app on macOS).
func TestPlatformRows_SystemsThatMeetNeverRuleOut(t *testing.T) {
	t.Parallel()
	line := Software{ID: "z", Display: "Example Meeting App", Vendor: "Example", Product: "Meeting App", Version: "7.1.9", Source: "agent"}
	mobile := Affected{CPE: "cpe:2.3:a:example:meeting_app:*:*:*:*:*:iphone_os:*:*", Range: VersionRange{StartIncl: "7.0", EndExcl: "7.5"}}
	for _, tc := range []struct {
		os     string
		v      Vuln
		closes bool
	}{
		{"Microsoft Windows 11 Pro", Vuln{CVE: "CVE-2099-7303", NVDAnswered: true, Published: uncNew, Affected: []Affected{mobile}}, true},
		{"Microsoft Windows 11 Pro", Vuln{CVE: "CVE-2099-7304", NVDAnswered: true, Published: uncNew, RangesFrom: RangesCVEOrg, Origin: RangeCNA, Affected: []Affected{mobile}}, true},
		{"macOS 15.2", Vuln{CVE: "CVE-2099-7303", NVDAnswered: true, Published: uncNew, Affected: []Affected{mobile}}, false},
		{"macOS 15.2", Vuln{CVE: "CVE-2099-7304", NVDAnswered: true, Published: uncNew, RangesFrom: RangesCVEOrg, Origin: RangeCNA, Affected: []Affected{mobile}}, false},
	} {
		a := Asset{ID: "pc", Name: "pc-01", OS: tc.os, AgentOS: tc.os, Software: []Software{line}}
		res := MatchAsset(a, []Vuln{tc.v}, map[string]bool{tc.v.CVE: true}, uncNow)
		if closed := len(res.NotAffected) == 1; closed != tc.closes {
			t.Errorf("%s on %s: closed %v, want %v (new %+v, unchecked %+v)", tc.v.CVE, tc.os, closed, tc.closes, res.New, res.Unchecked)
		}
	}
}

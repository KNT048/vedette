package findings

import (
	"slices"
	"testing"
)

// #901: NVD writes NA ("-", not applicable) in the attributes after the version. A software row's ANY means "not stated". NA covers
// it only on the Windows release rows (winUnpinned) and in the update attribute (evalUpdate); an application row keeps NA
// pinned as origin/main did, because "-" there often means "not ESR" or "not LTS" (reviews H1 of #906 r1 and r2; NISTIR 7696 itself
// gives NA against ANY as SUBSET, not a match). These tests use NVD's real shapes.

// cve202626111 is NVD's list for CVE-2026-26111 as a test box's nvd-recent copy stores it (2026-11-16): the server releases with
// software edition "-" and target x64.
func cve202626111() []Affected {
	return []Affected{
		{CPE: "cpe:2.3:o:microsoft:windows_server_2012:*:*:*:*:standard:*:x64:*", Range: VersionRange{EndExcl: "6.2.9200.25973"}},
		{CPE: "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*"},
		{CPE: "cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:-:*:x64:*", Range: VersionRange{EndExcl: "10.0.14393.8957"}},
		{CPE: "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:-:*:x64:*", Range: VersionRange{EndExcl: "10.0.17763.8511"}},
		{CPE: "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:-:*:x64:*", Range: VersionRange{EndExcl: "10.0.20348.4893"}},
		{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:-:*:x64:*", Range: VersionRange{EndExcl: "10.0.26100.32522"}},
	}
}

// winServer2025 is WINLAB01's Windows release row as the agent stores it (build 26100.<ubr>, target x64); swEdition replaces the
// software edition the row states ("*" for the agent's).
func winServer2025(ubr, swEdition string) Asset {
	a := winPC(26100, true, ubr, "x64")
	a.Name = "WINLAB01"
	a.Software[0].CPE = "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100." + ubr + ":*:*:*:" + swEdition + ":*:x64:*"
	return a
}

// On an exploited list, CVE-2026-26111's real rows make the unpatched build a version match naming the fix build, and close on a
// patched build, exactly as the same rows with software edition "*" do. A row stating another software edition is not matched by NA.
func TestNA_CVE202626111_WindowsServer2025(t *testing.T) {
	t.Parallel()
	kev := func(aff []Affected) Vuln {
		return Vuln{CVE: "CVE-2026-26111", Vendor: "Microsoft", Product: "Windows", Published: winDay("2026-10-13"), DateAdded: winDay("2026-11-10"), Affected: aff}
	}
	star := cve202626111()
	for i := range star {
		c, _ := ParseCPE(star[i].CPE)
		if c.SWEdition.Kind == NA {
			c.SWEdition = Attr{Kind: Any}
		}
		star[i].CPE = c.String()
	}
	for name, aff := range map[string][]Affected{"NVD's rows (-)": cve202626111(), "control (*)": star} {
		where, m := oneMatch(t, winServer2025("1742", "*"), kev(aff), false)
		wantMatch(t, name+" unpatched", where, m, "new", BasisVersion, SeverityHigh, "10.0.26100.32522")
		if f := FixedInFor(winServer2025("1742", "*"), kev(aff)); f == nil || f.Kind != "fixed" || f.Fixed != "10.0.26100.32522" {
			t.Errorf("%s: fixed_in %+v", name, f)
		}
		where, m = oneMatch(t, winServer2025("32600", "*"), kev(aff), true)
		wantMatch(t, name+" patched", where, m, "notaffected", "", "")
	}
	// The row states a software edition: NA ("not applicable") is not that value, so the rows cannot make it a version match, and a
	// patched build is not proved either (nothing reads).
	where, m := oneMatch(t, winServer2025("1742", "datacenter"), kev(cve202626111()), false)
	if where == "new" && m.Basis == BasisVersion {
		t.Errorf("stated software edition: %s %s %q", where, m.Basis, m.Evidence.Summary)
	}
	if where, _ := oneMatch(t, winServer2025("32600", "datacenter"), kev(cve202626111()), true); where == "notaffected" {
		t.Error("stated software edition: closed by NA rows")
	}
}

// Updates to plan: the M2-10 shapes of #898 still count as before, and CVE-2026-26111 joins the same monthly update (its fix build is
// below the group's). On a test box's copy this takes WINLAB01's plan from 2786 to 2787 CVEs and changes nothing else.
func TestNA_PlanCountsCVE202626111(t *testing.T) {
	t.Parallel()
	osEntry := func(product, hw, end string) Affected {
		return Affected{CPE: "cpe:2.3:o:microsoft:" + product + ":*:*:*:*:*:*:" + hw + ":*", Range: VersionRange{EndExcl: end}}
	}
	ntfs := tierV("CVE-2026-69902", "recent", 27, 0.01, osEntry("windows_11_24h2", "arm64", "10.0.26100.9711"), osEntry("windows_11_24h2", "x64", "10.0.26100.9711"),
		osEntry("windows_server_2025", "x64", "10.0.26100.33650"))
	dotnet := tierV("CVE-2026-23666", "recent", 300, 0.01, Affected{CPE: "cpe:2.3:a:microsoft:.net_framework:3.5:-:*:*:*:*:*:*"},
		Affected{CPE: "cpe:2.3:a:microsoft:.net_framework:4.8.1:*:*:*:*:*:*:*"})
	dotnet.Platforms = [][]string{{"microsoft:windows_10_21h2", "microsoft:windows_server_2025"}, {"microsoft:windows_10_21h2", "microsoft:windows_server_2025"}}
	client := tierV("CVE-2026-49001", "recent", 30, 0.01, osEntry("windows_11_24h2", "x64", "10.0.26100.9711"))
	wac := tierV("CVE-2026-49002", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:microsoft:windows_admin_center:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.4.2"}})
	yellow := tierV("CVE-2026-45585", "likely", 173, 0.3, Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*"})
	na := tierV("CVE-2026-26111", "recent", 34, 0.01, cve202626111()...)
	for _, target := range []string{"*", "x64"} {
		a := winServer2025("1742", "*")
		a.Software[0].CPE = "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100.1742:*:*:*:*:*:" + target + ":*"
		items, compared := planOf(a, []TierVuln{ntfs, dotnet, client, wac, yellow, na}, nil)
		if !compared || len(items) != 1 || items[0].Kind != "windows" || items[0].Fixed != "10.0.26100.33650" ||
			!slices.Equal(cvesOf(items[0]), []string{"CVE-2026-26111/recent/agent", "CVE-2026-69902/recent/agent"}) &&
				!slices.Equal(cvesOf(items[0]), []string{"CVE-2026-69902/recent/agent", "CVE-2026-26111/recent/agent"}) {
			t.Fatalf("target %s: items %+v", target, items)
		}
	}
	// A build past the fix: nothing to plan for it.
	if items, _ := planOf(winServer2025("32600", "*"), []TierVuln{na}, nil); len(items) != 0 {
		t.Fatalf("patched: items %+v", items)
	}
}

// The ordinary matcher (any product): NA after the version stays pinned as on origin/main (it matches NA, an unstated attribute lowers
// Yes to Unknown, a value gives No); only the update's NA reads the version string. Real shapes: Jenkins (CVE-2024-23897,
// software edition "-") and OpenSSH's release without an update ("9.8:-").
func TestNA_EvalAffected(t *testing.T) {
	t.Parallel()
	cpe := func(s string) CPE {
		c, err := ParseCPE(s)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	jenkins := cpe("cpe:2.3:a:jenkins:jenkins:*:*:*:*:-:*:*:*")
	lts := cpe("cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*")
	upTo := VersionRange{EndExcl: "2.442"}
	ssh := cpe("cpe:2.3:a:openbsd:openssh:9.8:-:*:*:*:*:*:*")
	tests := []struct {
		name string
		c    CPE
		r    VersionRange
		ver  string
		sw   string // "" no CPE
		want Tri
	}{
		{"NA, name-only row inside (as origin/main)", jenkins, upTo, "2.441", "", Unknown},
		{"NA, name-only row outside", jenkins, upTo, "2.442", "", No},
		{"NA, row's CPE leaves it ANY (as origin/main)", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:*:*:*:*", Unknown},
		{"NA, row's CPE states NA", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:-:*:*:*", Yes},
		{"NA, row states a value", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:lts:*:*:*", No},
		{"value, row states none (unchanged)", lts, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:*:*:*:*", Unknown},
		{"value, name-only row (unchanged)", lts, upTo, "2.441", "", Unknown},
		{"value, row states it (unchanged)", lts, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:lts:*:*:*", Yes},
		{"update NA, name-only release (unchanged)", ssh, VersionRange{}, "9.8", "", Yes},
		{"update NA, name-only p1 (unchanged)", ssh, VersionRange{}, "9.8p1", "", No},
		{"update NA, row's CPE leaves it ANY", ssh, VersionRange{}, "9.8", "cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*", Yes},
		{"update NA, row's CPE leaves it ANY, p1", ssh, VersionRange{}, "9.8p1", "cpe:2.3:a:openbsd:openssh:9.8p1:*:*:*:*:*:*:*", No},
		{"update NA, row states p1", ssh, VersionRange{}, "9.8", "cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*", No},
	}
	for _, tt := range tests {
		var sw CPE
		if tt.sw != "" {
			sw = cpe(tt.sw)
		}
		if got, _ := evalAffected(tt.c, tt.r, tt.ver, sw, tt.sw != ""); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// Reviews H1 of #906 (r1, r2): NVD's "-" on an application row is often "the plain edition" (Firefox not ESR, Jenkins not LTS), and
// inventory cannot tell the editions apart (firefox-esr and "Mozilla Firefox ESR" map to Mozilla / Firefox, Jenkins LTS and weekly are
// one package). Whether the CVE lists the named edition too (CVE-2024-9680 "esr", CVE-2024-23897 "lts") or leaves it out because it is
// not affected (CVE-2025-14326, Firefox 146 only: MFSA2025-92, not in ESR 140.6's MFSA2025-94), every answer is origin/main's: a
// product finding, no plan item, no fix of the other channel.
func TestNA_ApplicationEditionAsMain(t *testing.T) {
	t.Parallel()
	firefox := Vuln{CVE: "CVE-2024-9680", Vendor: "Mozilla", Product: "Firefox", Affected: []Affected{ // a test box's feeds_affected, 2026-11-16
		{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", Range: VersionRange{EndExcl: "115.16.1"}},
		{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*", Range: VersionRange{EndExcl: "131.0.2"}},
		{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", Range: VersionRange{StartIncl: "128.1.0", EndExcl: "128.3.1"}},
		{CPE: "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "115.16.0"}},
		{CPE: "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "128.0.1", EndExcl: "128.3.1"}},
		{CPE: "cpe:2.3:a:mozilla:thunderbird:131.0:*:*:*:*:*:*:*"},
		{CPE: "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*"},
	}}
	jenkins := Vuln{CVE: "CVE-2024-23897", Vendor: "Jenkins", Product: "Jenkins Command Line Interface (CLI)", Affected: []Affected{
		{CPE: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*", Range: VersionRange{EndExcl: "2.426.3"}},
		{CPE: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:-:*:*:*", Range: VersionRange{EndExcl: "2.442"}},
	}}
	// CVE-2025-14326 as a test box's feeds_recent_affected stores it: "-" rows only, ESR not affected.
	release := []Affected{
		{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*", Range: VersionRange{EndExcl: "146.0"}},
		{CPE: "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:-:*:*:*", Range: VersionRange{EndExcl: "146.0"}},
	}
	releaseKEV := Vuln{CVE: "CVE-2025-14326", Vendor: "Mozilla", Product: "Firefox", Affected: release}
	dev := func(v Vuln, display, vendor, product, ver string) Asset {
		return Asset{ID: "a", Name: "pc", OS: "Windows 11", Software: []Software{{ID: "s", Display: display, Vendor: vendor,
			Product: product, Version: ver, Source: "agent", KevKeys: []string{KevKey(v.Vendor, v.Product)}}}}
	}
	esr := "Mozilla Firefox ESR (x64 en-US)"
	for _, tt := range []struct {
		name, display, vendor, product, ver string
		v                                   Vuln
		want                                string // "product": a product finding, never a version one; "none": no finding
		badFix                              string // the other channel's fix fixed_in must not name; "" no check
	}{
		{"Firefox ESR 128.3.1 (patched)", esr, "Mozilla", "Firefox", "128.3.1", firefox, "product", "131.0.2"},
		{"Firefox ESR 115.16.1 (patched)", esr, "Mozilla", "Firefox", "115.16.1", firefox, "product", "131.0.2"},
		{"Jenkins LTS 2.426.3 (patched)", "Jenkins", "Jenkins", "Jenkins", "2.426.3", jenkins, "product", "2.442"},
		{"Firefox 130.0", "Mozilla Firefox", "Mozilla", "Firefox", "130.0", firefox, "product", ""},
		{"Jenkins 2.441", "Jenkins", "Jenkins", "Jenkins", "2.441", jenkins, "product", ""},
		{"Firefox 131.0.2", "Mozilla Firefox", "Mozilla", "Firefox", "131.0.2", firefox, "none", ""},
		{"Jenkins 2.442", "Jenkins", "Jenkins", "Jenkins", "2.442", jenkins, "none", ""},
		{"CVE-2025-14326, ESR 140.5.0", esr, "Mozilla", "Firefox", "140.5.0", releaseKEV, "product", "146.0"},
		{"CVE-2025-14326, ESR 140.6.0", esr, "Mozilla", "Firefox", "140.6.0", releaseKEV, "product", "146.0"},
		{"CVE-2025-14326, ESR 115.30.0", esr, "Mozilla", "Firefox", "115.30.0", releaseKEV, "product", "146.0"},
	} {
		a := dev(tt.v, tt.display, tt.vendor, tt.product, tt.ver)
		where, m := oneMatch(t, a, tt.v, false)
		if tt.want == "product" {
			wantMatch(t, tt.name, where, m, "nameonly", BasisProduct, SeverityMedium) // No finding
		} else if where != "none" {
			t.Errorf("%s: %s %s/%s %q", tt.name, where, m.Basis, m.Severity, m.Evidence.Summary)
		}
		if f := FixedInFor(a, tt.v); tt.badFix != "" && f != nil && f.Fixed == tt.badFix {
			t.Errorf("%s: fixed_in names the other channel's fix %+v", tt.name, f)
		}
	}
	// Updates to plan: CVE-2025-14326 is no plan item on an ESR host (origin/main), whatever its ESR version.
	for _, ver := range []string{"140.5.0", "140.6.0", "115.30.0"} {
		a := dev(releaseKEV, esr, "Mozilla", "Firefox", ver)
		a.Software[0].KevKeys = nil
		if items, _ := planOf(a, []TierVuln{tierV("CVE-2025-14326", "recent", 30, 0.01, release...)}, nil); len(items) != 0 {
			t.Errorf("ESR %s: plan %+v", ver, items)
		}
	}
}

// fixed_in reads a range whose update is NA ("the release without an update") as it reads one whose update is ANY.
func TestNA_FixedInReadsUpdateNARange(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2024-13160", Vendor: "Acme", Product: "Widget",
		Affected: []Affected{{CPE: "cpe:2.3:a:acme:widget:*:-:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.5"}}}}
	a := Asset{ID: "a", Name: "srv", Software: []Software{{ID: "s", Display: "Acme Widget", Vendor: "acme", Product: "widget", Version: "2.4", Source: "manual", KevKeys: []string{"acme|widget"}}}}
	if f := FixedInFor(a, v); f == nil || f.Kind != "fixed" || f.Fixed != "2.5" {
		t.Fatalf("fixed_in %+v", f)
	}
}

// The month rule reads a fix revision from a row whose NA attributes the device leaves unstated, and never from one whose
// update or edition is pinned, or whose NA the device's row contradicts.
func TestNA_WinFixRev(t *testing.T) {
	t.Parallel()
	in := newSWInfo(winServer2025("1742", "*").Software[0], "")
	d, ok := winDevice(in)
	if !ok {
		t.Fatal("not a Windows release row")
	}
	r := VersionRange{EndExcl: "10.0.26100.32522"}
	for row, want := range map[string]bool{
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:-:*:x64:*": true,
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:-:*:-:x64:-": true,
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*": true,
		"cpe:2.3:o:microsoft:windows_server_2025:*:-:*:*:*:*:x64:*": false, // update "-": kept strict
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:-:*:*:*:x64:*": false, // edition "-": kept strict
		"cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:x64:*": false, // version "-"
	} {
		c, _ := ParseCPE(row)
		if rev, ok := winFixRev(c, r, d, false); ok != want || ok && rev != 32522 {
			t.Errorf("%s: %d %v, want %v", row, rev, ok, want)
		}
	}
	dv, _ := winDevice(newSWInfo(winServer2025("1742", "datacenter").Software[0], ""))
	c, _ := ParseCPE("cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:-:*:x64:*")
	if _, ok := winFixRev(c, r, dv, false); ok {
		t.Error("a row stating a software edition read an NA row's fix")
	}
}

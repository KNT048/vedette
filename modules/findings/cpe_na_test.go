package findings

import (
	"slices"
	"strings"
	"testing"
)

// #901: NVD writes NA ("-", not applicable) in the attributes after the version. A software row's ANY means "not stated"; NA covers
// it only when no row of the same CVE and product states a value there at the same versions (naCovers, naValued; review H1 of #906:
// NISTIR 7696 itself gives NA against ANY as SUBSET, not a match). These tests use NVD's real shapes.

// cve202626111 is NVD's list for CVE-2026-26111 as the N100's nvd-recent copy stores it (2026-11-16): the server releases with
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
// below the group's). On the N100's copy this takes WINLAB01's plan from 2786 to 2787 CVEs and changes nothing else.
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

// The ordinary matcher (any product): an NA attribute covers a row that states NA, and one that states none when no sibling row
// states a value there; never a value. Real shapes: Jenkins (CVE-2024-23897, software edition "-" beside "lts": sib), the same row
// alone (a product whose list has no valued sibling), and OpenSSH's release without an update ("9.8:-").
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
	const sib = 1 << 2 // software edition (naValued)
	tests := []struct {
		name   string
		c      CPE
		r      VersionRange
		ver    string
		sw     string // "" no CPE
		valued uint8
		want   Tri
	}{
		{"NA alone, name-only row inside", jenkins, upTo, "2.441", "", 0, Yes},
		{"NA alone, name-only row outside", jenkins, upTo, "2.442", "", 0, No},
		{"NA alone, row's CPE leaves it ANY", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:*:*:*:*", 0, Yes},
		{"NA alone, row's CPE states NA", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:-:*:*:*", 0, Yes},
		{"NA alone, row states a value", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:lts:*:*:*", 0, No},
		{"NA beside lts, name-only row inside (as origin/main)", jenkins, upTo, "2.441", "", sib, Unknown},
		{"NA beside lts, name-only row outside", jenkins, upTo, "2.442", "", sib, No},
		{"NA beside lts, row's CPE leaves it ANY (as origin/main)", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:*:*:*:*", sib, Unknown},
		{"NA beside lts, row's CPE states NA", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:-:*:*:*", sib, Yes},
		{"NA beside lts, row states lts", jenkins, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:lts:*:*:*", sib, No},
		{"value, row states none (unchanged)", lts, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:*:*:*:*", 0, Unknown},
		{"value, name-only row (unchanged)", lts, upTo, "2.441", "", 0, Unknown},
		{"value, row states it (unchanged)", lts, upTo, "2.441", "cpe:2.3:a:jenkins:jenkins:2.441:*:*:*:lts:*:*:*", 0, Yes},
		{"update NA, name-only release (unchanged, D-500)", ssh, VersionRange{}, "9.8", "", 0, Yes},
		{"update NA, name-only p1 (unchanged, D-500)", ssh, VersionRange{}, "9.8p1", "", 0, No},
		{"update NA, row's CPE leaves it ANY", ssh, VersionRange{}, "9.8", "cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*", 0, Yes},
		{"update NA, row's CPE leaves it ANY, p1", ssh, VersionRange{}, "9.8p1", "cpe:2.3:a:openbsd:openssh:9.8p1:*:*:*:*:*:*:*", 0, No},
		{"update NA, row states p1", ssh, VersionRange{}, "9.8", "cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*", 0, No},
	}
	for _, tt := range tests {
		var sw CPE
		if tt.sw != "" {
			sw = cpe(tt.sw)
		}
		if got, _ := evalAffected(tt.c, tt.r, tt.ver, sw, tt.sw != "", tt.valued); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// naValued: a sibling counts only for the attribute it states a value in, and only at versions the NA row also names.
func TestNA_Valued(t *testing.T) {
	t.Parallel()
	v := func(rows ...Affected) Vuln { return Vuln{CVE: "CVE-0000-0001", Affected: rows} }
	row := func(cpe string, r VersionRange) Affected { return Affected{CPE: cpe, Range: r} }
	ff := row("cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*", VersionRange{EndExcl: "131.0.2"})
	esr := row("cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", VersionRange{EndExcl: "115.16.1"})
	tb := row("cpe:2.3:a:mozilla:thunderbird:*:*:*:*:esr:*:*:*", VersionRange{EndExcl: "115.16.0"})
	o16 := row("cpe:2.3:a:microsoft:office:2016:*:-:*:-:*:-:*", VersionRange{})
	rt13 := row("cpe:2.3:a:microsoft:office:2013:sp1:*:*:rt:*:*:*", VersionRange{})
	rt16 := row("cpe:2.3:a:microsoft:office:2016:*:*:*:rt:*:*:*", VersionRange{})
	x64 := row("cpe:2.3:a:microsoft:office:*:*:*:*:*:*:x64:*", VersionRange{})
	for name, tt := range map[string]struct {
		row  Affected
		list Vuln
		want uint8
	}{
		"Firefox - beside esr":                       {ff, v(ff, esr), 1 << 2},
		"Firefox - alone":                            {ff, v(ff), 0},
		"Firefox - beside Thunderbird esr":           {ff, v(ff, tb), 0},
		"Firefox - beside esr after its range":       {ff, v(ff, row("cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", VersionRange{StartIncl: "131.0.2", EndExcl: "140"})), 0},
		"Office 2016 beside 2013 rt (CVE-2015-2545)": {o16, v(rt13, o16), 0},
		"Office 2016 beside 2016 rt":                 {o16, v(rt13, rt16, o16), 1 << 2},
		"Office 2016 beside x64 at every version":    {o16, v(o16, x64), 1 << 4},
		"esr row has no NA":                          {esr, v(ff, esr), 0},
	} {
		c, err := tt.row.cpe()
		if err != nil {
			t.Fatal(err)
		}
		if got := naValued(tt.list, c, tt.row.Range); got != tt.want {
			t.Errorf("%s: %06b, want %06b", name, got, tt.want)
		}
	}
}

// review H1 of #906: NVD's "-" beside a named edition (Firefox ESR, Jenkins LTS) is the plain edition, and inventory cannot tell the
// two apart (firefox-esr and "Mozilla Firefox ESR" map to Mozilla / Firefox, Jenkins LTS and weekly are one package). The real KEV
// rows keep origin/main's answer: a patched ESR or LTS install is no version finding and is never sent to the other channel's fix.
func TestNA_ValuedSiblingKeepsProductMatch(t *testing.T) {
	t.Parallel()
	firefox := Vuln{CVE: "CVE-2024-9680", Vendor: "Mozilla", Product: "Firefox", Affected: []Affected{ // the N100's feeds_affected, 2026-11-16
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
	dev := func(v Vuln, vendor, product, ver string) Asset {
		return Asset{ID: "a", Name: "pc", OS: "Windows 11", Software: []Software{{ID: "s", Display: vendor + " " + product, Vendor: vendor,
			Product: product, Version: ver, Source: "agent", KevKeys: []string{KevKey(v.Vendor, v.Product)}}}}
	}
	for _, tt := range []struct {
		name, vendor, product, ver string
		v                          Vuln
		want                       string // "product": a product finding, never a version one; "none": no finding
	}{
		{"Firefox ESR 128.3.1 (patched)", "Mozilla", "Firefox", "128.3.1", firefox, "product"},
		{"Firefox ESR 115.16.1 (patched)", "Mozilla", "Firefox", "115.16.1", firefox, "product"},
		{"Jenkins LTS 2.426.3 (patched)", "Jenkins", "Jenkins", "2.426.3", jenkins, "product"},
		// Inside the plain edition's range only: the edition cannot be told, so it stays a product finding, as on origin/main.
		{"Firefox 130.0", "Mozilla", "Firefox", "130.0", firefox, "product"},
		{"Jenkins 2.441", "Jenkins", "Jenkins", "2.441", jenkins, "product"},
		// Patched on both editions: unchanged, nothing.
		{"Firefox 131.0.2", "Mozilla", "Firefox", "131.0.2", firefox, "none"},
		{"Jenkins 2.442", "Jenkins", "Jenkins", "2.442", jenkins, "none"},
	} {
		a := dev(tt.v, tt.vendor, tt.product, tt.ver)
		where, m := oneMatch(t, a, tt.v, false)
		switch tt.want {
		case "product":
			wantMatch(t, tt.name, where, m, "new", BasisProduct, SeverityMedium)
		default:
			if where != "none" {
				t.Errorf("%s: %s %s/%s %q", tt.name, where, m.Basis, m.Severity, m.Evidence.Summary)
			}
		}
		if f := FixedInFor(a, tt.v); strings.HasSuffix(tt.name, "(patched)") && f != nil && (f.Fixed == "131.0.2" || f.Fixed == "2.442") {
			t.Errorf("%s: fixed_in names the other channel's fix %+v", tt.name, f)
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

// The month rule (D-618) reads a fix revision from a row whose NA attributes the device leaves unstated, and never from one whose
// update or edition is pinned, or whose NA the device's row contradicts.
func TestNA_WinFixRev(t *testing.T) {
	t.Parallel()
	in := newSWInfo(winServer2025("1742", "*").Software[0], "")
	d, ok := winDevice(in)
	if !ok {
		t.Fatal("not a Windows release row")
	}
	r := VersionRange{EndExcl: "10.0.26100.32522"}
	if n := naValued(Vuln{Affected: cve202626111()}, mustCPE(t, "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:-:*:x64:*"), r); n != 0 {
		t.Fatalf("CVE-2026-26111's Server 2025 row has a valued sibling: %06b", n)
	}
	for row, want := range map[string]bool{
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:-:*:x64:*": true,
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:-:*:-:x64:-": true,
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*": true,
		"cpe:2.3:o:microsoft:windows_server_2025:*:-:*:*:*:*:x64:*": false, // update "-": kept strict
		"cpe:2.3:o:microsoft:windows_server_2025:*:*:-:*:*:*:x64:*": false, // edition "-": kept strict
		"cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:x64:*": false, // version "-"
	} {
		c, _ := ParseCPE(row)
		if rev, ok := winFixRev(c, r, d, false, 0); ok != want || ok && rev != 32522 {
			t.Errorf("%s: %d %v, want %v", row, rev, ok, want)
		}
	}
	dv, _ := winDevice(newSWInfo(winServer2025("1742", "datacenter").Software[0], ""))
	c, _ := ParseCPE("cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:-:*:x64:*")
	if _, ok := winFixRev(c, r, dv, false, 0); ok {
		t.Error("a row stating a software edition read an NA row's fix")
	}
	// review L3 of #906: beside a row of the same release that states a software edition, NA is that edition's plain sibling and
	// pins the row like any edition (naValued, as pinnedAttrs).
	if _, ok := winFixRev(c, r, d, false, 1<<2); ok {
		t.Error("an NA row with a valued sibling read a fix")
	}
	if tv, _, _ := winEval(c, r, d, 1<<2); tv != Unknown {
		t.Errorf("winEval of an NA row with a valued sibling: %v", tv)
	}
}

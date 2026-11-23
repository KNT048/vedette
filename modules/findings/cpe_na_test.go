package findings

import (
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

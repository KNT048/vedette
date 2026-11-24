package versionscheme

import (
	"slices"
	"testing"
)

// spans reads ranges as a CVE record states them: {start, lessThan, lessThanOrEqual}.
func spans(t *testing.T, s *Scheme, rows ...[3]string) []Span {
	t.Helper()
	var out []Span
	for _, r := range rows {
		sp, ok := s.Span(r[0], r[1], r[2])
		if !ok {
			t.Fatalf("%s: range %q does not read", s.Name, r)
		}
		out = append(out, sp)
	}
	return out
}

type judgeCase struct {
	name             string
	version, build   string
	want             State
	fixLabel, reason string
}

func runJudge(t *testing.T, s *Scheme, sp []Span, cases []judgeCase) {
	t.Helper()
	for _, c := range cases {
		in, ok := s.Installed(c.version, c.build)
		if !ok {
			if c.want != NotComparable {
				t.Errorf("%s %s: %q %q does not read", s.Name, c.name, c.version, c.build)
			}
			continue
		}
		v := Judge(in, sp)
		fix := ""
		if v.Fix != nil {
			fix = v.Fix.Display
		}
		if v.State != c.want || fix != c.fixLabel {
			t.Errorf("%s %s (%s): state %v fix %q, want %v %q", s.Name, c.name, c.reason, v.State, fix, c.want, c.fixLabel)
		}
	}
}

// CVE-2025-22225 as VMware states it: per train, the fixed build. A build is compared only inside its update; an update with no
// row of its own is placed by release order; a build without a known update is never placed.
func TestESXi_CVE2025_22225(t *testing.T) {
	t.Parallel()
	s, ok := Lookup("vmware-esxi")
	if !ok {
		t.Fatal("no vmware-esxi scheme")
	}
	sp := spans(t, s, [3]string{"8.0", "ESXi80U3d-24585383", ""}, [3]string{"8.0", "ESXi80U2d-24585300", ""}, [3]string{"7.0", "ESXi70U3s-24585291", ""})
	u3d, u2d, u3s := "8.0 U3d (build 24585383)", "8.0 U2d (build 24585300)", "7.0 U3s (build 24585291)"
	runJudge(t, s, sp, []judgeCase{
		{"8.0 U3 before the fix", "8.0.3", "24022510", Affected, u3d, "same train, lower build"},
		{"8.0 U3d itself", "8.0.3", "24585383", NotAffected, "", "the boundary build is the fix"},
		{"8.0 U3 one build before", "8.0.3", "24585382", Affected, u3d, "the build just below the fix"},
		{"8.0 U2d itself", "8.0.2", "24585300", NotAffected, "", "patched U2d is below the U3d build and still fixed"},
		{"8.0 U2 after U2d", "8.0.2", "24585301", NotAffected, "", "a later build of U2"},
		{"8.0 U2 before U2d", "8.0.2", "23305546", Affected, u2d, "same train"},
		{"8.0 U1", "8.0.1", "21495797", Affected, u2d, "older train: the nearest later train's fix"},
		{"8.0 GA patch", "8.0.0", "21203435", Affected, u2d, "8.0b"},
		{"7.0 U3 before U3s", "7.0.3", "24411414", Affected, u3s, "7.0 U3r"},
		{"7.0 U3s", "7.0.3", "24585291", NotAffected, "", "the fix"},
		{"7.0 U2", "7.0.2", "17867351", Affected, u3s, "older train of 7.0"},
		{"6.7", "6.7.0", "17700523", NotAffected, "", "before every stated range"},
		{"no build", "8.0.3", "", NotComparable, "", "the version alone does not place a patch"},
		{"build of another update", "8.0.2", "24022510", NotComparable, "", "the table says 8.0 U3, the host says U2"},
		{"not a version", "eight", "24022510", NotComparable, "", ""},
	})
	// a range in another notation does not read: nothing is compared
	if _, ok := s.Span("8.0", "8.0 U3d", ""); ok {
		t.Error("\"8.0 U3d\" read as an ESXi release")
	}
}

// VMware's notation from 9.0 on, and an 8.0 GA patch.
func TestESXi_Notations(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]Version{
		"ESXi80U3d-24585383":       {Train: "8.0 U3", Label: "8.0 U3d", Display: "8.0 U3d (build 24585383)"},
		"ESXi70U3s-24585291":       {Train: "7.0 U3", Label: "7.0 U3s", Display: "7.0 U3s (build 24585291)"},
		"ESXi80b-21203435":         {Train: "8.0", Label: "8.0b", Display: "8.0b (build 21203435)"},
		"ESXi-9.0.2.0100-25595025": {Train: "9.0.2", Label: "9.0.2.0100", Display: "9.0.2.0100 (build 25595025)"},
		"9.0.x.x":                  {Train: "9.0", Label: "9.0.x.x", Display: "9.0.x.x", LineStart: true},
	} {
		got, ok := VMwareESXi.Parse(in)
		if !ok || got.Train != want.Train || got.Label != want.Label || got.Display != want.Display || got.LineStart != want.LineStart {
			t.Errorf("%q: %+v %v", in, got, ok)
		}
	}
	sp := spans(t, VMwareESXi, [3]string{"9.0.x.x", "ESXi-9.0.2.0100-25595025", ""})
	runJudge(t, VMwareESXi, sp, []judgeCase{
		{"9.0.2 before", "9.0.2.0", "25000000", Affected, "9.0.2.0100 (build 25595025)", "same train"},
		{"9.0.1", "9.0.1.0", "24000000", Affected, "9.0.2.0100 (build 25595025)", "older train"},
		{"9.0.3", "9.0.3.0", "25000000", NotAffected, "", "later train"},
		{"9.1", "9.1.0.0", "25000000", NotAffected, "", "another line"},
	})
}

// NetScaler: one fixed build per line, FIPS apart, a line older than every fix is affected (rows start at 0).
func TestNetScaler(t *testing.T) {
	t.Parallel()
	sp := spans(t, NetScaler, [3]string{"0", "14.1-73.37", ""}, [3]string{"0", "13.1-64.23", ""}, [3]string{"0", "13.1-37.247 FIPS", ""})
	runJudge(t, NetScaler, sp, []judgeCase{
		{"14.1 before", "14.1-60.52", "", Affected, "14.1-73.37", "same line"},
		{"14.1 fix", "14.1-73.37", "", NotAffected, "", "boundary"},
		{"13.1 after its fix", "13.1-64.23", "", NotAffected, "", "below the 14.1 build, its own line is fixed"},
		{"13.1 before", "13.1.49.13", "", Affected, "13.1-64.23", "dotted notation"},
		{"NS form", "NS13.1: Build 64.23.nc", "", NotAffected, "", "the build NetScaler shows"},
		{"13.0 end of life", "13.0-92.21", "", Affected, "13.1-64.23", "older line: the nearest later line's fix"},
		{"FIPS", "13.1-37.200 FIPS", "", Affected, "13.1-37.247 FIPS and NDcPP", "FIPS line"},
		{"FIPS fixed", "13.1-37.247 FIPS", "", NotAffected, "", "boundary"},
		{"NDcPP", "13.1-37.246 NDcPP", "", Affected, "13.1-37.247 FIPS and NDcPP", "the NDcPP builds share the FIPS line"},
		{"15.0", "15.0-1.1", "", NotAffected, "", "a later line"},
		{"text", "14.1 build 9", "", NotComparable, "", ""},
	})
}

// NetScaler's newer records write the line as the start and the build alone as the end.
func TestNetScaler_BuildInLine(t *testing.T) {
	t.Parallel()
	sp := spans(t, NetScaler, [3]string{"14.1", "72.61", ""}, [3]string{"13.1", "63.18", ""}, [3]string{"13.1 FIPS and NDcPP", "37.272", ""})
	if sp[0].End.Display != "14.1-72.61" || sp[2].End.Train != "13.1 FIPS and NDcPP" {
		t.Fatalf("%+v %+v", sp[0].End, sp[2].End)
	}
	runJudge(t, NetScaler, sp, []judgeCase{
		{"14.1 before", "14.1-60.52", "", Affected, "14.1-72.61", "same line"},
		{"13.1 after", "13.1-63.18", "", NotAffected, "", "boundary"},
		{"FIPS before", "13.1-37.250 FIPS", "", Affected, "13.1-37.272 FIPS and NDcPP", "FIPS line"},
		{"12.1", "12.1-65.25", "", NotAffected, "", "before every stated line start"},
	})
	if _, ok := NetScaler.Span("0", "72.61", ""); ok {
		t.Error("a build alone without its line was read")
	}
}

// CVE-2026-88779: NetScaler's FIPS/NDcPP fix written without the word ("13.1-37.282" beside "13.1-64.28") reads as the plain 13.1
// line; two ends in one train make that train not comparable, never a fix.
func TestNetScaler_TwoEndsInOneTrain(t *testing.T) {
	t.Parallel()
	sp := spans(t, NetScaler, [3]string{"0", "14.1-47.48", ""}, [3]string{"0", "13.1-64.28", ""}, [3]string{"0", "13.1-37.282", ""})
	if c := Conflicts(sp); !c["13.1"] || c["14.1"] || len(c) != 1 {
		t.Fatalf("conflicts %v", c)
	}
	runJudge(t, NetScaler, sp, []judgeCase{
		{"13.1 plain", "13.1-50.10", "", NotComparable, "", "which line 37.282 belongs to is not said"},
		{"14.1", "14.1-40.1", "", Affected, "14.1-47.48", "its own train decides"},
		{"13.0", "13.0-92.21", "", Affected, "14.1-47.48", "older line: the conflicting train is no fix"},
	})
	// the same end stated twice (CNA and ADP) is no conflict
	if c := Conflicts(spans(t, NetScaler, [3]string{"0", "13.1-64.28", ""}, [3]string{"0", "13.1-64.28", ""})); len(c) != 0 {
		t.Fatalf("a repeated end: %v", c)
	}
}

// The Linux kernel: a stable branch's fix decides for that branch; a branch without one is placed by release order (the mainline fix
// above it); a distribution's kernel is never read.
func TestLinuxKernel(t *testing.T) {
	t.Parallel()
	sp := spans(t, LinuxKernel, [3]string{"6.0", "6.1.149", ""}, [3]string{"6.0", "6.6.30", ""}, [3]string{"6.0", "6.17", ""})
	runJudge(t, LinuxKernel, sp, []judgeCase{
		{"6.1 before", "6.1.100", "", Affected, "6.1.149", "same branch"},
		{"6.1 fixed", "6.1.149", "", NotAffected, "", "boundary"},
		{"6.6 fixed", "6.6.31", "", NotAffected, "", "own branch fixed, though below 6.17"},
		{"6.12 no stable fix", "6.12.5", "", Affected, "6.17", "release order: below the mainline fix"},
		{"6.17", "6.17.1", "", NotAffected, "", "the mainline fix's branch"},
		{"5.15 before introduced", "5.15.100", "", NotAffected, "", "before 6.0"},
		{"distribution build", "6.8.0-45-generic", "", NotComparable, "", "never read"},
	})
}

func TestJava(t *testing.T) {
	t.Parallel()
	sp := spans(t, Java, [3]string{"8", "1.8.0_441", ""}, [3]string{"17", "17.0.14", ""})
	runJudge(t, Java, sp, []judgeCase{
		{"8 before", "1.8.0_431", "", Affected, "1.8.0_441", "same train"},
		{"8u form", "8u441", "", NotAffected, "", "boundary"},
		{"17 before", "17.0.13+11", "", Affected, "17.0.14", "same train"},
		{"21", "21.0.2", "", NotAffected, "", "a later train"},
	})
}

// Every scheme reads only its own notation: a version written another way is not placed, never compared by its numbers.
func TestSchemesRefuseOtherNotations(t *testing.T) {
	t.Parallel()
	for _, name := range Names() {
		s, _ := Lookup(name)
		for _, v := range []string{"", "n/a", "all versions", "5.x, 4.5.x", "R82.10 with Jumbo Hotfix Take 43", "<= 2.90(ABTQ.1)C0", "84c61fe1a75b4255df1e1e7c054c9e6d048da417"} {
			if got, ok := s.Parse(v); ok {
				t.Errorf("%s reads %q as %+v", name, v, got)
			}
		}
	}
}

// Junos: Juniper's record states the fixed release of each line; a release is placed by its R, service release and respin, the X
// releases and Junos OS Evolved are lines apart, and "0 lessThan 21.2R3-S8" covers the older lines (their fix is a later line).
func TestJunos(t *testing.T) {
	t.Parallel()
	sp := spans(t, Junos, [3]string{"0", "21.2R3-S8", ""}, [3]string{"21.4", "21.4R3-S7", ""}, [3]string{"22.2", "22.2R3-S3", ""},
		[3]string{"15.1X49", "15.1X49-D240", ""})
	runJudge(t, Junos, sp, []judgeCase{
		{name: "older service release", version: "21.4R3-S5.4", want: Affected, fixLabel: "21.4R3-S7"},
		{name: "earlier R of the line", version: "21.4R1", want: Affected, fixLabel: "21.4R3-S7"},
		{name: "the fix", version: "21.4R3-S7", want: NotAffected},
		{name: "a respin of the fix", version: "21.4R3-S7.2", want: NotAffected},
		{name: "later service release", version: "22.2R3-S4", want: NotAffected},
		{name: "older line, fix in a later line", version: "15.1R7.9", want: Affected, fixLabel: "21.2R3-S8"},
		{name: "X release line", version: "15.1X49-D200.3", want: Affected, fixLabel: "15.1X49-D240"},
		{name: "not a Junos release", version: "21.4", want: NotComparable},
	})
	if v, ok := Junos.Parse("22.4R3-S2-EVO"); !ok || v.Variant != "EVO" || v.Train != "22.4 EVO" {
		t.Errorf("Junos OS Evolved: %+v %v", v, ok)
	}
}

// A range from a line's start to that same start ("7.2.1" before "7.2.1") is empty: the vendor says no release of the line is
// affected. It reads as a span that ends in the line's own train before its first release, so a release of the line is judged by it
// (not affected), never by release order against another line's fix.
func TestSpan_LineNotAffected(t *testing.T) {
	t.Parallel()
	sp, ok := SynologyDSM.Span("7.2.1", "7.2.1", "")
	if !ok || sp.End == nil || sp.End.LineStart || sp.End.Train != "7.2.1" {
		t.Fatalf("empty line span: %+v %v", sp, ok)
	}
	later, ok := SynologyDSM.Span("7.3.2", "7.3.2-86009-5", "")
	if !ok {
		t.Fatal("7.3.2 span")
	}
	for _, v := range []string{"7.2.1-69057", "7.2.1-69057-5", "7.2.1-69057-13"} {
		installed, ok := SynologyDSM.Installed(v, "")
		if !ok {
			t.Fatal(v)
		}
		if got := Judge(installed, []Span{sp, later}); got.State != NotAffected || got.Fix != nil {
			t.Errorf("%s: %+v", v, got)
		}
	}
	if _, ok := SynologyDSM.Span("7.2.1", "7.2.2", ""); ok {
		t.Error("an end at another line's start reads")
	}
}

// A fixed release stored as its name reads back to the same place, so two fixes of one train can be ordered.
func TestRelease_ReadsTheNamesThisPackageWrites(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		scheme *Scheme
		text   string
		train  string
		build  []int
	}{
		{VMwareESXi, "8.0 U3d (build 24585383)", "8.0 U3", []int{24585383}},
		{VMwareESXi, "ESXi80U3d-24585383", "8.0 U3", []int{24585383}},
		{VMwareESXi, "9.0.2.0100 (build 25595025)", "9.0.2", []int{25595025}},
		{SynologyDSM, "7.2.1-69057 Update 6", "7.2.1", []int{69057, 6}},
		{SynologyDSM, "7.2.1-69057-13", "7.2.1", []int{69057, 13}},
		{Junos, "21.4R3-S5", "21.4", []int{3, 5, 0}},
	} {
		v, ok := c.scheme.Release(c.text)
		if !ok || v.Train != c.train || !slices.Equal(v.Build, c.build) {
			t.Errorf("%s Release(%q) = %+v, %v; want train %q build %v", c.scheme.Name, c.text, v, ok, c.train, c.build)
		}
		if again, ok := c.scheme.Release(v.Display); !ok || !sameTrain(again, v) || !slices.Equal(again.Build, v.Build) {
			t.Errorf("%s Release(%q) does not read its own name back: %+v", c.scheme.Name, v.Display, again)
		}
	}
	for _, text := range []string{"8.0", "7.2.1", "", "8.0 U3d (build 12)"} {
		if v, ok := VMwareESXi.Release(text); ok {
			t.Errorf("Release(%q) = %+v, want no release", text, v)
		}
	}
}

package findings

import (
	"strings"
	"testing"
	"time"
)

// oracleCover is the Oracle CSAF line source's cover of a July 2026 CVE (feeds line-sources.json: listed last_affected, absent
// unaffected_if_assessed, releases numbered for Oracle's own build).
var (
	oracleDay   = time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	oracleCover = LineCover{Source: "oracle-cpu-csaf", Product: "oracle|java se", Ref: "https://www.oracle.com/security-alerts/cpujul2026.html",
		Name: "Oracle", StatedAt: oracleDay, Absent: "unaffected_if_assessed", Builds: []string{"Oracle"}}
)

func oracleRow(line, status, last string, explicit bool) LineRow {
	return LineRow{Source: oracleCover.Source, Product: oracleCover.Product, Line: line, Status: status, LastAffected: last, Explicit: explicit}
}

// javaRow is a Java line as the agents report it: Oracle's Java 8 on Windows ("Java 8 Update 491", 8.0.4910.10), Temurin and others.
func javaRow(display, version string) Software {
	return Software{ID: "java", Display: display, Vendor: "Oracle", Product: "Java SE", Version: version, Source: "agent"}
}

// Oracle's release-line statements (M-13) on the Java versions the agents report. Oracle lists the newest affected release of each line
// it assessed: a version up to it is affected whatever the build; one past it is fixed only for Oracle's own build (another build numbers
// its releases its own way: Temurin's 8u492 is April 2026, Oracle's 8u491), else NVD decides. A line the document assessed and does not
// list is not affected by the convention (a row with explicit false) only from a fresh source whose document is not older than the CVE,
// and never when an NVD row covers the version. A line the document did not assess (Java 7), or a version Vedette cannot read in the
// product's scheme, decides nothing.
func TestLineJudge_OracleJava(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2026-46917"
	rows := []LineRow{oracleRow("8", "affected", "1.8.0_491", true), oracleRow("11", "affected", "11.0.31", true), oracleRow("21", "unaffected", "", false)}
	oracle8 := javaRow("Java 8 Update 491 (64-bit)", "8.0.4910.10")
	patchRows := []LineRow{oracleRow("8", "affected", "1.8.0_511-b33", true)}
	nvd21 := []Affected{{CPE: "cpe:2.3:a:oracle:jdk:21.0.7:*:*:*:*:*:*:*"}}
	for _, tc := range []struct {
		name  string
		sw    Software
		rows  []LineRow
		cover func(*LineCover)
		pub   time.Time
		nvd   []Affected
		want  lineVerdict
		out   outcome
	}{
		{"Oracle 8u491 on Windows: affected", oracle8, rows, nil, oracleDay, nil, lineAffected, outMatch},
		{"Oracle 8u491 as 1.8.0_491-b10", javaRow("Java SE Development Kit 8 Update 491", "1.8.0_491-b10"), rows, nil, oracleDay, nil, lineAffected, outMatch},
		{"Oracle 8u501: fixed", javaRow("Java 8 Update 501 (64-bit)", "8.0.5010.8"), rows, nil, oracleDay, nil, lineFixed, outNotAffected},
		{"Temurin 8u482: affected", javaRow("Eclipse Temurin JDK with Hotspot 8u482-b08 (x64)", "1.8.0_482"), rows, nil, oracleDay, nil, lineAffected, outMatch},
		// Oracle's bundled patch release 8u511b33 is the newest affected (November 2026 CSPU): a later build of 8u511 is fixed, the GA
		// build and a version that states no build are 8u511 itself, so affected
		{"Oracle 8u511 b34 on Windows: fixed", javaRow("Java 8 Update 511 (64-bit)", "8.0.5110.34"), patchRows, nil, oracleDay, nil, lineFixed, outNotAffected},
		{"Oracle 8u511 b34 from java -version: fixed", javaRow("Java SE Development Kit 8 Update 511", "1.8.0_511-b34"), patchRows, nil, oracleDay, nil, lineFixed, outNotAffected},
		{"Oracle 8u511 b33: affected", javaRow("Java 8 Update 511 (64-bit)", "8.0.5110.33"), patchRows, nil, oracleDay, nil, lineAffected, outMatch},
		{"Oracle 8u511 GA b09: affected", javaRow("Java 8 Update 511 (64-bit)", "8.0.5110.9"), patchRows, nil, oracleDay, nil, lineAffected, outMatch},
		{"Oracle 8u511 with no build: affected", javaRow("Java 8 Update 511", "8u511"), patchRows, nil, oracleDay, nil, lineAffected, outMatch},
		{"Oracle 8u521: fixed", javaRow("Java 8 Update 521 (64-bit)", "8.0.5210.8"), patchRows, nil, oracleDay, nil, lineFixed, outNotAffected},
		{"Oracle 8u501 b40: affected", javaRow("Java 8 Update 501 (64-bit)", "8.0.5010.40"), patchRows, nil, oracleDay, nil, lineAffected, outMatch},
		{"Temurin 8u492: past Oracle's number, another build", javaRow("Eclipse Temurin JDK with Hotspot 8u492-b09 (x64)", "1.8.0_492"), rows, nil, oracleDay, nil, lineNone, outNone},
		{"Temurin 21.0.7, NVD names 21.0.7 with an explicit row", javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7"), []LineRow{oracleRow("21", "unaffected", "", true)}, nil, oracleDay, nvd21, lineNone, outNone},
		{"Temurin 21.0.7: assessed, not listed", javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7"), rows, nil, oracleDay, nil, lineUnaffected, outNotAffected},
		{"Temurin 21.0.7, stale source", javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7"), rows, func(c *LineCover) { c.Stale = true }, oracleDay, nil, lineNone, outNone},
		{"Temurin 21.0.7, CVE newer than the document", javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7"), rows, nil, oracleDay.AddDate(0, 0, 3), nil, lineNone, outNone},
		{"Temurin 21.0.7, NVD lists it", javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7"), rows, nil, oracleDay, nvd21, lineNone, outMatch},
		{"Java 7: not assessed", javaRow("Java 7 Update 80", "7.0.800"), rows, nil, oracleDay, nil, lineNone, outNone},
		{"a version the scheme does not read", javaRow("Java 8 Update 491", "1.8.491.10"), rows, nil, oracleDay, nil, lineNone, outNone},
	} {
		c := oracleCover
		if tc.cover != nil {
			tc.cover(&c)
		}
		v := Vuln{CVE: cve, Published: tc.pub, Affected: tc.nvd, NVDAnswered: true, Lines: tc.rows, LineCovers: []LineCover{c}}
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{tc.sw}}
		s := a.Software[0]
		in := swInfoOn(s, a)
		if got := lineJudge(a, s, in, v).verdict; got != tc.want {
			t.Errorf("%s: verdict %d, want %d", tc.name, got, tc.want)
		}
		base := v
		base.Lines, base.LineCovers = nil, nil
		_, without := matchOne(a, s, in, base, false, nil, true, lineNow)
		want := tc.out
		if tc.want == lineNone { // decides nothing: the same answer as without the line source
			want = without
		}
		if _, got := matchOne(a, s, in, v, false, nil, true, lineNow); got != want {
			t.Errorf("%s: outcome %v, want %v", tc.name, got, want)
		}
	}
}

// The texts of Oracle's statements: an affected Java 8 names Oracle's newest affected release of the line and the advisory; a line
// Oracle assessed and does not list is closed with the convention in Oracle's terms (not a support date).
func TestLineJudge_OracleTexts(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2026-46917", Published: oracleDay, NVDAnswered: true, LineCovers: []LineCover{oracleCover},
		Lines: []LineRow{oracleRow("8", "affected", "1.8.0_491", true), oracleRow("21", "unaffected", "", false)}}
	a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{javaRow("Java 8 Update 491 (64-bit)", "8.0.4910.10")}}
	res := MatchAsset(a, []Vuln{v}, nil, lineNow)
	if len(res.New) != 1 || !strings.Contains(res.New[0].Evidence.Summary, "Oracle lists release line 8 as affected by CVE-2026-46917 up to 1.8.0_491 (https://www.oracle.com/security-alerts/cpujul2026.html)") {
		t.Errorf("matches %+v", res)
	}
	a.Software[0] = javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7")
	res = MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, lineNow)
	if len(res.NotAffected) != 1 || !strings.Contains(res.NotAffected[0].Evidence.Summary, "Oracle's advisory assesses release line 21 of Java and does not list it as affected by CVE-2026-46917") {
		t.Errorf("not affected %+v", res.NotAffected)
	}
}

// A CVE in a part of Java only Oracle's own build ships (its installer, the Java plugin, JavaFX in Java 8: the cover is limited to
// Oracle's builds) is decided by Oracle's rows for Oracle's Java only. For Temurin, which ships no such part, Oracle's "affected up to
// 21.0.12" decides nothing: the answer is the one without the line source.
func TestLineJudge_OracleOwnBuildPart(t *testing.T) {
	t.Parallel()
	c := oracleCover
	c.OnlyBuilds = []string{"Oracle"}
	v := Vuln{CVE: "CVE-2026-62574", Published: oracleDay, NVDAnswered: true, LineCovers: []LineCover{c},
		Lines: []LineRow{oracleRow("8", "affected", "1.8.0_501", true), oracleRow("21", "affected", "21.0.12", true)}}
	for _, tc := range []struct {
		sw   Software
		want lineVerdict
	}{
		{javaRow("Java 8 Update 491 (64-bit)", "8.0.4910.10"), lineAffected},
		{javaRow("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7"), lineNone},
		{javaRow("Eclipse Temurin JDK with Hotspot 8u482-b08 (x64)", "1.8.0_482"), lineNone},
	} {
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{tc.sw}}
		s := a.Software[0]
		in := swInfoOn(s, a)
		if got := lineJudge(a, s, in, v).verdict; got != tc.want {
			t.Errorf("%s: verdict %d, want %d", tc.sw.Display, got, tc.want)
		}
		res := MatchAsset(a, []Vuln{v}, nil, lineNow)
		if open := len(res.New) == 1; open != (tc.want == lineAffected) {
			t.Errorf("%s: new findings %+v", tc.sw.Display, res.New)
		}
	}
}

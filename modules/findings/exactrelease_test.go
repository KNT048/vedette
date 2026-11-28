package findings

import (
	"testing"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// A vendor's rows that list exact affected releases (one release per row, no range) say nothing about a release they do not list,
// unless the record states that every unlisted version is unaffected (defaultStatus "unaffected" from the vendor's own CNA). Two
// readings of such a list are common and the record does not say which one it uses: "these exact releases" and "the newest affected
// release of each train" (every earlier release of the train is affected too). A release is closed only where both readings agree.

// trainSpans reads rows of a vendor that numbers its releases major.minor.patch (a train is major.minor) as spans: each row is
// {start, endExcl, endIncl}; an exact release is {v, "", v}.
func trainSpans(t *testing.T, rows ...[3]string) []versionscheme.Span {
	t.Helper()
	var out []versionscheme.Span
	for _, r := range rows {
		sp, ok := versionscheme.LinuxKernel.Span(r[0], r[1], r[2])
		if !ok {
			t.Fatalf("span %v does not read", r)
		}
		out = append(out, sp)
	}
	return out
}

func TestTrainCleared_ExactReleases(t *testing.T) {
	t.Parallel()
	exact := [][3]string{{"3.0.12", "", "3.0.12"}, {"4.0.8", "", "4.0.8"}}
	twoInTrain := [][3]string{{"3.0.5", "", "3.0.5"}, {"3.0.12", "", "3.0.12"}}
	rangeAndExact := [][3]string{{"3.0.0", "3.0.5", ""}, {"3.0.12", "", "3.0.12"}}
	for _, tc := range []struct {
		name      string
		rows      [][3]string
		told      bool // the record states every unlisted version unaffected
		installed string
		want      bool
	}{
		{"exact list, no default: below a listed release stays open", exact, false, "3.0.7", false},
		{"exact list, no default: above a listed release stays open", exact, false, "3.0.13", false},
		{"exact list, no default: other train stays open", exact, false, "4.0.2", false},
		{"exact list, unaffected default: below the only listed release of the train stays open", exact, true, "3.0.7", false},
		{"exact list, unaffected default: above every listed release of the train closes", exact, true, "3.0.13", true},
		{"two releases in one train, unaffected default: an exact list, the gap closes", twoInTrain, true, "3.0.7", true},
		{"two releases in one train, no default: the gap stays open", twoInTrain, false, "3.0.7", false},
		{"a stated fixed release closes past it", [][3]string{{"3.0.0", "3.0.10", ""}}, false, "3.0.11", true},
		{"a stated fixed release, an exact release above: stays open", rangeAndExact, false, "3.0.7", false},
		{"a stated fixed release, an exact release above, unaffected default: closes", rangeAndExact, true, "3.0.7", true},
	} {
		spans := trainSpans(t, tc.rows...)
		told := make([]bool, len(spans))
		for i := range told {
			told[i] = tc.told
		}
		installed, ok := versionscheme.LinuxKernel.Parse(tc.installed)
		if !ok {
			t.Fatalf("%s: %s does not read", tc.name, tc.installed)
		}
		if got := trainCleared(installed, spans, told); got != tc.want {
			t.Errorf("%s: cleared %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The same class through the matcher: a CVE record of a product with a version scheme whose rows list one exact release per train.
func TestSchemeJudge_ExactReleasesDoNotClose(t *testing.T) {
	t.Parallel()
	sw := Software{ID: "rt", Display: "Runtime 21.0.7", Vendor: "Oracle", Product: "Java SE", Version: "21.0.7", Source: "agent"}
	p, ok := productid.ResolveStored(sw.Vendor, sw.Product, sw.Display, sw.CPE)
	if !ok || p.Scheme == "" {
		t.Fatal("the test line resolves to no product with a scheme")
	}
	rows := func(told bool, spans ...[3]string) []SchemedRange {
		out := schemedRows(t, p.Scheme, p.Key, spans...)
		for i := range out {
			out[i].Complete = told
		}
		return out
	}
	exact := [][3]string{{"17.0.20", "", "17.0.20"}, {"21.0.12", "", "21.0.12"}}
	for _, tc := range []struct {
		name      string
		schemed   []SchemedRange
		installed string
		closes    bool
	}{
		{"no default, below the listed release", rows(false, exact...), "21.0.7", false},
		{"no default, past the listed release", rows(false, exact...), "21.0.13", false},
		{"unaffected default, below the only listed release of the train", rows(true, exact...), "21.0.7", false},
		{"unaffected default, past every listed release of the train", rows(true, exact...), "21.0.13", true},
		{"a stated fixed release", rows(false, [3]string{"21.0.0", "21.0.10", ""}), "21.0.11", true},
	} {
		s := sw
		s.Version, s.Display = tc.installed, "Runtime "+tc.installed
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
		v := Vuln{CVE: "CVE-2099-0101", NVDAnswered: true, Origin: RangeCNA, RangesFrom: RangesCVEOrgPartial, Schemed: tc.schemed}
		in := swInfoOn(s, a)
		r, ok := schemeJudge(a, s, in, v)
		closed := ok && r.verdict.State == versionscheme.NotAffected
		if closed != tc.closes {
			t.Errorf("%s: scheme closes %v, want %v (%+v)", tc.name, closed, tc.closes, r.verdict)
		}
		if _, out := matchOne(a, s, in, v, false, nil, true, lineNow); (out == outNotAffected) != tc.closes {
			t.Errorf("%s: outcome %v", tc.name, out)
		}
	}
	// a listed release is affected whatever the default
	s := sw
	s.Version = "21.0.12"
	a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
	v := Vuln{CVE: "CVE-2099-0101", NVDAnswered: true, Origin: RangeCNA, Schemed: rows(false, exact...)}
	if r, ok := schemeJudge(a, s, swInfoOn(s, a), v); !ok || r.verdict.State != versionscheme.Affected {
		t.Errorf("listed release: %+v %v", r.verdict, ok)
	}
}

// An advisory's list of exact affected releases (a CSAF known_affected product version) decides "affected" for a listed release and
// nothing for another release of the same train.
func TestJudgeTextRanges_ExactReleases(t *testing.T) {
	t.Parallel()
	rs := []textRange{{start: "21.0.12", end: "21.0.12", endIncl: true, quote: "known_affected: Runtime 21.0.12"}}
	for _, tc := range []struct {
		version, want string
		ok            bool
	}{
		{"21.0.12", VerdictAffected, true},
		{"21.0.7", "", false},
		{"21.0.13", "", false},
	} {
		got, _, ok := judgeTextRanges(rs, tc.version, "", versionscheme.Java)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: %q %v, want %q %v", tc.version, got, ok, tc.want, tc.ok)
		}
	}
	// a range with a stated end still decides past it
	rs = []textRange{{start: "21.0.0", end: "21.0.10", quote: "vers:generic/>=21.0.0|<21.0.10"}}
	if got, _, ok := judgeTextRanges(rs, "21.0.11", "", versionscheme.Java); got != VerdictNotAffected || !ok {
		t.Errorf("past a stated end: %q %v", got, ok)
	}
}

// NVD's exact releases of a train read as "every release up to it" open the earlier releases and close nothing past them.
func TestSchemeJudge_NVDTrainListClosesNothing(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2099-0102", NVDAnswered: true, Affected: []Affected{{CPE: "cpe:2.3:a:oracle:jdk:21.0.12:*:*:*:*:*:*:*"}}}
	for _, tc := range []struct {
		installed string
		want      versionscheme.State
		ok        bool
	}{
		{"21.0.7", versionscheme.Affected, true},
		{"21.0.13", versionscheme.NotComparable, false},
	} {
		s := Software{ID: "rt", Display: "Runtime " + tc.installed, Vendor: "Oracle", Product: "Java SE", Version: tc.installed, Source: "agent"}
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
		r, ok := schemeJudge(a, s, swInfoOn(s, a), v)
		if ok != tc.ok || ok && r.verdict.State != tc.want {
			t.Errorf("%s: %+v %v, want %v %v", tc.installed, r.verdict, ok, tc.want, tc.ok)
		}
	}
}

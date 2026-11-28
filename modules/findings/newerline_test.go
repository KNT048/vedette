package findings

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// A vendor's own list of exact releases on two or more lines, with no range, names no line newer than every one of them: the flaw was
// fixed before that line branched. A release on such a line is not affected, with a proof scoped to the product and its line; never
// for one listed line (the vendor may have assessed only that train), another numbering, a third party's list, a record with ranges,
// a line between listed lines, and never by itself for an exploited CVE, which stays undecided as newer_line_exploited.
// Synthetic products only (Examplecorp Gizmo, Acme Runtime).
func TestMatch_NewerThanEveryListedLine(t *testing.T) {
	t.Parallel()
	gizmo := func(third bool, vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:a:examplecorp:gizmo:" + v + ":*:*:*:*:*:*:*", VendorCNA: !third})
		}
		return out
	}
	runtime := func(cpes ...string) []Affected {
		var out []Affected
		for _, c := range cpes {
			out = append(out, Affected{CPE: "cpe:2.3:a:acme:runtime:" + c + ":*:*:*:*:*:*", VendorCNA: true})
		}
		return out
	}
	record := func(vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:*:acme:runtime:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: v, EndIncl: v}, VendorCNA: true})
		}
		return out
	}
	besideNVD := func(aff []Affected) []Affected {
		for i := range aff {
			aff[i].AffectedOnly = true
		}
		return aff
	}
	ranged := append(gizmo(false, "4.2.9", "5.1.3"), Affected{CPE: "cpe:2.3:a:examplecorp:gizmo:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "5.2.0", EndExcl: "5.2.4"}, VendorCNA: true})
	gizmoRecord := func(vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:*:examplecorp:gizmo:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: v, EndIncl: v}, VendorCNA: true})
		}
		return out
	}
	for _, tc := range []struct {
		name, product, display, ver string
		aff                         []Affected
		from                        string
		exploited                   bool
		want                        string // "closed", "open" (no undecided reason checked), or the undecided reason
		line                        string
	}{
		{"a line newer than both listed lines", "Gizmo", "", "6.0.1", gizmo(false, "4.2.9", "5.1.3"), "", false, "closed", "6.0"},
		{"a newer minor line of the newest listed major", "Gizmo", "", "5.2.1", gizmo(false, "4.2.9", "5.1.3"), "", false, "closed", "5.2"},
		{"exploited: never by itself", "Gizmo", "", "6.0.1", gizmo(false, "4.2.9", "5.1.3"), "", true, UndecidedNewerLineExploited, ""},
		{"one listed line", "Gizmo", "", "6.0.1", gizmo(false, "4.2.7", "4.2.9"), "", false, UndecidedExactOnly, ""},
		{"a line between listed lines", "Gizmo", "", "5.0.1", gizmo(false, "4.2.9", "5.1.3"), "", false, UndecidedExactOnly, ""},
		{"another count of numbers than the list's", "Gizmo", "", "6.0.1.2", gizmo(false, "4.2.9", "5.1.3"), "", false, UndecidedExactOnly, ""},
		{"a third party's list", "Gizmo", "", "6.0.1", gizmo(true, "4.2.9", "5.1.3"), "", false, UndecidedThirdPartyBuild, ""},
		{"the record also gives a range: its rows decide as before", "Gizmo", "", "6.0.1", ranged, "", false, "ranges", ""},
		{"the record's rows beside NVD's list the installation's line", "Gizmo", "", "6.0.1",
			append(gizmo(false, "4.2.9", "5.1.3"), besideNVD(gizmoRecord("6.0.4"))...), "", false, "open", ""},
		{"the record's update form, two lines", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5", record("3u90", "2u50"), RangesCVEOrgPartial, false, "closed", "4 update"},
		{"NVD's numbering is not the name's", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5", runtime("1.3.0:update90", "1.2.0:update50"), "", false, UndecidedExactOnly, ""},
	} {
		vendor := "Examplecorp"
		if tc.product == "Runtime" {
			vendor = "Acme"
		}
		s := Software{ID: "w", Display: cmpOr(tc.display, tc.product+" "+tc.ver), Vendor: vendor, Product: tc.product, Version: tc.ver, Source: "agent"}
		v := Vuln{CVE: "CVE-2099-0203", Name: "flaw", DateAdded: uncNew, Published: uncNew, NVDAnswered: true, Affected: slices.Clone(tc.aff), RangesFrom: tc.from}
		if tc.exploited {
			v.Vendor, v.Product = vendor, tc.product
			s.KevKeys = []string{productid.NormKey(vendor, tc.product)}
		}
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
		in := swInfoOn(s, a)
		in.shadow = true
		m, out := matchOne(a, s, in, v, true, keyIDs(v), true, uncNow)
		if tc.want == "ranges" {
			if _, ok := afterLastListedLine(in, v, keyIDs(v)); ok {
				t.Errorf("%s: read as a list of exact releases", tc.name)
			}
			if m.gate != nil && slices.ContainsFunc(m.gate.proofs, func(p Proof) bool { return p.Kind == ProofAfterLastListedLine }) {
				t.Errorf("%s: a newer-line proof", tc.name)
			}
			continue
		}
		if (out == outNotAffected) != (tc.want == "closed") {
			t.Errorf("%s (%s): outcome %v, want %s", tc.name, tc.ver, out, tc.want)
			continue
		}
		if tc.want != "closed" {
			if tc.want == "open" {
				continue
			}
			res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, uncNow)
			got := "none"
			if len(res.Unchecked) == 1 && res.Unchecked[0].undecided != nil {
				got = res.Unchecked[0].undecided.Reason
			}
			if got != tc.want {
				t.Errorf("%s: undecided %s, want %s", tc.name, got, tc.want)
			}
			continue
		}
		if !strings.Contains(m.Evidence.Summary, "newer than every line") {
			t.Errorf("%s: note %q", tc.name, m.Evidence.Summary)
		}
		if m.gate == nil {
			t.Fatalf("%s: no gate shadow", tc.name)
		}
		var proof *Proof
		for i, p := range m.gate.proofs {
			if p.Kind == ProofAfterLastListedLine {
				proof = &m.gate.proofs[i]
			}
		}
		if proof == nil {
			t.Errorf("%s: no newer-line proof in %+v", tc.name, m.gate.proofs)
			continue
		}
		if vs := proof.Scope.Versions; !vs.Every || !slices.Equal(vs.Lines, []string{tc.line}) || len(vs.Ranges)+len(vs.Exact) != 0 {
			t.Errorf("%s: proof scope %+v, want every version of line %s", tc.name, vs, tc.line)
		}
		if would, cause, _ := gateWould(a, s, in, v, []*gateShadow{m.gate}); would != GateNotAffected.String() {
			t.Errorf("%s: the gate would answer %s (%s), want not_affected", tc.name, would, cause)
		}
		v.Vendor, v.Product = vendor, tc.product // the same proof for an exploited CVE: the gate does not close it
		if would, cause, _ := gateWould(a, s, in, v, []*gateShadow{m.gate}); would == GateNotAffected.String() || cause != CauseExploitedKind {
			t.Errorf("%s: exploited, the gate would answer %s (%s), want undecided (%s)", tc.name, would, cause, CauseExploitedKind)
		}
	}
}

// The gate accepts a newer-line proof only as every version of one line, from a CVE record or NVD's configuration, and never for an
// exploited CVE.
func TestGate_AfterLastListedLine(t *testing.T) {
	t.Parallel()
	shapes := []struct {
		name string
		vs   VersionSet
		ok   bool
	}{
		{"every version of one line", VersionSet{Every: true, Lines: []string{"2"}}, true},
		{"every version, no line", VersionSet{Every: true}, false},
		{"two lines", VersionSet{Every: true, Lines: []string{"2", "3"}}, false},
		{"a span of the line", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.0"}}}, false},
		{"an exact version of the line", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Exact: []string{"2.5"}}, false},
		{"all but the listed", VersionSet{Every: true, Lines: []string{"2"}, AllExceptListed: true, Exact: []string{"2.5"}}, false},
	}
	formats := []Format{FormatCVE5, FormatNVDCPE, FormatOSV, FormatCSAF, FormatOpenVEX, FormatDistroTracker, FormatMSRelease, FormatLineSource, FormatPerson, 0}
	r := &matrixRun{t: t}
	for _, sh := range shapes {
		for _, f := range formats {
			for _, exploited := range []bool{false, true} {
				for j := range mShapes {
					p := Proof{Kind: ProofAfterLastListedLine, CVE: mCVE, Src: ProofSource{Format: f, Ref: "main"}, Says: SaysNotAffected, Producer: "matrix",
						Scope: Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: sh.vs, Platform: PlatformSet{Any: true}}}
					allowed := sh.ok && (f == FormatCVE5 || f == FormatNVDCPE) && !exploited
					cont := oVersion[6][j] // every version of line 2
					if !sh.ok {
						cont = tN
					}
					r.check(mCase{name: func() string { return "newer line: " + sh.name + " " + f.String() + " " + mShapes[j].raw }, in: mInstall(0, j),
						ev: []Proof{p}, exploited: exploited, want: oracle(mkFixed, cont, allowed, false, false, false)})
				}
			}
		}
	}
	if r.soft != 0 {
		t.Errorf("soft count %d: the gate is stricter than the table for the newer-line kind", r.soft)
	}
}

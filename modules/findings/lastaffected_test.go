package findings

import (
	"slices"
	"strings"
	"testing"
)

// A vendor's list of exact affected releases with no range is read as OSV's last_affected: each listed release is the last affected
// release of its own line. A release of the same line strictly later than every listed one is not affected, with a proof scoped to
// the product, the line and the releases above the newest listed one; a release at or below it, on a line the list does not name, or
// read in another numbering than the list's, stays as it was. Synthetic products only (Examplecorp Gizmo, Acme Runtime).
func TestMatch_ExactListIsTheLastAffectedReleaseOfItsLine(t *testing.T) {
	t.Parallel()
	gizmo := func(vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:a:examplecorp:gizmo:" + v + ":*:*:*:*:*:*:*", VendorCNA: true})
		}
		return out
	}
	record := func(vs ...string) []Affected { // the vendor's CVE record: one version each, no lessThan
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:*:examplecorp:gizmo:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: v, EndIncl: v}, VendorCNA: true})
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
	runtimeRecord := func(vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:*:acme:runtime:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: v, EndIncl: v}, VendorCNA: true})
		}
		return out
	}
	besideNVD := func(aff []Affected) []Affected { // the record's rows read beside NVD's: they only ever say affected
		for i := range aff {
			aff[i].AffectedOnly = true
		}
		return aff
	}
	thirdParty := gizmo("4.2.7", "4.2.9")
	for i := range thirdParty {
		thirdParty[i].VendorCNA = false
	}
	ranged := append(gizmo("4.2.9"), Affected{CPE: "cpe:2.3:a:examplecorp:gizmo:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "5.0.0", EndExcl: "5.1.4"}, VendorCNA: true})
	for _, tc := range []struct {
		name, product, display, ver string
		aff                         []Affected
		from                        string // Vuln.RangesFrom
		exploited                   bool
		closes                      bool
		line, last                  string // the proof's line and last affected release, when it closes
	}{
		{"past the newest listed release of its line", "Gizmo", "", "4.2.10", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, true, "4.2", "4.2.9"},
		{"past it, on an exploited list", "Gizmo", "", "4.2.10", gizmo("4.2.7", "4.2.9", "5.1.3"), "", true, true, "4.2", "4.2.9"},
		{"past the one listed release of its line", "Gizmo", "", "5.1.4", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, true, "5.1", "5.1.3"},
		{"at the newest listed release", "Gizmo", "", "4.2.9", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, false, "", ""},
		{"between two listed releases of its line", "Gizmo", "", "4.2.8", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, false, "", ""},
		{"a line the list does not name, between listed lines", "Gizmo", "", "4.3.1", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, false, "", ""},
		{"a line newer than every listed one", "Gizmo", "", "6.0.1", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, false, "", ""},
		{"a line older than every listed one", "Gizmo", "", "3.9.9", gizmo("4.2.7", "4.2.9", "5.1.3"), "", false, false, "", ""},
		{"a third party's list of the builds it tested", "Gizmo", "", "4.2.10", thirdParty, "", false, false, "", ""},
		{"the record also gives a range", "Gizmo", "", "4.2.10", ranged, "", false, false, "", ""},
		{"a row that names the line, not a release in it", "Gizmo", "", "4.2.10", gizmo("4.2", "4.2.9"), "", false, false, "", ""},
		{"a row at the line's first release", "Gizmo", "", "4.2.10", gizmo("4.2.0", "4.2.9"), "", false, false, "", ""},
		{"a row with a build the forms do not read", "Gizmo", "", "4.2.10", gizmo("4.2.9", "4.2.8-1"), "", false, false, "", ""},
		{"the vendor's CVE record alone, past its release", "Gizmo", "", "4.2.10", record("4.2.9", "5.1.3"), RangesCVEOrgPartial, false, true, "4.2", "4.2.9"},
		{"the vendor's CVE record alone, a line it does not list", "Gizmo", "", "4.4.0", record("4.2.9", "5.1.3"), RangesCVEOrgPartial, false, false, "", ""},
		// a release and its update, as a name states them ("Acme Runtime 4 Update 30") beside a version that does not ("4.0.300.5")
		{"the record's update form, past it", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5", runtimeRecord("4u25", "3u90"), RangesCVEOrgPartial, false, true, "4 update", "4u25"},
		{"the record's update form, at it", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5", runtimeRecord("4u30"), RangesCVEOrgPartial, false, false, "", ""},
		{"the record's update form, the name states no update", "Runtime", "Acme Runtime 4 (64-bit)", "4.0.300.5", runtimeRecord("4u25"), RangesCVEOrgPartial, false, false, "", ""},
		{"NVD's numbering is not the name's", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5", runtime("1.4.0:update25"), "", false, false, "", ""},
		{"the record places it, NVD's numbering does not", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5",
			append(runtime("1.4.0:update25"), besideNVD(runtimeRecord("4u25"))...), "", false, false, "", ""},
		{"NVD's list in the name's numbering, the record's rows beside it agree", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5",
			append(runtime("4:update25"), besideNVD(runtimeRecord("4u25"))...), "", false, true, "4 update", "4u25"},
		{"NVD's list in the name's numbering, the record's rows beside it list a later update", "Runtime", "Acme Runtime 4 Update 30 (64-bit)", "4.0.300.5",
			append(runtime("4:update25"), besideNVD(runtimeRecord("4u31"))...), "", false, false, "", ""},
		{"NVD's update component in the name's numbering", "Runtime", "Acme Runtime 1.4.0 Update 30", "1.4.0.30", runtime("1.4.0:update25", "1.4.0:-"), "", false, true, "1.4 update", "1.4.0u25"},
		{"NVD's update ANY beside its updates", "Runtime", "Acme Runtime 1.4.0 Update 30", "1.4.0.30", runtime("1.4.0:update25", "1.4.0:*"), "", false, false, "", ""},
		{"NVD's update with a build the forms do not read", "Runtime", "Acme Runtime 1.4.0 Update 30", "1.4.0.30", runtime("1.4.0:update25_b50"), "", false, false, "", ""},
	} {
		vendor := "Examplecorp"
		if tc.product == "Runtime" {
			vendor = "Acme"
		}
		s := Software{ID: "w", Display: cmpOr(tc.display, tc.product+" "+tc.ver), Vendor: vendor, Product: tc.product, Version: tc.ver, Source: "agent"}
		v := Vuln{CVE: "CVE-2099-0201", Name: "flaw", DateAdded: uncNew, Published: uncNew, NVDAnswered: true, Affected: slices.Clone(tc.aff), RangesFrom: tc.from}
		if tc.exploited {
			v.Vendor, v.Product = vendor, tc.product
			s.KevKeys = []string{strings.ToLower(vendor) + "|" + strings.ToLower(tc.product)}
		}
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
		in := swInfoOn(s, a)
		in.shadow = true
		m, out := matchOne(a, s, in, v, true, keyIDs(v), true, uncNow)
		if (out == outNotAffected) != tc.closes {
			t.Errorf("%s (%s): outcome %v, closes want %v", tc.name, tc.ver, out, tc.closes)
			continue
		}
		if !tc.closes {
			if m.gate != nil && slices.ContainsFunc(m.gate.proofs, func(p Proof) bool { return p.Kind == ProofAfterLastAffected }) {
				t.Errorf("%s: a last-affected proof for a pair it does not close", tc.name)
			}
			continue
		}
		if !strings.Contains(m.Evidence.Summary, "last affected release") || !strings.Contains(m.Evidence.Summary, tc.last) {
			t.Errorf("%s: note %q, want the last affected release %s", tc.name, m.Evidence.Summary, tc.last)
		}
		if m.gate == nil {
			t.Fatalf("%s: no gate shadow", tc.name)
		}
		var proof *Proof
		for i, p := range m.gate.proofs {
			if p.Kind == ProofAfterLastAffected {
				proof = &m.gate.proofs[i]
			}
		}
		if proof == nil {
			t.Errorf("%s: no last-affected proof in %+v", tc.name, m.gate.proofs)
			continue
		}
		vs := proof.Scope.Versions
		if !slices.Equal(vs.Lines, []string{tc.line}) || len(vs.Ranges) != 1 || vs.Ranges[0] != (Span{From: tc.last, FromExcl: true}) || proof.Says != SaysNotAffected {
			t.Errorf("%s: proof scope %+v, want line %s after %s", tc.name, vs, tc.line, tc.last)
		}
		if would, cause, _ := gateWould(a, s, in, v, []*gateShadow{m.gate}); would != GateNotAffected.String() {
			t.Errorf("%s: the gate would answer %s (%s), want not_affected", tc.name, would, cause)
		}
	}
}

// The gate accepts an after-last-affected proof only in its own shape (one line, one span above an excluded release, nothing else),
// from a format that lists affected releases (a CVE record, NVD's configuration, OSV), for exploited CVEs too, and only for an
// installation whose stated line is that line and whose version is above the release.
func TestGate_AfterLastAffected(t *testing.T) {
	t.Parallel()
	good := VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.5", FromExcl: true}}}
	// oLast: does good contain shape j (mShapes): line 2 and above 2.5
	//                0.9 1.0 1.5 2.0 2.5 2.9.9 3.0 4.1  ""  abc  deb nolin
	oLast := [12]tv{tN, tN, tN, tN, tN, tY, tN, tN, tU, tU, tU, tU}
	shapes := []struct {
		name string
		vs   VersionSet
		ok   bool
	}{
		{"one line, above a release", good, true},
		{"no line", VersionSet{Scheme: SchemeGeneric, Ranges: []Span{{From: "2.5", FromExcl: true}}}, false},
		{"two lines", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2", "3"}, Ranges: []Span{{From: "2.5", FromExcl: true}}}, false},
		{"the release included", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.5"}}}, false},
		{"an end", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.5", FromExcl: true, To: "2.9"}}}, false},
		{"two spans", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.5", FromExcl: true}, {From: "2.7", FromExcl: true}}}, false},
		{"an exact version beside it", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.5", FromExcl: true}}, Exact: []string{"2.9.9"}}, false},
		{"every version of the line", VersionSet{Every: true, Lines: []string{"2"}}, false},
		{"all but the listed", VersionSet{Scheme: SchemeGeneric, Lines: []string{"2"}, Ranges: []Span{{From: "2.5", FromExcl: true}}, AllExceptListed: true}, false},
	}
	formats := []Format{FormatCVE5, FormatNVDCPE, FormatOSV, FormatCSAF, FormatOpenVEX, FormatDistroTracker, FormatMSRelease, FormatLineSource, FormatPerson, 0}
	r := &matrixRun{t: t}
	for _, sh := range shapes {
		for _, f := range formats {
			for _, exploited := range []bool{false, true} {
				for j := range mShapes {
					p := Proof{Kind: ProofAfterLastAffected, CVE: mCVE, Src: ProofSource{Format: f, Ref: "main"}, Says: SaysNotAffected, Producer: "matrix",
						Scope: Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: sh.vs, Platform: PlatformSet{Any: true}}}
					allowed := sh.ok && (f == FormatCVE5 || f == FormatNVDCPE || f == FormatOSV)
					cont := oLast[j]
					if !sh.ok {
						cont = tN // never closes: the oracle needs no containment table for a shape the kind cannot have
					}
					r.check(mCase{name: func() string { return "after last affected: " + sh.name + " " + f.String() + " " + mShapes[j].raw }, in: mInstall(0, j),
						ev: []Proof{p}, exploited: exploited, want: oracle(mkFixed, cont, allowed, false, false, false)})
				}
			}
		}
	}
	if r.soft != 0 {
		t.Errorf("soft count %d: the gate is stricter than the table for the after-last-affected kind", r.soft)
	}
}

// The ranges producer reads a record row that is one release as an affected statement only: a later release is not affected only
// through the after-last-affected proof of its own line, never through a fix with no line (a later line, another product's
// numbering).
func TestGateShadow_ExactRowIsNoFixOnItsOwn(t *testing.T) {
	t.Parallel()
	rows := []Affected{{CPE: "cpe:2.3:*:examplecorp:gizmo:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "4.2.9", EndIncl: "4.2.9"}, VendorCNA: true}}
	for _, c := range []struct {
		ver, would string
	}{{"4.2.10", "not_affected"}, {"6.0.1", "undecided"}, {"4.3.0", "undecided"}} {
		s := Software{ID: "w", Display: "Gizmo " + c.ver, Vendor: "Examplecorp", Product: "Gizmo", Version: c.ver, Source: "agent"}
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
		in := swInfoOn(s, a)
		in.shadow = true
		v := Vuln{CVE: "CVE-2099-0202", NVDAnswered: true, Affected: rows, RangesFrom: RangesCVEOrgPartial}
		g := rangeProofs(in, v, keyIDs(v))
		if would, cause, _ := gateWould(a, s, in, v, []*gateShadow{g}); would != c.would {
			t.Errorf("%s: gate %s (%s), want %s", c.ver, would, cause, c.would)
		}
	}
}

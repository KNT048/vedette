package findings

import (
	"strings"
	"testing"
)

// The record-shape rules, each on a product made up for the test: the rules read the shape of the rows, never the product they name.
// Every rule has its guard beside it, a row that could still say "affected" and must keep doing so.

func shapeRow(product, ver string, keyed bool) Software {
	s := Software{ID: "s-" + product, Display: "Example " + product, Vendor: "Example", Product: product, Version: ver, Source: "agent"}
	if keyed {
		s.KevKeys = []string{"example|" + strings.ToLower(product)}
	}
	return s
}

func shapeDecide(t *testing.T, s Software, v Vuln) (Tri, proofKind) {
	t.Helper()
	got, _, _, proof := decide(newSWInfo(s, ""), v, keyIDs(v))
	return got, proof
}

// An application row whose version is NA ("-") beside rows that version the same product is about no version: CPE name matching makes
// NA and a value DISJOINT, so the rows that compare decide. Alone, NA may name a product whose release is in its name, so it stays
// undecided; on an operating system or firmware it is never read as apart.
func TestRecordShape_NAVersionBesideVersionedRows(t *testing.T) {
	t.Parallel()
	na := Affected{CPE: "cpe:2.3:a:example:viewer:-:*:*:*:*:*:*:*"}
	upTo := Affected{CPE: "cpe:2.3:a:example:viewer:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "152.0.4191.52"}}
	fwNA := Affected{CPE: "cpe:2.3:o:example:viewer_firmware:-:*:*:*:*:*:*:*"}
	fwUpTo := Affected{CPE: "cpe:2.3:o:example:viewer_firmware:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.0"}}
	for _, tc := range []struct {
		name, product, ver string
		aff                []Affected
		want               Tri
		proof              proofKind
	}{
		{"NA beside a range the version is past", "Viewer", "158.0.4370.45", []Affected{na, upTo}, No, proofRange},
		{"inside the range: affected", "Viewer", "150.0.1", []Affected{na, upTo}, Yes, proofNone},
		{"NA alone stays undecided", "Viewer", "158.0.4370.45", []Affected{na}, Unknown, proofNone},
		{"an unknown version stays undecided", "Viewer", "latest", []Affected{na, upTo}, Unknown, proofNone},
		{"firmware NA is never apart", "Viewer Firmware", "3.0", []Affected{fwNA, fwUpTo}, Unknown, proofNone},
	} {
		v := uncVuln("CVE-2026-90001", "Example", tc.product, uncNew, tc.aff...)
		if got, proof := shapeDecide(t, shapeRow(tc.product, tc.ver, true), v); got != tc.want || proof != tc.proof {
			t.Errorf("%s: %v (proof %d), want %v (proof %d)", tc.name, got, proof, tc.want, tc.proof)
		}
	}

	// As a device reads it through NVD's list only: the NA row beside the range no longer leaves a question; NA alone still does.
	for _, tc := range []struct {
		aff  []Affected
		want int
	}{{[]Affected{na, upTo}, 0}, {[]Affected{na}, 1}} {
		a := Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{shapeRow("Viewer", "158.0.4370.45", false)}}
		res := MatchAsset(a, []Vuln{uncVuln("CVE-2026-90002", "Example", "Viewer", uncNew, tc.aff...)}, nil, uncNow)
		if len(res.New) != 0 || len(res.Unchecked) != tc.want {
			t.Errorf("%d rows: new %+v, unchecked %+v, want %d unchecked", len(tc.aff), res.New, res.Unchecked, tc.want)
		}
	}
}

// NVD's legacy "and earlier": a bare row of the product (every version, nothing pinned) beside a row of the same product that ends and
// has no start ("5.14 and earlier") is a marker, not "every version". A bare row beside a range that starts somewhere still says every
// version, and so does a bare row alone.
func TestRecordShape_EarlierMarker(t *testing.T) {
	t.Parallel()
	const cpe = "cpe:2.3:a:example:fetch_tool:*:*:*:*:*:*:*:*"
	bare := Affected{CPE: cpe}
	upTo := Affected{CPE: cpe, Range: VersionRange{EndIncl: "5.14"}}
	later := Affected{CPE: cpe, Range: VersionRange{StartIncl: "3.0", EndExcl: "3.5"}}
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      Tri
		proof     proofKind
	}{
		{"bare beside an end the version is past", "6.43.18", []Affected{bare, upTo}, No, proofRange},
		{"bare beside an end the version is inside", "5.0", []Affected{bare, upTo}, Yes, proofNone},
		{"bare beside a range that starts", "2.0", []Affected{bare, later}, Yes, proofNone},
		{"bare alone", "6.43.18", []Affected{bare}, Yes, proofNone},
	} {
		v := uncVuln("CVE-2026-90011", "Example", "Fetch Tool", uncNew, tc.aff...)
		if got, proof := shapeDecide(t, shapeRow("Fetch Tool", tc.ver, true), v); got != tc.want || proof != tc.proof {
			t.Errorf("%s: %v (proof %d), want %v (proof %d)", tc.name, got, proof, tc.want, tc.proof)
		}
	}
}

// An exact row named by a word ("preview_release") is no numbered release: beside a fix the version is past, the rows that compare
// decide. Alone, or beside rows the version is not past the end of, it keeps the CVE undecided.
func TestRecordShape_WordRelease(t *testing.T) {
	t.Parallel()
	const cpe = "cpe:2.3:a:example:browser:*:*:*:*:*:*:*:*"
	word := Affected{CPE: "cpe:2.3:a:example:browser:preview_release:*:*:*:*:*:*:*"}
	upTo := Affected{CPE: cpe, Range: VersionRange{EndIncl: "1.5.0.9"}}
	ahead := Affected{CPE: cpe, Range: VersionRange{StartIncl: "200.0", EndExcl: "201.0"}}
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      Tri
		proof     proofKind
	}{
		{"word beside a fix the version is past", "160.0", []Affected{word, upTo}, No, proofRange},
		{"inside the range: affected", "1.5.0.2", []Affected{word, upTo}, Yes, proofNone},
		{"word alone", "160.0", []Affected{word}, Unknown, proofNone},
		{"word beside a range the version is before", "160.0", []Affected{word, ahead}, Unknown, proofNone},
	} {
		v := uncVuln("CVE-2026-90021", "Example", "Browser", uncNew, tc.aff...)
		if got, proof := shapeDecide(t, shapeRow("Browser", tc.ver, true), v); got != tc.want || proof != tc.proof {
			t.Errorf("%s: %v (proof %d), want %v (proof %d)", tc.name, got, proof, tc.want, tc.proof)
		}
	}
}

// A partial CVE record (a CNA that lists what it tested) proves "not affected" for a version past a fix it states on a train it covers
// (OSV: introduced <= v < fixed): past a range from 0 with no listed train above the version, or past a range that starts on the
// version's own train. A version between the trains the record lists, on a train no row covers, or below an exact row stays a question.
func TestRecordShape_PartialRecordPastItsFix(t *testing.T) {
	t.Parallel()
	const cpe = "cpe:2.3:*:example:chat_desktop:*:*:*:*:*:*:*:*"
	rng := func(start, end string) Affected {
		return Affected{CPE: cpe, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	exact := Affected{CPE: "cpe:2.3:*:example:chat_desktop:3.0.0:*:*:*:*:*:*:*"}
	trains := []Affected{rng("", "2.49.1"), rng("2.50.0-rc0", "2.50.2"), rng("2.56.0-rc0", "2.56.1")}
	const (
		decided = iota // no finding, no question
		asked          // a question
		found          // a finding
	)
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      int
	}{
		{"past a fix from 0", "7.4.7", []Affected{rng("", "7.2.9")}, decided},
		{"past a fix from version 0", "7.4.7", []Affected{rng("0", "7.2.9")}, decided},
		{"inside the range", "7.2.1", []Affected{rng("", "7.2.9")}, found},
		{"past the fix of its own train", "2.56.1", trains, decided},
		{"past the fix of a listed older train", "2.50.5", trains, decided},
		{"between listed trains", "2.53.0", trains, asked},
		{"on a train no row covers", "2.57.0", []Affected{rng("2.56.0", "2.56.1")}, asked},
		{"an exact row above the version", "2.0.0", []Affected{rng("", "1.0.0"), exact}, asked},
		{"past one exact release of its train: no fix stated", "3.0.4", []Affected{exact}, asked},
		// "through 7.24.5": an inclusive end is the last version known affected, not a fix, so a later version is not proved fixed
		{"past an inclusive end: no fix stated", "7.25.2", []Affected{
			{CPE: cpe, Range: VersionRange{StartIncl: "0", EndIncl: "7.23.6"}},
			{CPE: cpe, Range: VersionRange{StartIncl: "7.24.0", EndIncl: "7.24.5"}},
		}, asked},
		{"past an inclusive end of its own train", "7.24.6", []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "7.24.0", EndIncl: "7.24.5"}}}, asked},
	} {
		v := uncVuln("CVE-2026-90031", "Example", "Chat Desktop", uncNew, tc.aff...)
		v.RangesFrom = RangesCVEOrgPartial
		a := Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{shapeRow("Chat Desktop", tc.ver, true)}}
		res := MatchAsset(a, []Vuln{v}, nil, uncNow)
		got := decided
		switch {
		case len(res.New) > 0:
			got = found
		case len(res.Unchecked) > 0:
			got = asked
		}
		if got != tc.want {
			t.Errorf("%s (%s): new %+v, unchecked %+v, want outcome %d", tc.name, tc.ver, res.New, res.Unchecked, tc.want)
		}
	}
}

// A CVE left undecided by a row that does not compare is called a version notation problem only when retyping the version could help:
// the row is of the version's own train or in another scheme. A row of another train in a literal the comparison does not read is the
// record's: the ranges do not decide the version.
func TestRecordShape_UndecidedLabel(t *testing.T) {
	t.Parallel()
	const cpe = "cpe:2.3:a:example:player:*:*:*:*:*:*:*:*"
	for _, tc := range []struct {
		name, bound, want string
	}{
		{"a literal of another train", "0.4.3-ac3", UndecidedRangesDoNotCover},
		{"a bound of the version's own train", "3.0.20-ac3", UndecidedSchemeMismatch},
	} {
		v := uncVuln("CVE-2026-90041", "Example", "Player", uncNew, Affected{CPE: cpe, Range: VersionRange{EndIncl: tc.bound}})
		a := Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{shapeRow("Player", "3.0.20", true)}}
		res := MatchAsset(a, []Vuln{v}, nil, uncNow)
		if len(res.Unchecked) != 1 || res.Unchecked[0].undecided == nil || res.Unchecked[0].undecided.Reason != tc.want {
			t.Errorf("%s: unchecked %+v, want reason %s", tc.name, res.Unchecked, tc.want)
		}
	}
}

// A CVE record row limited to one operating system (target_sw, as feeds reads an entry's platforms) beside NVD's single exact version
// makes a version it states affected on that system: the record's "0 before 8.9.4" calls 8.6.5 affected on Windows. On another system
// the row does not apply, and NVD's exact row alone decides nothing.
func TestRecordShape_RecordRowOfOneSystem(t *testing.T) {
	t.Parallel()
	v := uncVuln("CVE-2026-90051", "Example", "Text Editor", uncNew,
		Affected{CPE: "cpe:2.3:a:example:text_editor:8.9.3:*:*:*:*:*:*:*"},
		Affected{CPE: "cpe:2.3:*:example:text_editor:*:*:*:*:*:windows:*:*", Range: VersionRange{EndExcl: "8.9.4"}, AffectedOnly: true})
	for _, tc := range []struct {
		os    string
		found bool
	}{{"Windows 11 Pro", true}, {"Ubuntu 24.04 LTS", false}} {
		a := Asset{ID: "pc", Name: "pc-01", OS: tc.os, AgentOS: tc.os, Software: []Software{shapeRow("Text Editor", "8.6.5", false)}}
		res := MatchAsset(a, []Vuln{v}, nil, uncNow)
		if got := len(res.New) == 1 && res.New[0].Basis == BasisVersion; got != tc.found {
			t.Errorf("%s: new %+v, unchecked %+v, want a version finding %v", tc.os, res.New, res.Unchecked, tc.found)
		}
	}
}

// An NA row that names a build (an edition, a system or an architecture) beside versioned rows of other builds is not about no version
// of the same build: it names the build NVD lists with no version, as a product sold per year or per channel is written ("-" with an
// edition, or with "x64"). Reading it as apart would leave only the rows of the other builds, which the install's own build rules out:
// a CVE NVD calls affected on the install's build would close. It stays undecided, or decides affected where the build is known.
func TestRecordShape_NAOfOneBuildBesideOtherBuilds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		aff  []Affected
	}{
		{"NA on the install's system beside another system's range", []Affected{
			{CPE: "cpe:2.3:a:example:mail_client:-:*:*:*:*:macos:*:*"},
			{CPE: "cpe:2.3:a:example:mail_client:*:*:*:*:*:android:*:*", Range: VersionRange{EndExcl: "4.2"}},
		}},
		{"NA of one edition beside another edition's exact release", []Affected{
			{CPE: "cpe:2.3:a:example:mail_client:-:*:*:*:subscription:*:*:*"},
			{CPE: "cpe:2.3:a:example:mail_client:2019:*:*:*:*:*:*:*"},
		}},
	} {
		v := uncVuln("CVE-2026-90061", "Example", "Mail Client", uncNew, tc.aff...)
		a := Asset{ID: "mac", Name: "mac-01", OS: "macOS 14.5", AgentOS: "macOS 14.5", Software: []Software{shapeRow("Mail Client", "16.80.1", false)}}
		res := MatchAsset(a, []Vuln{v}, nil, uncNow)
		if len(res.New) == 0 && len(res.Unchecked) == 0 {
			t.Errorf("%s: closed as not affected, want a finding or a question (NVD lists the install's build with no version)", tc.name)
		}
	}

	// An NA row that names no build stays apart beside versioned rows of other builds: the rows that compare decide.
	v := uncVuln("CVE-2026-90062", "Example", "Viewer", uncNew,
		Affected{CPE: "cpe:2.3:a:example:viewer:-:*:*:*:*:*:*:*"},
		Affected{CPE: "cpe:2.3:a:example:viewer:*:*:*:*:*:android:*:*", Range: VersionRange{EndExcl: "152.0.4191.52"}})
	a := Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", AgentOS: "Windows 11", Software: []Software{shapeRow("Viewer", "158.0.4370.45", false)}}
	if res := MatchAsset(a, []Vuln{v}, nil, uncNow); len(res.New) != 0 || len(res.Unchecked) != 0 {
		t.Errorf("NA of no build beside other builds: new %+v, unchecked %+v, want decided", res.New, res.Unchecked)
	}
}

// A bare row is NVD's "and earlier" marker only beside a bounded row of the same build: beside a range pinned to one system, the bare
// row still says every version of every build, and the install on another system stays affected by it.
func TestRecordShape_EarlierMarkerOfAnotherBuild(t *testing.T) {
	t.Parallel()
	v := uncVuln("CVE-2026-90071", "Example", "Fetch Tool", uncNew,
		Affected{CPE: "cpe:2.3:a:example:fetch_tool:*:*:*:*:*:*:*:*"},
		Affected{CPE: "cpe:2.3:a:example:fetch_tool:*:*:*:*:*:windows:*:*", Range: VersionRange{EndIncl: "5.14"}})
	a := Asset{ID: "mac", Name: "mac-01", OS: "macOS 14.5", AgentOS: "macOS 14.5", Software: []Software{shapeRow("Fetch Tool", "6.43.18", false)}}
	res := MatchAsset(a, []Vuln{v}, nil, uncNow)
	if len(res.New) == 0 && len(res.Unchecked) == 0 {
		t.Errorf("closed as not affected, want the bare row of every build to keep the CVE")
	}
}

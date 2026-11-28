package findings

import (
	"slices"
	"testing"
)

// A record that lists only the release lines its vendor still supports says nothing about an older line it does not list: a version of
// such a line, outside every row, is not proved "not affected". It stays undecided (ranges_start_at_branch_only) and is never a finding
// on that basis. A row that holds the version, a range from version 0, a fix on the version's own line, the vendor's complete list
// and a line newer than every listed one still decide as before. The products are made up: the rule reads the rows' shape only.
func TestUnlistedLine_OlderLineIsNotClosed(t *testing.T) {
	t.Parallel()
	const gw = "cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*"
	rng := func(start, end string) Affected {
		return Affected{CPE: gw, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	upTo := func(end string) Affected { return Affected{CPE: gw, Range: VersionRange{EndExcl: end}} }
	complete := func(af Affected) Affected { af.VendorList = true; return af }
	lineFix := func(af Affected, fix string) Affected { af.LineFix = fix; return af }
	supported := []Affected{rng("2.3.0", "2.3.6"), rng("8.0.0", "8.0.21"), rng("9.0.0", "9.0.10")}
	majors := []Affected{rng("20.0.0", "20.19.4"), rng("22.0.0", "22.17.1"), rng("24.0.0", "24.4.1")}

	const (
		closed    = "closed"
		undecided = "undecided"
		affected  = "affected"
	)
	// the products the record's own CNA states every version of unaffected that it does not list (CVE JSON 5 defaultStatus)
	statesUnlisted := map[string][]string{
		"the product's own CNA states every version its record does not list unaffected": {"cpe:2.3:*:example:gateway:*:*:*:*:*:*:*:*"},
		"the own CNA's word on another product of the vendor":                            {"cpe:2.3:*:example:router:*:*:*:*:*:*:*:*"},
	}
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      string
	}{
		{"an older line below every listed line", "7.0.5", supported[1:], undecided},
		{"an unlisted line between listed lines", "3.1.32", supported, undecided},
		{"an older major line below the supported majors", "18.20.8", majors[1:], undecided},
		{"an older line below a range that starts at a line's first release", "1.4.2", []Affected{rng("2.0", "2.0.9")}, undecided},
		{"inside a listed range: affected", "8.0.5", supported, affected},
		{"a range with no start holds an older line: affected", "7.0.5", []Affected{upTo("8.0.21"), rng("9.0.0", "9.0.10")}, affected},
		{"a range from 0 holds an older line: affected", "1.2.0", []Affected{rng("0", "7.2.9"), rng("8.0.0", "8.0.21")}, affected},
		{"past the fix of a range from 0 on its own train", "7.2.12", []Affected{rng("0", "7.2.9"), rng("8.0.0", "8.0.21")}, closed},
		{"past the fix of its own minor line", "8.0.25", supported, closed},
		{"past the fix of its own major line", "20.20.0", majors, closed},
		{"past the fix a range spanning several lines ends at", "7.4.8", []Affected{rng("6.4.0", "7.4.7"), rng("7.6.0", "7.6.2")}, closed},
		{"a complete CVE record states every unlisted version", "7.0.5", nil, closed},
		{"past the fix of a range with no start on the record's major line", "53.8.0", []Affected{upTo("53.3.0"), rng("54.0.0", "56.0.0")}, closed},
		{"an older line between the ranges of a record of major lines", "28.11.0", []Affected{rng("15.0", "15.42.0"), rng("40.0", "40.17.0"), rng("54.0.0", "57.0.0")}, undecided},
		{"a newer line past every fix", "10.0.1", supported, closed},
		{"the vendor's complete list states every unlisted version", "7.0.5", []Affected{complete(rng("8.0.0", "8.0.21")), complete(rng("9.0.0", "9.0.10"))}, closed},
		{"a fixed release the record states on its line", "3.1.32", []Affected{lineFix(rng("3.0.0", "3.0.5"), "3.1.0"), rng("8.0.0", "8.0.21")}, closed},
		{"a start inside a line states where the flaw came in", "2.2.34", []Affected{rng("2.4.17", "2.4.60")}, closed},
		{"the product's own CNA states every version its record does not list unaffected", "7.0.5", supported[1:], closed},
		{"the own CNA's word on another product of the vendor", "7.0.5", supported[1:], undecided},
	} {
		v := uncVuln("CVE-2026-91001", "Example", "Gateway", uncNew, tc.aff...)
		if tc.aff == nil { // the CNA's record when NVD has none, with defaultStatus stating every version it does not list
			v = uncVuln("CVE-2026-91001", "Example", "Gateway", uncNew, rng("8.0.0", "8.0.21"), rng("9.0.0", "9.0.10"))
			v.RangesFrom = RangesCVEOrg
		}
		v.UnlistedUnaffected = statesUnlisted[tc.name]
		for _, keyed := range []bool{true, false} {
			s := shapeRow("Gateway", tc.ver, keyed)
			s.CPE = "cpe:2.3:a:example:gateway:" + tc.ver + ":*:*:*:*:*:*:*"
			a := Asset{ID: "srv", Name: "srv-01", OS: "Windows Server 2022", Software: []Software{s}}
			res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, uncNow)
			got := ""
			switch {
			case len(res.Existing)+len(res.New) == 1 && len(res.NotAffected) == 0:
				got = affected
			case len(res.NotAffected) == 1 && len(res.Existing)+len(res.New) == 0 && len(res.Unchecked) == 0:
				got = closed
			case len(res.NotAffected)+len(res.Existing)+len(res.New) == 0 && slices.ContainsFunc(res.Unchecked, func(u Unchecked) bool {
				return u.CVE == v.CVE && u.Reason == UncheckedNoNVDVersions && u.Listed && u.undecided != nil && u.undecided.Reason == UndecidedBranchOnly
			}):
				got = undecided
			}
			if got != tc.want {
				t.Errorf("%s (%s, keyed %v): %q, want %q (not affected %d, findings %d, unchecked %+v)", tc.name, tc.ver, keyed, got, tc.want,
					len(res.NotAffected), len(res.Existing)+len(res.New), res.Unchecked)
			}
		}
	}
}

// The questions an older unlisted line leaves: one per CVE, about the version's ranges (versions listed), with the reason that says the
// ranges start at later lines.
func TestUnlistedLine_QuestionSaysTheLineIsNotListed(t *testing.T) {
	t.Parallel()
	const gw = "cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*"
	v := uncVuln("CVE-2026-91002", "Example", "Gateway", uncNew,
		Affected{CPE: gw, Range: VersionRange{StartIncl: "8.0.0", EndExcl: "8.0.21"}}, Affected{CPE: gw, Range: VersionRange{StartIncl: "9.0.0", EndExcl: "9.0.10"}})
	a := Asset{ID: "srv", Name: "srv-01", OS: "Windows Server 2022", Software: []Software{shapeRow("Gateway", "3.1.32", true)}}
	qs := questionsOfMatch(MatchAsset(a, []Vuln{v}, nil, uncNow))
	if len(qs) != 1 || qs[0].Kind != QuestionNoRangeData || qs[0].CVE != v.CVE || !qs[0].Detail.Listed || qs[0].Detail.Undecided == nil ||
		qs[0].Detail.Undecided.Reason != UndecidedBranchOnly {
		t.Fatalf("questions %+v, want one no_range_data question with reason %s", qs, UndecidedBranchOnly)
	}
}

// A line holds several readings: when another reading of it decides the CVE (a distribution's word on its package, a version the rows
// prove), a reading on an unlisted older line asks nothing more and takes nothing away from that decision.
func TestUnlistedLine_AnotherReadingOfTheLineDecides(t *testing.T) {
	t.Parallel()
	const gw = "cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*"
	v := uncVuln("CVE-2026-91003", "Example", "Gateway", uncNew,
		Affected{CPE: gw, Range: VersionRange{StartIncl: "8.0.0", EndExcl: "8.0.21"}}, Affected{CPE: gw, Range: VersionRange{StartIncl: "9.0.0", EndExcl: "9.0.10"}})
	decided, unlisted := shapeRow("Gateway", "8.0.25", true), shapeRow("Gateway", "3.1.32", true)
	a := Asset{ID: "srv", Name: "srv-01", OS: "Windows Server 2022", Software: []Software{decided, unlisted}}
	res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, uncNow)
	if len(res.NotAffected) != 1 || len(res.Unchecked) != 0 || len(res.New)+len(res.Existing) != 0 {
		t.Fatalf("not affected %d, unchecked %+v, findings %d: want the decided reading's proof alone", len(res.NotAffected), res.Unchecked, len(res.New)+len(res.Existing))
	}
}

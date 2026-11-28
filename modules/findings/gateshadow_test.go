package findings

import "testing"

// The ranges producer scopes each row's fix to its own line: a fix holds up to the next row's start, and past the last row only when
// the rows are one line of releases. The gate then closes only a version a fix's span contains; the matcher's own outcome is
// unchanged (the shadow is recorded beside it).
func TestGateShadow_RangesScopeEachFixToItsLine(t *testing.T) {
	t.Parallel()
	branched := []Affected{
		{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.0.5"}},
		{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.1", EndExcl: "6.1.2"}},
	}
	single := []Affected{{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}}
	for _, c := range []struct {
		name, version string
		rows          []Affected
		would         string
		cause         GateCause
	}{
		{"past the fix of its own line", "6.1.4", branched, "not_affected", ""},
		{"between two lines: past the first fix, below the next start", "6.0.7", branched, "not_affected", ""},
		{"a later line no row speaks for", "6.2.1", branched, "undecided", CauseLineNotStated},
		{"older than every row", "5.9", branched, "undecided", CauseLineNotStated},
		{"one line of releases: past its fix", "7.0", single, "not_affected", ""},
	} {
		a := nas(c.version)
		s := a.Software[0]
		in := swInfoOn(s, a)
		v := qnapVuln(c.rows...)
		g := rangeProofs(s, in, v, keyIDs(v))
		would, cause, producer := gateWould(a, s, in, v, []*gateShadow{g})
		if would != c.would || cause != c.cause || producer != prodRanges {
			t.Errorf("%s (%s): gate %s (%s) by %s, want %s (%s)", c.name, c.version, would, cause, producer, c.would, c.cause)
		}
	}
}

// Every "not affected" the matcher returns carries what the gate reads from the step that decided it.
func TestGateShadow_NotAffectedCarriesItsStep(t *testing.T) {
	t.Parallel()
	res := MatchAsset(nas("6.1.4"), []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.1", EndExcl: "6.1.2"}})}, map[string]bool{"CVE-2022-27593": true}, t0)
	if len(res.NotAffected) != 1 {
		t.Fatalf("not affected = %d, want 1: %+v", len(res.NotAffected), res)
	}
	if g := res.NotAffected[0].gate; g == nil || g.producer != prodRanges || len(g.proofs) == 0 {
		t.Fatalf("gate shadow = %+v", g)
	}
}

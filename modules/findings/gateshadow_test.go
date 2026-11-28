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
		g := rangeProofs(in, v, keyIDs(v))
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

// A pass records the gate's answers in shadow beside its counts, in memory: per group of pairs decided not affected, and per finding it
// closed as gone. The counts and the findings are those of the matcher alone.
func TestGateShadow_PassRecordsTheGateBesideItsCounts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.inv.assets = map[string]AssetView{"a-1": {ID: "a-1", Hostname: ptr("nas01"), IP: "192.0.2.10", Kind: "nas", Approved: true}}
	rows := []Affected{{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.0.5"}}, {CPE: qnapCPE, Range: VersionRange{StartIncl: "6.1", EndExcl: "6.1.2"}}}
	e.feeds.vulns = []Vuln{qnapVuln(rows...)}
	e.inv.match = map[string]Asset{"a-1": nas("6.1.0")}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := e.svc.gateShadowReport(); len(r.would) != 0 || len(r.gone) != 0 {
		t.Fatalf("an affected pair has no shadow: %+v", r)
	}
	e.inv.match = map[string]Asset{"a-1": nas("6.1.4")} // updated past the fix of its line: the finding closes as gone
	e.advance(ReconcileEvery)
	res, err := e.svc.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.Closed != 1 {
		t.Fatalf("closed %d, want 1: %+v", res.Closed, res)
	}
	r := e.svc.gateShadowReport()
	if len(r.would) != 1 || r.would[0].producer != prodRanges || r.would[0].would != "not_affected" || r.would[0].n != 1 {
		t.Errorf("would = %+v, want one pair the ranges producer proves not affected", r.would)
	}
	if len(r.gone) != 1 || r.gone[0].via != string(ViaVersionMoved) || r.gone[0].would != gateWouldExit {
		t.Errorf("gone = %+v, want the version move the gate also proves", r.gone)
	}
}

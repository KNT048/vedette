package findings

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// "I have this" on Home means "alert me about this product" for the ONE device it
// declared: there a version-less row of the answered key matches entries from the scope's date on. The same product on
// any other device (found by a scan, added from the catalog) is matched as before: nothing is hidden there.
func TestHaveScope_OnlyTheDeclaredDeviceIsScoped(t *testing.T) {
	t.Parallel()
	day := func(s string) time.Time { d, _ := time.Parse(time.DateOnly, s); return d }
	e := newEnv(t)
	e.feeds.vulns = []Vuln{
		{CVE: "CVE-2009-0556", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2022-03-03"), HasTemplate: true},  // a scan checks them: product matches stay findings
		{CVE: "CVE-2026-21508", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2026-10-27"), HasTemplate: true}, // same week, earlier
		{CVE: "CVE-2026-21509", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2026-11-01"), HasTemplate: true}, // the answered one
		{CVE: "CVE-2026-30001", Vendor: "QNAP", Product: "Photo Station", HasTemplate: true},                               // no date: kept
	}
	declared := Asset{ID: "a-declared", Name: "QNAP", Software: nas("").Software}
	e.inv.match["a-declared"] = declared
	e.svc.cfg.HaveSince = func(context.Context) (map[string]Have, error) {
		return map[string]Have{"a-declared": {Key: "QNAP|Photo Station", Since: day("2026-11-01").AddDate(0, 0, -7)}}, nil
	}
	cves := func(asset string) string {
		t.Helper()
		rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve FROM fnd_finding WHERE asset_id = ? ORDER BY cve`, asset)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return fmt.Sprint(out)
	}
	for _, id := range []string{"a-1", "a-declared"} {
		if _, err := e.svc.OnMatchChanged(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := cves("a-declared"), "[CVE-2026-21508 CVE-2026-21509 CVE-2026-30001]"; got != want {
		t.Errorf("declared device: %s, want %s", got, want)
	}
	if got, want := cves("a-1"), "[CVE-2009-0556 CVE-2026-21508 CVE-2026-21509 CVE-2026-30001]"; got != want {
		t.Errorf("the same product on another device was scoped: %s, want %s", got, want)
	}
	// With a version the version decides, not the answer on Home.
	if got := haveScope(nas("6.1"), e.feeds.vulns, MatchAsset(nas("6.1"), e.feeds.vulns, nil, t0), map[string]Have{"a-1": {Key: "qnap|photo station", Since: day("2026-11-01")}}, nil, t0); len(got.New) != 4 {
		t.Fatalf("with a version: %+v", got.New)
	}
}

// Review LOW of #663: the "I have this" scope keeps the matcher's proofs: a second row of the declared
// device with a readable version outside the range still closes its finding.
func TestHaveScope_KeepsNotAffected(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a-declared", Name: "QNAP", Software: nas("").Software}
	proof := Match{CVE: "CVE-2022-27593", SoftwareID: "s-2"}
	got := haveScope(a, nil, MatchResult{NotAffected: []Match{proof}}, map[string]Have{a.ID: {Key: "qnap|photo station", Since: t0}}, nil, t0)
	if len(got.NotAffected) != 1 || got.NotAffected[0].CVE != proof.CVE || got.NotAffected[0].SoftwareID != proof.SoftwareID {
		t.Fatalf("NotAffected = %+v", got.NotAffected)
	}
}

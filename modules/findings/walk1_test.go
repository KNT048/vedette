package findings

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// D-484 (customer walk 1, W1-3): "I have this" on Home means "alert me about this product" for the ONE device it
// declared: there a version-less row of the answered key matches entries from the scope's date on. The same product on
// any other device (found by a scan, added from the catalog) is matched as before: nothing is hidden there.
func TestHaveScope_OnlyTheDeclaredDeviceIsScoped(t *testing.T) {
	t.Parallel()
	day := func(s string) time.Time { d, _ := time.Parse(time.DateOnly, s); return d }
	e := newEnv(t)
	e.feeds.vulns = []Vuln{
		{CVE: "CVE-2009-0556", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2022-03-03")},
		{CVE: "CVE-2026-21508", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2026-10-27")}, // same week, earlier
		{CVE: "CVE-2026-21509", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2026-11-01")}, // the answered one
		{CVE: "CVE-2026-30001", Vendor: "QNAP", Product: "Photo Station"},                               // no date: kept
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

// W1-12: one action and one note for the open findings among many; each gets its own history, audit row and event; a
// closed one is skipped with its reason kept; all or nothing.
func TestSetStatusMany_OneRowEachAllOrNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station"})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	e.pub.take()
	before := e.count(`SELECT count(*) FROM core_audit`)
	for _, c := range []struct {
		name   string
		ids    []string
		action Action
		note   string
		want   error
	}{
		{"unknown id", []string{res.Created[0], "f-nope"}, ActionFalsePositive, "lab", ErrNotFound},
		{"note required", res.Created, ActionFalsePositive, "", ErrNoteRequired},
		{"reopen", res.Created, ActionReopen, "", ErrBadAction},
		{"none", nil, ActionPatched, "", ErrTooMany},
		{"too many", make([]string, MaxBulk+1), ActionPatched, "", ErrTooMany},
	} {
		if c.name == "too many" {
			for i := range c.ids {
				c.ids[i] = fmt.Sprintf("f-%d", i)
			}
		}
		if _, _, err := e.svc.SetStatusMany(t.Context(), c.ids, c.action, c.note, "it@acme.example"); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if e.count(`SELECT count(*) FROM core_audit`) != before || e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'suspected'`) != 2 || len(e.pub.take()) != 0 {
		t.Fatal("a refused bulk change wrote something")
	}
	if _, err := e.svc.SetStatus(t.Context(), res.Created[1], ActionPatched, "updated to 6.1.2", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	n, skipped, err := e.svc.SetStatusMany(t.Context(), append(res.Created, res.Created[0]), ActionFalsePositive, "iPhone on guest Wi-Fi", "it@acme.example")
	if err != nil || n != 1 || skipped != 1 {
		t.Fatalf("bulk = %d changed, %d skipped, %v", n, skipped, err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'false_positive' AND resolution_note = 'iPhone on guest Wi-Fi'`) != 1 ||
		e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'patched' AND resolution_note = 'updated to 6.1.2'`) != 1 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.status'`) != 2 || len(e.pub.take()) != 1 {
		t.Fatal("an open finding gets its own status, audit row and event; a closed one keeps its reason")
	}
}

// W1-2, W1-32: a device with no hostname and no IP is named, never shown by its internal id, even in old evidence.
func TestRow_DeviceWithoutIPIsNamedNotByItsID(t *testing.T) {
	t.Parallel()
	r := Record{ID: "f-1", AssetID: "a-vft3", CVE: "CVE-2023-36845", Finding: Finding{Evidence: &Evidence{Summary: "a-vft3 runs Juniper Junos 15.1R7.9."}}}
	row := newRow(r, &AssetView{ID: "a-vft3", Name: "a-vft3", IP: NoIP, Kind: "switch", Display: "Juniper Junos"}, nil)
	if row.Asset.Name != "Juniper Junos" || row.Evidence.Summary != "Juniper Junos runs Juniper Junos 15.1R7.9." || row.Asset.HasIP() {
		t.Fatalf("asset = %+v, evidence = %q", row.Asset, row.Evidence.Summary)
	}
	row = newRow(r, &AssetView{ID: "a-vft3", Name: "Juniper Networks EX4200-48T", IP: NoIP, Kind: "switch"}, nil)
	if row.Asset.Name != "Juniper Networks EX4200-48T" || row.Evidence.Summary != "Juniper Networks EX4200-48T runs Juniper Junos 15.1R7.9." {
		t.Fatalf("asset = %+v, evidence = %q", row.Asset, row.Evidence.Summary)
	}
}

// Review LOW of #663: the "I have this" scope keeps the matcher's proofs (D-530): a second row of the declared
// device with a readable version outside the range still closes its finding.
func TestHaveScope_KeepsNotAffected(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a-declared", Name: "QNAP", Software: nas("").Software}
	proof := Match{CVE: "CVE-2022-27593", SoftwareID: "s-2"}
	got := haveScope(a, nil, MatchResult{NotAffected: []Match{proof}}, map[string]Have{a.ID: {Key: "qnap|photo station", Since: t0}}, nil, t0)
	if len(got.NotAffected) != 1 || got.NotAffected[0] != proof {
		t.Fatalf("NotAffected = %+v", got.NotAffected)
	}
}

package feeds

import (
	"database/sql"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The reporting window: by default an older CVE stays only with evidence of exploitation in the wild (an exploited-list entry, a
// vendor's exploited signal) or a public exploit its source dates inside the window; an old public exploit alone, or a scan template
// (no date of its own), does not keep it. Every age reported keeps every CVE; switched off again, the next prune drops the older ones
// back, a pinned CVE's data stays but the CVE is outside the window all the same.
func TestWindow_OldCVEsStayOnlyWithEvidenceOfExploitation(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	now := epoch0
	old, recent := now.AddDate(-5, 0, 0), now.AddDate(0, -2, 0)
	ts := func(t time.Time) string { return store.FormatTS(t) }
	rec := func(cve string, pub time.Time) NVDRecord {
		return NVDRecord{CVE: cve, Published: pub, LastModified: now, Status: "Analyzed", Affected: []AffectedRow{{CPE: "cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*", EndExcl: "2.0"}}}
	}
	applyV(t, db, now, "cisa-kev", []Vuln{vuln("CVE-2019-0001", "Acme", "Box", "2021-11-03")}, false)
	write(t, db, func(tx *sql.Tx) error {
		for _, g := range []struct {
			cve, kind, source string
			first             time.Time
		}{
			{"CVE-2019-0002", SignalExploited, msrcFeedID, old},              // the vendor said exploited, years ago
			{"CVE-2019-0003", SignalPublicExploit, exploitDBFeedID, old},     // an exploit as old as the flaw
			{"CVE-2019-0004", SignalPublicExploit, metasploitFeedID, recent}, // a new exploit of an old flaw
			{"CVE-2019-0004", SignalPublicExploit, exploitDBFeedID, old},     // beside an old one
			{"CVE-2019-0005", SignalPublicExploit, nucleiFeedID, now},        // a scan template, dated by this box
			{"CVE-2019-0006", SignalPublicExploit, pocGitHubFeedID, recent},  // a proof of concept that does not qualify
		} {
			if err := putSignal(t.Context(), tx, g.cve, g.kind, g.source, ts(g.first), ts(now), g.cve != "CVE-2019-0006", ""); err != nil {
				return err
			}
		}
		return nil
	})
	all := []NVDRecord{rec("CVE-2019-0001", old), rec("CVE-2019-0002", old), rec("CVE-2019-0003", old), rec("CVE-2019-0004", old),
		rec("CVE-2019-0005", old), rec("CVE-2019-0006", old), rec("CVE-2019-0007", old), rec("CVE-2026-0008", recent)}
	store1 := func(at time.Time, pins []string) {
		write(t, db, func(tx *sql.Tx) error {
			ret, err := retentionOf(t.Context(), tx, at, pins)
			if err != nil {
				return err
			}
			_, err = writeNVDRecords(t.Context(), tx, all, ret, at)
			return err
		})
	}
	held := func() []string {
		got, err := stringSet(t.Context(), db.Reader(), `SELECT cve FROM feeds_cve`)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Sorted(maps.Keys(got))
	}
	inside := []string{"CVE-2019-0001", "CVE-2019-0002", "CVE-2019-0004", "CVE-2026-0008"}
	store1(now, nil)
	if got := held(); !slices.Equal(got, inside) {
		t.Fatalf("stored by default: %v, want %v", got, inside)
	}
	ids := make([]string, len(all))
	for i, r := range all {
		ids[i] = r.CVE
	}
	outside := func(at time.Time) []string {
		got, err := s.OutsideWindow(t.Context(), ids, at)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Sorted(maps.Keys(got))
	}
	if got := outside(now); len(got) != 0 {
		t.Fatalf("outside among the stored: %v", got)
	}

	// every age: every record is stored and kept
	write(t, db, func(tx *sql.Tx) error { return saveWindow(t.Context(), tx, true, "admin@example.test", now) })
	store1(now, nil)
	write(t, db, func(tx *sql.Tx) error { return pruneCatalogue(t.Context(), tx, now, nil) })
	if got := held(); len(got) != len(all) {
		t.Fatalf("every age: %v", got)
	}
	if got := outside(now); len(got) != 0 {
		t.Fatalf("every age, outside: %v", got)
	}
	if w, err := s.Window(t.Context(), now); err != nil || !w.EveryAge || w.By != "admin@example.test" || !w.Since.Equal(now) {
		t.Fatalf("window %+v %v", w, err)
	}

	// off again: the prune drops the older CVEs back; a pinned one keeps its data, outside the window
	write(t, db, func(tx *sql.Tx) error { return saveWindow(t.Context(), tx, false, "admin@example.test", now) })
	if got, want := outside(now), []string{"CVE-2019-0003", "CVE-2019-0005", "CVE-2019-0006", "CVE-2019-0007"}; !slices.Equal(got, want) {
		t.Fatalf("outside after switching off: %v, want %v", got, want)
	}
	write(t, db, func(tx *sql.Tx) error { return pruneCatalogue(t.Context(), tx, now, []string{"CVE-2019-0007"}) })
	if got, want := held(), append(slices.Clone(inside), "CVE-2019-0007"); !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Fatalf("after the prune: %v, want %v", got, want)
	}
	if got := outside(now); !slices.Equal(got, []string{"CVE-2019-0007"}) {
		t.Fatalf("a pinned CVE is outside the window all the same: %v", got)
	}

	// a year on, the new exploit is old too: CVE-2019-0004 leaves; the exploited ones stay
	later := now.AddDate(1, 0, 1)
	write(t, db, func(tx *sql.Tx) error { return pruneCatalogue(t.Context(), tx, later, nil) })
	if got := held(); !slices.Equal(got, []string{"CVE-2019-0001", "CVE-2019-0002"}) {
		t.Fatalf("a year later: %v", got)
	}
}

// GET and PUT /feeds/window: a viewer reads it, only an administrator changes it; a change is audited and makes findings match again,
// a save that changes nothing does neither.
func TestWindow_SettingIsAdminsAuditedAndRematches(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c, b := e.get("/feeds/window")
	if c != 200 || b["every_age"] != false || b["window_days"] != float64(365) || b["changed_at"] != nil {
		t.Fatalf("default: %d %v", c, b)
	}
	if c, _, _ := e.do("PUT", "/feeds/window", "operator", `{"every_age":true}`); c != 403 {
		t.Fatalf("operator: %d", c)
	}
	c, b, _ = e.do("PUT", "/feeds/window", "admin", `{"every_age":true}`)
	if c != 200 || b["every_age"] != true || b["changed_by"] == nil {
		t.Fatalf("on: %d %v", c, b)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_audit WHERE action = 'feeds.report_window' AND detail LIKE 'on:%'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	if n := len(e.pub.named(EventRangesUpdated)); n != 1 {
		t.Fatalf("%d re-match events", n)
	}
	if c, _, _ := e.do("PUT", "/feeds/window", "admin", `{"every_age":true}`); c != 200 || len(e.pub.named(EventRangesUpdated)) != 1 ||
		count(t, e.db, `SELECT count(*) FROM core_audit WHERE action = 'feeds.report_window'`) != 1 {
		t.Fatal("a save that changes nothing audited or re-matched")
	}
}

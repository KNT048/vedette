package exposure

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// An OpenVAS step an older version stored as stopped (no reason, the older stop line) gets, at start-up, its stop time from the
// exposure.greenbone_scan row written with it and the reason the audit log proves: a terms change that stopped it (who) or the
// module switched off. With neither it keeps no reason (a Stop or a shutdown, which leave no row). Without a time on record it is
// left as it is. The older lines are the exact texts the older version stored.
func TestContract_INV34_StartUpGivesOlderStopsTheirTimeAndProvedReason(t *testing.T) {
	t.Parallel()
	const (
		stopped     = "OpenVAS was stopped before it finished, so its results are not shown. The results of the other checks above are kept."
		stoppedSome = "OpenVAS was stopped before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept."
		note        = "the scan of this target that was running was stopped"
	)
	type row struct{ user, action, target, detail string }
	for _, tc := range []struct {
		name    string
		line    string
		endedAt string        // set by an earlier migration ("" none)
		before  []row         // audit rows 10 minutes after OpenVAS started
		gb      bool          // the exposure.greenbone_scan row at 30 minutes
		after   []row         // audit rows 30 s after it
		reason  string        // "" none
		by      string        // who, for terms
		ended   time.Duration // the stop time after OpenVAS started; 0 = none
		read    string        // the line as read
	}{
		{name: "a Stop or a shutdown", line: stopped, gb: true, ended: 30 * time.Minute, read: stopped},
		{name: "terms withdrawn", line: stopped, gb: true, after: []row{{"owner@acme.example", "exposure.terms_revoke", ipA, note + " (the testing terms were withdrawn)"}},
			reason: StopTerms, by: "owner@acme.example", ended: 30 * time.Minute,
			read: "OpenVAS was stopped before it finished (the testing terms of this target were withdrawn or lowered by owner@acme.example), so its results are not shown. The results of the other checks above are kept."},
		{name: "terms lowered, on a domain line that kept some rows", line: "8.8.4.4 (www.acme.example): " + stoppedSome, gb: true,
			after:  []row{{"owner@acme.example", "exposure.terms_accept", ipA, note + " (the disruptive checks were taken out of this target's testing terms)"}},
			reason: StopTerms, by: "owner@acme.example", ended: 30 * time.Minute,
			read: "8.8.4.4 (www.acme.example): OpenVAS was stopped (the testing terms of this target were withdrawn or lowered by owner@acme.example) before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept."},
		{name: "a terms acceptance that stopped nothing", line: stopped, gb: true, before: []row{{"owner@acme.example", "exposure.terms_accept", ipA, "accepted"}},
			ended: 30 * time.Minute, read: stopped},
		{name: "the module switched off", line: stopped, gb: true, before: []row{{"admin@acme.example", "module.disable", ModuleID, ""}},
			reason: StopModule, ended: 30 * time.Minute,
			read: "OpenVAS was stopped before it finished (the External exposure module was switched off), so its results are not shown. The results of the other checks above are kept."},
		{name: "another module switched off", line: stopped, gb: true, before: []row{{"admin@acme.example", "module.disable", "feeds", ""}}, ended: 30 * time.Minute, read: stopped},
		{name: "no row, the time an earlier migration kept", line: stopped, endedAt: "+45m", before: []row{{"admin@acme.example", "module.disable", ModuleID, ""}},
			reason: StopModule, ended: 45 * time.Minute,
			read: "OpenVAS was stopped before it finished (the External exposure module was switched off), so its results are not shown. The results of the other checks above are kept."},
		{name: "no time on record", line: stopped, read: stopped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			s := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}}})
			start := e.clock.Now()
			run := `{"state":"stopped","started_at":"` + store.FormatTS(start) + `"}`
			if tc.endedAt != "" {
				run = `{"state":"stopped","started_at":"` + store.FormatTS(start) + `","ended_at":"` + store.FormatTS(start.Add(45*time.Minute)) + `"}`
			}
			if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(e.ctx(), `UPDATE exp_snapshot SET greenbone_run = ?, not_checked = ?, finished_at = NULL WHERE id = ?`, run, `[{"kind":"greenbone","text":"`+tc.line+`"}]`, s.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			write := func(rs ...row) {
				for _, r := range rs {
					if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { return e.svc.audit(e.ctx(), tx, r.user, r.action, r.target, r.detail) }); err != nil {
						t.Fatal(err)
					}
				}
			}
			e.advance(10 * time.Minute)
			write(tc.before...)
			e.advance(20 * time.Minute)
			if tc.gb {
				write(row{"admin@acme.example", "exposure.greenbone_scan", ipA, "stopped"})
			}
			e.advance(30 * time.Second)
			write(tc.after...)
			e.advance(time.Hour)
			e.svc.StopsAtStart(e.ctx())
			e.svc.StopsAtStart(e.ctx()) // a second start changes nothing
			got, err := e.svc.SnapshotOf(e.ctx(), e.ipTarget(), s.Date)
			if err != nil {
				t.Fatal(err)
			}
			r := got.GreenboneRun
			if r.State != GBRunStopped || (tc.reason == "") != (r.Stop == nil) || (r.Stop != nil && r.Stop.Reason != tc.reason) ||
				(tc.by != "") != (r.Stop != nil && r.Stop.By != nil) || (tc.by != "" && *r.Stop.By != tc.by) {
				t.Fatalf("run %+v, stop %+v", r, r.Stop)
			}
			if tc.ended == 0 {
				if r.EndedAt != nil || got.FinishedAt != nil {
					t.Fatalf("a time was made up: ended %v, finished %v", r.EndedAt, got.FinishedAt)
				}
			} else if want := store.FormatTS(start.Add(tc.ended)); r.EndedAt == nil || *r.EndedAt != want || got.FinishedAt == nil || *got.FinishedAt != want {
				t.Fatalf("ended %v, finished %v, want %s", r.EndedAt, got.FinishedAt, want)
			}
			if !slices.Contains(notChecked(got), tc.read) {
				t.Fatalf("not checked %q, want %q", notChecked(got), tc.read)
			}
		})
	}
}

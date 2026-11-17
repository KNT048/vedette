package exposure

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// waitRun waits until the run that runs now has ended (its done channel), so its state and snapshot are final.
func (e *env) waitRun() ScanRun {
	e.t.Helper()
	e.svc.runMu.Lock()
	run := e.svc.run
	e.svc.runMu.Unlock()
	if run == nil {
		e.t.Fatal("no run")
	}
	<-run.done
	return e.svc.runView(run)
}

// A stopped OpenVAS step of a scan, and the 10 minutes after it passed: OpenVAS may run again unless a gate says no.
func againEnv(t *testing.T) (*env, *fakeGB, string, Snapshot) {
	t.Helper()
	e, h := gbEnv(t)
	id, snap := stoppedScan(t, e, h, func() { e.svc.cancelRun("admin@acme.example") })
	h.gvm.with(func(g *fakeGVM) { g.states, g.onPoll = []string{"Running", "Done"}, nil })
	e.advance(ScanEvery + time.Minute)
	return e, h, id, snap
}

// OpenVAS again goes through the gates of Scan now: a proof that expired, an IP the box no longer goes out through, an IP on the
// shared exclusion list are refused before anything is sent, and each refusal is audited.
func TestContract_INV34_OpenVASAgainKeepsTheScanGates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		set    func(e *env)
		status int
		code   string
	}{
		{"proof expired", func(e *env) {
			e.advance(31 * 24 * time.Hour)
			e.prober.set(ipC)
			e.detect(ipC)
		}, 409, "expired"},
		{"IP no longer the box's", func(e *env) {
			e.detect(ipB)
		}, 409, "ip_not_current"},
		{"IP excluded", func(e *env) {
			e.svc.cfg.Safety = &fakeSafety{s: Safety{Exclusions: prefixes(t, ipA)}}
		}, 400, "out_of_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, h, id, _ := againEnv(t)
			tc.set(e)
			cmds := len(h.gvm.cmds)
			_, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id)
			wantAPI(t, err, tc.status, tc.code)
			if len(h.gvm.cmds) != cmds {
				t.Fatalf("OpenVAS was asked: %q", h.gvm.cmds[cmds:])
			}
			found := false
			for _, a := range e.audits() {
				found = found || (a.Action == "exposure.scan" && strings.HasPrefix(a.Detail, "OpenVAS again: not done: "+tc.code))
			}
			if !found {
				t.Fatalf("not audited: %+v", e.audits())
			}
		})
	}
}

// One run at a time: a second press while OpenVAS runs again is 409 busy (never "nothing to run again"); a Stop then ends it with the
// person who pressed it, and the step reads stopped by them.
func TestContract_INV34_OpenVASAgainBusyAndStop(t *testing.T) {
	t.Parallel()
	e, h, id, _ := againEnv(t)
	started := make(chan struct{})
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running"}
		g.onPoll = func() {
			select {
			case <-started:
			default:
				close(started)
			}
		}
	})
	run, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id)
	if err != nil || run.Phase != PhaseGreenbone {
		t.Fatalf("run %+v, %v", run, err)
	}
	<-started
	_, err = e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id)
	wantAPI(t, err, 409, "busy")
	e.svc.cancelRun("operator@acme.example")
	end := e.waitRun()
	if end.Status != RunStopped || end.SnapshotID == nil {
		t.Fatalf("end %+v", end)
	}
	got := e.newest(id)
	st := got.GreenboneRun.Stop
	if got.GreenboneRun.State != GBRunStopped || !got.GreenboneRun.Again || st == nil || st.Reason != StopPerson || st.By == nil || *st.By != "operator@acme.example" {
		t.Fatalf("run %+v, stop %+v", got.GreenboneRun, st)
	}
}

// Withdrawing the testing terms while OpenVAS runs again stops it, and the step says who withdrew them.
func TestContract_INV34_OpenVASAgainStopsWhenTheTermsGo(t *testing.T) {
	t.Parallel()
	e, h, id, _ := againEnv(t)
	once := false
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running"}
		g.onPoll = func() {
			if !once {
				once = true
				go func() { _, _ = e.svc.RevokeTerms(e.ctx(), "owner@acme.example", id) }()
			}
		}
	})
	if _, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id); err != nil {
		t.Fatal(err)
	}
	if end := e.waitRun(); end.Status != RunStopped {
		t.Fatalf("end %+v", end)
	}
	got := e.newest(id)
	if st := got.GreenboneRun.Stop; got.GreenboneRun.State != GBRunStopped || st == nil || st.Reason != StopTerms || st.By == nil || *st.By != "owner@acme.example" {
		t.Fatalf("run %+v", got.GreenboneRun)
	}
}

// Only a recent scan: OpenVAS checks the ports that scan found open, so a scan that started more than 24 hours ago needs a new deep
// scan; and a step whose findings OpenVAS had before it ended keeps them (it is not run again, so a stop or a refusal cannot lose them).
func TestContract_INV34_OpenVASAgainOnlyForARecentScanWithoutFindings(t *testing.T) {
	t.Parallel()
	e, _, id, _ := againEnv(t)
	e.advance(AgainWithin)
	_, err := e.svc.StartOpenVAS(e.ctx(), Actor{Email: "operator@acme.example"}, id)
	wantAPI(t, err, 409, "nothing_to_rerun")
	if !strings.Contains(err.Error(), "more than 24 hours ago") {
		t.Fatalf("message: %v", err)
	}

	e2, _, id2, snap2 := againEnv(t)
	if err := e2.db.Write(e2.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e2.ctx(), `UPDATE exp_snapshot SET greenbone_run = '{"state":"ended","addresses":[]}', greenbone = ? WHERE id = ?`,
			`[{"ip":"`+ipA+`","port":"443/tcp","severity":7.5,"name":"Weak TLS","qod":98,"cves":[],"solution":"Fix TLS.","oid":"1.3.6.1.4.1.25623.1.0.1"}]`, snap2.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err = e2.svc.StartOpenVAS(e2.ctx(), Actor{Email: "operator@acme.example"}, id2)
	wantAPI(t, err, 409, "nothing_to_rerun")
	if got := e2.newest(id2); len(got.Greenbone) != 1 || got.GreenboneRun.State != GBRunEnded {
		t.Fatalf("the findings were touched: %+v", got.GreenboneRun)
	}
}

// A shutdown whose OpenVAS stop outlasts Close's wait stores the step as stopped by the shutdown, not as a restart at the next start.
func TestContract_INV34_ASlowShutdownIsAShutdown(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	e.enable()
	s := e.scanIP(gbOpen())
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_snapshot SET greenbone_run = '{"state":"running","started_at":"2026-11-09T10:00:00.000Z","addresses":[]}', not_checked = ?, finished_at = NULL WHERE id = ?`,
			`[{"kind":"greenbone","text":"`+gbPending+`"}]`, s.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	id := e.ipTarget()
	e.svc.cutAtShutdown(&scanRun{gbSnap: s.ID, view: ScanRun{TargetID: id}})
	got := e.newest(id)
	if st := got.GreenboneRun.Stop; got.GreenboneRun.State != GBRunStopped || st == nil || st.Reason != StopShutdown || got.GreenboneRun.EndedAt == nil ||
		!strings.Contains(strings.Join(notChecked(got), " "), "Vedette shut down") {
		t.Fatalf("run %+v, lines %q", got.GreenboneRun, notChecked(got))
	}
	e.svc.CutOffAtStart(e.ctx()) // the next start leaves it as it is
	if st := e.newest(id).GreenboneRun.Stop; st == nil || st.Reason != StopShutdown {
		t.Fatalf("after start-up %+v", st)
	}
}

// Settings › Scanning › History: a step a restart cut, not corrected yet, reads stopped, never "still scanning"; each row is named
// by its target and day.
func TestContract_INV34_HistoryReadsACutStepAsStopped(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	e.enable()
	s := e.scanIP(gbOpen())
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_snapshot SET greenbone_run = '{"state":"running","addresses":[]}' WHERE id = ?`, s.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	recs, err := e.svc.RecentScans(e.ctx(), 10)
	if err != nil || len(recs) != 1 || recs[0].Greenbone != GBRunStopped || recs[0].Date != s.Date {
		t.Fatalf("records %+v, %v", recs, err)
	}
}

// newest is the newest snapshot of target id as the page reads it.
func (e *env) newest(id string) Snapshot {
	e.t.Helper()
	metas, err := e.svc.Snapshots(e.ctx(), id)
	if err != nil || len(metas) == 0 {
		e.t.Fatalf("snapshots %v, %v", metas, err)
	}
	got, err := e.svc.SnapshotOf(e.ctx(), id, metas[0].Date)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

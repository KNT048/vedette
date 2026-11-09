package response_test

import (
	"database/sql"
	"testing"
	"time"
)

// INV-19: resp_log refuses every SQL form that rewrites or removes a row, not only UPDATE/DELETE and INSERT OR REPLACE (REPLACE INTO,
// upserts, UPDATE OR REPLACE ...). The chain still verifies and a normal append still works afterwards.
func TestContract_INV19_RespLogRefusesEveryRewrite(t *testing.T) {
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	var n int
	var detail string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT count(*) FROM resp_log`).Scan(&n))
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT detail FROM resp_log WHERE seq = 1`).Scan(&detail))
	if n < 2 {
		t.Fatalf("%d log lines", n)
	}
	cols := `seq, id, ts, kind, actor, detail, prev_hash, hash`
	for _, q := range []string{
		`REPLACE INTO resp_log (` + cols + `) SELECT seq, id, ts, kind, actor, 'x', prev_hash, hash FROM resp_log WHERE seq = 1`,
		`REPLACE INTO resp_log (` + cols + `) SELECT seq, 'rl-other', ts, kind, actor, 'x', prev_hash, hash FROM resp_log WHERE seq = 1`,
		`INSERT INTO resp_log (id, ts, kind, actor, detail, prev_hash, hash) SELECT id, ts, kind, actor, 'x', prev_hash, hash FROM resp_log WHERE seq = 1 ON CONFLICT (id) DO UPDATE SET detail = 'x'`,
		`INSERT INTO resp_log (` + cols + `) SELECT seq, 'rl-new', ts, kind, actor, 'x', prev_hash, hash FROM resp_log WHERE seq = 1 ON CONFLICT (seq) DO UPDATE SET detail = excluded.detail`,
		`INSERT INTO resp_log (` + cols + `) SELECT seq, 'rl-new3', ts, kind, actor, 'x', prev_hash, hash FROM resp_log WHERE seq = 1 ON CONFLICT DO NOTHING`,
		`UPDATE OR REPLACE resp_log SET id = (SELECT id FROM resp_log WHERE seq = 2) WHERE seq = 1`,
		`INSERT OR REPLACE INTO resp_log (rowid, id, ts, kind, actor, detail, prev_hash, hash) SELECT rowid, 'rl-new4', ts, kind, actor, 'x', prev_hash, hash FROM resp_log WHERE seq = 1`,
	} {
		err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), q); return err })
		if err == nil {
			t.Errorf("accepted: %.80s", q)
		}
	}
	var n2 int
	var d2 string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT count(*) FROM resp_log`).Scan(&n2))
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT detail FROM resp_log WHERE seq = 1`).Scan(&d2))
	if n2 != n || d2 != detail {
		t.Fatalf("the log changed: %d -> %d lines, line 1 %q -> %q", n, n2, detail, d2)
	}
	if r, err := e.svc.VerifyLog(e.ctx()); err != nil || !r.OK {
		t.Fatalf("verify = %+v, %v", r, err)
	}
	e.clock.Advance(time.Minute)
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	if r, err := e.svc.VerifyLog(e.ctx()); err != nil || !r.OK {
		t.Fatalf("verify after append = %+v, %v", r, err)
	}
}

// INV-19 (L3): the append-only log cannot be grown by one row per trigger event. A burst that overflows the backlog is counted in full
// (the metric) but writes one coalesced line (and one audit line) per minute, with the count since the last line.
func TestContract_INV19_EventDropLinesAreCoalescedPerMinute(t *testing.T) {
	e := newEnv(t)
	e.svc.SetBacklogForTest(2)
	for i := range 50 {
		e.must(e.svc.StoreEvent(e.ctx(), e.iocEvent("flood-"+itoaTest(i), "198.51.100.7")))
	}
	lines := func() int {
		return e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'event_backlog%'`)
	}
	if e.svc.DroppedEvents() != 48 || lines() != 1 {
		t.Fatalf("dropped %d events, %d log lines, want 48 and 1", e.svc.DroppedEvents(), lines())
	}
	audit := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.events_dropped'`)
	if audit != 1 {
		t.Fatalf("%d audit lines, want 1", audit)
	}
	e.clock.Advance(61 * time.Second)
	e.must(e.svc.StoreEvent(e.ctx(), e.iocEvent("flood-next", "198.51.100.7")))
	if lines() != 2 || !e.logHas("refused", "event_backlog: 48 unprocessed") {
		t.Fatalf("%d log lines after a minute; the second line must carry the 47 events dropped since the first", lines())
	}
	if r, err := e.svc.VerifyLog(e.ctx()); err != nil || !r.OK {
		t.Fatalf("verify = %+v, %v", r, err)
	}
}

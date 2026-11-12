package notify_test

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify"
)

// D-215: notify_send, resolved notify_incident and notify_notice are kept 1 year; open incidents and queued notices are never deleted.
func TestRetentionDeletesOnlyHistoryOlderThanAYear(t *testing.T) {
	g := &gate{on: false} // the job is Housekeeping: it must work with the module off
	e := newEnv(t, func(c *notify.Config) { c.Modules = g })
	now := e.clock.Now()
	old, young := store.FormatTS(now.Add(-366*24*time.Hour)), store.FormatTS(now.Add(-364*24*time.Hour))
	e.write(func(tx *sql.Tx) error {
		for _, q := range []string{
			// sends: one past a year, one inside
			`INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, what, link, message) VALUES ('s-old', 'vuln', 'n-covered', 'slack', 'x', '` + old + `', 1, 'w', '/findings', '{}')`,
			`INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, what, link, message) VALUES ('s-new', 'vuln', 'n-covered', 'slack', 'x', '` + young + `', 0, 'w', '/findings', '{}')`,
			// incidents: resolved old / resolved young / open (new) very old / acknowledged very old / resolved without handled_at, old last_seen
			incident("i-res-old", "resolved", old, old), incident("i-res-new", "resolved", young, young),
			incident("i-open-new", "new", old, ""), incident("i-open-ack", "acknowledged", old, old), incident("i-res-nohandled", "resolved", old, ""),
			`INSERT INTO notify_incident_device (incident_id, asset_id, name) VALUES ('i-res-old', 'a1', 'PC')`,
			// notices: old and loose / old but queued / old but a young send still covers it / young
			notice("n-loose", old), notice("n-queued", old), notice("n-covered", old), notice("n-young", young),
			`INSERT INTO notify_notice_finding (notice_id, finding_id) VALUES ('n-loose', 'f1')`,
			`INSERT INTO notify_pending (id, channel, notice_id, notice, reason, due_at, created_at) VALUES ('pq-1', 'slack', 'n-queued', '{}', 'quiet', '` + young + `', '` + young + `')`,
			`INSERT INTO notify_send_notice (send_id, notice_id) VALUES ('s-new', 'n-covered')`,
			`INSERT INTO notify_send_notice (send_id, notice_id) VALUES ('s-old', 'n-covered')`,
		} {
			if _, err := tx.ExecContext(e.ctx(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err := e.svc.RunRetention(e.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		table, id string
		want      int
	}{
		{"notify_send", "s-old", 0}, {"notify_send", "s-new", 1},
		{"notify_incident", "i-res-old", 0}, {"notify_incident", "i-res-nohandled", 0}, {"notify_incident", "i-res-new", 1}, {"notify_incident", "i-open-new", 1}, {"notify_incident", "i-open-ack", 1},
		{"notify_notice", "n-loose", 0}, {"notify_notice", "n-queued", 1}, {"notify_notice", "n-covered", 1}, {"notify_notice", "n-young", 1},
	} {
		if n := e.count(`SELECT COUNT(*) FROM `+c.table+` WHERE id = ?`, c.id); n != c.want {
			t.Errorf("%s %s: %d rows, want %d", c.table, c.id, n, c.want)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_incident_device`) + e.count(`SELECT COUNT(*) FROM notify_notice_finding`); n != 0 {
		t.Errorf("%d rows of deleted incidents/notices are left (they follow their parent)", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_pending`); n != 1 {
		t.Errorf("the queue was touched: %d rows", n)
	}
	// one audit line for the run, with the counts; a run that deletes nothing writes none
	var detail string
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.retention'`); n != 1 {
		t.Fatalf("%d audit lines", n)
	}
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT detail FROM core_audit WHERE action = 'notify.retention'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "1 send record(s), 2 resolved incident(s), 1 vulnerability notice(s)") {
		t.Errorf("audit detail = %q", detail)
	}
	if err := e.svc.RunRetention(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.retention'`); n != 1 {
		t.Errorf("a run that deleted nothing wrote an audit line: %d", n)
	}
	// ... and the cut moves with the clock: a year later the rest of the closed history goes too, the open incident stays
	e.clock.Add(400 * 24 * time.Hour)
	if err := e.svc.RunRetention(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send`) != 0 || e.count(`SELECT COUNT(*) FROM notify_incident WHERE status = 'resolved'`) != 0 || e.count(`SELECT COUNT(*) FROM notify_incident WHERE status <> 'resolved'`) != 2 {
		t.Error("the later run did not delete the closed history, or deleted an open incident")
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending`) != 1 {
		t.Error("the queue was touched by the later run")
	}
}

func TestRetentionIsAHousekeepingJob(t *testing.T) {
	e := newEnv(t)
	found := 0
	for _, j := range e.svc.Jobs() {
		if j.Housekeeping != (j.Name == "retention") {
			t.Errorf("job %s: Housekeeping = %v", j.Name, j.Housekeeping)
		}
		if j.Name == "retention" {
			found++
			if j.Module != "notify" || j.Every < time.Hour || j.Run == nil {
				t.Errorf("job = %+v", j)
			}
		}
	}
	if found != 1 {
		t.Fatalf("%d retention jobs", found)
	}
}

func incident(id, status, lastSeen, handled string) string {
	h := "NULL"
	if handled != "" {
		h = "'" + handled + "'"
	}
	return `INSERT INTO notify_incident (id, kind, title, link, severity, what, action, first_seen, last_seen, status, handled_at, dedupe_key) VALUES ('` + id + `', 'trap', 't', '/x', 'high', 'w', 'a', '` +
		lastSeen + `', '` + lastSeen + `', '` + status + `', ` + h + `, '` + strings.Repeat(id[len(id)-1:], 64) + `')`
}

func notice(id, at string) string {
	return `INSERT INTO notify_notice (id, created_at, product, cves) VALUES ('` + id + `', '` + at + `', 'p', '[]')`
}

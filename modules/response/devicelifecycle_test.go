package response_test

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/modules/response"
)

// A finding that goes to another device with its software line takes what is still to be decided about it there: its plans, its
// pending requests and the events the rules have not run on yet name the device the finding is on now (and that device's name). What
// was already decided or done keeps the device it was about: an approved, executed, rejected or expired request and an event the rules
// already ran on are history. Rows of another finding, or of this finding on a third device, do not move.
func TestFindingMovedTakesWhatIsPendingAndKeepsHistory(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-new"] = response.DeviceInfo{ID: "a-new", Name: "web-02", IP: "192.0.2.42", Kind: "server"}
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES
		('plan-f1','f1','CVE-2024-0001','a-old','nas-01','2026-11-09T09:00:00.000Z','m','p','path','[]','[]'),
		('plan-f2','f2','CVE-2024-0002','a-old','nas-01','2026-11-09T09:00:00.000Z','m','p','path','[]','[]')`)
	for _, r := range []struct{ id, finding, asset, status string }{
		{"r-pending", "f1", "a-old", "pending"},
		{"r-approved", "f1", "a-old", "approved"},
		{"r-executed", "f1", "a-old", "executed"},
		{"r-rejected", "f1", "a-old", "rejected"},
		{"r-expired", "f1", "a-old", "expired"},
		{"r-other", "f2", "a-old", "pending"},
		{"r-third", "f1", "a-third", "pending"},
	} {
		e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES (?, 'ai', 'p', ?, 'CVE-2024-0001', ?, 'nas-01', 't', 'low', ?, '2026-11-09T09:00:00.000Z', '2026-11-10T09:00:00.000Z', 1, '[]')`,
			r.id, r.finding, r.asset, r.status)
	}
	e.exec1(`INSERT INTO resp_events (id, trigger, ts, summary, fields, asset_id, finding_id, cve, processed) VALUES
		('ev-waiting','finding','2026-11-09T09:00:00.000Z','s','{"device":"nas-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','a-old','f1','CVE-2024-0001',0),
		('ev-done','finding','2026-11-09T08:00:00.000Z','s','{"device":"nas-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','a-old','f1','CVE-2024-0001',1)`)

	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-new"})
	}); err != nil {
		t.Fatal(err)
	}

	device := func(table, id string) string {
		t.Helper()
		var asset, name string
		q := `SELECT asset_id, fields ->> '$.device' || ' ' || (fields ->> '$.ip') FROM ` + table + ` WHERE id = ?`
		if table != "resp_events" {
			q = `SELECT asset_id, asset_name FROM ` + table + ` WHERE id = ?`
		}
		if err := e.db.Reader().QueryRowContext(e.ctx(), q, id).Scan(&asset, &name); err != nil {
			t.Fatal(err)
		}
		if name != "" {
			return asset + "/" + name
		}
		return asset
	}
	for _, c := range []struct{ table, id, want string }{
		{"resp_plans", "plan-f1", "a-new/web-02"},
		{"resp_plans", "plan-f2", "a-old/nas-01"},
		{"resp_actions", "r-pending", "a-new/web-02"},
		{"resp_actions", "r-approved", "a-old/nas-01"},
		{"resp_actions", "r-executed", "a-old/nas-01"},
		{"resp_actions", "r-rejected", "a-old/nas-01"},
		{"resp_actions", "r-expired", "a-old/nas-01"},
		{"resp_actions", "r-other", "a-old/nas-01"},
		{"resp_actions", "r-third", "a-third/nas-01"},
		{"resp_events", "ev-waiting", "a-new/web-02 192.0.2.42"}, // a rule reads the device's name and address from the event
		{"resp_events", "ev-done", "a-old/nas-01 192.0.2.10"},
	} {
		if got := device(c.table, c.id); got != c.want {
			t.Errorf("%s %s: on %s, want %s", c.table, c.id, got, c.want)
		}
	}
	if n := e.count(`SELECT count(*) FROM resp_events WHERE id = 'ev-waiting' AND device_kind = 'server'`); n != 1 {
		t.Error("the waiting event kept the kind of the device the finding left")
	}
}

// When the device the finding went to cannot be named (no directory row), the rows still follow it and keep the name they stored.
func TestFindingMovedKeepsTheStoredNameWhenTheDeviceIsUnknown(t *testing.T) {
	e := newEnv(t)
	e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
		VALUES ('r1', 'ai', 'p', 'f1', 'CVE-2024-0001', 'a-old', 'nas-01', 't', 'low', 'pending', '2026-11-09T09:00:00.000Z', '2026-11-10T09:00:00.000Z', 1, '[]')`)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-gone"})
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM resp_actions WHERE id = 'r1' AND asset_id = 'a-gone' AND asset_name = 'nas-01'`); n != 1 {
		t.Fatal("the pending request did not follow the finding with its stored name")
	}
}

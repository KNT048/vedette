package main

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/exposure"
)

// D-384: a scan day of an exposure target that shows a port the previous scan day did not makes one new_port event in response,
// through exposure's own Diff. The first scan day is the baseline; a second scan on the same day does not repeat an event; nothing
// is read while exposure is off, and nothing reaches response while it is off.
func TestExposureSnapshotOpensNewPorts(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	s.setModule("exposure", true)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('xt-1', 'ip', '203.0.113.10', '', '2026-11-01T00:00:00.000Z')`)
	day := func(date string, ports ...string) {
		t.Helper()
		rows := make([]string, len(ports))
		for i, p := range ports {
			ip, port, _ := strings.Cut(p, " ")
			rows[i] = fmt.Sprintf(`{"ip":%q,"port":%s,"service":"svc-%s"}`, ip, port, port)
		}
		exec(`DELETE FROM exp_snapshot WHERE target_id = 'xt-1' AND date = ?`, date)
		exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts) VALUES (?, 'xt-1', ?, ?, '[]', ?, '[]', '[]', '{}')`,
			"sn-"+date, date, date+"T10:00:00.000Z", "["+strings.Join(rows, ",")+"]")
		if err := s.d.Bus.Publish(ctx, events.Event{Name: exposure.EventSnapshotCreated, Data: exposure.SnapshotCreatedEvent{TargetID: "xt-1", Date: date}}); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() []string {
		t.Helper()
		rows, err := s.d.DB.Reader().QueryContext(ctx, `SELECT id FROM resp_events WHERE trigger = 'new_port' ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		return out
	}
	want := func(step string, ids ...string) {
		t.Helper()
		if got := stored(); strings.Join(got, " ") != strings.Join(ids, " ") {
			t.Fatalf("%s: events %v, want %v", step, got, ids)
		}
	}

	day("2026-11-10", "203.0.113.10 443")
	want("the first scan day is the baseline")
	day("2026-11-11", "203.0.113.10 443", "203.0.113.10 8080", "2a01:4f8::5 22")
	want("two ports opened", "port:xt-1:2026-11-11:203.0.113.10:8080", "port:xt-1:2026-11-11:2a01:4f8::5:22")
	// The same day again, one more port; 443 is only spelled differently from the day before, so it is not new.
	day("2026-11-11", "::ffff:203.0.113.10 443", "203.0.113.10 8080", "2a01:4f8::5 22", "203.0.113.10 3389")
	want("a second scan of the day", "port:xt-1:2026-11-11:203.0.113.10:3389", "port:xt-1:2026-11-11:203.0.113.10:8080", "port:xt-1:2026-11-11:2a01:4f8::5:22")

	s.setModule("exposure", false)
	day("2026-11-12", "203.0.113.10 21")
	s.setModule("exposure", true)
	s.setModule("response", false)
	day("2026-11-13", "203.0.113.10 23")
	s.setModule("response", true)
	want("exposure or response off", "port:xt-1:2026-11-11:203.0.113.10:3389", "port:xt-1:2026-11-11:203.0.113.10:8080", "port:xt-1:2026-11-11:2a01:4f8::5:22")

	var many []string
	for p := 1000; p < 1000+maxPortsPerScan+5; p++ {
		many = append(many, fmt.Sprintf("203.0.113.10 %d", p))
	}
	day("2026-11-14", many...)
	if n := len(stored()) - 3; n != maxPortsPerScan {
		t.Fatalf("one scan announced %d new ports, want the cap %d", n, maxPortsPerScan)
	}
}

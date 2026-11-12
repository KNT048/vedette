package notify_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// "alerts" log source (core INV-13): the delivery log by date range, never a token.
func TestExportAlertsIsTheDeliveryLogByDateRangeWithoutTokens(t *testing.T) {
	e := newEnv(t)
	tok := strings.Join([]string{"tok", "approve", "c4e91a"}, "-")
	at := func(h int) string { return "2026-11-09T" + strings.Repeat("0", 2-len(itoa(h))) + itoa(h) + ":00:00.000Z" }
	e.write(func(tx *sql.Tx) error {
		for _, r := range []struct{ id, kind, to, link string }{
			{"s-3", "approval", "email", "/response"},
			{"s-1", "incident", "https://user:" + tok + "@hooks.company.com/path/" + tok + "?k=" + tok, "https://box.example:8443/incidents/i1?next=/approve/" + tok + "#" + tok},
			{"s-2", "approval", "#it-alerts", "https://box.example:8443/approve/" + tok},
		} {
			at := map[string]string{"s-1": at(1), "s-2": at(2), "s-3": at(3)}[r.id]
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, error, what, link, message, recipient) VALUES (?, ?, 'ref', 'slack', ?, ?, 1, NULL, 'a title', ?, ?, 'approver@acme.example')`,
				r.id, r.kind, r.to, at, r.link, `{"link":"https://box.example:8443/approve/`+tok+`"}`); err != nil {
				return err
			}
		}
		return nil
	})
	export := func(from, to time.Time) (string, []map[string]any) {
		var b bytes.Buffer
		if err := e.svc.ExportAlerts(e.ctx(), from, to, &b); err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
			if l == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("line %q: %v", l, err)
			}
			rows = append(rows, m)
		}
		return b.String(), rows
	}
	raw, rows := export(time.Time{}, time.Time{})
	if len(rows) != 3 || rows[0]["id"] != "s-1" || rows[1]["id"] != "s-2" || rows[2]["id"] != "s-3" {
		t.Fatalf("rows = %v (oldest first)", rows)
	}
	if strings.Contains(raw, tok) || strings.Contains(raw, "approver@acme.example") || strings.Contains(raw, `"message"`) {
		t.Fatalf("a token, a recipient or the message is in the export:\n%s", raw)
	}
	if rows[0]["to"] != "https://hooks.company.com" || rows[0]["link"] != "/incidents/i1" || rows[1]["link"] != "/approve/…" || rows[2]["link"] != "/response" || rows[1]["to"] != "#it-alerts" {
		t.Fatalf("to/link not cut as documented: %v", rows)
	}
	if rows[0]["ok"] != true || rows[0]["error"] != nil || rows[0]["what"] != "a title" || rows[0]["channel"] != "slack" || rows[0]["at"] != at(1) {
		t.Fatalf("row = %v", rows[0])
	}
	// both ends inclusive; a zero end is open
	_, rows = export(time.Date(2026, 11, 9, 2, 0, 0, 0, time.UTC), time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC))
	if len(rows) != 2 || rows[0]["id"] != "s-2" || rows[1]["id"] != "s-3" {
		t.Fatalf("ranged rows = %v", rows)
	}
	if _, rows = export(time.Time{}, time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)); len(rows) != 1 || rows[0]["id"] != "s-1" {
		t.Fatalf("to only = %v", rows)
	}
	if _, rows = export(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), time.Time{}); len(rows) != 0 {
		t.Fatalf("an empty range gave %v", rows)
	}
}

func itoa(n int) string { return string(rune('0'+n/10)) + string(rune('0'+n%10)) }

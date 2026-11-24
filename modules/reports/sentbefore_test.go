package reports

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
)

// A report sent before the group totals and the New section's still-open count were kept has neither field. Shown again from the
// history, it must not say "0 findings" over a group that lists rows or "0 still open" over new findings that are open: the fields
// stay absent, and the page counts the listed rows as it did before.
func TestSentBeforeTheCountsKeepsThemAbsent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveRecipients("boss@acme.example")
	item, err := e.svc.SendNow(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	err = e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(e.ctx(), `SELECT document FROM rep_history WHERE id = ?`, item.ID).Scan(&raw); err != nil {
			return err
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			return err
		}
		open, _ := doc["open"].(map[string]any)
		groups, _ := open["groups"].([]any)
		for _, g := range groups {
			delete(g.(map[string]any), "total")
		}
		if nw, ok := doc["new"].(map[string]any); ok {
			delete(nw, "open")
		}
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(e.ctx(), `UPDATE rep_history SET document = ? WHERE id = ?`, string(b), item.ID)
		return err
	})
	mustNoErr(t, err)
	got, err := NewReportsHandlers(e.svc).ReportsGetReportsHistoryID(e.ctx(), oas.ReportsGetReportsHistoryIDParams{ID: item.ID})
	mustNoErr(t, err)
	b, err := got.MarshalJSON()
	mustNoErr(t, err)
	var out struct {
		Document struct {
			Open *struct {
				Groups []map[string]json.RawMessage `json:"groups"`
			} `json:"open"`
			New map[string]json.RawMessage `json:"new"`
		} `json:"document"`
	}
	mustNoErr(t, json.Unmarshal(b, &out))
	if out.Document.Open == nil || len(out.Document.Open.Groups) == 0 || out.Document.New == nil {
		t.Fatalf("the sample report has no Still open groups or New section: %s", b)
	}
	for _, g := range out.Document.Open.Groups {
		if v, ok := g["total"]; ok {
			t.Errorf("group %s of a report sent before the totals says total %s", g["label"], strings.TrimSpace(string(v)))
		}
	}
	if v, ok := out.Document.New["open"]; ok {
		t.Errorf("New of a report sent before the count says open %s", v)
	}
}

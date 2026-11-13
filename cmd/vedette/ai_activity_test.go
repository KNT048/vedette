package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/modules/ai"
)

// seedActivity writes one chained row at the given time, the way the module does: sealed after the newest row, head moved in the same
// transaction. The AI calls themselves are not made here; the rows are what the retention and the export work on.
func seedActivity(t *testing.T, s *stack, at time.Time, n int) ai.ActivityEntry {
	t.Helper()
	var sealed ai.ActivityEntry
	err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		prev := ai.Genesis
		if err := tx.QueryRowContext(t.Context(), `SELECT hash FROM ai_activity ORDER BY seq DESC LIMIT 1`).Scan(&prev); err != nil && err != sql.ErrNoRows {
			return err
		}
		var err error
		sealed, err = ai.Seal(prev, ai.ActivityEntry{ID: fmt.Sprintf("act-seed-%d", n), TS: ai.FormatTS(at), Job: "explain-finding", Trigger: "system:test",
			InputHash: ai.HashContent("in"), OutputHash: ai.HashContent("out"), Summary: "seed", Result: ai.ResultOK})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO ai_activity (id, ts, job, profile, model, trigger, hooks, tools, input_hash, output_hash, summary, tokens_in, tokens_out, result, prev_hash, hash)
			VALUES (?, ?, ?, '', '', ?, '[]', '[]', ?, ?, ?, 0, 0, ?, ?, ?)`, sealed.ID, sealed.TS, sealed.Job, sealed.Trigger, sealed.InputHash, sealed.OutputHash, sealed.Summary, string(sealed.Result), sealed.PrevHash, sealed.Hash); err != nil {
			return err
		}
		return chainhead.Advance(t.Context(), tx, "ai_activity", sealed.Hash, at)
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// The retention prune is wired: the ai job is registered, it prunes through core's chainhead.Prune, the log still verifies from the
// anchor, and the export of the pruned log verifies on its own and says where the chain starts.
func TestAIActivityPruneEndToEnd(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	s := newStackWith(t, func(d *deps) { d.Clock = func() time.Time { return now } })
	var job func(context.Context) error
	for _, w := range wiredModules() {
		if w.ID != "ai" {
			continue
		}
		if w.Jobs == nil {
			t.Fatal("the ai module registers no job: the retention prune never runs")
		}
		names := map[string]bool{}
		for _, j := range w.Jobs(*s.d) {
			names[j.Name] = true
			switch {
			case j.Module != "ai" || (j.Name != "activity-prune" && j.Name != "activity-verify" && j.Name != "budget-watch"):
				t.Fatalf("unexpected ai job %+v", j)
			case j.Name == "activity-prune":
				job = j.Run
			}
		}
		if !names["activity-verify"] { // D-430: the daily check of the chain raises a notify incident
			t.Fatal("no activity-verify job: a broken chain is never reported")
		}
		if !names["budget-watch"] { // D-531: 80 % and 100 % of a monthly AI budget reach the alert channels
			t.Fatal("no budget-watch job: a used-up AI budget is never reported")
		}
	}
	if job == nil {
		t.Fatal("no activity-prune job")
	}
	old := []ai.ActivityEntry{
		seedActivity(t, s, now.Add(-400*24*time.Hour), 1),
		seedActivity(t, s, now.Add(-300*24*time.Hour), 2),
		seedActivity(t, s, now.Add(-100*24*time.Hour), 3),
	}
	seedActivity(t, s, now.Add(-time.Hour), 4)
	if _, err := s.d.AI.SetRetention(t.Context(), "admin@example.test", 365); err != nil {
		t.Fatal(err)
	}
	if res, err := s.d.AI.VerifyActivity(t.Context()); err != nil || !res.OK || res.Count != 4 {
		t.Fatalf("verify before = %+v, %v", res, err)
	}
	if err := job(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err := s.d.AI.ListActivity(t.Context(), ai.ActivityFilter{})
	if err != nil || page.Total != 3 {
		t.Fatalf("after the prune: total %d, %v; want 3 (only the row older than a year goes)", page.Total, err)
	}
	if res, err := s.d.AI.VerifyActivity(t.Context()); err != nil || !res.OK || res.Count != 3 {
		t.Fatalf("verify from the anchor = %+v, %v", res, err)
	}
	// the export: the rows verify against the anchor that core reports, and core says the chain is complete and pruned
	var buf bytes.Buffer
	if err := s.d.AI.ExportActivity(t.Context(), time.Time{}, time.Time{}, &buf); err != nil {
		t.Fatal(err)
	}
	var rows []ai.ActivityEntry
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var e ai.ActivityEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, e)
	}
	if len(rows) != 3 || rows[0].ID != old[1].ID || rows[0].PrevHash != old[0].Hash {
		t.Fatalf("exported rows = %d, first %+v", len(rows), rows[0])
	}
	if res := ai.VerifyChain(rows, old[0].Hash, nil); !res.OK {
		t.Fatalf("the exported rows do not verify from the anchor: %+v", res)
	}
	e, err := s.d.Logs.Build(t.Context(), logexport.Request{Categories: []string{"ai_activity"}, Format: logexport.JSON, MaxBytes: 1 << 20, ExportedAt: now, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	c := e.Chains["ai_activity"]
	if !c.Complete || c.AnchorKind != "pruned" || c.Anchor == nil || *c.Anchor != old[0].Hash || c.Count != 3 || (c.HeadHash == nil || !strings.EqualFold(*c.HeadHash, rows[2].Hash)) {
		t.Fatalf("chain info of the export = %+v", c)
	}
}

package ai_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// Slice 3 of WP-25: the activity log (S-AI-8, D-48): list, verify, retention, the export source, the prune.

// threeCalls makes an explain, a blocked explain and a connection test, ten minutes apart, and returns their rows oldest first.
func (a *api) threeCalls() []actRow {
	a.t.Helper()
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")
	a.clock.Add(10 * time.Minute)
	a.facts.mu.Lock()
	f := a.facts.cves["CVE-2022-27593"]
	f.Description += " Reported by citizen 123456789012."
	a.facts.cves["CVE-2022-27593"] = f
	a.facts.mu.Unlock()
	a.explain("CVE-2022-27593", 409, "ai_unavailable") // stopped by the personal-data hook
	a.clock.Add(10 * time.Minute)
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	rows := a.activity()
	if len(rows) != 3 {
		a.t.Fatalf("activity rows = %d, want 3", len(rows))
	}
	return rows
}

func TestActivityRolesAndRoutes(t *testing.T) {
	a := newAPI(t)
	for _, p := range []string{"/ai/activity", "/ai/activity/verify"} {
		a.want("GET", p, "", "", 401, "unauthenticated")
		a.want("GET", p, "viewer", "", 403, "forbidden")
		a.want("GET", p, "operator", "", 200, "")
	}
	a.want("GET", "/ai/activity/settings", "operator", "", 403, "forbidden")
	a.want("GET", "/ai/activity/settings", "admin", "", 200, "")
	a.want("PUT", "/ai/activity/settings", "operator", `{"retention_days":365}`, 403, "forbidden")
	// there is no way to edit or remove an entry
	a.want("DELETE", "/ai/activity", "admin", "", 405, "")
	a.want("PUT", "/ai/activity", "admin", `{}`, 405, "")
}

func TestContract_INV17_ListIsNewestFirstAndFiltered(t *testing.T) {
	a := newAPI(t)
	rows := a.threeCalls()
	got := a.want("GET", "/ai/activity", "operator", "", 200, "")
	items := got["items"].([]any)
	if len(items) != 3 || got["total"] != float64(3) || got["retention_days"] != float64(365) {
		t.Fatalf("list = %v", got)
	}
	first := items[0].(map[string]any)
	if first["job"] != "connection-test" || first["id"] != rows[2].ID || items[2].(map[string]any)["id"] != rows[0].ID {
		t.Fatalf("order = %v", items)
	}
	hash := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, it := range items {
		m := it.(map[string]any)
		if _, ok := m["hooks"].([]any); !ok {
			t.Fatalf("hooks is %v, want a list", m["hooks"])
		}
		if _, ok := m["tools"].([]any); !ok {
			t.Fatalf("tools is %v, want a list", m["tools"])
		}
		if !hash.MatchString(m["hash"].(string)) || !hash.MatchString(m["prev_hash"].(string)) || !hash.MatchString(m["input_hash"].(string)) {
			t.Fatalf("hashes of %v", m)
		}
	}
	// the filters narrow the items; the total is the size of the log
	n := func(q string) int {
		return len(a.want("GET", "/ai/activity?"+q, "operator", "", 200, "")["items"].([]any))
	}
	if n("job=explain-finding") != 2 || n("result=blocked_by_hook") != 1 || n("result=ok") != 2 || n("job=nothing") != 0 {
		t.Fatal("job and result filters")
	}
	from := rows[1].TS // the second call and after
	if n("from="+from) != 2 || n("to="+rows[0].TS) != 1 || n("from="+from+"&to="+from) != 1 {
		t.Fatal("date filters")
	}
	if total := a.want("GET", "/ai/activity?job=nothing", "operator", "", 200, "")["total"]; total != float64(3) {
		t.Fatalf("total with a filter = %v", total)
	}
	blocked := a.want("GET", "/ai/activity?result=blocked_by_hook", "operator", "", 200, "")["items"].([]any)[0].(map[string]any)
	if len(blocked["hooks"].([]any)) == 0 || blocked["tokens_in"] != float64(0) || blocked["profile"] != "" {
		t.Fatalf("blocked row = %v", blocked)
	}
}

func TestContract_INV18_VerifyAndTamper(t *testing.T) {
	a := newAPI(t)
	if v := a.want("GET", "/ai/activity/verify", "operator", "", 200, ""); v["ok"] != true || v["count"] != float64(0) {
		t.Fatalf("an empty log verifies: %v", v)
	}
	rows := a.threeCalls()
	v := a.want("GET", "/ai/activity/verify", "operator", "", 200, "")
	if v["ok"] != true || v["count"] != float64(3) || v["broken_at"] != nil || v["entry_id"] != nil {
		t.Fatalf("verify = %v", v)
	}
	// someone with the database file edits the summary of the middle row (the trigger is dropped first: the file can be edited)
	if err := a.exec(`DROP TRIGGER ai_activity_no_update`); err != nil {
		t.Fatal(err)
	}
	if err := a.exec(fmt.Sprintf(`UPDATE ai_activity SET summary = 'edited' WHERE id = '%s'`, rows[1].ID)); err != nil {
		t.Fatal(err)
	}
	v = a.want("GET", "/ai/activity/verify", "operator", "", 200, "")
	if v["ok"] != false || v["broken_at"] != float64(2) || v["entry_id"] != rows[1].ID {
		t.Fatalf("verify after an edit = %v", v)
	}
	// the newest rows are deleted: the head the box keeps says there were more
	b := newAPI(t)
	b.threeCalls()
	if err := b.exec(`DELETE FROM ai_activity WHERE seq = (SELECT max(seq) FROM ai_activity)`); err != nil {
		t.Fatal(err)
	}
	if v := b.want("GET", "/ai/activity/verify", "operator", "", 200, ""); v["ok"] != false || v["broken_at"] != float64(3) {
		t.Fatalf("verify after the newest row was deleted = %v", v)
	}
}

func TestContract_INV19_RetentionSettings(t *testing.T) {
	a := newAPI(t)
	if s := a.want("GET", "/ai/activity/settings", "admin", "", 200, ""); s["retention_days"] != float64(365) {
		t.Fatalf("default = %v", s)
	}
	a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":89}`, 400, "")
	m := a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":3651}`, 400, "invalid_retention")
	if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "90") || !strings.Contains(msg, "3650") {
		t.Fatalf("message = %q", msg)
	}
	if s := a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":90}`, 200, ""); s["retention_days"] != float64(90) {
		t.Fatalf("saved = %v", s)
	}
	if got := newAPIOver(a.env).want("GET", "/ai/activity", "operator", "", 200, ""); got["retention_days"] != float64(90) {
		t.Fatalf("after a restart = %v", got)
	}
	if rows := a.auditRows(); len(rows) == 0 || !strings.HasPrefix(rows[len(rows)-1], "ai.activity_retention 90 days") {
		t.Fatalf("audit = %q", rows)
	}
}

// ageing makes a call now, then lets the box clock run by the given days.
func (a *api) ageing(days int) {
	a.t.Helper()
	a.clock.Add(time.Duration(days) * 24 * time.Hour)
}

func TestContract_INV19_PruneKeepsTheChainVerifiable(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")                                            // row 1, at day 0
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "") // row 2, at day 0
	old := a.activity()
	a.ageing(100)
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"][0].Name = "NAS-2"
	a.facts.mu.Unlock()
	a.explain("CVE-2022-27593", 200, "") // row 3, at day 100
	a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":90}`, 200, "")
	n, err := a.svc.PruneActivity(a.ctx())
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v; want 2", n, err)
	}
	left := a.activity()
	if len(left) != 1 || left[0].PrevHash != old[1].Hash {
		t.Fatalf("rows left = %+v", left)
	}
	v := a.want("GET", "/ai/activity/verify", "operator", "", 200, "")
	if v["ok"] != true || v["count"] != float64(1) {
		t.Fatalf("verify after a prune = %v", v)
	}
	var anchor, anchorID string
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT last_pruned_hash, last_pruned_id FROM core_chain_anchor WHERE chain = 'ai_activity'`).Scan(&anchor, &anchorID); err != nil || anchor != old[1].Hash || anchorID != old[1].ID {
		t.Fatalf("anchor = %q %q, %v", anchor, anchorID, err)
	}
	head, err := chainhead.Load(a.ctx(), a.db.Reader(), "ai_activity")
	if err != nil || head == nil || head.Count != 1 || head.Hash != left[0].Hash {
		t.Fatalf("head = %+v, %v", head, err)
	}
	if n, err := a.svc.PruneActivity(a.ctx()); err != nil || n != 0 {
		t.Fatalf("a second prune removed %d, %v", n, err)
	}
	// every row ages out: the chain goes on from the anchor, not from the start
	a.ageing(400)
	if n, err := a.svc.PruneActivity(a.ctx()); err != nil || n != 1 {
		t.Fatalf("pruned %d, %v; want 1", n, err)
	}
	if rows := a.activity(); len(rows) != 0 {
		t.Fatalf("rows = %+v", rows)
	}
	if v := a.want("GET", "/ai/activity/verify", "operator", "", 200, ""); v["ok"] != true || v["count"] != float64(0) {
		t.Fatalf("verify of an empty pruned log = %v", v)
	}
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"][0].Name = "NAS-3"
	a.facts.mu.Unlock()
	a.explain("CVE-2022-27593", 200, "")
	after := a.activity()
	var lastPruned string
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT last_pruned_hash FROM core_chain_anchor WHERE chain = 'ai_activity'`).Scan(&lastPruned); err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].PrevHash != lastPruned || after[0].PrevHash == ai.Genesis {
		t.Fatalf("the first row after a full prune links to %q, want the anchor %q", after[0].PrevHash, lastPruned)
	}
	if v := a.want("GET", "/ai/activity/verify", "operator", "", 200, ""); v["ok"] != true || v["count"] != float64(1) {
		t.Fatalf("verify = %v", v)
	}
}

func TestContract_INV19_PruneNeverRemovesAYoungerRow(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "") // a row made now
	a.clock.Add(-200 * 24 * time.Hour)   // the clock steps back: the next row has an old time stamp
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	a.clock.Add(200 * 24 * time.Hour)
	a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":90}`, 200, "")
	if n, err := a.svc.PruneActivity(a.ctx()); err != nil || n != 0 {
		t.Fatalf("pruned %d, %v: a row younger than the retention came before it", n, err)
	}
	if rows := a.activity(); len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
}

func TestPruneJob(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")
	a.ageing(500)
	js := a.svc.Jobs()
	if len(js) != 1 || js[0].Module != "ai" || js[0].Name != "activity-prune" || js[0].Every < time.Hour || js[0].Run == nil {
		t.Fatalf("jobs = %+v", js)
	}
	if err := js[0].Run(a.ctx()); err != nil {
		t.Fatal(err)
	}
	if rows := a.activity(); len(rows) != 0 {
		t.Fatalf("the job left %d rows", len(rows))
	}
}

func TestContract_INV18_ExportSourceCarriesTheChain(t *testing.T) {
	a := newAPI(t)
	a.threeCalls()
	var buf bytes.Buffer
	if err := a.svc.ExportActivity(a.ctx(), time.Time{}, time.Time{}, &buf); err != nil {
		t.Fatal(err)
	}
	var entries []ai.ActivityEntry
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var e ai.ActivityEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 3 {
		t.Fatalf("exported rows = %d", len(entries))
	}
	// what is exported verifies offline: the fields are those of the hash
	if res := ai.VerifyChain(entries, "", nil); !res.OK {
		t.Fatalf("the exported chain does not verify: %+v", res)
	}
	for _, secret := range []string{keyA, "seq", "profile_id"} {
		if bytes.Contains(buf.Bytes(), []byte(secret)) {
			t.Fatalf("the export holds %q", secret)
		}
	}
	// through the registry of core: the source is the category ai_activity, and the file says the chain is complete
	reg := logexport.New()
	reg.Register("ai_activity", a.svc.ExportActivity)
	exp, err := reg.Build(a.ctx(), logexport.Request{Categories: []string{"ai_activity"}, Format: logexport.JSON, MaxBytes: 1 << 20, ExportedAt: a.clock.Now(), Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exp.Close() }()
	if c := exp.Chains["ai_activity"]; exp.Counts["ai_activity"] != 3 || !c.Complete || c.AnchorKind != "genesis" || c.Count != 3 {
		t.Fatalf("export = counts %v chains %+v", exp.Counts, exp.Chains)
	}
	// a date range and a pruned log
	buf.Reset()
	if err := a.svc.ExportActivity(a.ctx(), mustTime(t, entries[1].TS), time.Time{}, &buf); err != nil || bytes.Count(buf.Bytes(), []byte("\n")) != 2 {
		t.Fatalf("range export: %d lines, %v", bytes.Count(buf.Bytes(), []byte("\n")), err)
	}
	a.ageing(400)
	a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":90}`, 200, "")
	if n, err := a.svc.PruneActivity(a.ctx()); err != nil || n != 3 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"][0].Name = "NAS-9"
	a.facts.cves["CVE-2022-27593"] = ai.CVEFacts{CVE: "CVE-2022-27593", Vendor: "QNAP", Product: "Photo Station", Description: "Plain."}
	a.facts.mu.Unlock()
	a.explain("CVE-2022-27593", 200, "")
	exp2, err := reg.Build(a.ctx(), logexport.Request{Categories: []string{"ai_activity"}, Format: logexport.JSON, MaxBytes: 1 << 20, ExportedAt: a.clock.Now(), Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exp2.Close() }()
	if c := exp2.Chains["ai_activity"]; !c.Complete || c.AnchorKind != "pruned" {
		t.Fatalf("export of a pruned log = %+v", exp2.Chains)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestContract_INV17_ACancelledCallRowNamesTheProfile(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	ctx, cancel := context.WithCancel(a.ctx())
	defer cancel()
	a.fake.setOnCall(cancel)
	a.fake.failWith("Claude", &provider.Error{Kind: provider.ErrNetwork})
	_, _ = a.svc.ExplainCVE(ctx, "it@acme.example", "CVE-2022-27593")
	rows := a.activity()
	if len(rows) != 1 || rows[0].Profile != "Claude" || rows[0].Model != "claude-haiku-5-5" {
		t.Fatalf("cancelled row = %+v", rows)
	}
	var pid string
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT COALESCE(profile_id, '') FROM ai_activity`).Scan(&pid); err != nil || pid != id {
		t.Fatalf("profile_id = %q, %v; want %q", pid, err, id)
	}
}

func TestPruneIsOffWithoutAPruner(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")
	a.ageing(500)
	a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":90}`, 200, "") // the setting is saved
	svc, err := ai.New(a.ctx(), ai.Config{DB: a.db, Secrets: a.sec, Audit: audit.New(a.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: a.clock.Now, Factory: a.fake.factory})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := svc.PruneActivity(a.ctx()); !errors.Is(err, ai.ErrNoPruner) || n != 0 {
		t.Fatalf("prune without a pruner = %d, %v", n, err)
	}
	if len(svc.Jobs()) != 0 {
		t.Fatal("a job is offered without a pruner")
	}
	if rows := a.activity(); len(rows) != 1 {
		t.Fatalf("rows = %d: nothing may be removed without core's helper", len(rows))
	}
}

func TestPruneFailureLeavesTheLogAlone(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")
	a.want("POST", "/ai/profiles/test", "admin", cloudBody("Draft", keyA), 200, "")
	a.ageing(500)
	a.want("PUT", "/ai/activity/settings", "admin", `{"retention_days":90}`, 200, "")
	a.pruner.failWith(errors.New("core refused"))
	if n, err := a.svc.PruneActivity(a.ctx()); err == nil || n != 0 {
		t.Fatalf("prune = %d, %v; want an error", n, err)
	}
	// the delete and the move of the anchor are one transaction: nothing was removed and the chain still verifies
	if rows := a.activity(); len(rows) != 2 {
		t.Fatalf("rows = %d after a failed prune", len(rows))
	}
	if v := a.want("GET", "/ai/activity/verify", "operator", "", 200, ""); v["ok"] != true || v["count"] != float64(2) {
		t.Fatalf("verify = %v", v)
	}
	a.pruner.failWith(nil)
	if n, err := a.svc.PruneActivity(a.ctx()); err != nil || n != 2 {
		t.Fatalf("prune = %d, %v", n, err)
	}
}

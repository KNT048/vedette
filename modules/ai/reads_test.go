package ai_test

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// Slice 7 (D-311, D-312, D-119): the box's record of the reads it made through a connection is the only thing a config_read evidence
// can name, at most 24 hours old; and the activity row that links a plan to the proposals sent for it.

type offModules struct{}

func (offModules) Enabled(string) bool { return false }

func readRows(t *testing.T, a *api) []ai.ReadRecord {
	t.Helper()
	rows, err := a.db.Reader().QueryContext(a.ctx(), `SELECT id, ts, connection_id, connection_name, tool FROM ai_read ORDER BY ts`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []ai.ReadRecord
	for rows.Next() {
		var r ai.ReadRecord
		if err := rows.Scan(&r.ID, &r.TS, &r.ConnectionID, &r.ConnectionName, &r.Tool); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestConfigReadIsAReadTheBoxMade(t *testing.T) {
	a := newAskAPI(t)
	a.conns.tools = []read.ReadTool{
		{ConnectionID: "cn1", ConnectionName: "Edge firewall", Kind: "http", Name: "fetch_url", Schema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":false}`)},
		{ConnectionID: "cn2", ConnectionName: "Core switch‮", Kind: "ssh", Name: "show_run", Schema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
	}
	a.conns.out = map[string]string{"cn1/fetch_url": "status ok", "cn2/show_run": "hostname core"}
	ctx := a.ctx()

	// The model names an id it made up: nothing.
	if _, ok, err := a.svc.ConfigRead(ctx, "rd-forged"); ok || err != nil {
		t.Fatalf("a made-up id was found: %v %v", ok, err)
	}
	// Two reads that answered, and one call of a tool that was not offered: two rows, written by the runner.
	a.fake.play(turn{calls: []provider.ToolCall{call("conn_cn1__fetch_url", `{"path":"/api/status"}`), call("conn_cn2__show_run", `{}`), call("write_config", `{}`)}}, turn{text: "Status ok."})
	a.ask("What do the firewall and the switch say?", 200, "")
	rows := readRows(t, a)
	if len(rows) != 2 || rows[0].ConnectionID == rows[1].ConnectionID {
		t.Fatalf("read rows = %+v", rows)
	}
	var fw ai.ReadRecord
	for _, r := range rows {
		if r.ConnectionID == "cn1" {
			fw = r
		}
		if strings.ContainsRune(r.ConnectionName, '‮') {
			t.Errorf("a bidi control was stored: %q", r.ConnectionName)
		}
	}
	got, ok, err := a.svc.ConfigRead(ctx, fw.ID)
	if err != nil || !ok || got.ConnectionID != "cn1" || got.Tool != "fetch_url" || !strings.Contains(got.Summary, `"fetch_url"`) || !strings.Contains(got.Summary, `"Edge firewall"`) {
		t.Fatalf("lookup = %+v %v %v", got, ok, err)
	}
	if strings.Contains(got.Summary, "status ok") {
		t.Fatal("the output of the read is in the summary")
	}
	// The id is the box's: the model was never told it.
	for _, req := range a.fake.askRequests() {
		b, _ := json.Marshal(req)
		if strings.Contains(string(b), fw.ID) {
			t.Fatal("the read id reached the model")
		}
	}
	// The plan job lists only the reads of the connections it asks for.
	if l, err := a.svc.RecentReads(ctx, []string{"cn1"}); err != nil || len(l) != 1 || l[0].ID != fw.ID {
		t.Fatalf("recent reads of cn1 = %+v %v", l, err)
	}
	if l, err := a.svc.RecentReads(ctx, []string{"cn9"}); err != nil || len(l) != 0 {
		t.Fatalf("recent reads of cn9 = %+v %v", l, err)
	}
	if l, err := a.svc.RecentReads(ctx, nil); err != nil || len(l) != 0 {
		t.Fatalf("recent reads of no connection = %+v %v", l, err)
	}
	// A read that failed is not recorded.
	a.conns.err = errors.New("the device did not answer")
	a.fake.play(turn{calls: []provider.ToolCall{call("conn_cn1__fetch_url", `{"path":"/api/status"}`)}}, turn{text: "No answer."})
	a.ask("And now?", 200, "")
	if n := len(readRows(t, a)); n != 2 {
		t.Fatalf("a failed read was recorded: %d rows", n)
	}
	// With the module off the lookup finds nothing (fail closed).
	off, err := ai.New(ctx, ai.Config{DB: a.db, Secrets: a.sec, Audit: audit.New(a.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: a.clock.Now, Modules: offModules{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := off.ConfigRead(ctx, fw.ID); ok {
		t.Fatal("a read was found with the module off")
	}
	if l, _ := off.RecentReads(ctx, []string{"cn1"}); len(l) != 0 {
		t.Fatal("reads were listed with the module off")
	}
	// After 24 hours the read proves nothing; the next read recorded removes the old rows.
	a.clock.Add(ai.ReadMaxAge + time.Millisecond)
	if _, ok, _ := a.svc.ConfigRead(ctx, fw.ID); ok {
		t.Fatal("a read older than 24 hours was found")
	}
	if l, _ := a.svc.RecentReads(ctx, []string{"cn1", "cn2"}); len(l) != 0 {
		t.Fatalf("old reads listed: %+v", l)
	}
	a.conns.err = nil
	a.fake.play(turn{calls: []provider.ToolCall{call("conn_cn1__fetch_url", `{"path":"/api/status"}`)}}, turn{text: "Status ok."})
	a.ask("Once more?", 200, "")
	if rows := readRows(t, a); len(rows) != 1 || rows[0].ID == fw.ID {
		t.Fatalf("old rows were kept: %+v", rows)
	}
}

func TestRecordProposalsLinksTheActivityLog(t *testing.T) {
	a := newAPI(t)
	err := a.svc.RecordProposals(a.ctx(), ai.ProposalRecord{Summary: "Sent 2 AI-generated proposals of the response plan for CVE-2024-0001 to Response (no AI call)", Input: "f1", Output: "x",
		Links: []ai.ActivityLink{{Kind: "proposal", ID: "pr-1"}, {Kind: "action", ID: "act-1"}, {Kind: "action", ID: "bad id"}, {Kind: "other", ID: "x-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	got := a.want("GET", "/ai/activity", "admin", "", 200, "")
	items := list(got["items"])
	if len(items) != 1 {
		t.Fatalf("activity = %v", got)
	}
	row := items[0].(map[string]any)
	links, _ := json.Marshal(row["links"])
	if row["job"] != "response-plan" || row["trigger"] != "system:ai:response" || row["tokens_in"] != float64(0) || string(links) != `[{"id":"pr-1","kind":"proposal"},{"id":"act-1","kind":"action"}]` {
		t.Fatalf("row = %v links %s", row, links)
	}
	if v := a.want("GET", "/ai/activity/verify", "admin", "", 200, ""); v["ok"] != true {
		t.Fatalf("the chain does not verify: %v", v)
	}
	// The row is not a run of the job: no model was called.
	if u := a.want("GET", "/ai/usage", "admin", "", 200, ""); len(list(u["by_skill"])) != 0 {
		t.Fatalf("the row counts as a run: %v", u["by_skill"])
	}
}

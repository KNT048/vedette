package main

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-10 (D-97) in the real wiring: a connection read is evidence only when core/conn says the connection and the tool are
// there, on and read-only; the AI proposal goes through the Go port, never through HTTP.

func TestWiringConfigReadEvidenceIsReadStrictlyFromCoreConn(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	c := s.connCreate(connInput("Office firewall", "tok-0123456789-abcdef"))
	ev := responseEvidence{s.d.Conn}
	found := func(id string) bool {
		t.Helper()
		ref, ok, err := ev.ConfigRead(ctx, id)
		if err != nil {
			t.Fatalf("ConfigRead(%q): %v", id, err)
		}
		if ok && ref.Summary != "Read fetch_url on Office firewall" {
			t.Errorf("summary %q", ref.Summary)
		}
		return ok
	}
	if !found(c.ID + "/fetch_url") {
		t.Fatal("an enabled read tool of an enabled connection is not evidence")
	}
	for name, id := range map[string]string{
		"two slashes":        c.ID + "/fetch_url/x",
		"no slash":           c.ID,
		"empty tool":         c.ID + "/",
		"empty connection":   "/fetch_url",
		"a write tool":       c.ID + "/send_request",
		"no such tool":       c.ID + "/nothing",
		"no such connection": "cn-nope/fetch_url",
		"a traversal":        c.ID + "/../fetch_url",
		"a space":            c.ID + "/fetch url",
		"a newline":          c.ID + "/fetch_url\n",
		"too long":           c.ID + "/" + strings.Repeat("a", 97),
		"empty":              "",
	} {
		if found(id) {
			t.Errorf("%s: %q was accepted", name, id)
		}
	}
	update := func(f func(in *conn.Input)) {
		t.Helper()
		in := connInput("Office firewall", "")
		in.Secret = secrets.Value{}
		f(&in)
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := s.d.Conn.Update(ctx, tx, "admin@acme.example", c.ID, in)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	update(func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: "fetch_url", Enabled: false}} })
	if found(c.ID + "/fetch_url") {
		t.Error("a disabled tool is evidence")
	}
	update(func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: "fetch_url", Enabled: true}} })
	if !found(c.ID + "/fetch_url") {
		t.Fatal("the tool is not evidence again once it is on")
	}
	update(func(in *conn.Input) { in.Enabled = false })
	if found(c.ID + "/fetch_url") {
		t.Error("a read of a disabled connection is evidence")
	}
}

func TestWiringProposeThroughTheGoPort(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, m := range []string{"notify", "inventory", "response"} {
		s.setModule(m, true)
	}
	ctx := t.Context()
	c := s.connCreate(connInput("Office firewall", "tok-0123456789-abcdef"))
	svc := s.d.Response
	body := response.ProposeBody{Trigger: "finding", ActionID: "blocklist_add", Params: map[string]string{"ip": "198.51.100.7"}, Confidence: 0.9,
		Evidence: []response.ProposedEvidence{{Kind: "ioc_hit", ID: "det-1"}}, Why: "A listed address."}
	// No logs lookup is wired yet: an ioc_hit fails closed.
	_, err := svc.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_invalid")
	// A connection read the core/conn store vouches for is accepted, and the request is the AI's, pending, never pre-approved.
	body.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: c.ID + "/fetch_url"}}
	res, err := svc.Propose(ctx, body)
	if err != nil || res.Outcome != "request" || res.Request == nil || res.Request.Source != "ai" || res.Request.PreApproved || res.Request.Status != response.StatusPending {
		t.Fatalf("propose: %v %+v", err, res)
	}
	if n := s.count(`SELECT count(*) FROM resp_log WHERE kind = 'proposal' AND actor = 'ai:response'`); n != 1 {
		t.Errorf("%d proposal lines by ai:response", n)
	}
	acts, err := svc.AIActions(ctx)
	if err != nil || len(acts) == 0 {
		t.Fatalf("AIActions: %v %v", err, acts)
	}
	// The same thing over HTTP does not exist (FORBID-5).
	for _, role := range []string{"operator", "admin"} {
		code, v := s.do("POST", "/response/ai/proposals", role, `{"trigger":"finding","action_id":"blocklist_add","params":{"ip":"198.51.100.8"},"confidence":0.9,"evidence":[],"why":"x"}`)
		if code != 404 || at(v, "error", "code") != "not_found" {
			t.Errorf("POST /response/ai/proposals as %s: %d %v", role, code, v)
		}
	}
	if n := s.count(`SELECT count(*) FROM resp_actions`); n != 1 {
		t.Errorf("%d requests after the HTTP attempts, want the 1 of the port", n)
	}
}

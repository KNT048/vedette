package write_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/write"
	"github.com/knt048/vedette/core/secrets"
)

// Outcomes and read-only steps (D-94 (1), M1 and M4 of the review of 13b-6): an answer that does not say "refused" is never "nothing changed", and the
// writer is the last gate of a step that must only read.

// a write that the server answers with a redirect was received and, in the common Post/Redirect/Get pattern, applied: "303 See
// Other" after a POST means "done, look over there". The writer records it as failed ("as far as the answer shows, did not apply the
// step"), so response says "Nothing was changed", the item is not in force, the connection can be deleted and no undo is offered. An
// answer that does not say "refused" and does not say "done" is an unknown outcome (D-94 (1): ambiguous -> read back, never assume).
func TestWriterRedirectAfterAWriteIsUnknown(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var applied atomic.Bool
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			applied.Store(true) // the device did the work, then redirects to the result page
			w.Header().Set("Location", "/api/v2/block/42")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	c := r.api(f)
	res := r.do(post(c, f, "/api/v2/block", `{"ip":"198.51.100.7"}`))
	if !applied.Load() {
		t.Fatal("the fake did not see the POST")
	}
	if res.Status != write.StatusUnknown {
		t.Fatalf("the device applied the POST and answered 303; the writer says %s (%q): response will record \"Nothing was changed\" and the change is not in force", res.Status, res.Detail)
	}
}

// mcpConn is an MCP connection to f with the write tools on.
func (r *rig) mcpConn(url string, tools ...string) conn.Connection {
	r.t.Helper()
	c := r.create(conn.Input{Name: "MCP " + url, Kind: "mcp-http", Target: url + "/mcp", AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{url + "/mcp"}, Enabled: true})
	c = r.tested(c)
	var in []conn.ToolInput
	for _, t := range tools {
		in = append(in, conn.ToolInput{Name: t, Enabled: true})
	}
	return r.update(c.ID, func(x *conn.Input) { x.Tools = in })
}

// an MCP write tool that reports isError ran on the server; the MCP specification puts API failures and business-logic
// errors there, which can come after part of the work was done. The writer records "failed" (nothing applied) instead of "unknown".
func TestWriterMCPToolErrorOnAWriteIsUnknown(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{{Name: "block_ip"}}, FailTool: "block_ip"})
	c := r.mcpConn(f.URL, "block_ip")
	res := r.do(write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Tool: "block_ip", Args: json.RawMessage(`{"address":"198.51.100.7"}`)})
	if res.Status != write.StatusUnknown {
		t.Fatalf("a write tool that ran and reported an error: %s (%q), want %s (it may have been applied)", res.Status, res.Detail, write.StatusUnknown)
	}
}

// after a tools/call was sent, a JSON-RPC error is classified by whether the server's own message contains the word
// "refused": the device chooses "nothing changed" (failed) or "state unknown" by its wording. Two errors that differ only in their text
// must end the same way.
func TestWriterMCPErrorWordingDoesNotDecideTheOutcome(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var msg atomic.Value
	msg.Store("internal error")
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		b, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(b, &m)
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var out any
		switch m.Method {
		case "initialize":
			out = map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}}}
		case "tools/list":
			out = map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"tools": []map[string]any{{"name": "block_ip"}}}}
		default:
			out = map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32000, "message": msg.Load().(string)}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	c := r.mcpConn(f.URL, "block_ip")
	step := write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Tool: "block_ip", Args: json.RawMessage(`{"address":"198.51.100.7"}`)}
	a := r.do(step)
	const refusedText = "3 of 5 rules written; commit refused by peer"
	msg.Store(refusedText)
	b := r.do(step)
	if a.Status != b.Status || a.Status != write.StatusUnknown {
		t.Fatalf("the same failed tools/call: %q -> %s, %q -> %s; the server's wording picks \"nothing changed\" over \"state unknown\"", "internal error", a.Status, refusedText, b.Status)
	}
}

// a check before or a read-back is "a GET without a body", and it skips the write-tool gate. The writer's own header check
// (transport.ForbiddenHeader) lacks the method-override headers that response's forbiddenHeader refuses at save time, so a read step
// that carries X-HTTP-Method-Override: DELETE goes out, on a connection whose write tool is off. The writer says it trusts nothing it is
// handed; here it trusts that response validated the headers.
func TestWriterReadStepCannotCarryAMethodOverride(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.tested(r.create(conn.Input{Name: "Read-only API", Kind: "http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f.URL + "/api/"}, Enabled: true}))
	if len(conn.WriteTools(c)) != 0 {
		t.Fatalf("write tools on: %v", conn.WriteTools(c))
	}
	n := len(f.Requests())
	for _, h := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		s := get(c, f, write.PhaseVerify, "/api/v2/cmdb/firewall/policy/7")
		s.Headers = map[string]string{h: "DELETE"}
		res := r.do(s)
		if res.Status != write.StatusNotSent {
			got := f.Requests()[n:]
			t.Fatalf("%s: a read-back with a method override went out (%s) on a connection with no write tool; the device saw %d request(s), the last with %s=%q",
				h, res.Status, len(got), h, strings.Join(got[len(got)-1].Header.Values(h), ","))
		}
	}
}

// the same for SSH. A step whose phase says "precheck" or "verify" skips the write-tool gate, and the writer checks its lines
// for control and shell characters only: the read-only rule (data/cli-ban.json) lives in response alone. With run_approved_command off,
// a "read-back" of configure/interface/shutdown is typed into the device. The writer is the last gate (FORBID-1) and knows the phase.
func TestWriterSSHReadStepCannotTypeAChange(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(string) string { return "" }})
	c := r.tested(r.create(conn.Input{Name: "Switch (read only)", Kind: "ssh", Target: f.Addr, AuthType: "basic", Username: str(sshUsr), Secret: secrets.NewValue(sshPW),
		Allow: []string{"show version"}, Enabled: true}))
	if len(conn.WriteTools(c)) != 0 {
		t.Fatalf("write tools on: %v", conn.WriteTools(c))
	}
	res := r.do(sshStep(c, write.PhaseVerify, "configure terminal", "interface Gi1/0/1", "shutdown", "end"))
	if res.Status != write.StatusNotSent || strings.Contains(strings.Join(f.Lines(), "|"), "shutdown") {
		t.Fatalf("a read-back step typed %v into a switch whose write tool is off (%s)", f.Lines(), res.Status)
	}
}

// M2(a): an undo is held to the identity of the connection (id, kind, address), not to its fingerprint: a rotated token, a renewed pin, a changed
// allow-list or a tool switched off must not strand the undo of a change that is still in force. A run keeps the full fingerprint.
func TestWriterUndoSurvivesEditsOfTheConnectionButNotAnotherDevice(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	undo := func(cur conn.Connection) write.Step {
		return write.Step{ConnectionID: cur.ID, ConnIdentity: c.Identity(), ByIdentity: true, Phase: write.PhaseRollback, Method: "POST", URL: f.URL + "/api/v2/unblock", Body: `{}`}
	}
	back := func(cur conn.Connection) write.Step {
		return write.Step{ConnectionID: cur.ID, ConnIdentity: c.Identity(), ByIdentity: true, Phase: write.PhaseVerify, Method: "GET", URL: f.URL + "/api/v2/list"}
	}
	// The token is rotated and the write tool is switched off: the run (full fingerprint) is refused, the undo and its read-back go out.
	cur := r.update(c.ID, func(in *conn.Input) {
		in.Secret = secrets.NewValue("tok-9876543210-zyxwvu")
		in.Tools = []conn.ToolInput{{Name: "send_request", Enabled: false}}
	})
	wantStatus(t, r.do(post(c, f, "/api/v2/block", `{}`)), write.StatusConnectionChanged)
	n := len(f.Requests())
	wantStatus(t, r.do(undo(cur)), write.StatusOK)
	wantStatus(t, r.do(back(cur)), write.StatusOK)
	got := f.Requests()[n:]
	if len(got) != 2 || got[0].Header.Get("Authorization") != "Bearer tok-9876543210-zyxwvu" {
		t.Fatalf("the undo went out with %+v: it must use the connection as it is now", got)
	}
	// Another device (the address changed): not the device the change was made on. A connection that is off sends nothing either.
	other := conntest.NewHTTPS(t, nil)
	moved := r.update(c.ID, func(in *conn.Input) {
		in.Target, in.Allow, in.Secret = other.URL, []string{other.URL + "/api/"}, secrets.NewValue(token)
	})
	s := undo(moved)
	s.URL = other.URL + "/api/v2/unblock"
	wantStatus(t, r.do(s), write.StatusConnectionChanged)
	r.update(c.ID, func(in *conn.Input) { in.Enabled = false })
	wantStatus(t, r.do(undo(cur)), write.StatusNotSent)
	// Only a rollback and its read-back are steps of an undo.
	r.update(c.ID, func(in *conn.Input) { in.Enabled = true })
	bad := undo(cur)
	bad.Phase = write.PhaseRun
	wantStatus(t, r.do(bad), write.StatusNotSent)
}

// L5: a #fragment is refused; a ?query is part of the approved step and stays, the allow-list judging the path.
func TestWriterRefusesAFragmentAndKeepsTheQuery(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	wantStatus(t, r.do(post(c, f, "/api/v2/block#frag", `{}`)), write.StatusNotSent)
	n := len(f.Requests())
	wantStatus(t, r.do(post(c, f, "/api/v2/block?vdom=root", `{}`)), write.StatusOK)
	if got := f.Requests()[n:]; len(got) != 1 || got[0].RawQuery != "vdom=root" {
		t.Fatalf("the device saw %+v", got)
	}
}

// M4: the method-override headers, X-Real-IP and the others that response refuses at save time are refused by the writer on a write too.
func TestWriterRefusesTheHeadersResponseRefuses(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())
	for _, h := range []string{"Via", "X-Forwarded", "X-Real-IP", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		s := post(c, f, "/api/v2/block", `{}`)
		s.Headers = map[string]string{h: "x"}
		if res := r.do(s); res.Status != write.StatusNotSent {
			t.Errorf("%s: %s", h, res.Status)
		}
	}
	if len(f.Requests()) != n {
		t.Fatal("a request with a refused header went out")
	}
}

// M4: a read step that types a change into a switch is refused by the list of commands, and so is a read step on a connection that has the write tool on.
func TestWriterSSHReadStepsAreHeldToTheCommandBanWithTheWriteToolOn(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	c := r.sw(f)
	for _, l := range []string{"configure terminal", "conf t", "shutdown", "write memory", "reload", "write erase"} {
		if res := r.do(sshStep(c, write.PhasePrecheck, "terminal length 0", l)); res.Status != write.StatusNotSent {
			t.Errorf("%q in a check: %s", l, res.Status)
		}
	}
	if len(f.Lines()) != 0 {
		t.Fatalf("lines reached the switch: %v", f.Lines())
	}
	wantStatus(t, r.do(sshStep(c, write.PhaseVerify, "terminal length 0", "show interfaces Gi1/0/5 status")), write.StatusOK)
}

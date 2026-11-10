package write_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/write"
	"github.com/knt048/vedette/core/secrets"
)

// The writer (D-94, response FORBID-1): every refusal stops a step before a byte is sent, and what is sent is what the step says.

const (
	admin  = "admin@acme.example"
	token  = "tok-0123456789-abcdef"
	sshPW  = "pw-0123456789"
	sshUsr = "vedette"
)

type rig struct {
	t   *testing.T
	env *authtest.Env
	svc *conn.Service
	w   *write.Writer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t)
	svc, err := conn.New(conn.Config{DB: env.DB, Secrets: env.Secrets, Audit: env.Audit, Clock: env.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	w, err := write.New(write.Config{Conns: svc})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: env, svc: svc, w: w}
}

func (r *rig) create(in conn.Input) conn.Connection {
	r.t.Helper()
	var c conn.Connection
	err := r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) (err error) { c, err = r.svc.Create(r.t.Context(), tx, admin, in); return })
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *rig) update(id string, f func(*conn.Input)) conn.Connection {
	r.t.Helper()
	cur := r.get(id)
	in := conn.Input{Name: cur.Name, Kind: cur.Kind, Target: cur.Target, AuthType: cur.Auth.Type, Username: cur.Username, Allow: cur.Allow, Enabled: cur.Enabled}
	f(&in)
	var c conn.Connection
	err := r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) (err error) { c, err = r.svc.Update(r.t.Context(), tx, admin, id, in); return })
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *rig) get(id string) conn.Connection {
	r.t.Helper()
	c, err := r.svc.Get(r.t.Context(), id)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

// tested runs the first Test: it pins the certificate or host key and makes the connection ready.
func (r *rig) tested(c conn.Connection) conn.Connection {
	r.t.Helper()
	if _, err := r.svc.Test(r.t.Context(), admin, c.ID, func(context.Context, *sql.Tx) error { return nil }); err != nil {
		r.t.Fatalf("test: %v", err)
	}
	return r.get(c.ID)
}

func str(s string) *string { return &s }

// api is a ready HTTPS connection with its write tool on.
func (r *rig) api(f *conntest.HTTPS) conn.Connection {
	r.t.Helper()
	c := r.create(conn.Input{Name: "API " + f.Host, Kind: "http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f.URL + "/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}})
	return r.tested(c)
}

func (r *rig) sw(f *conntest.SSH) conn.Connection {
	r.t.Helper()
	c := r.create(conn.Input{Name: "Switch", Kind: "ssh", Target: f.Addr, AuthType: "basic", Username: str(sshUsr), Secret: secrets.NewValue(sshPW), Allow: []string{"show version"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "run_approved_command", Enabled: true}}})
	return r.tested(c)
}

func post(c conn.Connection, f *conntest.HTTPS, path, body string) write.Step {
	return write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Method: "POST", URL: f.URL + path, Body: body}
}

func get(c conn.Connection, f *conntest.HTTPS, phase, path string) write.Step {
	return write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: phase, Method: "GET", URL: f.URL + path}
}

func (r *rig) do(s write.Step) write.Result {
	r.t.Helper()
	return r.w.Do(r.t.Context(), s)
}

func wantStatus(t *testing.T, got write.Result, want write.Status) {
	t.Helper()
	if got.Status != want {
		t.Fatalf("status %s (%q), want %s", got.Status, got.Detail, want)
	}
}

// The exact request: method, path, headers and body; the credential is the connection's, sent only after the pin passed.
func TestWriterSendsTheExactRequest(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())
	s := post(c, f, "/api/v2/block", `{"ip":"198.51.100.7"}`)
	s.Headers = map[string]string{"X-Vedette-Test": "v1"}
	res := r.do(s)
	wantStatus(t, res, write.StatusOK)
	if res.Output != "" {
		t.Errorf("a write step returned output: %q", res.Output)
	}
	got := f.Requests()[n:]
	if len(got) != 1 {
		t.Fatalf("%d requests", len(got))
	}
	q := got[0]
	if q.Method != "POST" || q.Path != "/api/v2/block" || string(q.Body) != `{"ip":"198.51.100.7"}` || q.Header.Get("Authorization") != "Bearer "+token ||
		q.Header.Get("X-Vedette-Test") != "v1" || q.Header.Get("Content-Type") != "application/json" || q.Header.Get("Accept") != "application/json" {
		t.Fatalf("the device saw %+v", q)
	}
	// A read returns what the device printed (to compare and drop) and never a body of its own.
	rd := r.do(get(c, f, write.PhaseVerify, "/api/v2/list"))
	wantStatus(t, rd, write.StatusOK)
	if rd.Output != `{"ok":true}` {
		t.Errorf("read output %q", rd.Output)
	}
}

// Each refusal sends nothing: the device sees no request, not even the one that would have been refused.
func TestWriterRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())
	step := func(mod func(*write.Step)) write.Step {
		s := post(c, f, "/api/v2/block", `{"ip":"198.51.100.7"}`)
		mod(&s)
		return s
	}
	cases := map[string]struct {
		s    write.Step
		want write.Status
	}{
		"unknown id":          {step(func(s *write.Step) { s.ConnectionID = "cn-unknown" }), write.StatusNotSent},
		"changed connection":  {step(func(s *write.Step) { s.ConnFP = "0123456789abcdef0123456789abcdef" }), write.StatusConnectionChanged},
		"no phase":            {step(func(s *write.Step) { s.Phase = "" }), write.StatusNotSent},
		"outside the target":  {step(func(s *write.Step) { s.URL = "https://elsewhere.test/api/v2/block" }), write.StatusNotSent},
		"outside the allow":   {step(func(s *write.Step) { s.URL = f.URL + "/admin/reboot" }), write.StatusNotSent},
		"prefix of the allow": {step(func(s *write.Step) { s.URL = f.URL + "/api-evil/x" }), write.StatusNotSent},
		"dot segments":        {step(func(s *write.Step) { s.URL = f.URL + "/api/../admin" }), write.StatusNotSent},
		"encoded slash":       {step(func(s *write.Step) { s.URL = f.URL + "/api/v2%2Fblock" }), write.StatusNotSent},
		"encoded backslash":   {step(func(s *write.Step) { s.URL = f.URL + "/api/v2%5cblock" }), write.StatusNotSent},
		"encoded dot":         {step(func(s *write.Step) { s.URL = f.URL + "/api/%2e%2e/admin" }), write.StatusNotSent},
		"backslash":           {step(func(s *write.Step) { s.URL = f.URL + `/api/v2\block` }), write.StatusNotSent},
		"plain http":          {step(func(s *write.Step) { s.URL = strings.Replace(f.URL, "https", "http", 1) + "/api/x" }), write.StatusNotSent},
		"placeholder in url":  {step(func(s *write.Step) { s.URL = f.URL + "/api/v2/{ip}" }), write.StatusNotSent},
		"placeholder in body": {step(func(s *write.Step) { s.Body = `{"id":"{found_id}"}` }), write.StatusNotSent},
		"shown runtime value": {step(func(s *write.Step) { s.Body = `{"expiry":<expiry_s>}` }), write.StatusNotSent},
		"placeholder header":  {step(func(s *write.Step) { s.Headers = map[string]string{"X-A": "{name}"} }), write.StatusNotSent},
		"authorization":       {step(func(s *write.Step) { s.Headers = map[string]string{"Authorization": "Bearer x"} }), write.StatusNotSent},
		"host":                {step(func(s *write.Step) { s.Headers = map[string]string{"Host": "evil.test"} }), write.StatusNotSent},
		"forwarded":           {step(func(s *write.Step) { s.Headers = map[string]string{"X-Forwarded-For": "1.2.3.4"} }), write.StatusNotSent},
		"cookie":              {step(func(s *write.Step) { s.Headers = map[string]string{"cookie": "a=b"} }), write.StatusNotSent},
		"line break header":   {step(func(s *write.Step) { s.Headers = map[string]string{"X-A": "a\r\nX-B: b"} }), write.StatusNotSent},
		"odd method":          {step(func(s *write.Step) { s.Method = "TRACE" }), write.StatusNotSent},
		"read with a body":    {step(func(s *write.Step) { s.Phase, s.Method = write.PhaseVerify, "GET" }), write.StatusNotSent},
		"read that posts":     {step(func(s *write.Step) { s.Phase, s.Body = write.PhasePrecheck, "" }), write.StatusNotSent},
		"commands on an API":  {step(func(s *write.Step) { s.Lines = []string{"show version"} }), write.StatusNotSent},
		"a tool on an API":    {step(func(s *write.Step) { s.Tool = "block" }), write.StatusNotSent},
		"body too large":      {step(func(s *write.Step) { s.Body = `"` + strings.Repeat("a", 70<<10) + `"` }), write.StatusNotSent},
	}
	for name, c := range cases {
		if got := r.do(c.s); got.Status != c.want {
			t.Errorf("%s: status %s (%q), want %s", name, got.Status, got.Detail, c.want)
		}
	}
	if len(f.Requests()) != n {
		t.Fatalf("%d requests reached the device through a refusal", len(f.Requests())-n)
	}
}

// The connection is reloaded on every step: off, a write tool off, a connection that was never tested, one edited since the request.
func TestWriterReadsTheConnectionAgain(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())

	// The write tool is turned off: run and rollback are refused, a check and a read-back are not tools.
	off := r.update(c.ID, func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: "send_request", Enabled: false}} })
	s := post(off, f, "/api/v2/block", `{}`)
	wantStatus(t, r.do(s), write.StatusNotSent)
	s.Phase = write.PhaseRollback
	wantStatus(t, r.do(s), write.StatusNotSent)
	wantStatus(t, r.do(get(off, f, write.PhaseVerify, "/api/v2/list")), write.StatusOK)

	// The connection is off.
	r.update(c.ID, func(in *conn.Input) {
		in.Tools = []conn.ToolInput{{Name: "send_request", Enabled: true}}
		in.Enabled = false
	})
	cur := r.get(c.ID)
	wantStatus(t, r.do(post(cur, f, "/api/v2/block", `{}`)), write.StatusNotSent)
	wantStatus(t, r.do(get(cur, f, write.PhaseVerify, "/api/v2/list")), write.StatusNotSent)

	// It is on again, but the request was made against the version before (the fingerprint moved with each edit above).
	r.update(c.ID, func(in *conn.Input) { in.Enabled = true })
	wantStatus(t, r.do(post(c, f, "/api/v2/block", `{}`)), write.StatusConnectionChanged)
	if got := len(f.Requests()) - n; got != 1 {
		t.Fatalf("%d requests, want only the one read-back", got)
	}

	// Never tested: nothing is pinned and the connection is not ready.
	fresh := conntest.NewHTTPS(t, nil)
	untested := r.create(conn.Input{Name: "Untested", Kind: "http", Target: fresh.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{fresh.URL + "/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}})
	for _, ph := range []string{write.PhaseRun, write.PhaseRollback, write.PhasePrecheck, write.PhaseVerify} {
		s := post(untested, fresh, "/x", `{}`)
		s.Phase = ph
		if ph == write.PhasePrecheck || ph == write.PhaseVerify {
			s = get(untested, fresh, ph, "/x")
		}
		wantStatus(t, r.do(s), write.StatusNotSent)
	}
	if len(fresh.Requests()) != 0 {
		t.Fatal("a request reached a connection that was never tested")
	}
}

// A certificate that is not the pinned one gets nothing: the Authorization header goes only after the pin passed.
func TestWriterSendsNothingToAnotherCertificate(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())
	f.Rotate(t)
	res := r.do(post(c, f, "/api/v2/block", `{}`))
	wantStatus(t, res, write.StatusNotSent)
	if !strings.Contains(res.Detail, "nothing was sent") || strings.Contains(res.Detail, token) {
		t.Errorf("detail %q", res.Detail)
	}
	if len(f.Requests()) != n {
		t.Fatal("a request reached a server with another certificate")
	}
}

// Every dial goes through the address policy: a name that now points at the metadata service is not dialled.
func TestWriterDialsThroughThePolicy(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	conntest.ResolveName(t, f.Host, "169.254.169.254") // the name now points somewhere the policy refuses
	n := len(f.Requests())
	res := r.do(post(c, f, "/api/v2/block", `{}`))
	wantStatus(t, res, write.StatusNotSent)
	if !strings.Contains(res.Detail, "169.254.169.254") {
		t.Errorf("detail %q", res.Detail)
	}
	if len(f.Requests()) != n {
		t.Fatal("a request went to a refused address")
	}
}

// What the device answered decides the status: 2xx ok, 4xx failed (nothing applied), 5xx unknown (may have been applied), and a read that
// fails just failed.
func TestWriterStatusFollowsTheAnswer(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var code atomic.Int32
	code.Store(200)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(code.Load()))
		_, _ = io.WriteString(w, "token "+token+" echoed")
	}))
	c := r.api(f)
	for _, tc := range []struct {
		code  int32
		phase string
		want  write.Status
	}{{200, write.PhaseRun, write.StatusOK}, {204, write.PhaseRun, write.StatusOK}, {404, write.PhaseRun, write.StatusFailed}, {401, write.PhaseRun, write.StatusFailed},
		{302, write.PhaseRun, write.StatusUnknown}, {303, write.PhaseRollback, write.StatusUnknown}, {302, write.PhaseVerify, write.StatusFailed}, {500, write.PhaseRun, write.StatusUnknown}, {503, write.PhaseRollback, write.StatusUnknown},
		{500, write.PhaseVerify, write.StatusFailed}, {404, write.PhasePrecheck, write.StatusFailed}} {
		code.Store(tc.code)
		s := post(c, f, "/api/v2/block", `{}`)
		s.Phase = tc.phase
		if tc.phase == write.PhaseVerify || tc.phase == write.PhasePrecheck {
			s = get(c, f, tc.phase, "/api/v2/list")
		}
		res := r.do(s)
		if res.Status != tc.want {
			t.Errorf("HTTP %d in %s: %s (%q), want %s", tc.code, tc.phase, res.Status, res.Detail, tc.want)
		}
		if strings.Contains(res.Detail, token) || res.Output != "" && tc.want != write.StatusOK {
			t.Errorf("HTTP %d: detail %q output %q", tc.code, res.Detail, res.Output)
		}
	}
}

// One call at a time per connection (D-94 (6)): four steps sent together reach the device one after the other.
func TestWriterRunsOneCallAtATimePerConnection(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var inFlight, peak atomic.Int32
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		now := inFlight.Add(1)
		for {
			p := peak.Load()
			if now <= p || peak.CompareAndSwap(p, now) {
				break
			}
		}
		hold := time.NewTimer(60 * time.Millisecond)
		select {
		case <-hold.C:
		case <-req.Context().Done():
			hold.Stop()
		}
		inFlight.Add(-1)
		_, _ = io.WriteString(w, `{}`)
	}))
	c := r.api(f)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wantStatus(t, r.do(post(c, f, "/api/v2/block", `{}`)), write.StatusOK)
		}()
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("%d calls were in flight at once", peak.Load())
	}
	// A step that waits for its turn gives up with its context, and sends nothing.
	release, started := make(chan struct{}), make(chan struct{})
	var once sync.Once
	slow := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			once.Do(func() { close(started) })
			<-release
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	c2 := r.api(slow)
	done := make(chan write.Result, 1)
	go func() { done <- r.do(post(c2, slow, "/api/x", `{}`)) }()
	<-started // the first step holds the connection's turn
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	wait := r.w.Do(ctx, post(c2, slow, "/api/y", `{}`))
	wantStatus(t, wait, write.StatusNotSent)
	close(release)
	wantStatus(t, <-done, write.StatusOK)
	for _, q := range slow.Requests() {
		if q.Path == "/api/y" {
			t.Fatal("a step that never got its turn reached the device")
		}
	}
}

// The budgets are the transport's: HTTP and MCP calls 15 s, an SSH line 20 s, a session 60 s, an item step 90 s.
func TestWriterBudgets(t *testing.T) {
	t.Parallel()
	if write.CallBudget != 15*time.Second || write.LineBudget != 20*time.Second || write.SessionBudget != 60*time.Second || write.StepBudget != 90*time.Second {
		t.Fatalf("budgets: %v %v %v %v", write.CallBudget, write.LineBudget, write.SessionBudget, write.StepBudget)
	}
}

// ---- SSH ----

func sshStep(c conn.Connection, phase string, lines ...string) write.Step {
	return write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: phase, Lines: lines}
}

// The lines go out one at a time, after the host key matched; a read returns the output of every line.
func TestWriterSendsSSHLinesAndStopsAfterAnError(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		switch {
		case line == "show interfaces Gi1/0/5":
			return "GigabitEthernet1/0/5 is up"
		case strings.HasPrefix(line, "interface bad"), line == "show bad3":
			return "% Invalid input detected at '^' marker."
		}
		return ""
	}})
	c := r.sw(f)
	res := r.do(sshStep(c, write.PhaseRun, "terminal length 0", "configure terminal", "interface Gi1/0/5", "shutdown", "end"))
	wantStatus(t, res, write.StatusOK)
	if want := []string{"terminal length 0", "configure terminal", "interface Gi1/0/5", "shutdown", "end"}; strings.Join(f.Lines(), "|") != strings.Join(want, "|") {
		t.Fatalf("lines %v", f.Lines())
	}
	if res.Output != "" || res.Detail != "5 commands sent" {
		t.Errorf("result %+v", res)
	}
	rd := r.do(sshStep(c, write.PhasePrecheck, "terminal length 0", "show interfaces Gi1/0/5"))
	wantStatus(t, rd, write.StatusOK)
	if !strings.Contains(rd.Output, "GigabitEthernet1/0/5 is up") {
		t.Errorf("read output %q", rd.Output)
	}

	// A refused line of a write is an unknown outcome, whichever line it is: the wording of the device never decides "nothing changed". The
	// lines after the error are never sent.
	n := len(f.Lines())
	bad := r.do(sshStep(c, write.PhaseRun, "interface bad1", "shutdown"))
	wantStatus(t, bad, write.StatusUnknown)
	half := r.do(sshStep(c, write.PhaseRun, "terminal length 0", "interface bad2", "shutdown", "end"))
	wantStatus(t, half, write.StatusUnknown)
	if got := f.Lines()[n:]; strings.Join(got, "|") != "interface bad1|terminal length 0|interface bad2" {
		t.Fatalf("lines after the errors: %v", got)
	}
	if !strings.Contains(half.Detail, "Invalid input") || strings.Contains(half.Detail, sshPW) {
		t.Errorf("detail %q", half.Detail)
	}
	// A read that fails just failed.
	wantStatus(t, r.do(sshStep(c, write.PhaseVerify, "show bad3")), write.StatusFailed)
}

// A control character in a line is refused before any session is opened: one approved line stays one line.
func TestWriterRefusesControlCharactersInCommands(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	c := r.sw(f)
	logins := f.Logins()
	for name, l := range map[string]string{"escape": "show \x1b[2J", "ctrl-z": "end\x1a", "ctrl-u": "x\x15shutdown", "newline": "a\nshutdown", "carriage return": "a\rshutdown", "nul": "a\x00b", "tab": "a\tb",
		"c1": "a\u0085b", "del": "a\x7fb", "shell": "show version; reboot", "pipe": "show run | include x", "empty": "  ", "long": strings.Repeat("a", 600)} {
		if res := r.do(sshStep(c, write.PhaseRun, "configure terminal", l)); res.Status != write.StatusNotSent {
			t.Errorf("%s: %s (%q)", name, res.Status, res.Detail)
		}
	}
	for name, s := range map[string]write.Step{
		"no lines":       sshStep(c, write.PhaseRun),
		"too many lines": sshStep(c, write.PhaseRun, make([]string, 65)...),
		"a url":          {ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Lines: []string{"x"}, URL: "https://x.test/"},
		"a placeholder":  sshStep(c, write.PhaseRun, "interface {interface}"),
		"a shown value":  sshStep(c, write.PhaseRun, "no <seq>"),
	} {
		for i := range s.Lines {
			if s.Lines[i] == "" && name == "too many lines" {
				s.Lines[i] = "x"
			}
		}
		if res := r.do(s); res.Status != write.StatusNotSent {
			t.Errorf("%s: %s", name, res.Status)
		}
	}
	if len(f.Lines()) != 0 || f.Logins() != logins {
		t.Fatalf("something reached the switch: %v, %d new logins", f.Lines(), f.Logins()-logins)
	}
}

// A switch with another host key gets no credential and no line.
func TestWriterSendsNothingToAnotherHostKey(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	c := r.sw(f)
	calls := f.AuthCalls()
	f.RotateHostKey(t)
	res := r.do(sshStep(c, write.PhaseRun, "terminal length 0", "shutdown"))
	wantStatus(t, res, write.StatusNotSent)
	if f.AuthCalls() != calls || len(f.Lines()) != 0 {
		t.Fatalf("a credential or a line reached a switch with another host key (%d auth calls, lines %v)", f.AuthCalls()-calls, f.Lines())
	}
}

// A line that never gets its prompt is ended by the context of the step, and the outcome is unknown: the line was sent.
func TestWriterEndsAHungLineThroughTheContext(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	// The context ends once the hung line has reached the device, not after a fixed time: on a loaded machine a fixed
	// 400 ms could end before the session was even up, which is a different case (nothing sent).
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		if line == "hang" {
			time.AfterFunc(100*time.Millisecond, cancel)
			<-hang
		}
		return ""
	}})
	c := r.sw(f)
	start := time.Now()
	res := r.w.Do(ctx, sshStep(c, write.PhaseRun, "terminal length 0", "hang", "end"))
	if res.Status != write.StatusUnknown || time.Since(start) > 10*time.Second {
		t.Fatalf("%s (%q) after %v", res.Status, res.Detail, time.Since(start))
	}
	if got := f.Lines(); strings.Join(got, "|") != "terminal length 0|hang" {
		t.Fatalf("lines %v", got)
	}
}

// ---- MCP ----

// The arguments of a tool are typed JSON values, sent as they are; a tool that is off is refused, a tool that reports an error failed.
func TestWriterCallsAnMCPToolWithTypedArguments(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{{Name: "block_ip"}, {Name: "unblock_ip"}, {Name: "broken"}}, FailTool: "broken"})
	c := r.create(conn.Input{Name: "MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f.URL + "/mcp"}, Enabled: true})
	c = r.tested(c) // finds the tools: write tools that start off
	tools := []conn.ToolInput{{Name: "block_ip", Enabled: true}, {Name: "broken", Enabled: true}}
	c = r.update(c.ID, func(in *conn.Input) { in.Tools = tools })
	step := func(tool, args string) write.Step {
		return write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Tool: tool, Args: json.RawMessage(args)}
	}
	n := len(f.Calls())
	res := r.do(step("block_ip", `{"address":"198.51.100.7","ttl":3600,"big":12345678901234567890,"flags":["a","b"],"on":true,"nested":{"x":null}}`))
	wantStatus(t, res, write.StatusOK)
	var call *conntest.MCPCall
	for _, x := range f.Calls()[n:] {
		if x.RPCMethod == "tools/call" {
			call = &x
		}
	}
	if call == nil || call.Authorization != "Bearer "+token || call.Args["address"] != "198.51.100.7" || call.Args["ttl"] != float64(3600) || call.Args["on"] != true {
		t.Fatalf("the server saw %+v", call)
	}
	if fl, _ := call.Args["flags"].([]any); len(fl) != 2 || fl[0] != "a" {
		t.Errorf("flags %v", call.Args["flags"])
	}
	wantStatus(t, r.do(step("broken", `{}`)), write.StatusUnknown) // a write tool that reports an error may have done part of the work
	// A tool that is off (unblock_ip), a tool that is not named, arguments that are not an object, an address of the step.
	before := len(f.Calls())
	wantStatus(t, r.do(step("unblock_ip", `{}`)), write.StatusNotSent)
	wantStatus(t, r.do(step("", `{}`)), write.StatusNotSent)
	wantStatus(t, r.do(step("block_ip", `[1]`)), write.StatusNotSent)
	wantStatus(t, r.do(step("block_ip", `{"a":"{ip}"}`)), write.StatusNotSent)
	wantStatus(t, r.do(write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Tool: "block_ip", URL: f.URL + "/other"}), write.StatusNotSent)
	wantStatus(t, r.do(write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseVerify, Tool: "block_ip"}), write.StatusNotSent)
	if len(f.Calls()) != before {
		t.Fatalf("%d calls went through refusals", len(f.Calls())-before)
	}
}

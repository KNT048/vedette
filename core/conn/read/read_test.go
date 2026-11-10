package read_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/core/conn/write"
	"github.com/knt048/vedette/core/secrets"
)

// The reader (D-93 (3), core INV-23, ai INV-14): the AI's only way to a device. Each refusal sends nothing; what is sent is a GET, one
// allow-listed command line, or a call of an MCP tool marked read.

const (
	admin  = "admin@acme.example"
	token  = "tok-0123456789-abcdef"
	sshPW  = "pw-0123456789"
	sshUsr = "vedette"
)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type rig struct {
	t   *testing.T
	env *authtest.Env
	svc *conn.Service
	r   *read.Reader
	log *logBuf
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t)
	svc, err := conn.New(conn.Config{DB: env.DB, Secrets: env.Secrets, Audit: env.Audit, Clock: env.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	lb := &logBuf{}
	r, err := read.New(read.Config{Conns: svc, Log: slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: env, svc: svc, r: r, log: lb}
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

func (r *rig) test(c conn.Connection) error {
	_, err := r.svc.Test(r.t.Context(), admin, c.ID, func(context.Context, *sql.Tx) error { return nil })
	return err
}

func (r *rig) tested(c conn.Connection) conn.Connection {
	r.t.Helper()
	if err := r.test(c); err != nil {
		r.t.Fatalf("test: %v", err)
	}
	return r.get(c.ID)
}

// pause waits on a timer (a test that waits for the real clock: the connection's turn is not a thing a fake clock moves).
func pause(d time.Duration) { <-time.After(d) }

func str(s string) *string { return &s }

// defaultReads are the addresses (path and query) that a connection of api names as readable.
var defaultReads = []string{"/api/v1/status", "/api/x", "/api/echo", "/api/fail", "/api/hop", "/api/slow", "/api/first", "/api/second", "/api/n0", "/api/n1", "/api/big"}

// api is a ready HTTPS connection: fetch_url is on, with the addresses in reads (defaultReads) as exact entries of the allow-list
// next to the prefix /api/ that the writer uses; send_request is on too.
func (r *rig) api(f *conntest.HTTPS, reads ...string) conn.Connection {
	r.t.Helper()
	if len(reads) == 0 {
		reads = defaultReads
	}
	allow := []string{f.URL + "/api/"}
	for _, p := range reads {
		allow = append(allow, f.URL+p)
	}
	c := r.create(conn.Input{Name: "API " + f.Host, Kind: "http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: allow, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}, {Name: "fetch_url", Enabled: true}}})
	return r.tested(c)
}

func (r *rig) sw(f *conntest.SSH, allow ...string) conn.Connection {
	r.t.Helper()
	if len(allow) == 0 {
		allow = []string{"show version"}
	}
	c := r.create(conn.Input{Name: "Switch " + f.Host, Kind: "ssh", Target: f.Addr, AuthType: "basic", Username: str(sshUsr), Secret: secrets.NewValue(sshPW), Allow: allow, Enabled: true,
		Tools: []conn.ToolInput{{Name: "run_approved_command", Enabled: true}}})
	return r.tested(c)
}

// mcp is a ready MCP connection with the tools in read on.
func (r *rig) mcp(f *conntest.MCP, read ...string) conn.Connection {
	r.t.Helper()
	c := r.create(conn.Input{Name: "MCP " + f.Host, Kind: "mcp-http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f.URL}, Enabled: true})
	c = r.tested(c)
	return r.update(c.ID, func(in *conn.Input) {
		for _, n := range read {
			in.Tools = append(in.Tools, conn.ToolInput{Name: n, Enabled: true, Access: str("read")})
		}
	})
}

func (r *rig) call(c conn.Connection, tool string, args map[string]any) (string, error) {
	r.t.Helper()
	return r.r.CallRead(read.WithActor(r.t.Context(), "ai:job-7"), c.ID, tool, args)
}

func (r *rig) mustCall(c conn.Connection, tool string, args map[string]any) string {
	r.t.Helper()
	out, err := r.call(c, tool, args)
	if err != nil {
		r.t.Fatalf("%s: %v", tool, err)
	}
	return out
}

func (r *rig) list() []read.ReadTool {
	r.t.Helper()
	l, err := r.r.ListReadTools(r.t.Context())
	if err != nil {
		r.t.Fatal(err)
	}
	return l
}

func (r *rig) wantRefused(c conn.Connection, tool string) {
	r.t.Helper()
	if out, err := r.call(c, tool, nil); !errors.Is(err, read.ErrUnavailable) || out != "" {
		r.t.Fatalf("%s: got %q, %v; want the refusal", tool, out, err)
	}
}

func toolNames(l []read.ReadTool) []string {
	var out []string
	for _, t := range l {
		out = append(out, t.ConnectionName+"/"+t.Name)
	}
	return out
}

// ListReadTools: only what the AI may use.
func TestListReadTools_OnlyReadToolsThatAreOn(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f1, f2, f3, f4 := conntest.NewHTTPS(t, nil), conntest.NewHTTPS(t, nil), conntest.NewHTTPS(t, nil), conntest.NewHTTPS(t, nil)
	good := r.api(f1)
	toolOff := r.api(f2)
	r.update(toolOff.ID, func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: "fetch_url", Enabled: false}} })
	off := r.api(f3)
	r.update(off.ID, func(in *conn.Input) { in.Enabled = false })
	untested := r.create(conn.Input{Name: "Untested", Kind: "http", Target: f4.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f4.URL + "/api/"}, Enabled: true})
	f5 := conntest.NewHTTPS(t, nil)
	failed := r.api(f5)
	f5.Rotate(t)
	if err := r.test(failed); err == nil {
		t.Fatal("the test of a rotated certificate passed")
	}
	if r.get(failed.ID).Status == "ok" {
		t.Fatal("the connection is still ok")
	}
	ssh := conntest.NewSSH(t, conntest.SSHOpts{})
	sw := r.sw(ssh)

	got := toolNames(r.list())
	want := []string{good.Name + "/fetch_url", sw.Name + "/run_allowed_command"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tools %v, want %v (not: write tools, a tool that is off, %s, %s, %s)", got, want, off.Name, untested.Name, failed.Name)
	}
	for _, rt := range r.list() {
		if !json.Valid(rt.Schema) {
			t.Errorf("%s: schema is not JSON: %s", rt.Name, rt.Schema)
		}
	}
}

func TestListReadTools_MCPTools(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{
		{Name: "get_status", Description: "Status", Schema: `{"type":"object","properties":{"zone":{"type":"string"}}}`},
		{Name: "block_ip", Description: "Block"}, {Name: "gone", Description: "Gone"}}})
	r.mcp(f, "get_status", "gone")
	// "block_ip" is a write tool that is off; "gone" is read and on but the server does not list it any more.
	l := r.list()
	if len(l) != 2 {
		t.Fatalf("tools %v", toolNames(l))
	}
	for _, rt := range l {
		if rt.Name == "get_status" && !strings.Contains(string(rt.Schema), `"zone"`) {
			t.Errorf("the server's schema is not given: %s", rt.Schema)
		}
		if rt.Name == "gone" && !strings.Contains(string(rt.Schema), `"object"`) {
			t.Errorf("a tool without a schema gets %s", rt.Schema)
		}
	}
}

func TestListReadTools_HoldsNoSecret(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	r.api(f)
	ssh := conntest.NewSSH(t, conntest.SSHOpts{})
	r.sw(ssh)
	m := conntest.NewMCP(t, conntest.MCPOpts{})
	r.mcp(m, "list_resources")
	l := r.list()
	if len(l) != 3 {
		t.Fatalf("tools %v", toolNames(l))
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, sshPW, sshUsr, "Bearer", "Authorization", "@", ssh.Addr} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the list holds %q: %s", secret, b)
		}
	}
	if r.log.String() != "" && strings.Contains(r.log.String(), token) {
		t.Error("the log holds the token")
	}
}

// A write tool, an unknown tool, a tool that is off, a connection that is off or not ready and an unknown id are one refusal, and the
// device sees nothing.
func TestCallRead_OneRefusalForEverythingUnavailable(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())

	fOff := conntest.NewHTTPS(t, nil)
	cOff := r.api(fOff)
	r.update(cOff.ID, func(in *conn.Input) { in.Enabled = false })
	fTool := conntest.NewHTTPS(t, nil)
	cTool := r.api(fTool)
	r.update(cTool.ID, func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: "fetch_url", Enabled: false}} })
	fNew := conntest.NewHTTPS(t, nil)
	cNew := r.create(conn.Input{Name: "New", Kind: "http", Target: fNew.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{fNew.URL + "/api/"}, Enabled: true})
	fBad := conntest.NewHTTPS(t, nil)
	cBad := r.api(fBad)
	fBad.Rotate(t)
	_ = r.test(cBad)
	mf := conntest.NewMCP(t, conntest.MCPOpts{})
	cm := r.mcp(mf, "list_resources")

	seen := map[*conntest.HTTPS]int{fOff: len(fOff.Requests()), fTool: len(fTool.Requests()), fNew: len(fNew.Requests())} // the Tests of the set-up
	errs := map[string]error{}
	for name, p := range map[string]struct {
		c    conn.Connection
		tool string
	}{
		"write tool":           {c, "send_request"},
		"unknown tool":         {c, "no_such_tool"},
		"empty tool":           {c, ""},
		"tool of another kind": {c, "run_allowed_command"},
		"unknown id":           {conn.Connection{ID: "cn-unknown"}, "fetch_url"},
		"connection off":       {cOff, "fetch_url"},
		"tool off":             {cTool, "fetch_url"},
		"never tested":         {cNew, "fetch_url"},
		"last test failed":     {cBad, "fetch_url"},
		"mcp write tool":       {cm, "run_action"},
		"mcp unknown":          {cm, "nope"},
	} {
		_, err := r.call(p.c, p.tool, map[string]any{"path": "/api/x"})
		if !errors.Is(err, read.ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
		errs[name] = err
	}
	var first string
	for name, err := range errs {
		if first == "" {
			first = err.Error()
		}
		if err.Error() != first {
			t.Errorf("%s: the refusal differs: %q vs %q", name, err.Error(), first)
		}
	}
	if len(f.Requests()) != n {
		t.Errorf("the device saw %d requests", len(f.Requests())-n)
	}
	for _, d := range []*conntest.HTTPS{fOff, fTool, fNew} {
		if len(d.Requests()) != seen[d] {
			t.Errorf("%s saw a request", d.Host)
		}
	}
	for _, mc := range mf.Calls() {
		if mc.RPCMethod == "tools/call" {
			t.Error("the MCP server saw a tool call")
		}
	}
}

// The exact request: a GET of an address the allow-list names, with the connection's sign-in and no body.
func TestCallRead_HTTPSendsOneGET(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"up":3}`) }))
	c := r.api(f, "/api/v1/status", "/api/v1/items?kind=a&limit=5")
	n := len(f.Requests())
	if out := r.mustCall(c, "fetch_url", map[string]any{"path": "/api/v1/status"}); out != `{"up":3}` {
		t.Errorf("output %q", out)
	}
	r.mustCall(c, "fetch_url", map[string]any{"path": "/api/v1/items?kind=a&limit=5"})
	got := f.Requests()[n:]
	if len(got) != 2 {
		t.Fatalf("%d requests", len(got))
	}
	q := got[0]
	if q.Method != "GET" || q.Path != "/api/v1/status" || q.RawQuery != "" || len(q.Body) != 0 ||
		q.Header.Get("Authorization") != "Bearer "+token || q.Header.Get("Accept") != "application/json" || q.Header.Get("Content-Type") != "" {
		t.Fatalf("the device saw %+v", q)
	}
	if got[1].Method != "GET" || got[1].Path != "/api/v1/items" || got[1].RawQuery != "kind=a&limit=5" {
		t.Fatalf("the device saw %+v", got[1])
	}
	// RESTCONF: the same rule, its own Accept.
	r2 := newRig(t)
	f2 := conntest.NewHTTPS(t, nil)
	c2 := r2.create(conn.Input{Name: "Root", Kind: "netconf-restconf", Target: f2.URL + "/restconf", AuthType: "basic", Username: str("u-admin"), Secret: secrets.NewValue("pw-restconf"),
		Allow: []string{f2.URL + "/restconf/data/interfaces"}, Enabled: true, Tools: []conn.ToolInput{{Name: "get_config", Enabled: true}}})
	c2 = r2.tested(c2)
	m := len(f2.Requests())
	r2.mustCall(c2, "get_config", map[string]any{"path": "/restconf/data/interfaces"})
	rc := f2.Requests()[m:]
	if len(rc) != 1 || rc[0].Method != "GET" || rc[0].Path != "/restconf/data/interfaces" || rc[0].Header.Get("Accept") != "application/yang-data+json" || !strings.HasPrefix(rc[0].Header.Get("Authorization"), "Basic ") {
		t.Fatalf("restconf request %+v", rc)
	}
}

// Every refusal of the arguments stops the call before a byte is sent.
func TestCallRead_HTTPArgumentsAreCheckedAtTheEdge(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())
	big := strings.Repeat("a", 3000)
	many := map[string]any{}
	for i := range 20 {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	cases := map[string]map[string]any{
		"unknown param":        {"path": "/api/x", "method": "POST"},
		"body":                 {"path": "/api/x", "body": "{}"},
		"headers":              {"path": "/api/x", "headers": map[string]any{"X": "y"}},
		"url instead of path":  {"url": f.URL + "/api/x"},
		"path is a number":     {"path": 5},
		"no leading slash":     {"path": "api/x"},
		"outside the allow":    {"path": "/admin/reboot"},
		"prefix of the allow":  {"path": "/api-evil/x"},
		"dot segments":         {"path": "/api/../admin"},
		"dot segment":          {"path": "/api/./x"},
		"empty segment":        {"path": "/api//x"},
		"encoded slash":        {"path": "/api/v2%2Fx"},
		"encoded backslash":    {"path": "/api/v2%5cx"},
		"encoded dot":          {"path": "/api/%2e%2e/admin"},
		"percent":              {"path": "/api/a%20b"},
		"backslash":            {"path": `/api/v2\x`},
		"query in the path":    {"path": "/api/x?admin=1"},
		"fragment":             {"path": "/api/x#y"},
		"placeholder":          {"path": "/api/{ip}"},
		"runtime placeholder":  {"path": "/api/<seq>"},
		"placeholder in query": {"path": "/api/x", "query": map[string]any{"a": "{name}"}},
		"control in path":      {"path": "/api/x\x01"},
		"newline in path":      {"path": "/api/x\nHost: evil"},
		"bidi in path":         {"path": "/api/x\u202e"},
		"control in query":     {"path": "/api/x", "query": map[string]any{"a": "b\r\nc"}},
		"query key":            {"path": "/api/x", "query": map[string]any{"a b": "c"}},
		"query is a string":    {"path": "/api/x", "query": "a=b"},
		"query value nested":   {"path": "/api/x", "query": map[string]any{"a": []any{"b"}}},
		"too many query keys":  {"path": "/api/x", "query": many},
		"path too long":        {"path": "/api/" + strings.Repeat("a", 600)},
		"string too long":      {"path": "/api/x", "query": map[string]any{"a": big}},
		"arguments too large":  {"path": "/api/x", "query": map[string]any{"a": big, "b": big, "c": big, "d": big}},
		"not JSON":             {"path": "/api/x", "query": map[string]any{"a": make(chan int)}},
	}
	for name, args := range cases {
		out, err := r.call(c, "fetch_url", args)
		switch {
		case err == nil:
			t.Errorf("%s: passed with %q", name, out)
		case errors.Is(err, read.ErrUnavailable):
			t.Errorf("%s: the tool was refused, not the arguments", name)
		case strings.ContainsAny(err.Error(), "\r\n"):
			t.Errorf("%s: the error is not one line: %q", name, err)
		}
	}
	if len(f.Requests()) != n {
		t.Errorf("the device saw %d requests", len(f.Requests())-n)
	}
	for _, q := range f.Requests() {
		if q.Method != "GET" {
			t.Errorf("a %s reached the device", q.Method)
		}
	}
}

// A redirect is an answer, not an instruction (D-94 (1)).
func TestCallRead_RedirectIsNotFollowed(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/hop" {
			http.Redirect(w, req, "/api/landed", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "landed")
	}))
	c := r.api(f)
	n := len(f.Requests())
	out, err := r.call(c, "fetch_url", map[string]any{"path": "/api/hop"})
	if err == nil || out != "" || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("got %q, %v", out, err)
	}
	if got := f.Requests()[n:]; len(got) != 1 || got[0].Path != "/api/hop" {
		t.Fatalf("the device saw %+v", got)
	}
}

func TestCallRead_HTTPErrorStatusesAreOneLineWithoutTheBody(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/api/") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "denied for Bearer "+token+"\nsecond line")
		}
	}))
	c := r.api(f)
	_, err := r.call(c, "fetch_url", map[string]any{"path": "/api/x"})
	if err == nil || err.Error() != "the device answered HTTP 403" {
		t.Fatalf("got %v", err)
	}
}

// Output is cleaned and capped; the cap leaves a marker.
func TestCallRead_OutputIsCleanedAndCapped(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	body := "line1\nline2\ttab\x1b[31mred\x00\u202eevil\u200bz\r\n" + strings.Repeat("x", 200<<10)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	c := r.api(f)
	out := r.mustCall(c, "fetch_url", map[string]any{"path": "/api/big"})
	if !strings.HasSuffix(out, read.Truncated) {
		t.Fatalf("no marker at the end: %q", out[len(out)-40:])
	}
	if len(out) > read.MaxOutput+len(read.Truncated) {
		t.Errorf("%d bytes returned", len(out))
	}
	if !strings.HasPrefix(out, "line1\nline2\ttabredevilz\n") {
		t.Errorf("not cleaned: %q", out[:60])
	}
	for _, bad := range []string{"\x1b", "\x00", "\u202e", "\u200b", "\r"} {
		if strings.Contains(out, bad) {
			t.Errorf("output holds %q", bad)
		}
	}
	// A short answer carries no marker.
	f2 := conntest.NewHTTPS(t, nil)
	if o := r.mustCall(r.api(f2), "fetch_url", map[string]any{"path": "/api/x"}); strings.Contains(o, "truncated") {
		t.Errorf("marker on a short output: %q", o)
	}
}

// A device that echoes the Authorization header never gets the credential out: not in the output, not in an error, not in the log.
func TestCallRead_EchoedCredentialNeverLeaves(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	secretish := []string{token, sshPW}

	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/fail" {
			w.WriteHeader(http.StatusTeapot)
		}
		_, _ = io.WriteString(w, "you sent: "+req.Header.Get("Authorization")) //nolint:gosec // a fake that echoes the header on purpose
	}))
	c := r.api(f)
	out := r.mustCall(c, "fetch_url", map[string]any{"path": "/api/echo"})
	if !strings.Contains(out, "***") {
		t.Errorf("the echo was not replaced: %q", out)
	}
	_, herr := r.call(c, "fetch_url", map[string]any{"path": "/api/fail"})

	// Basic: the header holds base64(user:password).
	fb := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, req.Header.Get("Authorization")) //nolint:gosec // a fake that echoes the header on purpose
	}))
	cb := r.create(conn.Input{Name: "Basic", Kind: "http", Target: fb.URL, AuthType: "basic", Username: str("svc-user"), Secret: secrets.NewValue("pw-basic-123456"), Allow: []string{fb.URL + "/api/x"}, Enabled: true, Tools: []conn.ToolInput{{Name: "fetch_url", Enabled: true}}})
	cb = r.tested(cb)
	outb := r.mustCall(cb, "fetch_url", map[string]any{"path": "/api/x"})

	ssh := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(string) string { return "login " + sshUsr + " password " + sshPW }})
	sw := r.sw(ssh)
	outs := r.mustCall(sw, "run_allowed_command", map[string]any{"command": "show version"})

	m := conntest.NewMCP(t, conntest.MCPOpts{FailTool: "boom", Tools: []conntest.MCPTool{{Name: "echo"}, {Name: "boom"}},
		Respond: func(_ string, _ map[string]any, authz string) string { return "header was " + authz }})
	cm := r.mcp(m, "echo", "boom")
	outm := r.mustCall(cm, "echo", nil)
	_, merr := r.call(cm, "boom", nil)

	all := strings.Join([]string{out, outb, outs, outm, fmt.Sprint(herr), fmt.Sprint(merr), r.log.String()}, "\n")
	for _, s := range append(secretish, "pw-basic-123456") {
		if strings.Contains(all, s) {
			t.Errorf("%q came out: %s", s, all)
		}
	}
	if !strings.Contains(fmt.Sprint(merr), "the server reported an error") {
		t.Errorf("mcp error: %v", merr)
	}
	for _, o := range []string{outb, outs, outm} {
		if !strings.Contains(o, "***") {
			t.Errorf("not redacted: %q", o)
		}
	}
	// The base64 of user:password is gone too.
	if strings.Contains(outb, "c3ZjLXVzZXI6") {
		t.Errorf("basic credential in base64: %q", outb)
	}
}

// A changed certificate or host key is refused before any credential is sent.
func TestCallRead_ChangedPinIsRefusedBeforeTheCredential(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	f.Rotate(t)
	n := len(f.Requests())
	_, err := r.call(c, "fetch_url", map[string]any{"path": "/api/x"})
	if err == nil || !strings.Contains(err.Error(), "not the one pinned") {
		t.Fatalf("https: %v", err)
	}
	if len(f.Requests()) != n {
		t.Error("a request reached a server with another certificate")
	}

	ssh := conntest.NewSSH(t, conntest.SSHOpts{})
	sw := r.sw(ssh)
	auth := ssh.AuthCalls()
	ssh.RotateHostKey(t)
	if _, err := r.call(sw, "run_allowed_command", map[string]any{"command": "show version"}); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("ssh: %v", err)
	}
	if ssh.AuthCalls() != auth {
		t.Error("a credential was sent to a server with another host key")
	}

	m := conntest.NewMCP(t, conntest.MCPOpts{})
	cm := r.mcp(m, "list_resources")
	m.Rotate(t)
	k := len(m.Requests())
	if _, err := r.call(cm, "list_resources", nil); err == nil {
		t.Fatal("mcp: passed")
	}
	if len(m.Requests()) != k {
		t.Error("a request reached an MCP server with another certificate")
	}
}

// The address policy of the dialer holds for a read: a name that now points at the metadata service or at loopback is refused, and
// nothing is sent.
func TestCallRead_AddressPolicyHolds(t *testing.T) {
	t.Parallel()
	for _, ip := range []string{"169.254.169.254", "::1", "224.0.0.1", "0.0.0.0"} {
		r := newRig(t)
		f := conntest.NewHTTPS(t, nil)
		c := r.api(f)
		n := len(f.Requests())
		conntest.ResolveName(t, f.Host, ip)
		_, err := r.call(c, "fetch_url", map[string]any{"path": "/api/x"})
		if err == nil || errors.Is(err, read.ErrUnavailable) {
			t.Errorf("%s: %v", ip, err)
		}
		if len(f.Requests()) != n {
			t.Errorf("%s: a request was sent", ip)
		}
	}
}

// 15 seconds is the whole call; the test shortens it.
func TestCallRead_DeadlineEndsAStuckDevice(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	release := make(chan struct{})
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/slow" {
			select {
			case <-release:
			case <-req.Context().Done():
			}
		}
		_, _ = io.WriteString(w, "late")
	}))
	t.Cleanup(func() { close(release) })
	c := r.api(f)
	r.r.SetBudgetForTest(300 * time.Millisecond)
	start := time.Now()
	out, err := r.call(c, "fetch_url", map[string]any{"path": "/api/slow"})
	if err == nil || out != "" || err.Error() != "timed out" {
		t.Fatalf("got %q, %v", out, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
	if read.CallBudget != 15*time.Second {
		t.Errorf("the budget of a call is %s", read.CallBudget)
	}
}

// SSH: one command that is on the allow-list, exactly; one line, then the session stops.
func TestCallRead_SSHRunsOneAllowedLine(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ssh := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(l string) string { return "output of " + l }})
	sw := r.sw(ssh, "show version", "show interfaces status")
	out := r.mustCall(sw, "run_allowed_command", map[string]any{"command": "  show interfaces status "})
	if out != "output of show interfaces status" {
		t.Errorf("output %q", out)
	}
	if got := ssh.Lines(); len(got) != 1 || got[0] != "show interfaces status" {
		t.Fatalf("the device was sent %q", got)
	}
}

func TestCallRead_SSHRefusesWhatIsNotOneAllowedReadLine(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ssh := conntest.NewSSH(t, conntest.SSHOpts{})
	sw := r.sw(ssh, "show version", "reload")
	cases := map[string]map[string]any{
		"not on the list":    {"command": "show running-config"},
		"prefix of an entry": {"command": "show"},
		"entry plus more":    {"command": "show version extra"},
		"case differs":       {"command": "Show Version"},
		"newline":            {"command": "show version\nreload"},
		"carriage return":    {"command": "show version\rreload"},
		"trailing newline":   {"command": "show version\n"},
		"control character":  {"command": "show version\x1a"},
		"shell character":    {"command": "show version; reload"},
		"changes the device": {"command": "reload"},
		"placeholder":        {"command": "show {interface}"},
		"missing":            {},
		"not a string":       {"command": 5},
		"unknown param":      {"command": "show version", "lines": []any{"reload"}},
		"too long":           {"command": strings.Repeat("a", 600)},
	}
	for name, args := range cases {
		if out, err := r.call(sw, "run_allowed_command", args); err == nil {
			t.Errorf("%s: passed with %q", name, out)
		}
	}
	for _, l := range ssh.Lines() {
		if l != "show version" {
			t.Errorf("the device was sent %q", l)
		}
	}
}

// MCP: tools/call with exactly the typed arguments, held to the server's schema.
func TestCallRead_MCPCallsTheToolWithTypedArguments(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	schema := `{"type":"object","properties":{"zone":{"type":"string","maxLength":10},"limit":{"type":"integer"},"deep":{"type":"boolean"},` +
		`"mode":{"type":"string","enum":["a","b"]},"ids":{"type":"array","items":{"type":"integer"}},"opts":{"type":"object","properties":{"x":{"type":"number"}}}},"required":["zone"]}`
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{{Name: "get_status", Schema: schema}, {Name: "run_action"}}})
	c := r.mcp(f, "get_status")
	args := map[string]any{"zone": "dmz", "limit": 5, "deep": true, "mode": "a", "ids": []any{1, 2}, "opts": map[string]any{"x": 1.5}}
	if out := r.mustCall(c, "get_status", args); out != "ran get_status" {
		t.Errorf("output %q", out)
	}
	var calls []conntest.MCPCall
	for _, mc := range f.Calls() {
		if mc.RPCMethod == "tools/call" {
			calls = append(calls, mc)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("%d tool calls", len(calls))
	}
	b, _ := json.Marshal(calls[0].Args)
	if string(b) != `{"deep":true,"ids":[1,2],"limit":5,"mode":"a","opts":{"x":1.5},"zone":"dmz"}` || calls[0].Authorization != "Bearer "+token {
		t.Errorf("the server saw %s with %q", b, calls[0].Authorization)
	}
	before := len(f.Calls())
	for name, a := range map[string]map[string]any{
		"unknown param":    {"zone": "dmz", "force": true},
		"missing required": {"limit": 1},
		"wrong type":       {"zone": 5},
		"integer is float": {"zone": "dmz", "limit": 1.5},
		"enum":             {"zone": "dmz", "mode": "c"},
		"too long":         {"zone": "0123456789a"},
		"array item":       {"zone": "dmz", "ids": []any{"x"}},
		"nested unknown":   {"zone": "dmz", "opts": map[string]any{"y": 1}},
		"nested type":      {"zone": "dmz", "opts": map[string]any{"x": "1"}},
		"placeholder":      {"zone": "{zone}"},
		"control":          {"zone": "a\x00b"},
		"newline":          {"zone": "a\nb"},
		"huge":             {"zone": strings.Repeat("a", 9000)},
		"too many items":   {"zone": "dmz", "ids": make([]any, 100)},
	} {
		if out, err := r.call(c, "get_status", a); err == nil || errors.Is(err, read.ErrUnavailable) {
			t.Errorf("%s: %q, %v", name, out, err)
		}
	}
	for _, mc := range f.Calls()[before:] {
		if mc.RPCMethod == "tools/call" {
			t.Errorf("a refused call reached the server: %+v", mc)
		}
	}
	// A tool of the server that is not marked read is refused, however it is named.
	r.wantRefused(c, "run_action")
}

func TestCallRead_MCPToolWithoutASchemaTakesNoArguments(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{})
	c := r.mcp(f, "list_resources")
	if _, err := r.call(c, "list_resources", map[string]any{"x": 1}); err == nil {
		t.Error("an undeclared argument passed")
	}
	if out := r.mustCall(c, "list_resources", nil); out != "ran list_resources" {
		t.Errorf("output %q", out)
	}
}

// One call at a time per connection, and the writer takes the same turn.
func TestCallRead_OneAtATimePerConnection(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var now, peak atomic.Int32
	gate := make(chan struct{})
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, "/api/") {
			return
		}
		n := now.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		if req.URL.Path == "/api/first" {
			<-gate
		} else {
			pause(30 * time.Millisecond)
		}
		now.Add(-1)
		_, _ = io.WriteString(w, "ok")
	}))
	c := r.api(f)
	w, err := write.New(write.Config{Conns: r.svc})
	if err != nil {
		t.Fatal(err)
	}
	var wrote atomic.Pointer[write.Result]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = r.call(c, "fetch_url", map[string]any{"path": "/api/first"}) }()
	deadline := time.Now().Add(5 * time.Second)
	for now.Load() == 0 && time.Now().Before(deadline) {
		pause(5 * time.Millisecond)
	}
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i == 2 {
				res := w.Do(t.Context(), write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Method: "POST", URL: f.URL + "/api/w", Body: `{}`})
				wrote.Store(&res)
				return
			}
			_, _ = r.call(c, "fetch_url", map[string]any{"path": fmt.Sprintf("/api/n%d", i)})
		}()
	}
	pause(200 * time.Millisecond)
	if now.Load() != 1 {
		t.Errorf("%d calls ran at once while the first held the connection", now.Load())
	}
	close(gate)
	wg.Wait()
	if peak.Load() != 1 {
		t.Errorf("up to %d calls on one connection at once", peak.Load())
	}
	if res := wrote.Load(); res == nil || res.Status != write.StatusOK {
		t.Errorf("the write ended %+v", res)
	}
}

// A waiting call gives up with the deadline.
func TestCallRead_WaitingForTheTurnEndsWithTheDeadline(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	gate := make(chan struct{})
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/first" {
			<-gate
		}
	}))
	t.Cleanup(func() { close(gate) })
	c := r.api(f)
	go func() { _, _ = r.call(c, "fetch_url", map[string]any{"path": "/api/first"}) }()
	for len(f.Requests()) < 2 { // the Test of the connection, then the first call
		pause(5 * time.Millisecond)
	}
	r.r.SetBudgetForTest(200 * time.Millisecond)
	_, err := r.call(c, "fetch_url", map[string]any{"path": "/api/second"})
	if err == nil || !strings.Contains(err.Error(), "did not finish in time") {
		t.Fatalf("got %v", err)
	}
}

// The log line names the connection, the tool and the actor; never an argument, an output or a secret.
func TestCallRead_LogsWhoReadWhatAndNothingElse(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OUTPUT-NEEDLE") }))
	c := r.api(f)
	r.mustCall(c, "fetch_url", map[string]any{"path": "/api/x"})
	r.wantRefused(c, "send_request")
	r.wantRefused(conn.Connection{ID: "cn-x\nfake=line"}, "fetch_url")
	_, _ = r.r.CallRead(t.Context(), c.ID, "fetch_url", nil) // an unnamed actor
	lg := r.log.String()
	for _, want := range []string{"conn.read", "connection_id=" + c.ID, "tool=fetch_url", "actor=ai:job-7", "outcome=ok", "outcome=refused", "tool=send_request", "actor=unknown"} {
		if !strings.Contains(lg, want) {
			t.Errorf("the log lacks %q:\n%s", want, lg)
		}
	}
	for _, bad := range []string{"/api/x", "OUTPUT-NEEDLE", token, "\nfake=line"} {
		if strings.Contains(lg, bad) {
			t.Errorf("the log holds %q:\n%s", bad, lg)
		}
	}
	if n := strings.Count(lg, "\n"); n != 4 {
		t.Errorf("%d log lines for 4 calls:\n%s", n, lg)
	}
}

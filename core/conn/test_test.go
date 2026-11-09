package conn_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/secrets"
)

// The Test operation (D-94, core INV-23): a real, harmless read over HTTPS, SSH or MCP against in-process fakes on loopback, with the
// pin taken at the first success and every later attempt held to it.

type tester struct {
	*rig
	guards atomic.Int32
}

func newTester(t *testing.T) *tester { t.Helper(); return &tester{rig: newRig(t)} }

func (r *tester) test(id string) (conn.TestResult, error) {
	r.t.Helper()
	return r.svc.Test(r.t.Context(), admin, id, func(context.Context, *sql.Tx) error { r.guards.Add(1); return nil })
}

func (r *tester) get(id string) conn.Connection {
	r.t.Helper()
	c, err := r.svc.Get(r.t.Context(), id)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *tester) httpTo(f *conntest.HTTPS, kind string) conn.Connection {
	r.t.Helper()
	return r.must(conn.Input{Name: "Fake " + kind, Kind: kind, Target: f.URL, AuthType: "token", Secret: secrets.NewValue(secret1), Allow: []string{f.URL + "/"}, Enabled: true})
}

func (r *tester) auditTests() []string {
	r.t.Helper()
	rows, err := r.env.DB.Reader().QueryContext(r.t.Context(), `SELECT user || ' ' || target || ' ' || coalesce(detail, '') FROM core_audit WHERE action = 'connection.test' ORDER BY id`)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestTestHTTPPinsOnFirstUseThenHoldsIt(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.httpTo(f, "http")

	res, err := r.test(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Connected. 2 tools found (1 can change something). The certificate is now pinned."; res.Message != want {
		t.Fatalf("message %q, want %q", res.Message, want)
	}
	got := r.get(c.ID)
	if got.Status != "ok" || got.LastTest == nil || got.Pin == nil || got.Pin.Kind != "tls_sha256" || got.Pin.Value != f.SPKISHA256() || got.Pin.FirstSeen == "" {
		t.Fatalf("saved %+v pin %+v", got, got.Pin)
	}
	if res.Connection.Pin == nil || res.ToolsFound != 2 || res.LatencyMS < 0 {
		t.Fatalf("result %+v", res)
	}
	reqs := f.Requests()
	if len(reqs) != 1 || reqs[0].Method != "GET" || reqs[0].Header.Get("Authorization") != "Bearer "+secret1 {
		t.Fatalf("the device saw %+v", reqs)
	}
	if a := r.auditTests(); len(a) != 1 || !strings.Contains(a[0], "pinned certificate") {
		t.Fatalf("audit %v", a)
	}
	if got.UpdatedAt == c.UpdatedAt {
		t.Error("a new pin must move updated_at: a request made before it must not carry on silently")
	}

	// A second Test: same pin, no new pin message, updated_at does not move.
	again, err := r.test(c.ID)
	if err != nil || again.Message != "Connected. 2 tools found (1 can change something)." {
		t.Fatalf("second test: %v %q", err, again.Message)
	}
	if r.get(c.ID).UpdatedAt != got.UpdatedAt {
		t.Error("a Test that changed nothing moved updated_at")
	}

	// The device shows another certificate: refused, nothing sent, the pin stays, the status says so.
	f.Rotate(t)
	n := len(f.Requests())
	_, err = r.test(c.ID)
	ae := want(t, err, 502, "pin_mismatch", "")
	if !strings.Contains(ae.Message, "The certificate of "+f.URL+" is not the one pinned at the first test. Nothing was sent.") || !strings.Contains(ae.Message, `"Forget pinned key"`) {
		t.Fatalf("message %q", ae.Message)
	}
	if len(f.Requests()) != n {
		t.Fatal("a request reached a device whose certificate changed")
	}
	after := r.get(c.ID)
	if after.Status != "error" || after.Pin == nil || after.Pin.Value != got.Pin.Value {
		t.Fatalf("after a mismatch: status %s pin %+v", after.Status, after.Pin)
	}
	if after.UpdatedAt != got.UpdatedAt {
		t.Error("a failed test moved updated_at")
	}

	// "Forget pinned key" then Test pins the new certificate.
	in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Allow: c.Allow, Enabled: true, ClearPin: true}
	if _, err := r.update(c.ID, in); err != nil {
		t.Fatal(err)
	}
	res, err = r.test(c.ID)
	if err != nil || !strings.HasSuffix(res.Message, "The certificate is now pinned.") || r.get(c.ID).Pin.Value != f.SPKISHA256() {
		t.Fatalf("re-pin: %v %q", err, res.Message)
	}
}

func TestTestOffSendsNothingAndGuardsRunFirst(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.httpTo(f, "http")
	off := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Allow: c.Allow, Enabled: false}
	if _, err := r.update(c.ID, off); err != nil {
		t.Fatal(err)
	}
	_, err := r.test(c.ID)
	_ = want(t, err, 409, "connection_off", "")
	_, err = r.test("cn-nope")
	_ = want(t, err, 404, "not_found", "")
	if len(f.Requests()) != 0 {
		t.Fatal("a request went to a connection that is off")
	}

	on := off
	on.Enabled = true
	if _, err := r.update(c.ID, on); err != nil {
		t.Fatal(err)
	}
	// The guard runs before anything is sent (a read-only transaction) and again inside the write transaction.
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	if r.guards.Load() != 2 {
		t.Fatalf("the guard ran %d times, want 2 (before the dial, inside the write transaction)", r.guards.Load())
	}
	// A guard that refuses before the dial: nothing is sent.
	n := len(f.Requests())
	_, err = r.svc.Test(t.Context(), admin, c.ID, func(context.Context, *sql.Tx) error { return apierr.Forbidden() })
	_ = want(t, err, 403, "forbidden", "")
	if len(f.Requests()) != n {
		t.Fatal("a request was sent although the guard refused")
	}
	// A guard that refuses only in the write transaction (the admin was demoted while the test ran): nothing is saved.
	var calls int
	rows := len(r.auditTests())
	_, err = r.svc.Test(t.Context(), admin, c.ID, func(context.Context, *sql.Tx) error {
		if calls++; calls == 2 {
			return apierr.Forbidden()
		}
		return nil
	})
	_ = want(t, err, 403, "forbidden", "")
	if len(r.auditTests()) != rows {
		t.Fatal("a result was saved although the guard refused inside the transaction")
	}
}

func TestTestFailuresAreSavedAndNeverShowTheSecret(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	var status atomic.Int32
	status.Store(401)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// A careless device that echoes the Authorization header in the body, in a header, and in a status line.
		w.Header().Set("X-Echo", req.Header.Get("Authorization"))
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, "denied: "+req.Header.Get("Authorization")) //nolint:gosec // a test device that echoes its input; the response is never HTML
	}))
	c := r.httpTo(f, "http")
	for st, wantMsg := range map[int32]string{401: "was reached, but the device refused the sign-in (HTTP 401).", 403: "(HTTP 403)", 404: "the device answered HTTP 404.", 503: "the device answered HTTP 503."} {
		status.Store(st)
		_, err := r.test(c.ID)
		ae := want(t, err, 502, "device_error", "")
		if !strings.Contains(ae.Message, wantMsg) {
			t.Errorf("status %d: message %q, want it to contain %q", st, ae.Message, wantMsg)
		}
		if got := r.get(c.ID); got.Status != "error" || got.LastTest == nil || got.Pin != nil {
			t.Errorf("status %d: saved %+v (a failed first test must pin nothing)", st, got)
		}
		blob, _ := json.Marshal(ae.Body())
		all := string(blob) + strings.Join(r.auditTests(), "\n")
		if strings.Contains(all, secret1) || strings.Contains(all, "Bearer") || strings.Contains(all, "denied") {
			t.Errorf("status %d: the secret or the device's text is in %s", st, all)
		}
	}
	status.Store(200)
	res, err := r.test(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if blob, _ := json.Marshal(res.Connection); strings.Contains(string(blob), secret1) {
		t.Fatal("the secret is in the result")
	}
}

func TestTestUnreachable(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := conntest.AllowLoopback(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close() // nothing listens any more
	target := "https://" + host + ":" + port
	c := r.must(conn.Input{Name: "Dead", Kind: "http", Target: target, AuthType: "none", Allow: []string{target + "/"}, Enabled: true})
	_, err = r.test(c.ID)
	ae := want(t, err, 502, "unreachable", "")
	if want := "Could not connect to " + target + ". Check the address, the box's network and the firewall."; ae.Message != want {
		t.Fatalf("message %q", ae.Message)
	}
	if got := r.get(c.ID); got.Status != "error" || got.LastTest == nil {
		t.Fatalf("saved %+v", got)
	}
}

// INV-23: the policy runs at dial time on what the name resolves to: a name that now points at the metadata service, at the box, or
// at loopback is not dialled, whatever it looked like when it was saved.
func TestTestRefusesAddressesAtDialTime(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	for name, ip := range map[string]string{"metadata": "169.254.169.254", "box address": boxAddr, "box subnet": "10.88.7.7", "loopback": "127.0.0.1", "v4-mapped": "::ffff:127.0.0.1", "nat64 metadata": "64:ff9b::a9fe:a9fe"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			host := conntest.ResolveTo(t, ip)
			target := "https://" + host
			c := r.must(conn.Input{Name: "Rebound " + name, Kind: "http", Target: target, AuthType: "none", Allow: []string{target + "/"}, Enabled: true})
			_, err := r.test(c.ID)
			ae := want(t, err, 502, "address_refused", "")
			if !strings.Contains(ae.Message, target+" now points to ") {
				t.Fatalf("message %q", ae.Message)
			}
			if got := r.get(c.ID); got.Status != "error" {
				t.Fatalf("status %s", got.Status)
			}
		})
	}
	// An allowed fake socket does not open the rest of loopback: the same name on another port is refused.
	ln, _ := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	host := conntest.AllowLoopback(t, ln)
	other, _ := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	defer func() { _ = other.Close() }()
	_, port, _ := net.SplitHostPort(other.Addr().String())
	target := "https://" + host + ":" + port
	c := r.must(conn.Input{Name: "Other port", Kind: "http", Target: target, AuthType: "none", Allow: []string{target + "/"}, Enabled: true})
	_, err := r.test(c.ID)
	_ = want(t, err, 502, "address_refused", "")
}

func TestTestDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	var landed atomic.Int32
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/login" {
			landed.Add(1)
		}
		http.Redirect(w, req, "/login", http.StatusFound)
	}))
	c := r.httpTo(f, "automation")
	if _, err := r.test(c.ID); err != nil { // a device that answers with a redirect is reachable
		t.Fatal(err)
	}
	if landed.Load() != 0 || len(f.Requests()) != 1 {
		t.Fatalf("landed %d, requests %d: the redirect must not be followed", landed.Load(), len(f.Requests()))
	}
}

func TestTestRestconfAndAutomationProbes(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.httpTo(f, "netconf-restconf")
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	if q := f.Requests()[0]; q.Method != "GET" || q.Path != "/restconf" || q.Header.Get("Accept") != "application/yang-data+json" {
		t.Fatalf("restconf probe %+v", q)
	}
	c2 := r.must(conn.Input{Name: "Basic", Kind: "automation", Target: f.URL + "/api/v2", AuthType: "basic", Username: str("lan"), Secret: secrets.NewValue("pw-0123456789"), Allow: []string{f.URL + "/api/v2/"}, Enabled: true})
	if _, err := r.test(c2.ID); err != nil {
		t.Fatal(err)
	}
	q := f.Requests()[1]
	user, pass, ok := (&http.Request{Header: q.Header}).BasicAuth()
	if q.Path != "/api/v2" || !ok || user != "lan" || pass != "pw-0123456789" {
		t.Fatalf("automation probe %+v", q)
	}
}

// D-94 (3): tools found on an MCP server are write tools and start off; a later Test keeps what the administrator set.
func TestTestMCPDiscoversWriteToolsThatStartOff(t *testing.T) {
	t.Parallel()
	for name, sse := range map[string]bool{"json": false, "sse": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newTester(t)
			f := conntest.NewMCP(t, conntest.MCPOpts{SSE: sse, Tools: []conntest.MCPTool{{Name: "list_resources", Description: "List\nwhat it holds"}, {Name: "run_action", Description: strings.Repeat("d", 300)}, {Name: "bad name!", Description: "x"}}})
			c := r.must(conn.Input{Name: "MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "token", Secret: secrets.NewValue(secret1), Allow: []string{f.URL + "/mcp"}, Enabled: true})
			if len(c.Tools) != 0 {
				t.Fatalf("a new MCP connection has tools %v before the first test", c.Tools)
			}
			res, err := r.test(c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if want := "Connected. 2 tools found (2 can change something). The certificate is now pinned."; res.Message != want {
				t.Fatalf("message %q", res.Message)
			}
			got := r.get(c.ID)
			for _, tl := range got.Tools {
				if tl.Access != "write" || tl.Enabled {
					t.Errorf("tool %+v must be write and off", tl)
				}
			}
			if len(got.Tools) != 2 || got.Tools[0].Description != "List what it holds" || len([]rune(got.Tools[1].Description)) > 200 {
				t.Fatalf("tools %+v: bad names are dropped, descriptions are one line of at most 200 characters", got.Tools)
			}
			if len(conn.WriteTools(got)) != 0 {
				t.Fatal("a discovered tool is on")
			}
			var seq []string
			for _, cl := range f.Calls() {
				seq = append(seq, cl.HTTPMethod+" "+cl.RPCMethod)
			}
			if s := strings.Join(seq, ", "); s != "POST initialize, POST notifications/initialized, POST tools/list, DELETE " {
				t.Fatalf("requests %s", s)
			}

			// The administrator marks one read and turns it on; a second Test keeps that and finds nothing new.
			read := "read"
			in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Allow: c.Allow, Enabled: true, Tools: []conn.ToolInput{{Name: "list_resources", Enabled: true, Access: &read}}}
			if _, err := r.update(c.ID, in); err != nil {
				t.Fatal(err)
			}
			before := r.get(c.ID)
			if _, err := r.test(c.ID); err != nil {
				t.Fatal(err)
			}
			after := r.get(c.ID)
			if len(after.Tools) != 2 || after.Tools[0].Access != "read" || !after.Tools[0].Enabled || after.UpdatedAt != before.UpdatedAt {
				t.Fatalf("after the second test %+v (updated_at %s -> %s)", after.Tools, before.UpdatedAt, after.UpdatedAt)
			}
		})
	}
}

func TestTestMCPOversizedAnswerFails(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Oversize: true})
	c := r.must(conn.Input{Name: "Big", Kind: "mcp-http", Target: f.URL, AuthType: "none", Allow: []string{f.URL}, Enabled: true})
	_, err := r.test(c.ID)
	ae := want(t, err, 502, "device_error", "")
	if !strings.Contains(ae.Message, "larger than 1 MB") {
		t.Fatalf("message %q", ae.Message)
	}
	if got := r.get(c.ID); got.Status != "error" || len(got.Tools) != 0 || got.Pin != nil {
		t.Fatalf("saved %+v", got)
	}
}

func sshBasic(f *conntest.SSH, name string) conn.Input {
	return conn.Input{Name: name, Kind: "ssh", Target: f.Addr, AuthType: "basic", Username: str("vedette"), Secret: secrets.NewValue("pw-0123456789"), Allow: []string{"show version"}, Enabled: true}
}

func TestTestSSHPinsTheHostKeyAndRefusesAChangedOne(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	c := r.must(sshBasic(f, "Switch"))
	res, err := r.test(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Connected. 2 tools found (1 can change something). The host key is now pinned."; res.Message != want {
		t.Fatalf("message %q", res.Message)
	}
	got := r.get(c.ID)
	if got.Pin == nil || got.Pin.Kind != "ssh_hostkey" || got.Pin.Value != f.HostKeyPin() || got.Status != "ok" {
		t.Fatalf("saved %+v pin %+v", got, got.Pin)
	}
	if len(f.Lines()) != 0 {
		t.Fatalf("a Test sent commands: %v", f.Lines())
	}
	logins := f.Logins()
	calls := f.AuthCalls()

	f.RotateHostKey(t)
	_, err = r.test(c.ID)
	ae := want(t, err, 502, "pin_mismatch", "")
	if !strings.HasPrefix(ae.Message, "The SSH host key of "+f.Addr+" is not the one pinned at the first test. Nothing was sent.") {
		t.Fatalf("message %q", ae.Message)
	}
	if f.AuthCalls() != calls || f.Logins() != logins {
		t.Fatal("a credential was sent to a server whose host key changed")
	}
	if got := r.get(c.ID); got.Status != "error" || got.Pin.Value != f.HostKeyPin() && got.Pin.Value == "" {
		t.Fatalf("saved %+v", got)
	}
}

func TestTestSSHKeyAndWrongPassword(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	signer, priv := conntest.NewSSHKey(t)
	pem, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	f := conntest.NewSSH(t, conntest.SSHOpts{AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()}})
	var block strings.Builder
	block.WriteString(string(pemEncode(pem)))
	c := r.must(conn.Input{Name: "Key", Kind: "ssh", Target: f.Addr, AuthType: "ssh-key", Username: str("vedette"), Secret: secrets.NewValue(block.String()), Allow: []string{"show version"}, Enabled: true})
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	bad := r.must(conn.Input{Name: "Bad pw", Kind: "ssh", Target: f.Addr, AuthType: "basic", Username: str("vedette"), Secret: secrets.NewValue("not-the-password-1"), Allow: []string{"x"}, Enabled: true})
	_, err = r.test(bad.ID)
	ae := want(t, err, 502, "device_error", "")
	if !strings.Contains(ae.Message, "the device refused the sign-in") || strings.Contains(ae.Message, "not-the-password-1") {
		t.Fatalf("message %q", ae.Message)
	}
	if got := r.get(bad.ID); got.Status != "error" || got.Pin != nil {
		t.Fatalf("a failed first test pinned %+v", got.Pin)
	}
}

// A connection edited while its Test ran is a different connection: the result is not saved.
func TestTestResultIsNotSavedForAConnectionEditedMeanwhile(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	var id atomic.Value
	var edited atomic.Bool
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if edited.CompareAndSwap(false, true) {
			ctx := req.Context()
			c, _ := r.svc.Get(ctx, id.Load().(string))
			in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Secret: secrets.NewValue(secret2), Allow: c.Allow, Enabled: true}
			_ = r.env.DB.Write(ctx, func(tx *sql.Tx) error { _, err := r.svc.Update(ctx, tx, admin, c.ID, in); return err })
		}
		_, _ = io.WriteString(w, "{}")
	}))
	c := r.httpTo(f, "http")
	id.Store(c.ID)
	_, err := r.test(c.ID)
	_ = want(t, err, 409, "connection_changed", "")
	if got := r.get(c.ID); got.Status != "untested" || got.Pin != nil || got.LastTest != nil {
		t.Fatalf("a result of the old configuration was saved: %+v", got)
	}
	// and the next Test of the new configuration works
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
}

func pemEncode(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// scanTree calls fn with the path (slash-separated, relative to the repository) and the text of every non-test Go source file in the
// repository: every top-level directory (core, modules, cmd, host, internal, content, scripts, tools, whatever holds Go files).
func scanTree(t *testing.T, fn func(rel, src string)) {
	t.Helper()
	root := filepath.Join("..", "..")
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); p != root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // walking our own source tree
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fn(filepath.ToSlash(rel), string(b))
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("the scan saw %d files: the walk is broken", n)
	}
}

// Boundary: the fakes reach loopback, which the policy refuses, so nothing but a test may import them; and the hooks that open a
// socket are named only by conntest and the transport itself.
func TestConntestIsOnlyImportedByTests(t *testing.T) {
	t.Parallel()
	sawConntest := false
	sawTop := map[string]bool{}
	scanTree(t, func(rel, src string) {
		sawTop[strings.SplitN(rel, "/", 2)[0]] = true
		if strings.HasPrefix(rel, "core/conn/conntest/") {
			sawConntest = true
			return
		}
		if strings.Contains(src, "core/conn/conntest") {
			t.Errorf("%s imports conntest: its fakes open loopback, which the address policy refuses; only tests may", rel)
		}
		for _, hook := range []string{"AllowSocketForTest", "ResolveForTest", "RedirectForTest"} {
			if strings.Contains(src, hook) && !strings.HasPrefix(rel, "core/conn/internal/transport/") {
				t.Errorf("%s names %s: only conntest and the transport itself may open a loopback socket", rel, hook)
			}
		}
	})
	if !sawTop["content"] || !sawTop["scripts"] || !sawTop["cmd"] {
		t.Fatalf("the scan did not reach every top-level directory with Go files: %v", sawTop)
	}
	if !sawConntest {
		t.Fatal("the scan did not see conntest: the check would pass vacuously")
	}
}

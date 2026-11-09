package conn_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
)

const (
	admin     = "admin@acme.example"
	boxSubnet = "10.88.0.0/16"   // a container bridge network: refused whole
	boxAddr   = "192.168.10.250" // the management address of the mock, so both sides refuse the same host
	secret1   = "tok-0123456789-abcdef"
	secret2   = "tok-9876543210-zyxwvu"
)

type rig struct {
	t     *testing.T
	env   *authtest.Env
	svc   *conn.Service
	inUse atomic.Bool
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, env: authtest.New(t)}
	svc, err := conn.New(conn.Config{
		DB: r.env.DB, Secrets: r.env.Secrets, Audit: r.env.Audit, Clock: r.env.Clock.Now,
		InUse: func(context.Context, string) (bool, error) { return r.inUse.Load(), nil },
		BoxAddrs: func(context.Context) []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix(boxAddr + "/32"), netip.MustParsePrefix(boxSubnet)}
		},
		AssetExists: func(_ context.Context, id string) (bool, error) { return id == "a-fw01", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

func (r *rig) create(in conn.Input) (c conn.Connection, err error) {
	r.t.Helper()
	err = r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) (err error) { c, err = r.svc.Create(r.t.Context(), tx, admin, in); return })
	return c, err
}

func (r *rig) update(id string, in conn.Input) (c conn.Connection, err error) {
	r.t.Helper()
	err = r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) (err error) { c, err = r.svc.Update(r.t.Context(), tx, admin, id, in); return })
	return c, err
}

func (r *rig) del(id string) error {
	r.t.Helper()
	return r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) error { return r.svc.Delete(r.t.Context(), tx, admin, id) })
}

func (r *rig) must(in conn.Input) conn.Connection {
	r.t.Helper()
	c, err := r.create(in)
	if err != nil {
		r.t.Fatalf("create %q: %v", in.Name, err)
	}
	return c
}

func (r *rig) exec(q string, args ...any) {
	r.t.Helper()
	err := r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(r.t.Context(), q, args...); return err })
	if err != nil {
		r.t.Fatal(err)
	}
}

func str(s string) *string { return &s }

func httpIn(name string) conn.Input {
	return conn.Input{Name: name, Kind: "http", Target: "https://192.168.10.50", AuthType: "token", Secret: secrets.NewValue(secret1), Allow: []string{"https://192.168.10.50/api/"}, Enabled: true}
}

func sshIn(name string, key string) conn.Input {
	return conn.Input{Name: name, Kind: "ssh", Target: "192.168.10.51:22", AuthType: "ssh-key", Username: str("vedette"), Secret: secrets.NewValue(key), Allow: []string{"show version"}, Enabled: true}
}

func key(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "features", "core", "testdata", "keys", name)) //nolint:gosec // a fixture of the mock of the GUI
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// want asserts an API error with a status, a code and the field it names.
func want(t *testing.T, err error, status int, code, field string) *apierr.Error {
	t.Helper()
	ae, ok := apierr.As(err)
	if !ok {
		t.Fatalf("error = %v, want %d %s", err, status, code)
	}
	if ae.Status != status || ae.Code != code || (field != "" && ae.Extra["field"] != field) {
		t.Fatalf("error = %d %s field=%v (%s), want %d %s field=%s", ae.Status, ae.Code, ae.Extra["field"], ae.Message, status, code, field)
	}
	return ae
}

// The shared test vector of the fingerprint (response INV-9 and core/conn agree on it).
func TestFingerprintVector(t *testing.T) {
	t.Parallel()
	got := conn.Fingerprint("cn-1", "http", "https://192.168.10.1", "2026-11-09T10:00:00.000Z")
	if got != "5c44d33d9abf4dc98bc0a226d8bc8f37" {
		t.Fatalf("fingerprint = %s: the vector changed; every stored request would be refused as connection_changed", got)
	}
	if conn.Fingerprint("cn-1", "http", "https://192.168.10.1", "2026-11-09T10:00:00.001Z") == got {
		t.Fatal("another updated_at gave the same fingerprint")
	}
}

// D-93 (4): editing a secret moves updated_at; the name, the status, the last test and the connection's own switch do not.
func TestUpdatedAtMovesOnSecurityFieldsOnly(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	base := r.must(httpIn("Office API"))
	r.env.Clock.Advance(time.Hour)

	same := func(label string, c conn.Connection) {
		t.Helper()
		if c.UpdatedAt != base.UpdatedAt || c.Fingerprint() != base.Fingerprint() {
			t.Errorf("%s moved updated_at (%s -> %s)", label, base.UpdatedAt, c.UpdatedAt)
		}
	}
	moved := func(label string, c conn.Connection) {
		t.Helper()
		if c.UpdatedAt == base.UpdatedAt || c.Fingerprint() == base.Fingerprint() {
			t.Errorf("%s did not move updated_at", label)
		}
		base = c
		r.env.Clock.Advance(time.Hour)
	}
	edit := func(f func(in *conn.Input)) (conn.Connection, error) {
		in := httpIn("Office API")
		in.Secret = secrets.Value{}
		f(&in)
		return r.update(base.ID, in)
	}

	// Not security fields.
	c, err := edit(func(in *conn.Input) { in.Name = "Renamed API" })
	if err != nil {
		t.Fatal(err)
	}
	same("name", c)
	c, err = edit(func(in *conn.Input) { in.Name = "Renamed API"; in.Enabled = false })
	if err != nil {
		t.Fatal(err)
	}
	same("the connection's own switch", c)
	c, err = edit(func(in *conn.Input) { in.Name = "Renamed API"; in.Enabled = false; in.AssetID = str("a-fw01") })
	if err != nil {
		t.Fatal(err)
	}
	same("the linked device", c)
	r.exec(`UPDATE core_connection SET status = 'ok', last_test = '2026-11-09T09:00:00.000Z' WHERE id = ?`, base.ID)
	g, err := r.svc.Get(t.Context(), base.ID)
	if err != nil {
		t.Fatal(err)
	}
	same("status and last test", g)

	// Security fields, one at a time.
	back := func(in *conn.Input) { in.Name = "Renamed API"; in.Enabled = false; in.AssetID = str("a-fw01") }
	c, err = edit(func(in *conn.Input) { back(in); in.Secret = secrets.NewValue(secret2) })
	if err != nil {
		t.Fatal(err)
	}
	moved("a new secret", c)
	c, err = edit(func(in *conn.Input) {
		back(in)
		in.Allow = []string{"https://192.168.10.50/api/", "https://192.168.10.50/v2/"}
	})
	if err != nil {
		t.Fatal(err)
	}
	moved("the allow-list", c)
	c, err = edit(func(in *conn.Input) {
		back(in)
		in.Allow = []string{"https://192.168.10.50/api/", "https://192.168.10.50/v2/"}
		in.Tools = []conn.ToolInput{{Name: "send_request", Enabled: true}}
	})
	if err != nil {
		t.Fatal(err)
	}
	moved("a write tool turned on", c)
	if got := conn.WriteTools(c); len(got) != 1 || got[0] != "send_request" {
		t.Errorf("write tools on = %v", got)
	}
	c, err = edit(func(in *conn.Input) {
		back(in)
		in.Allow = []string{"https://192.168.10.50/api/", "https://192.168.10.50/v2/"}
		in.Tools = []conn.ToolInput{{Name: "send_request", Enabled: true}}
		in.AuthType, in.Username = "basic", str("ops")
		in.Secret = secrets.NewValue(secret1)
	})
	if err != nil {
		t.Fatal(err)
	}
	moved("another sign-in", c)
	c, err = r.update(base.ID, conn.Input{Name: "Renamed API", Kind: "http", Target: "https://192.168.10.50:8443", AuthType: "basic", Username: str("ops"), Secret: secrets.NewValue(secret1),
		Allow: []string{"https://192.168.10.50:8443/api/"}, Enabled: false, Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	moved("another address", c)
	c, err = r.update(base.ID, conn.Input{Name: "Renamed API", Kind: "http", Target: "https://192.168.10.50:8443", AuthType: "none", Allow: []string{"https://192.168.10.50:8443/api/"}, Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	moved("no sign-in at all", c)
	// A pin forgotten by clear_pin is a security change; one that was not there is not.
	r.exec(`UPDATE core_connection SET pin = 'tls-sha256:`+strings.Repeat("ab", 32)+`', pin_seen = '2026-11-09T09:00:00.000Z' WHERE id = ?`, base.ID)
	base, _ = r.svc.Get(t.Context(), base.ID)
	pinned := func(forget bool) conn.Input {
		return conn.Input{Name: "Renamed API", Kind: "http", Target: "https://192.168.10.50:8443", AuthType: "none", Allow: []string{"https://192.168.10.50:8443/api/"}, ClearPin: forget, Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}}
	}
	if c, err = r.update(base.ID, pinned(false)); err != nil || c.Pin == nil {
		t.Fatalf("a plain edit lost the pin: %v %+v", err, c.Pin)
	}
	same("an edit that keeps the pin", c)
	if c, err = r.update(base.ID, pinned(true)); err != nil || c.Pin != nil {
		t.Fatalf("clear_pin kept the pin: %v %+v", err, c.Pin)
	}
	moved("forgetting the pin", c)
	if c, err = r.update(base.ID, pinned(true)); err != nil {
		t.Fatal(err)
	}
	same("clear_pin with no pin", c)
}

// Two security changes in the same millisecond still give two fingerprints.
func TestUpdatedAtIsStrictlyLater(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	c := r.must(httpIn("Office API"))
	in := httpIn("Office API")
	in.Secret = secrets.NewValue(secret2)
	c2, err := r.update(c.ID, in) // the fake clock did not move
	if err != nil {
		t.Fatal(err)
	}
	if c2.UpdatedAt <= c.UpdatedAt {
		t.Fatalf("updated_at %s is not after %s", c2.UpdatedAt, c.UpdatedAt)
	}
}

// SYS-4: a secret is never in an answer, an audit row or a log, and it is encrypted at rest.
func TestSecretsNeverLeave(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	k := key(t, "ed25519")
	h := r.must(httpIn("Office API"))
	s := r.must(sshIn("File server", k))
	in := httpIn("Office API")
	in.Secret = secrets.NewValue(secret2)
	if _, err := r.update(h.ID, in); err != nil {
		t.Fatal(err)
	}
	if err := r.del(s.ID); err != nil {
		t.Fatal(err)
	}
	r.must(sshIn("File server 2", k))

	list, err := r.svc.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list)
	var logged strings.Builder
	rows, err := r.env.DB.Reader().QueryContext(t.Context(), `SELECT user, action, target, coalesce(detail,'') FROM core_audit WHERE action LIKE 'connection.%'`)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var a, b, c, d string
		if err := rows.Scan(&a, &b, &c, &d); err != nil {
			t.Fatal(err)
		}
		logged.WriteString(a + b + c + d)
		n++
	}
	_ = rows.Close()
	if n != 5 { // create x2, update, delete, create
		t.Errorf("audit rows = %d, want 5", n)
	}
	var blob strings.Builder
	blob.Write(raw)
	blob.WriteString(logged.String())
	blob.WriteString(r.env.Logs.String())
	for _, leak := range []string{secret1, secret2, "BEGIN OPENSSH", "b3BlbnNzaC1rZXk", secret1[:12], secret2[:12]} {
		if strings.Contains(blob.String(), leak) {
			t.Errorf("%q appears in an answer, an audit row or a log", leak)
		}
	}
	for _, c := range list {
		switch c.Kind {
		case "http":
			if c.Auth.Last4 == nil || *c.Auth.Last4 != secret2[len(secret2)-4:] || c.Auth.KeyFingerprint != nil {
				t.Errorf("token auth = %+v", c.Auth)
			}
		case "ssh":
			if c.Auth.Last4 != nil || c.Auth.KeyFingerprint == nil {
				t.Errorf("key auth = %+v", c.Auth)
			}
		}
	}
	// At rest: only ciphertext, and only the credential package can read it back.
	var ct []byte
	var sid string
	if err := r.env.DB.Reader().QueryRowContext(t.Context(), `SELECT s.id, s.ciphertext FROM core_secret s JOIN core_connection c ON c.secret_id = s.id WHERE c.name = 'Office API'`).Scan(&sid, &ct); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ct), secret2) {
		t.Error("the secret is stored in clear")
	}
	v, err := r.svc.VaultForTest().Open(t.Context(), r.env.DB.Reader(), sid)
	if err != nil || v.Reveal() != secret2 {
		t.Fatalf("cred.Open = %v", err)
	}
	if strings.Contains(v.String(), secret2) {
		t.Error("a credential value prints its content")
	}
	var purpose string
	if err := r.env.DB.Reader().QueryRowContext(t.Context(), `SELECT purpose FROM core_secret WHERE id = ?`, sid).Scan(&purpose); err != nil || purpose != "core_connection" {
		t.Errorf("purpose = %q %v", purpose, err)
	}
}

// The owning row and its secret go in one transaction, and the secret goes with the connection.
func TestDeleteTakesTheSecretAndIsRefusedWhileAChangeIsInForce(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	c := r.must(httpIn("Office API"))
	count := func(q string) (n int) {
		t.Helper()
		if err := r.env.DB.Reader().QueryRowContext(t.Context(), q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(`SELECT count(*) FROM core_secret WHERE purpose = 'core_connection'`) != 1 || count(`SELECT count(*) FROM core_connection_tool`) != 2 {
		t.Fatal("the connection did not store its secret and tools")
	}
	r.inUse.Store(true)
	ae := want(t, r.del(c.ID), 409, "in_use", "")
	if !strings.Contains(ae.Message, "Office API") || !strings.Contains(ae.Message, "still in force") {
		t.Errorf("message = %q", ae.Message)
	}
	if count(`SELECT count(*) FROM core_connection`) != 1 || count(`SELECT count(*) FROM core_secret WHERE purpose = 'core_connection'`) != 1 {
		t.Fatal("a refused delete removed something")
	}
	r.inUse.Store(false)
	if err := r.del(c.ID); err != nil {
		t.Fatal(err)
	}
	if count(`SELECT count(*) FROM core_connection`) != 0 || count(`SELECT count(*) FROM core_secret WHERE purpose = 'core_connection'`) != 0 || count(`SELECT count(*) FROM core_connection_tool`) != 0 {
		t.Fatal("the delete left a row, a tool or a secret behind")
	}
	_ = want(t, r.del(c.ID), 404, "not_found", "")
	if _, err := r.svc.Get(t.Context(), c.ID); err == nil {
		t.Fatal("Get found a deleted connection")
	}
}

// Both changes and the audit row are one transaction: an audit failure undoes the connection and its secret.
func TestCreateIsAtomicWithItsSecret(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	in := httpIn("Office API")
	failed := errors.New("boom")
	err := r.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := r.svc.Create(t.Context(), tx, admin, in); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	var n int
	if err := r.env.DB.Reader().QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM core_connection) + (SELECT count(*) FROM core_secret WHERE purpose = 'core_connection')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a rolled back create left %d rows (%v)", n, err)
	}
}

func TestToolsPerKind(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	k := key(t, "ed25519")
	mk := func(kind, target, auth string, allow []string, user *string, secret secrets.Value) conn.Connection {
		return r.must(conn.Input{Name: "k-" + kind, Kind: kind, Target: target, AuthType: auth, Username: user, Secret: secret, Allow: allow, Enabled: true})
	}
	got := map[string]conn.Connection{
		"http":     mk("http", "https://192.168.10.1", "token", []string{"https://192.168.10.1/api/"}, nil, secrets.NewValue(secret1)),
		"ssh":      mk("ssh", "192.168.10.2:22", "ssh-key", []string{"uname -a"}, str("ops"), secrets.NewValue(k)),
		"restconf": mk("netconf-restconf", "https://192.168.10.3", "basic", []string{"https://192.168.10.3/restconf/"}, str("admin"), secrets.NewValue(secret1)),
		"auto":     mk("automation", "https://automation.example.local", "token", []string{"https://automation.example.local/api/"}, nil, secrets.NewValue(secret1)),
		"mcp":      mk("mcp-http", "https://mcp.example.local/mcp", "none", []string{"https://mcp.example.local/mcp"}, nil, secrets.Value{}),
	}
	wantTools := map[string][]string{
		"http": {"fetch_url:read:on", "send_request:write:off"}, "ssh": {"run_allowed_command:read:on", "run_approved_command:write:off"},
		"restconf": {"get_config:read:on", "apply_config:write:off"}, "auto": {"list_jobs:read:on", "launch_job:write:off"}, "mcp": {},
	}
	for name, c := range got {
		var have []string
		for _, tl := range c.Tools {
			on := "off"
			if tl.Enabled {
				on = "on"
			}
			have = append(have, tl.Name+":"+tl.Access+":"+on)
		}
		if strings.Join(have, ",") != strings.Join(wantTools[name], ",") {
			t.Errorf("%s tools = %v, want %v", name, have, wantTools[name])
		}
		if len(conn.WriteTools(c)) != 0 {
			t.Errorf("%s: a write tool starts on: %v", name, conn.WriteTools(c))
		}
	}
	if got["restconf"].Username == nil || *got["restconf"].Username != "admin" || got["http"].Username != nil {
		t.Error("user name: Basic keeps it, a token has none")
	}
	// A write tool can be turned on, and only a tool of an MCP server can change its access.
	in := conn.Input{Name: "k-http", Kind: "http", Target: "https://192.168.10.1", AuthType: "token", Allow: []string{"https://192.168.10.1/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}, {Name: "no_such_tool", Enabled: true}}}
	c, err := r.update(got["http"].ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if w := conn.WriteTools(c); len(w) != 1 || w[0] != "send_request" || len(c.Tools) != 2 {
		t.Errorf("tools after the edit: %+v", c.Tools)
	}
	in.Tools = []conn.ToolInput{{Name: "get_virtual_ips", Enabled: true, Access: str("write")}}
	_, err = r.update(got["http"].ID, in)
	ae := want(t, err, 400, "invalid_tool_access", "tools")
	if ae.Message != "Only tools of an MCP server can be marked read or write; the built-in tools of this kind are fixed." {
		t.Errorf("message = %q", ae.Message)
	}
	// An MCP tool is found by the first Test (13b-5); the store keeps what a Test writes, and the input can mark one read.
	r.exec(`INSERT INTO core_connection_tool (connection_id, name, pos, access, description, enabled) VALUES (?, 'list_resources', 0, 'write', 'List', 0)`, got["mcp"].ID)
	mcp := conn.Input{Name: "k-mcp-http", Kind: "mcp-http", Target: "https://mcp.example.local/mcp", AuthType: "none", Allow: []string{"https://mcp.example.local/mcp"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "list_resources", Enabled: true, Access: str("read")}}}
	c, err = r.update(got["mcp"].ID, mcp)
	if err != nil || len(c.Tools) != 1 || c.Tools[0].Access != "read" || !c.Tools[0].Enabled {
		t.Fatalf("mcp tool = %+v %v", c.Tools, err)
	}
}

func TestPinIsForgottenOnClearPinKindOrServerOnly(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	c := r.must(httpIn("Office API"))
	pin := func() {
		t.Helper()
		r.exec(`UPDATE core_connection SET pin = 'tls-sha256:`+strings.Repeat("0f", 32)+`', pin_seen = '2026-11-09T09:00:00.000Z', status = 'ok' WHERE id = ?`, c.ID)
	}
	edit := func(f func(in *conn.Input)) (conn.Connection, error) {
		in := httpIn("Office API")
		in.Secret = secrets.Value{}
		f(&in)
		return r.update(c.ID, in)
	}
	pin()
	got, err := edit(func(in *conn.Input) {
		in.AuthType, in.Username, in.Secret = "basic", str("ops"), secrets.NewValue(secret2)
	})
	if err != nil || got.Pin == nil || got.Pin.Kind != "tls_sha256" || got.Pin.Value != strings.Repeat("0f", 32) || got.Pin.FirstSeen != "2026-11-09T09:00:00.000Z" {
		t.Fatalf("changing the sign-in lost the pin: %+v %v", got.Pin, err)
	}
	if got.Status != "ok" {
		t.Errorf("status after an edit that kept the address = %s", got.Status)
	}
	for _, same := range []string{"https://192.168.10.50/", "https://192.168.10.50/other", "https://192.168.10.50:443", "HTTPS://192.168.10.50"} {
		got, err = edit(func(in *conn.Input) {
			in.AuthType, in.Username, in.Target = "basic", str("ops"), same
			in.Allow = []string{strings.TrimSuffix(same, "/") + "/x/"}
		})
		if err != nil || got.Pin == nil {
			t.Fatalf("%s: a trailing slash, a path, the default port or the letter case changed the server: %v", same, err)
		}
	}
	// Another host or port: the pin goes, and so does the right to the saved secret.
	_, err = edit(func(in *conn.Input) {
		in.AuthType, in.Username, in.Target, in.Allow = "basic", str("ops"), "https://192.168.10.51", []string{"https://192.168.10.51/"}
	})
	ae := want(t, err, 400, "secret_required", "secret")
	if ae.Message != "Enter the secret again: the address changed, and a saved secret is only sent to the address it was saved for." {
		t.Errorf("message = %q", ae.Message)
	}
	if g, _ := r.svc.Get(t.Context(), c.ID); g.Pin == nil {
		t.Fatal("a refused edit forgot the pin")
	}
	got, err = edit(func(in *conn.Input) {
		in.AuthType, in.Username, in.Target, in.Allow, in.Secret = "basic", str("ops"), "https://192.168.10.51", []string{"https://192.168.10.51/"}, secrets.NewValue(secret2)
	})
	if err != nil || got.Pin != nil || got.Status != "untested" {
		t.Fatalf("another server kept the pin or the test result: %+v %v", got, err)
	}
	pin()
	got, err = edit(func(in *conn.Input) {
		in.AuthType, in.Username, in.Target, in.Allow, in.ClearPin = "basic", str("ops"), "https://192.168.10.51", []string{"https://192.168.10.51/"}, true
	})
	if err != nil || got.Pin != nil {
		t.Fatalf("clear_pin kept the pin: %+v %v", got.Pin, err)
	}
	// Another kind: the pin goes, and a new secret and user name are needed.
	pin()
	_, err = r.update(c.ID, sshIn("Office API", key(t, "ed25519")))
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := r.svc.Get(t.Context(), c.ID); g.Pin != nil || g.Kind != "ssh" || len(g.Tools) != 2 || g.Tools[0].Name != "run_allowed_command" {
		t.Fatalf("another kind: %+v", g)
	}
	pin()
	in := httpIn("Office API")
	in.Secret = secrets.Value{}
	_, err = r.update(c.ID, in) // back to HTTP: another kind, so the saved key is not offered to it
	_ = want(t, err, 400, "secret_required", "secret")
}

func TestStatusGoesBackToUntestedOnlyWhenTheTargetOrKindChanges(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	c := r.must(httpIn("Office API"))
	r.exec(`UPDATE core_connection SET status = 'ok', last_test = '2026-11-09T09:00:00.000Z' WHERE id = ?`, c.ID)
	in := httpIn("Office API")
	in.Secret = secrets.Value{}
	in.Allow = []string{"https://192.168.10.50/api/", "https://192.168.10.50/b/"}
	g, err := r.update(c.ID, in)
	if err != nil || g.Status != "ok" || g.LastTest == nil {
		t.Fatalf("an edit of the allow-list reset the test: %+v %v", g, err)
	}
	in.Target, in.Allow = "https://192.168.10.50/api", []string{"https://192.168.10.50/api/"}
	g, err = r.update(c.ID, in)
	if err != nil || g.Status != "untested" {
		t.Fatalf("another target kept the old test result: %+v %v", g, err)
	}
}

func TestListAndCountsAndNames(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if on, _ := r.svc.HasEnabled(t.Context()); on {
		t.Fatal("HasEnabled on an empty box")
	}
	for i := range conn.MaxConnections {
		in := httpIn("Conn " + string(rune('a'+i)))
		in.Enabled = i != 0
		r.must(in)
	}
	_, err := r.create(httpIn("One too many"))
	ae := want(t, err, 400, "too_many", "")
	if ae.Message != "A box holds up to 20 connections. Delete one you no longer use." {
		t.Errorf("message = %q", ae.Message)
	}
	list, _ := r.svc.List(t.Context())
	if len(list) != 20 || list[0].Name != "Conn a" || list[19].Name != "Conn t" {
		t.Fatalf("list = %d connections, first %q", len(list), list[0].Name)
	}
	_, err = r.update(list[1].ID, httpIn("conn A")) // another connection's name, in another case
	ae = want(t, err, 400, "duplicate_name", "name")
	if ae.Message != "Another connection already has this name. Pick a different one." {
		t.Errorf("message = %q", ae.Message)
	}
	in := httpIn("CONN B")
	in.Secret = secrets.Value{}
	if _, err := r.update(list[1].ID, in); err != nil { // its own name in another case is its own
		t.Fatal(err)
	}
	if on, err := r.svc.HasEnabled(t.Context()); err != nil || !on {
		t.Fatalf("HasEnabled = %v %v", on, err)
	}
	r.exec(`UPDATE core_connection SET enabled = 0`)
	if on, _ := r.svc.HasEnabled(t.Context()); on {
		t.Fatal("HasEnabled with every connection off")
	}
}

func TestNotReadyAndWriteTools(t *testing.T) {
	t.Parallel()
	on := conn.Connection{Kind: "http", Enabled: true, Status: "ok", Tools: []conn.Tool{{Name: "a", Access: "write", Enabled: true}, {Name: "b", Access: "write"}, {Name: "c", Access: "read", Enabled: true}}}
	if got := conn.WriteTools(on); len(got) != 1 || got[0] != "a" {
		t.Errorf("WriteTools = %v", got)
	}
	if conn.NotReady(on) != "" {
		t.Errorf("a connection that works is not ready: %s", conn.NotReady(on))
	}
	cases := map[string]func(c *conn.Connection){
		"off": func(c *conn.Connection) { c.Enabled = false }, "untested": func(c *conn.Connection) { c.Status = "untested" },
		"failed": func(c *conn.Connection) { c.Status = "error" }, "no host key": func(c *conn.Connection) { c.Kind = "ssh" },
	}
	for name, f := range cases {
		c := on
		f(&c)
		if conn.NotReady(c) == "" {
			t.Errorf("%s: ready", name)
		}
	}
}

// D-94: the address policy, on the host as typed and as normalised. The 17 URL forms and 8 SSH forms of the mock.
func TestTargetPolicy(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	urls := []string{"https://localhost", "https://LOCALHOST.", "https://api.localhost", "https://127.0.0.1", "https://127.1.2.3", "https://[::1]", "https://169.254.169.254",
		"https://[fe80::1]", "https://[ff02::1]", "https://224.0.0.1", "https://239.255.255.250", "https://0.0.0.0", "https://[::]", "https://2130706433", "https://0x7f.1",
		"https://192.168.010.001", "https://" + boxAddr,
		// More than the mock tests: other spellings of the same places.
		"https://[0:0:0:0:0:0:0:1]", "https://[::ffff:127.0.0.1]", "https://[::ffff:192.168.10.1]", "https://127.0.0.1.", "https://169.254.1.1:8443", "https://[fe80::1%25eth0]",
		"https://0177.0.0.1", "https://1.2.3", "https://0x7f000001", "https://[ff05::2]",
	}
	for i, target := range urls {
		in := httpIn("bad " + string(rune('a'+i)))
		in.Target, in.Allow = target, []string{target + "/"}
		_, err := r.create(in)
		ae := want(t, err, 400, "invalid_target", "target")
		if ae.Message == "Vedette does not connect to IPv6 addresses that carry an IPv4 address; use the IPv4 address." {
			continue // the whole sentence of the IPv6 forms that carry an IPv4 address
		}
		if !strings.HasPrefix(ae.Message, "Vedette never connects to ") || !strings.HasSuffix(ae.Message, ". Enter the address of the device or service itself.") {
			t.Errorf("%s: message = %q", target, ae.Message)
		}
	}
	for want, target := range map[string]string{"the box itself": "https://" + boxAddr, "a loopback address": "https://127.0.0.1", "a multicast address": "https://224.0.0.1", "an unspecified address": "https://0.0.0.0"} {
		in := httpIn("why " + want)
		in.Target, in.Allow = target, []string{target + "/"}
		_, err := r.create(in)
		if ae, ok := apierr.As(err); !ok || !strings.Contains(ae.Message, want) {
			t.Errorf("%s: %v, want a message with %q", target, err, want)
		}
	}
	sshs := []string{"localhost:22", "127.0.0.1:22", "169.254.169.254:22", "224.0.0.1:22", "0.0.0.0:22", "2130706433:22", "0x7f.1:22", boxAddr + ":22", "127.0.0.1", boxAddr}
	k := key(t, "ed25519")
	for i, target := range sshs {
		in := sshIn("bad ssh "+string(rune('a'+i)), k)
		in.Target = target
		_, err := r.create(in)
		_ = want(t, err, 400, "invalid_target", "target")
	}
	// A private range is fine, and so is a public name the administrator typed.
	for i, target := range []string{"https://10.1.2.3", "https://mcp.cloud.example.com", "https://192.168.10.1:8443/api", "https://[2001:db8::1]", "https://fw-1.corp.example"} {
		in := httpIn("ok " + string(rune('a'+i)))
		in.Target, in.Allow = target, []string{strings.TrimSuffix(target, "/") + "/"}
		if _, err := r.create(in); err != nil {
			t.Errorf("%s was refused: %v", target, err)
		}
	}
	for i, target := range []string{"10.1.2.3", "10.1.2.3:2222", "sw-1.corp.example:22"} {
		in := sshIn("ok ssh "+string(rune('a'+i)), k)
		in.Target = target
		if _, err := r.create(in); err != nil {
			t.Errorf("ssh %s was refused: %v", target, err)
		}
	}
}

func TestTargetForms(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	notValid := "The address is not valid. Enter it in full, for example https://192.168.10.1."
	plain := "The address must start with https://. Vedette sends sign-in details and changes only over HTTPS."
	for _, tc := range []struct{ target, msg string }{
		{"http://192.168.10.50", plain}, {"ftp://192.168.10.50", plain}, {"192.168.10.50", notValid}, {"", notValid}, {"https://", notValid},
		{"https://user:pw@192.168.10.50", "The address must not contain a user name or password. Enter the secret in its own field."},
		{"https://192.168.10.50:99999", notValid}, {"https://bad host", notValid}, {"https://192.168.10.50:0", notValid},
	} {
		for _, kind := range []string{"http", "netconf-restconf", "automation", "mcp-http"} {
			in := httpIn("t-" + kind)
			in.Kind, in.Target, in.Allow = kind, tc.target, []string{"https://192.168.10.50/"}
			if kind == "netconf-restconf" || kind == "automation" {
				in.AuthType, in.Username = "token", nil
			}
			_, err := r.create(in)
			ae := want(t, err, 400, "invalid_target", "target")
			if ae.Message != tc.msg {
				t.Errorf("%s %q: message = %q, want %q", kind, tc.target, ae.Message, tc.msg)
			}
		}
	}
	k := key(t, "ed25519")
	for _, target := range []string{"", "-bad:22", "host:", "host:99999", "host:0", "ho st:22", "https://host", "[::1]:22"} {
		in := sshIn("s", k)
		in.Target = target
		_, err := r.create(in)
		ae := want(t, err, 400, "invalid_target", "target")
		if ae.Message != "Enter the SSH server as host or host:port, for example 192.168.10.30:22." {
			t.Errorf("%q: message = %q", target, ae.Message)
		}
	}
}

func TestAllowList(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	n := 0
	try := func(target string, allow ...string) error {
		n++
		in := httpIn("Allow test " + strconv.Itoa(n))
		in.Target, in.Allow = target, allow
		_, err := r.create(in)
		return err
	}
	ae := want(t, try("https://192.168.10.50", "https://192.168.10.50/api/", "https://evil.example.com/"), 400, "invalid_allow", "allow")
	if ae.Message != "Each allow-list entry must be an address under https://192.168.10.50, for example https://192.168.10.50/api/." {
		t.Errorf("message = %q", ae.Message)
	}
	for _, bad := range [][]string{
		{"https://192.168.10.50.evil.example/"}, {"http://192.168.10.50/"}, {"https://192.168.10.50:8443/"}, {"192.168.10.50"}, {"/api/"},
		{"https://192.168.10.50/api/../../etc/"}, {"https://192.168.10.50/api/%2e%2e/x"},
	} {
		if err := try("https://192.168.10.50/api", bad...); err == nil {
			t.Errorf("%v was accepted under /api", bad)
		} else {
			_ = want(t, err, 400, "invalid_allow", "allow")
		}
	}
	if err := try("https://192.168.10.50/api", "https://192.168.10.50/other/"); err == nil {
		t.Error("another path is not under the target path")
	}
	if err := try("https://192.168.10.50/api", "https://192.168.10.50/api/v2/", "https://192.168.10.50/api", "https://192.168.10.50:443/api/x", "https://192.168.10.50/api/./y"); err != nil {
		t.Errorf("entries under the target were refused: %v", err)
	}
	_ = want(t, try("https://192.168.10.50"), 400, "allow_required", "allow")
	_ = want(t, try("https://192.168.10.50", " ", ""), 400, "allow_required", "allow")
	long := "https://192.168.10.50/" + strings.Repeat("a", 190)
	_ = want(t, try("https://192.168.10.50", long), 400, "invalid_allow", "allow")
	var many []string
	for i := range 31 {
		many = append(many, "https://192.168.10.50/"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	_ = want(t, try("https://192.168.10.50", many...), 400, "invalid_allow", "allow")
	_ = want(t, try("https://192.168.10.50", "https://192.168.10.50/a b"), 400, "invalid_allow", "allow")
	_ = want(t, try("https://192.168.10.50", "https://192.168.10.50/a\nhttps://192.168.10.50/b"), 400, "invalid_allow", "allow")
	// SSH allow-lists hold commands, not addresses, and no control character.
	in := sshIn("ssh cmds", key(t, "ed25519"))
	in.Allow = []string{"uname -a", "systemctl list-units --type=service", "uname -a"}
	c, err := r.create(in)
	if err != nil || len(c.Allow) != 2 {
		t.Fatalf("ssh commands: %v %v", c.Allow, err)
	}
	in = sshIn("ssh bad", key(t, "ed25519"))
	in.Allow = []string{"uname\x00 -a"}
	_, err = r.create(in)
	_ = want(t, err, 400, "invalid_allow", "allow")
}

func TestFieldRules(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	k := key(t, "ed25519")
	type tc struct {
		name         string
		f            func(in *conn.Input)
		code, field  string
		wantMessage  string
		httpOnlyBase bool
	}
	for _, c := range []tc{
		{"empty name", func(in *conn.Input) { in.Name = "  " }, "invalid_name", "name", `Give the connection a name of 1 to 40 characters, for example "Office firewall API".`, true},
		{"long name", func(in *conn.Input) { in.Name = strings.Repeat("n", 41) }, "invalid_name", "name", "", true},
		{"unknown kind", func(in *conn.Input) { in.Kind = "device-api" }, "invalid_kind", "kind", "Pick a kind: HTTP API, SSH / CLI, NETCONF / RESTCONF, automation platform or MCP server.", true},
		{"mcp-stdio", func(in *conn.Input) {
			in.Kind = "mcp-stdio"
			in.Target = "npx some-mcp-server"
			in.AuthType = "none"
			in.Secret = secrets.Value{}
		}, "kind_unsupported", "kind",
			`An MCP server that Vedette starts as a command is not supported. Use an MCP server that has a web address (kind "MCP server (URL)").`, true},
		{"unknown sign-in", func(in *conn.Input) { in.AuthType = "oauth" }, "invalid_auth", "auth_type", "Pick how the box signs in: none, token, user and password, or SSH key.", true},
		{"http with a key", func(in *conn.Input) { in.AuthType = "ssh-key" }, "invalid_auth", "auth_type", "This kind of connection cannot sign in that way. Pick one of the options the form offers.", true},
		{"basic without a user", func(in *conn.Input) { in.AuthType, in.Username = "basic", nil }, "username_required", "username", "Enter the user name the box signs in with.", true},
		{"spaces in the user", func(in *conn.Input) { in.AuthType, in.Username = "basic", str("a b") }, "invalid", "username", "The user name is 1 to 64 characters, with no spaces, colons or control characters.", true},
		{"colon in the user", func(in *conn.Input) { in.AuthType, in.Username = "basic", str("a:b") }, "invalid", "username", "", true},
		{"zero-width in the user", func(in *conn.Input) { in.AuthType, in.Username = "basic", str("zero\u200bwidth") }, "invalid", "username", "", true},
		{"long user", func(in *conn.Input) { in.AuthType, in.Username = "basic", str(strings.Repeat("u", 65)) }, "invalid", "username", "", true},
		{"short secret", func(in *conn.Input) { in.Secret = secrets.NewValue("short") }, "invalid_secret", "secret", "The secret is too short. Copy the whole token, password or key again.", true},
		{"no secret", func(in *conn.Input) { in.Secret = secrets.Value{} }, "secret_required", "secret", "Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards.", true},
		{"unknown asset", func(in *conn.Input) { in.AssetID = str("a-nope") }, "unknown_asset", "asset_id", "The device you linked is not in the inventory.", true},
	} {
		in := httpIn("Field rules")
		c.f(&in)
		_, err := r.create(in)
		ae := want(t, err, 400, c.code, c.field)
		if c.wantMessage != "" && ae.Message != c.wantMessage {
			t.Errorf("%s: message = %q, want %q", c.name, ae.Message, c.wantMessage)
		}
	}
	// SSH needs a user name, and it can use a key or a password, nothing else.
	in := sshIn("ssh rules", k)
	in.Username = nil
	_, err := r.create(in)
	_ = want(t, err, 400, "username_required", "username")
	in = sshIn("ssh rules", k)
	in.AuthType = "token"
	_, err = r.create(in)
	ae := want(t, err, 400, "invalid_auth", "auth_type")
	if ae.Message != "An SSH server cannot sign in that way. Pick one of the options the form offers." {
		t.Errorf("message = %q", ae.Message)
	}
	// A user name typed for a sign-in that has none is ignored.
	in = httpIn("token with a name")
	in.Username = str("ignored")
	if c, err := r.create(in); err != nil || c.Username != nil {
		t.Errorf("token user = %v %v", c.Username, err)
	}
	// A linked device that exists is kept; the allow-list and the name are tidied.
	in = httpIn("  Tidy   name ")
	in.AssetID = str("a-fw01")
	in.Allow = []string{" https://192.168.10.50/api/ ", "https://192.168.10.50/api/"}
	c, err := r.create(in)
	if err != nil || c.Name != "Tidy name" || c.AssetID == nil || len(c.Allow) != 1 || c.Allow[0] != "https://192.168.10.50/api/" {
		t.Fatalf("tidy = %+v %v", c, err)
	}
	// Auth none stores nothing, a secret given with it is dropped.
	in = httpIn("No sign-in")
	in.AuthType = "none"
	c, err = r.create(in)
	if err != nil || c.Auth.Last4 != nil || c.Auth.KeyFingerprint != nil {
		t.Fatalf("auth none = %+v %v", c.Auth, err)
	}
	var n int
	if err := r.env.DB.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_connection WHERE name = 'No sign-in' AND secret_id IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Errorf("a connection with no sign-in holds a secret (%d, %v)", n, err)
	}
}

func TestSSHKeys(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	good := key(t, "ed25519")
	c := r.must(sshIn("File server", good))
	if c.Auth.Last4 != nil || c.Auth.KeyFingerprint == nil || c.Username == nil || *c.Username != "vedette" {
		t.Fatalf("auth = %+v", c.Auth)
	}
	const keygen = "SHA256:/kA0pXYtDFuusYtey0m8NN8Hk6ZIkyj29OfaP2KL3Xk" // what `ssh-keygen -lf testdata/keys/ed25519` printed when the key was made (web/src/features/core/testdata/keys/README)
	if *c.Auth.KeyFingerprint != keygen {
		t.Errorf("fingerprint = %s, want %s", *c.Auth.KeyFingerprint, keygen)
	}
	in := sshIn("Locked", key(t, "ed25519-passphrase"))
	_, err := r.create(in)
	ae := want(t, err, 400, "invalid_secret", "secret")
	if ae.Message != "This private key is protected by a passphrase, which Vedette cannot type. Save a copy without one and paste that." {
		t.Errorf("message = %q", ae.Message)
	}
	_, err = r.create(sshIn("Weak", key(t, "rsa1024")))
	_ = want(t, err, 400, "invalid_secret", "secret")
	_, err = r.create(sshIn("Junk", "this is not a key but is long enough"))
	ae = want(t, err, 400, "invalid_secret", "secret")
	if strings.Contains(ae.Message, "not a key but") {
		t.Error("the error repeats the secret")
	}
	_, err = r.create(sshIn("Public", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINJzckVS03oMqejzJyfVQykGtl8hDOBYUA8dqX6PnilJ vedette-test-only"))
	_ = want(t, err, 400, "invalid_secret", "secret")
	// A password works for SSH too, with its last 4 characters.
	in = sshIn("Password ssh", "")
	in.AuthType, in.Secret = "basic", secrets.NewValue(secret1)
	if c, err := r.create(in); err != nil || c.Auth.Last4 == nil || c.Auth.KeyFingerprint != nil {
		t.Errorf("ssh password = %+v %v", c.Auth, err)
	}
	// Replacing the key moves the fingerprint; keeping it (blank secret) keeps it.
	keep := sshIn("File server", "")
	keep.Secret = secrets.Value{}
	if k, err := r.update(c.ID, keep); err != nil || *k.Auth.KeyFingerprint != keygen {
		t.Fatalf("a blank secret changed the key: %+v %v", k.Auth, err)
	}
	// A locked key on an edit is refused too, and the saved key stays.
	locked := sshIn("File server", key(t, "ed25519-passphrase"))
	_, err = r.update(c.ID, locked)
	_ = want(t, err, 400, "invalid_secret", "secret")
	if g, _ := r.svc.Get(t.Context(), c.ID); *g.Auth.KeyFingerprint != keygen {
		t.Error("a refused key replaced the saved one")
	}
}

func TestGetUnknownIs404(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	_, err := r.svc.Get(t.Context(), "cn-nope")
	ae := want(t, err, 404, "not_found", "")
	if ae.Message != "This connection no longer exists." {
		t.Errorf("message = %q", ae.Message)
	}
	_, err = r.update("cn-nope", httpIn("x"))
	_ = want(t, err, 404, "not_found", "")
}

// A stored secret that cannot be read is never an answer that names it: the store is the only reader.
func TestMigrationKeepsOneSecretPerConnection(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	a := r.must(httpIn("A"))
	in := httpIn("B")
	b := r.must(in)
	var n int
	if err := r.env.DB.Reader().QueryRowContext(t.Context(), `SELECT count(DISTINCT secret_id) FROM core_connection`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("distinct secrets = %d %v", n, err)
	}
	// The row refuses a secret with no sign-in and a sign-in with no secret.
	err := r.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_connection SET auth_type = 'none' WHERE id = ?`, a.ID)
		return err
	})
	if err == nil {
		t.Error("the table accepted a secret with no sign-in")
	}
	_ = b
}

// The column holds 2048 characters: a longer target is a 400 naming the field, not an internal error from the CHECK.
func TestTargetLongerThanTheColumnIs400NotAnInternalError(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	in := httpIn("Long target")
	in.Target = "https://192.168.10.50/" + strings.Repeat("a", 2100)
	in.Allow = []string{"https://192.168.10.50/"}
	_, err := r.create(in)
	ae := want(t, err, 400, "invalid_target", "target")
	if ae.Message != "The address is too long: at most 2048 characters." {
		t.Errorf("message = %q", ae.Message)
	}
	in.Target = "https://192.168.10.50/?q=" + strings.Repeat("a", 2100)
	_, err = r.create(in)
	_ = want(t, err, 400, "invalid_target", "target")
}

// A name is unique in any letter case of any script (the mock compares with Unicode lower case), and the case-folded key follows a rename.
func TestDuplicateNameIgnoresCaseBeyondASCII(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	first := r.must(httpIn("Ärger API"))
	for _, name := range []string{"ärger API", "ÄRGER api", "ärger  API"} {
		_, err := r.create(httpIn(name))
		_ = want(t, err, 400, "duplicate_name", "name")
	}
	r.must(httpIn("Другая"))
	_, err := r.create(httpIn("другая"))
	_ = want(t, err, 400, "duplicate_name", "name")
	// A rename frees the old name and takes the new one.
	in := httpIn("Renamed")
	in.Secret = secrets.Value{}
	if _, err := r.update(first.ID, in); err != nil {
		t.Fatal(err)
	}
	r.must(httpIn("ärger API"))
	_, err = r.create(httpIn("RENAMED"))
	_ = want(t, err, 400, "duplicate_name", "name")
}

// Names are counted in code points, not bytes or UTF-16 units: 40 emoji fit, 41 do not.
func TestNameLengthIsCodePoints(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := r.create(httpIn(strings.Repeat("😀", 40))); err != nil {
		t.Fatalf("40 code points: %v", err)
	}
	_, err := r.create(httpIn(strings.Repeat("😀", 41)))
	_ = want(t, err, 400, "invalid_name", "name")
}

// The secret of an input prints, formats and marshals as a placeholder: no log line or error that shows the input can show it.
func TestInputSecretIsRedactedWhenFormatted(t *testing.T) {
	t.Parallel()
	in := httpIn("Office API")
	for _, got := range []string{fmt.Sprintf("%v", in), fmt.Sprintf("%+v", in), fmt.Sprintf("%#v", in), fmt.Sprint(in.Secret), fmt.Sprintf("%s", in.Secret), fmt.Sprintf("%q", in.Secret)} { //nolint:gosec,staticcheck // the point
		if strings.Contains(got, secret1) || strings.Contains(got, secret1[:10]) {
			t.Errorf("a formatted input shows the secret: %s", got)
		}
	}
	b, err := json.Marshal(in)
	if err != nil || strings.Contains(string(b), secret1) {
		t.Errorf("json.Marshal(input) = %s %v", b, err)
	}
	logs := &strings.Builder{}
	slog.New(slog.NewTextHandler(logs, nil)).Info("create", "input", in, "secret", in.Secret)
	if strings.Contains(logs.String(), secret1) {
		t.Errorf("slog shows the secret: %s", logs)
	}
}

// Only the vault reads a credential: secrets.Store.Open refuses the purpose once conn.New restricted it, so another package that
// shares the Store (cmd/vedette hands one to response, auth, notify and core) cannot decrypt a connection's token or key.
func TestOnlyTheVaultDecryptsAConnectionCredential(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.must(httpIn("Office API"))
	var sid string
	if err := r.env.DB.Reader().QueryRowContext(t.Context(), `SELECT secret_id FROM core_connection`).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	pt, err := r.env.Secrets.Open(t.Context(), r.env.DB.Reader(), sid, "core_connection")
	if !errors.Is(err, secrets.ErrRestricted) || len(pt) != 0 {
		t.Fatalf("Store.Open of a connection credential = %q, %v; want ErrRestricted", pt, err)
	}
	if v, err := r.svc.VaultForTest().Open(t.Context(), r.env.DB.Reader(), sid); err != nil || v.Reveal() != secret1 {
		t.Fatalf("the vault does not read it: %v", err)
	}
	// One holder: a second service on the same Store cannot take the purpose.
	_, err = conn.New(conn.Config{DB: r.env.DB, Secrets: r.env.Secrets, Audit: r.env.Audit})
	if err == nil {
		t.Fatal("a second conn.New on one secrets.Store was accepted: two holders")
	}
}

// A pin that changes value is another server: updated_at moves, not only when a pin appears or goes.
func TestChangedPinValueMovesUpdatedAt(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	c := r.must(httpIn("Office API"))
	r.exec(`UPDATE core_connection SET pin = 'tls-sha256:`+strings.Repeat("0f", 32)+`', pin_seen = '2026-11-09T09:00:00.000Z' WHERE id = ?`, c.ID)
	pinned, _ := r.svc.Get(t.Context(), c.ID)
	if pinned.UpdatedAt != c.UpdatedAt {
		t.Fatal("the test of a pin moved updated_at by itself")
	}
	if !conn.PinChangedForTest(pinned, strings.Repeat("a1", 32)) {
		t.Error("a pin with another value is not counted as a security change")
	}
	if conn.PinChangedForTest(pinned, strings.Repeat("0f", 32)) {
		t.Error("the same pin value is counted as a change")
	}
}

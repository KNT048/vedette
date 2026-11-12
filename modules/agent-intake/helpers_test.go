package agentintake_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// clock is a manual clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// intakeOnly is the composite handler of a test server: the module's operations over the 501 fallback.
type intakeOnly struct {
	server.Fallback
	*agentintake.IntakeHandlers
	*agentintake.WazuhHandlers
}

type world struct {
	t     *testing.T
	db    *store.DB
	inv   *inventory.Service
	svc   *agentintake.Service
	h     http.Handler
	gate  *servertest.Gate
	clock *clock
	logs  *bytes.Buffer
	aud   *audit.Log
	conn  *conn.Service
}

// boxAddr is the box's own address in the tests: the address policy refuses it as a Wazuh server.
const boxAddr = "192.168.10.250"

const (
	peerA = "192.0.2.10" // the address most tests connect from
	macA  = "52:54:00:aa:bb:01"
)

func newWorld(t *testing.T) *world {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "agent-intake", agentintake.Migrations); err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)}
	aud := audit.New(clk.Now)
	logs := &bytes.Buffer{}
	lg := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	inv, err := inventory.New(inventory.Config{DB: db, Audit: aud, Clock: clk.Now, Log: lg})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := conn.New(conn.Config{DB: db, Secrets: sec, Audit: aud, Clock: clk.Now,
		BoxAddrs: func(context.Context) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(boxAddr + "/32")} }})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := agentintake.New(agentintake.Config{DB: db, Audit: aud, Sink: inv, Software: inv, Secrets: sec, Conn: cs, Clock: clk.Now, Log: lg,
		TrustAnchor: func(context.Context) ([]byte, error) { return []byte(anchorFile), nil }})
	if err != nil {
		t.Fatal(err)
	}
	gate := servertest.NewGate()
	h, err := server.New(server.Config{
		API:        intakeOnly{Fallback: server.Fallback{Log: lg}, IntakeHandlers: agentintake.NewIntakeHandlers(svc), WazuhHandlers: agentintake.NewWazuhHandlers(svc)},
		Auth:       &servertest.Auth{Users: servertest.StandardUsers()},
		Modules:    gate,
		Log:        lg,
		BodyLimits: agentintake.BodyLimits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, db: db, inv: inv, svc: svc, h: h, gate: gate, clock: clk, logs: logs, aud: aud, conn: cs}
}

// reply is one HTTP answer.
type reply struct {
	code   int
	body   map[string]any
	header http.Header
	raw    string
}

// post sends a JSON body (a string, or any value to marshal) from the TCP address remote.
func (w *world) post(path, remote string, body any, hdr ...string) reply {
	w.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			w.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequestWithContext(w.t.Context(), http.MethodPost, server.Prefix+path, rd)
	r.RemoteAddr = remote + ":40000"
	if rd != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	out := reply{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	}
	return out
}

func (r reply) errCode() string {
	m, _ := r.body["error"].(map[string]any)
	c, _ := m["code"].(string)
	return c
}

func (r reply) invalid() bool { v, _ := r.body["node_invalid"].(bool); return v }

// token issues a token and returns its id and secret.
func (w *world) token(name string, days int) (string, string) {
	w.t.Helper()
	tk, secret, err := w.svc.IssueToken(w.t.Context(), "admin@acme.example", name, days)
	if err != nil {
		w.t.Fatal(err)
	}
	return tk.ID, secret
}

func enrollBody(secret, host string) map[string]any {
	return map[string]any{
		"enroll_secret":   secret,
		"host_identifier": host,
		"host_details": map[string]any{
			"system_info":  map[string]any{"hostname": host, "cpu_brand": "x"},
			"os_version":   map[string]any{"platform": "ubuntu", "name": "Ubuntu"},
			"osquery_info": map[string]any{"version": "5.12.1"},
		},
	}
}

// enroll enrols a node and returns its key; it fails the test unless the box accepts.
func (w *world) enroll(secret, host, remote string) string {
	w.t.Helper()
	r := w.post("/intake/osquery/enroll", remote, enrollBody(secret, host))
	k, _ := r.body["node_key"].(string)
	if r.code != 200 || r.invalid() || len(k) != 43 {
		w.t.Fatalf("enroll: %d %s", r.code, r.raw)
	}
	return k
}

// snap is one osquery snapshot event, with the outer keys real osquery adds.
func snap(name string, rows ...map[string]string) map[string]any {
	if rows == nil {
		rows = []map[string]string{}
	}
	return map[string]any{
		"name": name, "action": "snapshot", "hostIdentifier": "srv", "calendarTime": "Wed Nov 11 08:00:00 2026 UTC", "unixTime": 1788000000,
		"epoch": 0, "counter": 0, "numerics": false, "decorations": map[string]string{"host": "srv"}, "snapshot": rows,
	}
}

func logBody(key string, events ...map[string]any) map[string]any {
	if events == nil {
		events = []map[string]any{}
	}
	return map[string]any{"node_key": key, "log_type": "result", "data": events}
}

func ifaceRow(mac, addr string) map[string]string {
	return map[string]string{"mac": mac, "address": addr}
}

func debRow(name, version string) map[string]string {
	return map[string]string{"name": name, "version": version, "arch": "amd64", "source": ""}
}

// device returns the device the inventory has at ip, if any.
func (w *world) device(ip string) (inventory.Device, bool) {
	w.t.Helper()
	l, err := w.inv.Devices(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.IP == ip {
			return d, true
		}
	}
	return inventory.Device{}, false
}

func (w *world) deviceCount() int {
	w.t.Helper()
	l, err := w.inv.Devices(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	return len(l.Items)
}

func (w *world) count(q string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.db.Reader().QueryRowContext(w.t.Context(), q, args...).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *world) exec(q string, args ...any) {
	w.t.Helper()
	err := w.db.Write(w.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(w.t.Context(), q, args...)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

func sha256sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

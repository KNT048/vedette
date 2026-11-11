package mcpserver_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	mcpserver "github.com/knt048/vedette/modules/mcp-server"
)

var t0 = time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type switches struct{ on atomic.Bool }

func (s *switches) Enabled(id string) bool { return id == mcpserver.ModuleID && s.on.Load() }

func str(s string) *string   { return &s }
func num(f float64) *float64 { return &f }

// fakeSource answers from fixed data. off names the modules that are off; calls counts the reads.
type fakeSource struct {
	assets   []mcpserver.Asset
	findings []mcpserver.Finding
	cves     map[string]mcpserver.CVEEntry
	iocs     map[string]mcpserver.IOCAnswer
	hot      []mcpserver.HotCVE
	off      map[string]bool
	calls    atomic.Int32
}

func (f *fakeSource) gate(m string) error {
	f.calls.Add(1)
	if f.off[m] {
		return mcpserver.SourceOffError{Module: m}
	}
	return nil
}

func (f *fakeSource) Assets(context.Context) ([]mcpserver.Asset, error) {
	if err := f.gate("inventory"); err != nil {
		return nil, err
	}
	return append([]mcpserver.Asset(nil), f.assets...), nil
}

func (f *fakeSource) Asset(_ context.Context, id string) (mcpserver.Asset, bool, error) {
	if err := f.gate("inventory"); err != nil {
		return mcpserver.Asset{}, false, err
	}
	for _, a := range f.assets {
		if a.ID == id {
			return a, true, nil
		}
	}
	return mcpserver.Asset{}, false, nil
}

func (f *fakeSource) Findings(context.Context) ([]mcpserver.Finding, error) {
	if err := f.gate("findings"); err != nil {
		return nil, err
	}
	return append([]mcpserver.Finding(nil), f.findings...), nil
}

func (f *fakeSource) Finding(_ context.Context, id string) (mcpserver.Finding, bool, error) {
	if err := f.gate("findings"); err != nil {
		return mcpserver.Finding{}, false, err
	}
	for _, x := range f.findings {
		if x.ID == id {
			return x, true, nil
		}
	}
	return mcpserver.Finding{}, false, nil
}

func (f *fakeSource) CVE(_ context.Context, cve string) (mcpserver.CVEEntry, bool, error) {
	if err := f.gate("feeds"); err != nil {
		return mcpserver.CVEEntry{}, false, err
	}
	e, ok := f.cves[cve]
	return e, ok, nil
}

func (f *fakeSource) IOC(_ context.Context, v string) (mcpserver.IOCAnswer, error) {
	if err := f.gate("feeds"); err != nil {
		return mcpserver.IOCAnswer{}, err
	}
	if strings.Contains(v, "/") || strings.Contains(v, " ") {
		return mcpserver.IOCAnswer{}, mcpserver.ErrNotIOC
	}
	if a, ok := f.iocs[v]; ok {
		return a, nil
	}
	return mcpserver.IOCAnswer{Value: v, Type: "domain", Sources: []string{}}, nil
}

func (f *fakeSource) Hot(context.Context, string) ([]mcpserver.HotCVE, error) {
	if err := f.gate("feeds"); err != nil {
		return nil, err
	}
	return append([]mcpserver.HotCVE(nil), f.hot...), nil
}

func sampleSource() *fakeSource {
	return &fakeSource{
		assets: []mcpserver.Asset{
			{ID: "as-fw", Name: "fw01", IP: str("192.168.1.1"), Hostname: str("fw01"), Kind: "firewall", Vendor: str("Fortinet"), Model: str("FortiGate 60F"), OS: str("FortiOS 7.2.4"),
				Approved: true, FirstSeen: "2026-11-01T00:00:00.000Z", LastSeen: "2026-11-11T08:00:00.000Z",
				Services: []mcpserver.NetService{{Port: 443, Proto: "tcp", Name: "https", Product: str("FortiGate SSL VPN")}},
				Software: []mcpserver.Software{{Name: "FortiOS 7.2.4", Vendor: "fortinet", Product: "fortios", Version: str("7.2.4")}}},
			{ID: "as-nas", Name: "nas", IP: str("192.168.1.20"), Kind: "nas", FirstSeen: "2026-11-02T00:00:00.000Z", LastSeen: "2026-11-11T08:00:00.000Z",
				Services: []mcpserver.NetService{}, Software: []mcpserver.Software{}},
		},
		findings: []mcpserver.Finding{
			{ID: "fn-1", AssetID: "as-fw", CVE: "CVE-2024-21762", Status: "confirmed", Severity: "critical", Confidence: 1, Basis: "scan", FirstSeen: "2026-11-10T00:00:00.000Z",
				LastSeen: "2026-11-11T00:00:00.000Z", Evidence: &mcpserver.Evidence{Template: "CVE-2024-21762", CheckedAt: "2026-11-10T01:00:00.000Z"},
				History: []mcpserver.HistoryStep{{At: "2026-11-10T00:00:00.000Z", Action: "created"}, {At: "2026-11-10T01:00:00.000Z", Action: "confirmed"}}},
			{ID: "fn-2", AssetID: "as-nas", CVE: "CVE-2023-27997", Status: "patched", Severity: "high", Confidence: 0.6, Basis: "version", FirstSeen: "2026-11-03T00:00:00.000Z",
				LastSeen: "2026-11-05T00:00:00.000Z", ResolvedAt: str("2026-11-05T00:00:00.000Z"), History: []mcpserver.HistoryStep{}},
		},
		cves: map[string]mcpserver.CVEEntry{"CVE-2024-21762": {CVE: "CVE-2024-21762", Vendor: "Fortinet", Product: "FortiOS", Name: "Fortinet FortiOS Out-of-Bound Write",
			Description: "An out-of-bounds write.", RequiredAction: "Apply mitigations per vendor instructions.", DateAdded: "2024-02-09", DueDate: str("2024-02-16"),
			Ransomware: true, EPSS: num(0.92), HasScanTemplate: true, Links: []string{"https://fortiguard.example/psirt"}}},
		iocs: map[string]mcpserver.IOCAnswer{"bad.example": {Value: "bad.example", Type: "domain", Listed: true, Verdict: str("block"), Category: "Botnet command-and-control server",
			Sources: []string{"abuse.ch Feodo"}, Score: num(0.9), FirstSeen: str("2026-11-01"), LastSeen: str("2026-11-10")}},
		hot: []mcpserver.HotCVE{{CVE: "CVE-2026-1000", Vendor: "Acme", Product: "Router", DateAdded: "2026-11-09"}, {CVE: "CVE-2026-1001", Vendor: "Acme", Product: "Router", DateAdded: "2026-11-10", EPSS: num(0.1)}},
		off: map[string]bool{},
	}
}

// world is a service on a migrated database with the fake source, its HTTP endpoint served by httptest.
type world struct {
	t     *testing.T
	db    *store.DB
	svc   *mcpserver.Service
	src   *fakeSource
	clock *clock
	sw    *switches
	h     http.Handler
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context(), db, mcpserver.ModuleID, mcpserver.Migrations); err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, db: db, src: sampleSource(), clock: &clock{now: t0}, sw: &switches{}}
	w.sw.on.Store(true)
	svc, err := mcpserver.New(mcpserver.Config{DB: db, Audit: audit.New(w.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: w.clock.Now, Source: w.src, Modules: w.sw,
		Listen: mcpserver.DefaultListen, Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	w.svc, w.h = svc, svc.Handler()
	return w
}

// token creates a token with these scopes and returns it in full.
func (w *world) token(name string, scopes ...string) string {
	w.t.Helper()
	secret, _, err := w.svc.Create(w.t.Context(), "admin@example.com", name, scopes)
	if err != nil {
		w.t.Fatal(err)
	}
	return secret
}

// auditRows returns the core_audit rows of one action, oldest first, as "user|target|detail".
func (w *world) auditRows(action string) []string {
	w.t.Helper()
	rows, err := w.db.Reader().QueryContext(w.t.Context(), `SELECT user, target, coalesce(detail, '') FROM core_audit WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var u, tg, d string
		if err := rows.Scan(&u, &tg, &d); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, u+"|"+tg+"|"+d)
	}
	return out
}

func (w *world) scalar(q string, args ...any) string {
	w.t.Helper()
	var v sql.NullString
	if err := w.db.Reader().QueryRowContext(w.t.Context(), q, args...).Scan(&v); err != nil {
		w.t.Fatal(err)
	}
	return v.String
}

// client is a fake MCP client: it speaks the 2026-07-28 revision (modern) or the initialize-based one (legacy, 2025-06-18).
type client struct {
	w      *world
	token  string
	modern bool
	next   int
}

func (w *world) modern(token string) *client { return &client{w: w, token: token, modern: true} }
func (w *world) legacy(token string) *client { return &client{w: w, token: token} }

type reply struct {
	status int
	header http.Header
	raw    []byte
	msg    struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
}

func (r reply) result(t *testing.T) map[string]any {
	t.Helper()
	if r.status != http.StatusOK || r.msg.Error != nil {
		t.Fatalf("status %d, error %+v: %s", r.status, r.msg.Error, r.raw)
	}
	var m map[string]any
	if err := json.Unmarshal(r.msg.Result, &m); err != nil {
		t.Fatalf("result: %v: %s", err, r.raw)
	}
	return m
}

func (r reply) code() int {
	if r.msg.Error == nil {
		return 0
	}
	return r.msg.Error.Code
}

// post sends raw with the headers given; nil headers are the client's own.
func (c *client) post(body []byte, hdr map[string]string) reply {
	c.w.t.Helper()
	req := httptest.NewRequestWithContext(c.w.t.Context(), http.MethodPost, "http://127.0.0.1:8765/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	c.w.h.ServeHTTP(rec, req)
	out := reply{status: rec.Code, header: rec.Header(), raw: rec.Body.Bytes()}
	if len(out.raw) > 0 && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(out.raw, &out.msg); err != nil {
			c.w.t.Fatalf("answer is not JSON: %v: %s", err, out.raw)
		}
	}
	return out
}

// request sends one JSON-RPC request the way a conforming client of its era does.
func (c *client) request(method string, params map[string]any) reply {
	c.w.t.Helper()
	c.next++
	if params == nil {
		params = map[string]any{}
	}
	hdr := map[string]string{}
	if c.modern {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo": map[string]any{"name": "fake", "version": "1"}}
		hdr["MCP-Protocol-Version"] = "2026-07-28"
		hdr["Mcp-Method"] = method
		if n, ok := params["name"].(string); ok {
			hdr["Mcp-Name"] = n
			if strings.ContainsFunc(n, func(r rune) bool { return r > 0x7e || r < 0x20 }) {
				hdr["Mcp-Name"] = "=?base64?" + base64.StdEncoding.EncodeToString([]byte(n)) + "?="
			}
		}
	} else if method != "initialize" {
		hdr["MCP-Protocol-Version"] = "2025-06-18"
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method, "params": params})
	return c.post(body, hdr)
}

// call runs a tool and returns the result object.
func (c *client) call(name string, args map[string]any) reply {
	c.w.t.Helper()
	p := map[string]any{"name": name}
	if args != nil {
		p["arguments"] = args
	}
	return c.request("tools/call", p)
}

// structured returns structuredContent of a successful tool result and checks the text block carries the same JSON.
func structured(t *testing.T, r reply) any {
	t.Helper()
	m := r.result(t)
	if m["isError"] != false {
		t.Fatalf("isError = %v: %s", m["isError"], r.raw)
	}
	content, _ := m["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content = %v", m["content"])
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	var fromText any
	if err := json.Unmarshal([]byte(text), &fromText); err != nil {
		t.Fatalf("text block is not the JSON: %v", err)
	}
	a, _ := json.Marshal(fromText)
	b, _ := json.Marshal(m["structuredContent"])
	if !bytes.Equal(a, b) {
		t.Fatalf("text block %s differs from structuredContent %s", a, b)
	}
	return m["structuredContent"]
}

// toolError returns the text of an isError result.
func toolError(t *testing.T, r reply) string {
	t.Helper()
	m := r.result(t)
	if m["isError"] != true {
		t.Fatalf("isError = %v: %s", m["isError"], r.raw)
	}
	if _, has := m["structuredContent"]; has {
		t.Fatalf("an error result carries structuredContent: %s", r.raw)
	}
	content, _ := m["content"].([]any)
	text, _ := content[0].(map[string]any)["text"].(string)
	return text
}

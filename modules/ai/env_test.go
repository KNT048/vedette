package ai_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
)

// The API keys of the tests are made-up values; none looks like a real credential.
const (
	keyA = "test-key-AAAA1111"
	keyB = "test-key-BBBB2222"
)

// fakeProviders answers in place of the real providers: no test makes a network call.
type fakeProviders struct {
	mu                sync.Mutex
	calls             []string // profile names, in order
	fail              map[string]error
	tools             bool
	structd           bool
	keys              []string // the API key each call carried: what would have reached the host
	onCall            func()   // runs inside every call, before the answer (a test cancels a context here)
	probeIn, probeOut int      // tokens of every probe call; 0 = the default 14 in and 3 out
	answer            string   // the text of every answer that is not a probe
	usageIn, usageOut int      // tokens of every answer that is not a probe; 0 = the default 14 in and 3 out
	reqs              []provider.Request
	// script, when set, answers every request that carries tools or follows a tool turn instead of the default text (slice 5, ask).
	script func(ctx context.Context, p ai.Profile, req provider.Request) (provider.Response, error)
}

func (f *fakeProviders) factory(p ai.Profile) (provider.Provider, error) {
	return fakeProvider{f, p}, nil
}

func (f *fakeProviders) setCaps(tools, structured bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools, f.structd = tools, structured
}

func (f *fakeProviders) failWith(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.fail, name)
		return
	}
	f.fail[name] = err
}

func (f *fakeProviders) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeProvider struct {
	f *fakeProviders
	p ai.Profile
}

func (p fakeProvider) Complete(ctx context.Context, req provider.Request) (provider.Response, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.calls = append(p.f.calls, p.p.Name)
	p.f.keys = append(p.f.keys, p.p.APIKey.Reveal())
	p.f.reqs = append(p.f.reqs, req)
	if p.f.onCall != nil {
		p.f.onCall()
	}
	if err := p.f.fail[p.p.Name]; err != nil {
		return provider.Response{}, err
	}
	if len(req.Tools) > 0 && !p.f.tools {
		return provider.Response{}, &provider.Error{Kind: provider.ErrRequest, Status: 400}
	}
	if p.f.script != nil && req.Schema == nil {
		return p.f.script(ctx, p.p, req)
	}
	text := "ok"
	if req.Schema != nil {
		if !p.f.structd {
			return provider.Response{}, &provider.Error{Kind: provider.ErrRequest, Status: 400}
		}
		text = `{"ok":true}`
		if req.Schema.Name != "probe" {
			text = p.f.answer
		}
	}
	isProbe := req.Schema == nil || req.Schema.Name == "probe"
	in, out := 14, 3
	switch {
	case isProbe && p.f.probeIn > 0:
		in, out = p.f.probeIn, p.f.probeOut
	case !isProbe && p.f.usageIn > 0:
		in, out = p.f.usageIn, p.f.usageOut
	}
	return provider.Response{Text: text, Usage: provider.Usage{InputTokens: in, OutputTokens: out}}, nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t.Add(0) }

// Add moves the clock of the box, forward or back.
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t           *testing.T
	db          *store.DB
	sec         *secrets.Store
	fake        *fakeProviders
	clock       *clock
	svc         *ai.Service
	facts       *fakeFacts
	pruner      *fakePruner
	hookTimeout time.Duration // 0 = the default; a test sets a tiny one to run out of time
	askTimeout  time.Duration // 0 = the default
	data        *fakeData
	conns       *fakeConns
}

func (e *env) ctx() context.Context { return e.t.Context() }

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "ai", ai.Migrations); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, sec: sec, fake: &fakeProviders{fail: map[string]error{}, tools: true, structd: true}, clock: &clock{t: time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)}, facts: newFacts(), pruner: &fakePruner{}, data: newFakeData(), conns: &fakeConns{}}
	e.svc = e.newService()
	return e
}

// newService builds a service over the same database, as a restart does.
func (e *env) newService() *ai.Service {
	e.t.Helper()
	svc, err := ai.New(e.ctx(), ai.Config{DB: e.db, Secrets: e.sec, Audit: audit.New(e.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now, Factory: e.fake.factory, Facts: e.facts, ChainPruner: e.pruner, HookTimeout: e.hookTimeout, Data: e.data, Conns: e.conns, ConnTargets: e.conns.targets, AskTimeout: e.askTimeout})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

type api struct {
	*env
	h http.Handler
}

func newAPI(t *testing.T) *api { return newAPIGate(t, servertest.NewGate()) }

func newAPIGate(t *testing.T, gate *servertest.Gate) *api {
	t.Helper()
	e := newEnv(t)
	return &api{env: e, h: e.handler(gate)}
}

type composite struct {
	server.Fallback
	*ai.AIHandlers
}

func (e *env) handler(gate *servertest.Gate) http.Handler {
	e.t.Helper()
	h, err := server.New(server.Config{
		API:        composite{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, AIHandlers: ai.NewAIHandlers(e.svc)},
		Auth:       &servertest.Auth{Users: servertest.StandardUsers()},
		Modules:    gate,
		Log:        slog.New(slog.DiscardHandler),
		BodyLimits: ai.BodyLimits,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func (a *api) do(method, path, user, body string) (int, map[string]any, string) {
	a.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(a.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, r)
	var out map[string]any
	raw := w.Body.String()
	if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			a.t.Fatalf("%s %s: body is not JSON: %v: %s", method, path, err, raw)
		}
	}
	return w.Code, out, raw
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func (a *api) want(method, path, user, body string, status int, code string) map[string]any {
	a.t.Helper()
	got, m, raw := a.do(method, path, user, body)
	if got != status || (code != "" && errCode(m) != code) {
		a.t.Fatalf("%s %s as %s = %d %s (want %d %s): %s", method, path, user, got, errCode(m), status, code, raw)
	}
	return m
}

// profile bodies
func cloudBody(name, key string) string {
	return `{"name":"` + name + `","kind":"anthropic","api_style":"anthropic","base_url":"https://api.anthropic.com","model":"claude-haiku-5-5","api_key":"` + key + `","location":"cloud","daily_cap":60000}`
}

func internalBody(name string) string {
	return `{"name":"` + name + `","kind":"openai-compatible","api_style":"openai","base_url":"http://192.168.10.5:11434/v1","model":"qwen3:8b","location":"internal","daily_cap":300000}`
}

func (a *api) addProfile(body string) map[string]any {
	a.t.Helper()
	return a.want("POST", "/ai/profiles", "admin", body, 200, "")
}

func (a *api) auditRows() []string {
	a.t.Helper()
	rows, err := a.db.Reader().QueryContext(a.ctx(), `SELECT action || ' ' || target || ' ' || coalesce(detail, '') FROM core_audit WHERE action LIKE 'ai.%' ORDER BY rowid`)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			a.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// keysSeen returns the keys the provider calls carried.
func (f *fakeProviders) keysSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

func (f *fakeProviders) setOnCall(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onCall = fn
}

func (f *fakeProviders) setProbeUsage(in, out int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeIn, f.probeOut = in, out
}

// newServiceWith builds a service over the same database with another key store: the keys sealed with the first one cannot be opened.
func (e *env) newServiceWith(sec *secrets.Store) (*ai.Service, error) {
	return ai.New(e.ctx(), ai.Config{DB: e.db, Secrets: sec, Audit: audit.New(e.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now, Factory: e.fake.factory})
}

func (a *api) exec(q string) error {
	a.t.Helper()
	return a.db.Write(a.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(a.ctx(), q)
		return err
	})
}

func (f *fakeProviders) setAnswer(text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = text
}

func (f *fakeProviders) setUsage(in, out int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usageIn, f.usageOut = in, out
}

func (f *fakeProviders) called(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}

// lastRequest returns the newest request the fake provider got that was not a connection probe.
func (f *fakeProviders) lastRequest(t *testing.T) provider.Request {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.reqs) - 1; i >= 0; i-- {
		if f.reqs[i].Schema == nil || f.reqs[i].Schema.Name != "probe" {
			return f.reqs[i]
		}
	}
	t.Fatal("the provider got no request")
	return provider.Request{}
}

// fakeFacts is the box's data about CVEs and devices.
type fakeFacts struct {
	mu     sync.Mutex
	cves   map[string]ai.CVEFacts
	assets map[string][]ai.AssetFact
}

func (f *fakeFacts) CVE(_ context.Context, id string) (ai.CVEFacts, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.cves[id]
	return v, ok, nil
}

func (f *fakeFacts) AffectedAssets(_ context.Context, cve string) ([]ai.AssetFact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ai.AssetFact(nil), f.assets[cve]...), nil
}

const goodExplain = `{"why":"NAS-PHOTOS runs the affected product.","patch_steps":["Update to the fixed build."],"temp_mitigations":["Remove the port forward."],"detection_hints":["Check the access log."]}`

func newFacts() *fakeFacts {
	return &fakeFacts{
		cves: map[string]ai.CVEFacts{"CVE-2022-27593": {CVE: "CVE-2022-27593", Vendor: "QNAP", Product: "Photo Station", Name: "QNAP Photo Station External Reference", Description: "An externally controlled reference allows remote attackers to modify system files.",
			RequiredAction: "Apply updates per vendor instructions.", DateAdded: "2022-09-08", Links: []string{"https://www.qnap.com/en/security-advisory/qsa-22-24", "javascript:alert(1)", "ftp://files.example.com/patch.txt", "https://nvd.nist.gov/vuln/detail/CVE-2022-27593", "https://example.com/third"}, Ransomware: true}},
		assets: map[string][]ai.AssetFact{"CVE-2022-27593": {{Name: "NAS-PHOTOS", IP: "192.168.10.40", Kind: "nas", Basis: "product", Status: "open"}}},
	}
}

// fakePruner is core's chainhead.Prune (issue #194) with a way to make it fail: the tests prune against the real helper, so the
// anchor and the head they check are the ones core writes.
type fakePruner struct {
	mu   sync.Mutex
	fail error
}

func (p *fakePruner) Prune(ctx context.Context, tx *sql.Tx, chain, lastPrunedID, lastPrunedHash string, removed int64, now time.Time) error {
	p.mu.Lock()
	fail := p.fail
	p.mu.Unlock()
	if fail != nil {
		return fail
	}
	return chainhead.Prune(ctx, tx, chain, lastPrunedID, lastPrunedHash, removed, now)
}

func (p *fakePruner) failWith(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail = err
}

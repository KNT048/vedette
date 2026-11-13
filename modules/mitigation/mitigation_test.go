package mitigation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/findings"
)

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

const (
	qnapCVE  = "CVE-2022-27593"
	otherCVE = "CVE-2021-0001"
)

func ptr[T any](v T) *T { return &v }

type fakeInv struct {
	mu     sync.Mutex
	assets map[string]findings.AssetView
}

func (f *fakeInv) Assets(_ context.Context, ids []string) (map[string]findings.AssetView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]findings.AssetView{}
	for _, id := range ids {
		if a, ok := f.assets[id]; ok {
			out[id] = a
		}
	}
	return out, nil
}

func (f *fakeInv) MatchInput(context.Context, string) (findings.Asset, bool, error) {
	return findings.Asset{}, false, nil
}

func (f *fakeInv) AssetIDs(context.Context) ([]string, error) { return nil, nil }

type fakeFeeds struct{}

func (fakeFeeds) KevInfo(_ context.Context, cves []string) (map[string]findings.KevInfo, error) {
	out := map[string]findings.KevInfo{}
	for _, c := range cves {
		out[c] = findings.KevInfo{Name: "KEV " + c, Vendor: "QNAP", Product: "Photo Station", DateAdded: "2022-09-01", Links: []string{"https://example.test/a"}}
	}
	return out, nil
}

func (fakeFeeds) Vulns(context.Context) ([]findings.Vuln, error) { return nil, nil }

type fakeVendors map[string]bool

func (v fakeVendors) HasFirewallVendor(_ context.Context, vendor string) (bool, error) {
	return v[vendor], nil
}

type fakeAI struct {
	mu    sync.Mutex
	avail map[Skill]bool
	out   AIOutput
	err   error
	calls []AIRequest
}

func (f *fakeAI) Available(_ context.Context, s Skill) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.avail[s]
}

func (f *fakeAI) Run(_ context.Context, r AIRequest) (AIOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r)
	return f.out, f.err
}

type fakeVerifier struct{ err error }

func (v fakeVerifier) Verify(context.Context, Update) error { return v.err }

// rig is the real stack minus sessions: a database with core, findings and mitigation migrated, the
// findings and mitigation handlers on the real HTTP server, and fakes for inventory, feeds, AI and the
// signature verifier.
type rig struct {
	t       *testing.T
	db      *store.DB
	svc     *findings.Service
	loader  *Loader
	ai      *fakeAI
	vendors fakeVendors
	inv     *fakeInv
	gate    *servertest.Gate
	h       http.Handler
	ids     map[string]string // cve -> finding id on asset a-1
	actions *ActionHandlers
}

type composite struct {
	server.Fallback
	*findings.FindingHandlers
	*ActionHandlers
}

func newRig(t *testing.T) *rig {
	t.Helper()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "findings", FS: findings.Migrations}, {Module: "mitigation", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.DiscardHandler)
	clock := func() time.Time { return t0 }
	a := audit.New(clock)
	r := &rig{
		t: t, db: db, ai: &fakeAI{avail: map[Skill]bool{}}, vendors: fakeVendors{}, gate: servertest.NewGate(), ids: map[string]string{},
		inv: &fakeInv{assets: map[string]findings.AssetView{"a-1": {ID: "a-1", Hostname: ptr("nas01"), IP: "192.168.10.21", Kind: "nas", Display: "Photo Station"}}},
	}
	var err error
	if r.svc, err = findings.NewService(findings.ServiceConfig{DB: db, Audit: a, Inventory: r.inv, Feeds: fakeFeeds{}, Log: log, Clock: clock}); err != nil {
		t.Fatal(err)
	}
	fh := findings.NewFindingHandlers(r.svc, r.inv, fakeFeeds{}, r.gate)
	prov, err := NewProvider(db, r.vendors, r.ai)
	if err != nil {
		t.Fatal(err)
	}
	fh.SetGuidance(prov)
	r.loader = NewLoader(db, a, fakeVerifier{}, log, clock)
	r.actions, err = NewActionHandlers(db, a, r.svc, fh, r.ai, clock)
	if err != nil {
		t.Fatal(err)
	}
	r.h, err = server.New(server.Config{
		API:     composite{Fallback: server.Fallback{Log: log}, FindingHandlers: fh, ActionHandlers: r.actions},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: r.gate,
		Log:     log,
	})
	if err != nil {
		t.Fatal(err)
	}
	sw := []findings.Software{{ID: "s-1", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "6.0.3", KevKeys: []string{"qnap|photo station"}}}
	vulns := []findings.Vuln{{CVE: qnapCVE, Vendor: "QNAP", Product: "Photo Station"}, {CVE: otherCVE, Vendor: "QNAP", Product: "Photo Station"}}
	res, err := r.svc.UpsertFromMatch(t.Context(), findings.Asset{ID: "a-1", Name: "nas01", Software: sw}, vulns)
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed findings: %+v %v", res, err)
	}
	for _, id := range res.Created {
		rec, _ := r.svc.Get(t.Context(), id)
		r.ids[rec.CVE] = id
	}
	return r
}

func (r *rig) call(method, path, user, body string) (int, map[string]any) {
	r.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(r.t.Context(), method, server.Prefix+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	req.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			r.t.Fatalf("%s %s: not JSON: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code, out
}

func errCode(b map[string]any) string {
	m, _ := b["error"].(map[string]any)
	c, _ := m["code"].(string)
	return c
}

func (r *rig) count(query string) int {
	r.t.Helper()
	var n int
	if err := r.db.Reader().QueryRowContext(r.t.Context(), query).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func qnapPack(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(testPackDir + qnapCVE + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// install loads the QNAP test pack through the real loader.
func (r *rig) install() {
	r.t.Helper()
	res, err := r.loader.Install(r.t.Context(), Update{Version: "2026.11.1", Docs: []Doc{{Name: qnapCVE + ".json", Data: qnapPack(r.t)}}})
	if err != nil || res.Loaded != 1 || len(res.Rejected) != 0 {
		r.t.Fatalf("install: %+v %v", res, err)
	}
}

// modify returns the QNAP pack with edit applied to its decoded JSON.
func modify(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(qnapPack(t), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContract_INV2_LoaderFailsClosedWithoutVerifier(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	l := NewLoader(r.db, audit.New(nil), nil, slog.New(slog.DiscardHandler), nil)
	_, err := l.Install(t.Context(), Update{Version: "2026.11.1", Docs: []Doc{{Name: "a", Data: qnapPack(t)}}})
	if !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("err = %v", err)
	}
	if r.count(`SELECT count(*) FROM mit_pack`) != 0 {
		t.Fatal("a pack was stored without a verifier")
	}
}

func TestContract_INV2_LoaderRefusesBadSignatureAndKeepsOldPacks(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	bad := NewLoader(r.db, audit.New(nil), fakeVerifier{err: errors.New("bad sig")}, slog.New(slog.DiscardHandler), nil)
	_, err := bad.Install(t.Context(), Update{Version: "2026.11.2"}) // would withdraw every pack
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("err = %v", err)
	}
	if r.count(`SELECT count(*) FROM mit_pack`) != 1 {
		t.Fatal("an unsigned update changed the loaded packs")
	}
}

func TestContract_INV2_LoaderRequiresConfirmation(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	cases := map[string]func(m map[string]any){
		"draft":           func(m map[string]any) { m["status"] = "draft" },
		"no status":       func(m map[string]any) { delete(m, "status") },
		"no confirmer":    func(m map[string]any) { m["confirmed_by"] = " " },
		"no confirmed_at": func(m map[string]any) { delete(m, "confirmed_at") },
		"no drafted_with": func(m map[string]any) { m["drafted_with"] = "" },
		"no sources":      func(m map[string]any) { m["sources"] = []any{} },
		"javascript url": func(m map[string]any) {
			m["sources"] = []any{map[string]any{"title": "x", "url": "javascript:alert(1)"}}
		},
		"bad cve":       func(m map[string]any) { m["cve"] = "CVE-1" },
		"unknown field": func(m map[string]any) { m["rules"] = []any{"suricata"} },
		"unknown vendor": func(m map[string]any) {
			m["firewall"] = []any{map[string]any{"vendor": "acme", "label": "x", "intro": "x"}}
		},
		"bad indicator": func(m map[string]any) {
			m["compromise"] = map[string]any{"summary": "s", "indicators": []any{map[string]any{"kind": "magic", "title": "t", "detail": "d"}}, "if_found": []any{}}
		},
	}
	for name, edit := range cases {
		res, err := r.loader.Install(t.Context(), Update{Version: "2026.11.1", Docs: []Doc{{Name: name, Data: modify(t, edit)}}})
		if !errors.Is(err, ErrNoValidPack) || res.Loaded != 0 || len(res.Rejected) != 1 || res.Rejected[0].Name != name {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	for name, data := range map[string][]byte{"not json": []byte("cve: x"), "trailing": append(qnapPack(t), []byte(`{}`)...), "huge": make([]byte, maxDocBytes+1)} {
		res, err := r.loader.Install(t.Context(), Update{Version: "2026.11.1", Docs: []Doc{{Name: name, Data: data}}})
		if !errors.Is(err, ErrNoValidPack) || res.Loaded != 0 || len(res.Rejected) != 1 {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	if r.count(`SELECT count(*) FROM mit_pack`) != 0 {
		t.Fatal("an unconfirmed pack was stored")
	}
}

func TestLoaderReplacesAllPacksAndIgnoresDetectedInFile(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	// the test file claims detected=true for fortigate: the file never decides that
	var detected string
	if err := r.db.Reader().QueryRowContext(t.Context(), `SELECT json_extract(body, '$.firewall[0].detected') FROM mit_pack`).Scan(&detected); err != nil || detected != "0" {
		t.Fatalf("detected = %q err=%v", detected, err)
	}
	dup := Doc{Name: "dup", Data: qnapPack(t)}
	res, err := r.loader.Install(t.Context(), Update{Version: "2026.11.2", Docs: []Doc{{Name: "one", Data: qnapPack(t)}, dup}})
	if err != nil || res.Loaded != 1 || len(res.Rejected) != 1 {
		t.Fatalf("duplicate: %+v %v", res, err)
	}
	other := modify(t, func(m map[string]any) { m["cve"] = "CVE-2020-1234" })
	if res, err = r.loader.Install(t.Context(), Update{Version: "2026.11.3", Docs: []Doc{{Name: "other", Data: other}}}); err != nil || res.Loaded != 1 {
		t.Fatalf("replacing update: %+v %v", res, err)
	}
	if r.count(`SELECT count(*) FROM mit_pack WHERE cve = 'CVE-2022-27593'`) != 0 {
		t.Fatal("a withdrawn pack is still loaded")
	}
	if r.count(`SELECT count(*) FROM core_audit WHERE action = 'mitigation.packs_loaded'`) != 3 {
		t.Fatal("each load must be audited")
	}
}

func TestContract_POST1_GuidanceFillsThePageAndSubstitutesDevice(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	r.vendors["fortinet"] = true
	r.ai.avail[SkillExplain] = true
	id := r.ids[qnapCVE]
	code, b := r.call("GET", "/findings/"+id, "viewer", "")
	if code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	pack, _ := b["pack"].(map[string]any)
	if pack == nil || pack["confirmed_by"] != "a Vedette maintainer" || pack["drafted_with"] != "claude-sonnet-5-5" {
		t.Fatalf("pack = %v", b["pack"])
	}
	steps := pack["patch"].(map[string]any)["steps"].([]any)
	if !strings.Contains(steps[0].(string), "nas01") || !strings.Contains(steps[1].(string), "http://192.168.10.21:8080") {
		t.Fatalf("placeholders not replaced: %v", steps)
	}
	if strings.Contains(string(mustJSON(t, b)), "{IP}") || strings.Contains(string(mustJSON(t, b)), "{HOST}") {
		t.Fatal("a placeholder is left in the page")
	}
	det := map[string]bool{}
	for _, g := range pack["firewall"].([]any) {
		gm := g.(map[string]any)
		det[gm["vendor"].(string)] = gm["detected"].(bool)
	}
	if !det["fortigate"] || det["mikrotik"] || det["generic"] {
		t.Fatalf("detected = %v", det) // INV-5
	}
	rc := b["recheck"].(map[string]any)
	if rc["code"] != "curl -sI http://192.168.10.21/photo/" {
		t.Fatalf("recheck = %v", rc)
	}
	if c := b["compromise"].(map[string]any); !strings.Contains(c["indicators"].([]any)[0].(map[string]any)["detail"].(string), "192.168.10.21:8080") {
		t.Fatalf("compromise = %v", c)
	}
	if av := b["ai_available"].(map[string]any); av["explain"] != true || av["config"] != false {
		t.Fatalf("ai_available = %v", av)
	}
	// a CVE without a pack: pack null, generic recheck text, still a normal page
	_, b = r.call("GET", "/findings/"+r.ids[otherCVE], "viewer", "")
	if b["pack"] != nil || b["compromise"] != nil || len(b["recheck"].(map[string]any)["steps"].([]any)) != 3 {
		t.Fatalf("no-pack page = %v", b)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContract_INV4_DeviceValuesAreNeverEscapedIntoCommands(t *testing.T) {
	t.Parallel()
	hostile := []string{"$(reboot)", "a;b", `x"y`, "a b", "nas\n01", "`id`", "{IP}", "-rf", "", strings.Repeat("a", 65), "nas/../x", "ñas"}
	for _, h := range hostile {
		repl := deviceReplacer(&findings.AssetView{IP: "192.168.10.21", Hostname: ptr(h)})
		got := repl.Replace("ssh {HOST} # {IP}")
		if got != "ssh 192.168.10.21 # 192.168.10.21" {
			t.Errorf("hostname %q gave %q", h, got)
		}
	}
	for _, ip := range []string{"192.168.1.1; rm -rf /", "fe80::1%eth0", "", "999.1.1.1", "$(id)"} {
		got := deviceReplacer(&findings.AssetView{IP: ip, Hostname: ptr("nas01")}).Replace("{HOST} {IP}")
		if got != "nas01 <IP>" {
			t.Errorf("ip %q gave %q", ip, got)
		}
	}
	if got := deviceReplacer(nil).Replace("{HOST} {IP}"); got != "<HOST> <IP>" {
		t.Errorf("no device gave %q", got)
	}
	if got := deviceReplacer(&findings.AssetView{IP: "10.0.0.1"}).Replace("{HOST}"); got != "10.0.0.1" {
		t.Errorf("nameless device gave %q", got)
	}
}

func TestContract_INV1_AppliedNeedsPackAndKeepsStatus(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	other := r.ids[otherCVE]
	code, b := r.call("POST", "/findings/"+other+"/applied", "operator", `{"item":"patch"}`)
	if code != 400 || errCode(b) != "no_pack" {
		t.Fatalf("no pack: %d %v", code, b)
	}
	r.install()
	id := r.ids[qnapCVE]
	for range 2 { // once per item
		code, b = r.call("POST", "/findings/"+id+"/applied", "operator", `{"item":"patch"}`)
		if code != 200 {
			t.Fatalf("%d %v", code, b)
		}
	}
	if code, b = r.call("POST", "/findings/"+id+"/applied", "operator", `{"item":"fortigate"}`); code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	applied := b["applied"].([]any)
	if len(applied) != 2 || applied[0].(map[string]any)["item"] != "fortigate" && applied[0].(map[string]any)["item"] != "patch" || applied[0].(map[string]any)["user"] != "it@acme.example" {
		t.Fatalf("applied = %v", applied)
	}
	if b["status"] != "suspected" {
		t.Fatalf("applied changed the status to %v", b["status"])
	}
	if r.count(`SELECT count(*) FROM core_audit WHERE action = 'mitigation.applied'`) != 2 {
		t.Fatal("expected one audit row per new item")
	}
	if code, _ = r.call("POST", "/findings/"+id+"/applied", "operator", `{"item":"magic"}`); code != 400 {
		t.Fatalf("bad item = %d", code)
	}
	if code, b = r.call("POST", "/findings/f-nope/applied", "operator", `{"item":"patch"}`); code != 404 {
		t.Fatalf("unknown finding = %d %v", code, b)
	}
	if code, _ = r.call("POST", "/findings/"+id+"/applied", "viewer", `{"item":"patch"}`); code != 403 {
		t.Fatalf("viewer = %d", code)
	}
}

func TestContract_INV3_AIResultIsLabelledStoredAndGated(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	id := r.ids[otherCVE]
	code, b := r.call("POST", "/findings/"+id+"/ai", "operator", `{"skill":"explain"}`)
	if code != 409 || errCode(b) != "ai_unavailable" {
		t.Fatalf("unavailable: %d %v", code, b)
	}
	if len(r.ai.calls) != 0 {
		t.Fatal("the AI was called although it is unavailable")
	}
	r.ai.avail[SkillExplain] = true
	r.ai.out = AIOutput{Model: "m1", Profile: "main", InputTok: 1200, OutputTok: 300, ActivityID: "act-1",
		Paragraphs: []string{"It matches."}, Steps: []string{"Patch."},
		Citations: []findings.Citation{{Title: "ok", URL: "https://example.test/x"}, {Title: "bad", URL: "javascript:alert(1)"}}}
	code, b = r.call("POST", "/findings/"+id+"/ai", "operator", `{"skill":"explain"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	ex := b["ai"].(map[string]any)["explain"].(map[string]any)
	if ex["model"] != "m1" || ex["profile"] != "main" || ex["skill"] != "explain" || ex["tokens"].(map[string]any)["input"] != float64(1200) {
		t.Fatalf("explain = %v", ex)
	}
	cites := ex["citations"].([]any)
	if cites[0].(map[string]any)["url"] != "https://example.test/x" || cites[1].(map[string]any)["url"] != nil {
		t.Fatalf("citations = %v", cites)
	}
	if b["pack"] != nil || b["ai"].(map[string]any)["config"] != nil {
		t.Fatalf("an AI result leaked into the pack or the other skill: %v", b)
	}
	if call := r.ai.calls[0]; call.Skill != SkillExplain || call.HasPack || call.User != "it@acme.example" || call.Finding.ID != id {
		t.Fatalf("call = %+v", call)
	}
	// it survives a reload of the page, and the audit row names no content
	_, b = r.call("GET", "/findings/"+id, "viewer", "")
	if b["ai"].(map[string]any)["explain"] == nil {
		t.Fatal("AI result lost")
	}
	if r.count(`SELECT count(*) FROM core_audit WHERE action = 'mitigation.ai'`) != 1 || r.count(`SELECT count(*) FROM mit_ai_output WHERE activity_id = 'act-1'`) != 1 {
		t.Fatal("audit or activity link missing")
	}
	// the AI module says it is unavailable after all
	r.ai.err = ErrAIUnavailable
	if code, b = r.call("POST", "/findings/"+id+"/ai", "operator", `{"skill":"explain"}`); code != 409 || errCode(b) != "ai_unavailable" {
		t.Fatalf("%d %v", code, b)
	}
	// the AI module's own error is what the page shows, not "No AI profile is assigned" (beta 0.1.0-beta.1: a cut answer read so)
	r.ai.err = apierr.New(502, "ai_cut_off", "The AI's answer was cut off at the output limit (12,000 tokens), so it was not used.")
	if code, b = r.call("POST", "/findings/"+id+"/ai", "operator", `{"skill":"explain"}`); code != 502 || errCode(b) != "ai_cut_off" || strings.Contains(string(mustJSON(t, b)), "assigned") {
		t.Fatalf("%d %v", code, b)
	}
	// any other failure is a 500 without detail
	r.ai.err = errors.New("provider said secret-token-123")
	if code, b = r.call("POST", "/findings/"+id+"/ai", "operator", `{"skill":"explain"}`); code != 500 || strings.Contains(string(mustJSON(t, b)), "secret-token") {
		t.Fatalf("%d %v", code, b)
	}
}

func TestSanitizeAICapsUntrustedOutput(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("é", maxAIText+10) + "\x00"
	o := AIOutput{Model: big, Paragraphs: make([]string, 50), Steps: []string{big}, InputTok: -5, Citations: make([]findings.Citation, 50)}
	res := sanitizeAI(SkillConfig, t0, o)
	if len([]rune(res.Model)) != 200 || len(res.Paragraphs) != maxAIParagraphs || len([]rune(res.Steps[0])) != maxAIText || len(res.Citations) != maxAICitations || res.Tokens.Input != 0 || strings.ContainsRune(res.Steps[0], 0) {
		t.Fatalf("not capped: %d %d %d", len([]rune(res.Model)), len(res.Paragraphs), len(res.Citations))
	}
}

func TestContract_FORBID3_MitigationOffMeansNoWhatToDo(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	id := r.ids[qnapCVE]
	r.gate.Set("mitigation", false)
	for _, c := range []struct{ path, body string }{{"/applied", `{"item":"patch"}`}, {"/ai", `{"skill":"explain"}`}} {
		if code, _ := r.call("POST", "/findings/"+id+c.path, "operator", c.body); code != 404 {
			t.Errorf("POST %s = %d", c.path, code)
		}
	}
	code, b := r.call("GET", "/findings/"+id, "viewer", "")
	if code != 200 || b["pack"] != nil || b["compromise"] != nil || b["id"] != id {
		t.Fatalf("finding page with mitigation off: %d %v", code, b)
	}
	// data stays: back on, the pack is there again
	r.gate.Set("mitigation", true)
	if _, b = r.call("GET", "/findings/"+id, "viewer", ""); b["pack"] == nil {
		t.Fatal("the pack is gone after the module was switched back on")
	}
}

func TestDeletingTheDeviceTakesAppliedAndAIWithIt(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	r.ai.avail[SkillExplain] = true
	id := r.ids[qnapCVE]
	r.call("POST", "/findings/"+id+"/applied", "operator", `{"item":"patch"}`)
	r.call("POST", "/findings/"+id+"/ai", "operator", `{"skill":"explain"}`)
	if r.count(`SELECT count(*) FROM mit_applied`) != 1 || r.count(`SELECT count(*) FROM mit_ai_output`) != 1 {
		t.Fatal("setup failed")
	}
	if _, err := r.svc.OnAssetDeleted(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	if r.count(`SELECT count(*) FROM mit_applied`)+r.count(`SELECT count(*) FROM mit_ai_output`) != 0 {
		t.Fatal("rows survived their finding")
	}
	if r.count(`SELECT count(*) FROM mit_pack`) != 1 {
		t.Fatal("the pack is not customer data and must stay")
	}
}

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "mitigation", Migrations, "mit_",
		storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "findings", FS: findings.Migrations})
}

func FuzzParsePack(f *testing.F) {
	b, err := os.ReadFile(testPackDir + qnapCVE + ".json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"status":"confirmed"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parsePack(data)
		if err == nil && (p.Status != "confirmed" || p.ConfirmedBy == "" || len(p.Sources) == 0) {
			t.Fatalf("accepted an unconfirmed pack: %+v", p)
		}
	})
}

func TestContract_INV1_AppliedShowsInTheHistory(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	id := r.ids[qnapCVE]
	code, b := r.call("POST", "/findings/"+id+"/applied", "operator", `{"item":"patch"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	hist := b["history"].([]any)
	last := hist[len(hist)-1].(map[string]any)
	applied := b["applied"].([]any)[0].(map[string]any)
	if last["action"] != "applied:patch" || last["user"] != "it@acme.example" || last["ts"] != applied["ts"] {
		t.Fatalf("last history row = %v, applied = %v", last, applied)
	}
	if hist[0].(map[string]any)["action"] != "created" {
		t.Fatalf("history = %v", hist)
	}
	// the list shows the same history
	_, b = r.call("GET", "/findings?asset=a-1", "viewer", "")
	for _, it := range b["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == id {
			h := m["history"].([]any)
			if len(h) != 1 {
				t.Fatalf("list history = %v: only the detail page composes the applied rows", h)
			}
		}
	}
}

func TestMarkAppliedSurfacesConstraintFailuresAndRefusesBadUsers(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	rec, err := r.svc.Get(t.Context(), r.ids[qnapCVE])
	if err != nil {
		t.Fatal(err)
	}
	// an item the table's CHECK refuses must be an error, not a silent no-op
	if err := r.actions.markApplied(t.Context(), rec, "bogus", "it@acme.example"); err == nil {
		t.Fatal("a CHECK failure was swallowed")
	}
	for _, u := range []string{"", strings.Repeat("a", 321), "a\x00b"} {
		err := r.actions.markApplied(t.Context(), rec, "patch", u)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Status != 400 {
			t.Errorf("user %q: err = %v", u, err)
		}
	}
	if r.count(`SELECT count(*) FROM mit_applied`) != 0 {
		t.Fatal("a refused request wrote a row")
	}
}

func TestContract_INV2_LoaderRefusesUpdatesThatWouldWipeThePacks(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	bad := modify(t, func(m map[string]any) { m["status"] = "draft" })
	for name, u := range map[string]Update{
		"no documents":  {Version: "2026.11.2"},
		"only rejected": {Version: "2026.11.2", Docs: []Doc{{Name: "draft", Data: bad}}},
	} {
		res, err := r.loader.Install(t.Context(), u)
		if !errors.Is(err, ErrNoValidPack) || res.Loaded != 0 {
			t.Errorf("%s: %+v %v", name, res, err)
		}
		if name == "only rejected" && len(res.Rejected) != 1 {
			t.Errorf("%s: the reasons must come back with the refusal: %+v", name, res)
		}
	}
	if r.count(`SELECT count(*) FROM mit_pack`) != 1 {
		t.Fatal("a refused update changed the loaded packs")
	}
	// a refused update does not use up its version
	res, err := r.loader.Install(t.Context(), Update{Version: "2026.11.2", Docs: []Doc{{Name: "ok", Data: qnapPack(t)}}})
	if err != nil || res.Loaded != 1 {
		t.Fatalf("retry with the same version: %+v %v", res, err)
	}
}

func TestContract_INV2_LoaderRefusesReplayedAndOlderVersions(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install() // 2026.11.1
	docs := []Doc{{Name: "ok", Data: qnapPack(t)}}
	for _, v := range []string{"2026.11.1", "2026.10.9", "2025.12.31", "!!!"} {
		if _, err := r.loader.Install(t.Context(), Update{Version: v, Docs: docs}); !errors.Is(err, ErrReplay) {
			t.Errorf("version %q: err = %v", v, err)
		}
	}
	if _, err := r.loader.Install(t.Context(), Update{Version: "2026.11.2", Docs: docs}); err != nil {
		t.Fatalf("a newer version was refused: %v", err)
	}
	if _, err := r.loader.Install(t.Context(), Update{Version: "2026.11.1", Docs: docs}); !errors.Is(err, ErrReplay) {
		t.Fatalf("the old version came back: %v", err)
	}
	// an unreadable version is refused on a first install as well, or it would block every later one
	fresh := newRig(t)
	if _, err := fresh.loader.Install(t.Context(), Update{Version: "!!!", Docs: docs}); err == nil {
		t.Fatal("an unreadable version was accepted")
	}
}

func TestConstructorsRefuseMissingDependencies(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := NewProvider(nil, r.vendors, r.ai); err == nil {
		t.Error("NewProvider accepted a nil database")
	}
	if _, err := NewProvider(r.db, nil, r.ai); err == nil {
		t.Error("NewProvider accepted nil vendors")
	}
	if _, err := NewProvider(r.db, r.vendors, nil); err == nil {
		t.Error("NewProvider accepted a nil AI")
	}
	a := audit.New(nil)
	fh := findings.NewFindingHandlers(r.svc, r.inv, fakeFeeds{}, r.gate)
	for name, args := range map[string][]any{"db": {nil, a, r.svc, fh, r.ai}, "audit": {r.db, nil, r.svc, fh, r.ai}, "findings": {r.db, a, nil, fh, r.ai}, "details": {r.db, a, r.svc, nil, r.ai}, "ai": {r.db, a, r.svc, fh, nil}} {
		var (
			db  *store.DB
			au  *audit.Log
			svc *findings.Service
			det Details
			ai  AI
		)
		db, _ = args[0].(*store.DB)
		au, _ = args[1].(*audit.Log)
		svc, _ = args[2].(*findings.Service)
		det, _ = args[3].(Details)
		ai, _ = args[4].(AI)
		if _, err := NewActionHandlers(db, au, svc, det, ai, nil); err == nil {
			t.Errorf("NewActionHandlers accepted a missing %s", name)
		}
	}
}

// Compromise commands are text from the signed pack: the page shows them with the device values put
// in and nothing else, whatever the device is called, and no code path here can run them (os/exec is
// banned by the linter, and core/exec is not imported).
func TestContract_INV6_CompromiseCommandsAreSignedTextOnly(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	r.inv.assets["a-1"] = findings.AssetView{ID: "a-1", Hostname: ptr("$(reboot);x"), IP: "192.168.10.21", Kind: "nas"}
	_, b := r.call("GET", "/findings/"+r.ids[qnapCVE], "viewer", "")
	var pack struct {
		Compromise struct {
			Indicators []struct {
				Commands []struct{ Code string } `json:"commands"`
			} `json:"indicators"`
		} `json:"compromise"`
	}
	if err := json.Unmarshal(qnapPack(t), &pack); err != nil {
		t.Fatal(err)
	}
	want := strings.NewReplacer("{IP}", "192.168.10.21", "{HOST}", "192.168.10.21")
	got := b["compromise"].(map[string]any)["indicators"].([]any)
	for i, in := range pack.Compromise.Indicators {
		for j, c := range in.Commands {
			shown := got[i].(map[string]any)["commands"].([]any)[j].(map[string]any)["code"]
			if shown != want.Replace(c.Code) {
				t.Errorf("indicator %d command %d: shown %q, signed %q", i, j, shown, c.Code)
			}
		}
	}
}

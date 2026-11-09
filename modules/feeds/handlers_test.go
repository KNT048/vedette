package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
)

type fakeInv struct {
	mu      sync.Mutex
	matches map[string][]MatchedAsset
	added   []ManualDevice
}

func (f *fakeInv) MatchProducts(_ context.Context, ps []Product) (map[string][]MatchedAsset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]MatchedAsset{}
	for _, p := range ps {
		if m, ok := f.matches[p.Key()]; ok {
			out[p.Key()] = m
		}
	}
	return out, nil
}

func (f *fakeInv) AddManualDevice(_ context.Context, tx *sql.Tx, _ string, d ManualDevice) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tx == nil {
		return errors.New("no transaction")
	}
	f.added = append(f.added, d)
	return nil
}

type published struct {
	Name    string
	Payload any
}

type fakePub struct {
	mu     sync.Mutex
	events []published
}

func (f *fakePub) Publish(_ context.Context, name string, payload any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, published{name, payload})
	return nil
}

func (f *fakePub) named(name string) []any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []any
	for _, e := range f.events {
		if e.Name == name {
			out = append(out, e.Payload)
		}
	}
	return out
}

type composite struct {
	server.Fallback
	*Handlers
}

// failingTransport proves a code path never touches the network.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected network request to %s", r.URL.Host)
	return nil, errors.New("no network in this test")
}

type env struct {
	t    *testing.T
	svc  *Service
	db   *store.DB
	h    http.Handler
	gate *servertest.Gate
	inv  *fakeInv
	pub  *fakePub
	mu   sync.Mutex
	now  time.Time
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) setNow(t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = t
}

// newEnv is the real stack of the module minus sessions: a migrated database, the real secrets store and audit
// log, the generated server with the module gate, and fakes for inventory, events and the network.
func newEnv(t *testing.T) *env {
	t.Helper()
	_, db := newStore(t)
	key := make([]byte, secrets.KeySize)
	sec, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, gate: servertest.NewGate(), inv: &fakeInv{matches: map[string][]MatchedAsset{}}, pub: &fakePub{}, now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	log := slog.New(slog.DiscardHandler)
	e.svc, err = NewService(Deps{DB: db, Secrets: sec, Audit: audit.New(e.clock), Modules: e.gate, Log: log, Inventory: e.inv, Events: e.pub, Clock: e.clock,
		Fetcher: Fetcher{Client: &http.Client{Transport: failingTransport{t}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Seed(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.h, err = server.New(server.Config{API: composite{server.Fallback{Log: log}, NewHandlers(e.svc)}, Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: e.gate, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) do(method, path, user, body string) (int, map[string]any, string) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(e.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%s %s: body is not JSON: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code, out, w.Body.String()
}

func (e *env) get(path string) (int, map[string]any) {
	e.t.Helper()
	c, b, _ := e.do("GET", path, "viewer", "")
	return c, b
}

func code(b map[string]any) string {
	er, _ := b["error"].(map[string]any)
	s, _ := er["code"].(string)
	return s
}

// at digs into decoded JSON by object keys and array indexes.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[k]
		case int:
			a, _ := v.([]any)
			if k >= len(a) {
				return nil
			}
			v = a[k]
		}
	}
	return v
}

// loadKEV stores the accepted rows of the KEV fixture (CVE-2026-10001 on Nov 3, -10002 on Nov 2, -10003 on Oct 30) with EPSS scores.
func (e *env) loadKEV() {
	e.t.Helper()
	data, err := os.ReadFile("testdata/kev.json")
	if err != nil {
		e.t.Fatal(err)
	}
	cat, err := ParseKEV(data)
	if err != nil || len(cat.Vulns) != 3 {
		e.t.Fatalf("fixture: %d vulns, %v", len(cat.Vulns), err)
	}
	applyV(e.t, e.db, e.clock(), "cisa-kev", cat.Vulns, false)
	write(e.t, e.db, func(tx *sql.Tx) error {
		_, err := applyEPSS(e.t.Context(), tx, map[string]float64{"CVE-2026-10001": 0.9, "CVE-2026-10002": 0.3, "CVE-2026-10003": 0.1}, map[string]float64{"CVE-2026-10001": 0.5, "CVE-2026-10003": 0.1})
		return err
	})
}

func rowsOf(t testing.TB, db *store.DB, table string) int {
	return count(t, db, "SELECT count(*) FROM "+table)
}

func TestContract_SYS5_ModuleOffMeansNoRoutes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, p := range []string{"/feeds/status", "/feeds/hot?window=7d", "/feeds/weekly", "/feeds/cve/CVE-2026-10001", "/feeds/search?q=a", "/feeds/sources"} {
		if c, _ := e.get(p); c != 200 && c != 404 {
			t.Errorf("%s on: %d", p, c)
		}
	}
	e.gate.Set("feeds", false)
	for _, p := range []string{"/feeds/status", "/feeds/hot?window=7d", "/feeds/sources"} {
		if c, b := e.get(p); c != 404 || code(b) != "not_found" {
			t.Errorf("%s off: %d %v", p, c, b)
		}
	}
	if n := rowsOf(t, e.db, "feeds_source"); n != len(BuiltinSources()) {
		t.Errorf("data not kept: %d feeds", n)
	}
}

func TestRolesAreEnforcedBeforeTheHandlers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, c := range []struct{ method, path, user string }{
		{"PUT", "/feeds/sources/ipsum", "operator"}, {"POST", "/feeds/sources/ipsum/fetch", "operator"}, {"POST", "/feeds/custom", "operator"},
		{"POST", "/feeds/parse-test", "viewer"}, {"DELETE", "/feeds/custom/x", "operator"}, {"POST", "/feeds/weekly/x", "viewer"},
	} {
		if got, _, _ := e.do(c.method, c.path, c.user, `{}`); got != 403 {
			t.Errorf("%s %s as %s: %d, want 403", c.method, c.path, c.user, got)
		}
	}
	if got, _, _ := e.do("GET", "/feeds/status", "", ""); got != 401 {
		t.Errorf("no session: %d", got)
	}
}

func TestContract_POST2_HotBoardOrderAndInventory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	host := "nas1"
	e.inv.matches["synology|diskstation manager"] = []MatchedAsset{{ID: "a1", Hostname: &host, IP: "10.0.0.5", Display: "NAS", How: HaveYes}}
	e.inv.matches["qnap|photo station"] = []MatchedAsset{{ID: "a2", IP: "10.0.0.6", Display: "QNAP", How: HaveMaybe}}

	c, b := e.get("/feeds/hot?window=7d")
	if c != 200 || at(b, "window") != "7d" {
		t.Fatalf("%d %v", c, b)
	}
	var order []string
	for i := 0; at(b, "rows", i) != nil; i++ {
		order = append(order, at(b, "rows", i, "key").(string)+"="+at(b, "rows", i, "you_have").(string))
	}
	// yes first; the rest by number of CVEs (all 1), then the top EPSS (fortinet 0.3 over qnap 0.1)
	if got := strings.Join(order, ","); got != "synology|diskstation manager=yes,fortinet|fortios=no,qnap|photo station=maybe" {
		t.Errorf("order: %s", got)
	}
	row := at(b, "rows", 0)
	if at(row, "display") != "Synology NAS (DSM)" || at(row, "ransomware") != true || at(row, "has_template") != false || at(row, "max_epss") != 0.9 ||
		at(row, "matched_assets", 0) != "a1" || at(row, "cves", 0, "cve") != "CVE-2026-10001" {
		t.Errorf("row: %v", row)
	}
	if d, _ := at(row, "max_epss_delta").(float64); d < 0.39 || d > 0.41 {
		t.Errorf("delta: %v", at(row, "max_epss_delta"))
	}
	if at(b, "rows", 1, "max_epss_delta") != nil { // no score of 7 days ago: not rising
		t.Errorf("fortinet delta: %v", at(b, "rows", 1, "max_epss_delta"))
	}
	if at(b, "latest", "cve") != "CVE-2026-10001" || at(b, "latest", "display") != "Synology NAS (DSM)" {
		t.Errorf("latest: %v", at(b, "latest"))
	}
	// the 24 h window, counted from the clock
	e.setNow(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	_, b = e.get("/feeds/hot?window=24h")
	if at(b, "rows", 0, "key") != "synology|diskstation manager" || at(b, "rows", 1) != nil {
		t.Errorf("24h: %v", b)
	}
}

func TestContract_PRE2_BadWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// The generated server rejects an unknown window before the handler (generic 400 invalid); the handler keeps its own check.
	if c, b := e.get("/feeds/hot?window=1h"); c != 400 {
		t.Errorf("%d %v", c, b)
	}
	_, err := NewHandlers(e.svc).FeedsGetFeedsHot(t.Context(), oas.FeedsGetFeedsHotParams{Window: "1h"})
	if ae, ok := apierr.As(err); !ok || ae.Code != "bad_window" {
		t.Errorf("handler: %v", err)
	}
}

func TestContract_INV10_InventoryOffMeansNull(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	e.inv.matches["synology|diskstation manager"] = []MatchedAsset{{ID: "a1", IP: "10.0.0.5", Display: "NAS", How: HaveYes}}
	e.gate.Set("inventory", false)
	_, b := e.get("/feeds/hot?window=7d")
	for i := 0; at(b, "rows", i) != nil; i++ {
		if at(b, "rows", i, "you_have") != nil || len(at(b, "rows", i, "matched_assets").([]any)) != 0 {
			t.Errorf("row %d: %v", i, at(b, "rows", i))
		}
	}
	if at(b, "rows", 0) == nil {
		t.Fatal("no rows")
	}
	// the order falls back to cves, then EPSS
	if at(b, "rows", 0, "key") != "synology|diskstation manager" {
		t.Errorf("first: %v", at(b, "rows", 0, "key"))
	}
	_, s := e.get("/feeds/status")
	if at(s, "inventory_on") != false {
		t.Errorf("status: %v", s)
	}
	c, d := e.get("/feeds/cve/CVE-2026-10001")
	if c != 200 || d["matched"] != nil {
		t.Errorf("cve: %d matched=%v", c, d["matched"])
	}
	// no inventory implementation at all behaves the same
	e.gate.Set("inventory", true)
	e.svc.Inventory = nil
	if _, s = e.get("/feeds/status"); at(s, "inventory_on") != false {
		t.Errorf("status without inventory: %v", s)
	}
}

func TestContract_INV11_YouHaveYesMaybeNo(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		have []MatchedAsset
		want YouHave
	}{{nil, HaveNo}, {[]MatchedAsset{{How: HaveMaybe}}, HaveMaybe}, {[]MatchedAsset{{How: HaveMaybe}, {How: HaveYes}}, HaveYes}} {
		if got := youHave(c.have); got != c.want {
			t.Errorf("%v: %s, want %s", c.have, got, c.want)
		}
	}
	e := newEnv(t)
	e.loadKEV()
	e.inv.matches["synology|diskstation manager"] = []MatchedAsset{{ID: "a1", IP: "10.0.0.5", Display: "NAS", How: HaveYes}}
	c, b := e.get("/feeds/cve/CVE-2026-10001")
	if c != 200 || at(b, "cve") != "CVE-2026-10001" || at(b, "matched", 0, "how") != "yes" || at(b, "matched", 0, "hostname") != nil || at(b, "display") != "Synology NAS (DSM)" {
		t.Errorf("%d %v", c, b)
	}
	if _, b = e.get("/feeds/cve/CVE-2026-10002"); at(b, "matched") == nil || len(at(b, "matched").([]any)) != 0 {
		t.Errorf("no match must be [] with the inventory on: %v", b["matched"])
	}
}

func TestContract_PRE3_NotInKEV(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if c, b := e.get("/feeds/cve/CVE-2020-0001"); c != 404 || code(b) != "not_in_kev" {
		t.Errorf("%d %v", c, b)
	}
}

func TestContract_PRE4_SearchKinds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	applyI(t, e.db, e.clock(), "abusech-feodo", []iocInput{{Kind: "ip", Value: "185.220.101.47", FirstSeen: "2026-09-12"}})
	applyI(t, e.db, e.clock(), "tor-exit", []iocInput{{Kind: "ip", Value: "185.220.101.47"}, {Kind: "ip", Value: "45.148.10.95"}})
	applyI(t, e.db, e.clock(), "ipsum", []iocInput{{Kind: "ip", Value: "103.75.190.12"}, {Kind: "domain", Value: "bad.example.net"}})

	if c, b := e.get("/feeds/search?q=%20%20"); c != 400 || code(b) != "empty_query" {
		t.Errorf("blank: %d %v", c, b)
	}
	if c, b := e.get("/feeds/search?q="); c != 400 {
		t.Errorf("empty: %d %v", c, b)
	}
	_, b := e.get("/feeds/search?q=cve-2026-10001")
	if at(b, "kind") != "cve" || at(b, "cve") != "CVE-2026-10001" || at(b, "found") != true {
		t.Errorf("cve: %v", b)
	}
	if _, b = e.get("/feeds/search?q=CVE-2020-1234"); at(b, "found") != false {
		t.Errorf("cve missing: %v", b)
	}
	// two independent sources, one of them block-class: block; Tor exit does not count toward block but this has feodo (CC0)
	_, b = e.get("/feeds/search?q=185.220.101.47")
	hit := at(b, "hit")
	if at(b, "kind") != "ioc" || at(b, "type") != "ip" || at(hit, "verdict") != "block" || at(hit, "first_seen") != "2026-09-12" ||
		at(hit, "category") != "Botnet command-and-control server, Tor exit node" || at(hit, "sources", 0) != "abuse.ch Feodo Tracker" || at(hit, "sources", 1) != "Tor exit list" {
		t.Errorf("block: %v", b)
	}
	// Tor exit alone is information only; one source alone is an alert
	if _, b = e.get("/feeds/search?q=45.148.10.95"); at(b, "hit", "verdict") != "alert" {
		t.Errorf("tor alone: %v", b)
	}
	if _, b = e.get("/feeds/search?q=103.75.190.12"); at(b, "hit", "verdict") != "alert" {
		t.Errorf("ipsum alone: %v", b)
	}
	if _, b = e.get("/feeds/search?q=BAD.example.net"); at(b, "type") != "domain" || at(b, "value") != "bad.example.net" || at(b, "hit", "verdict") != "alert" {
		t.Errorf("domain: %v", b)
	}
	// unknown, private and 1-label values are not hits and never an error
	for _, q := range []string{"8.8.8.8", "10.1.2.3", "intranet.local", "unknown.example.org"} {
		if c, b := e.get("/feeds/search?q=" + q); c != 200 || at(b, "kind") != "ioc" || b["hit"] != nil {
			t.Errorf("%s: %d %v", q, c, b)
		}
	}
	// text: vendor, product, name or the recognised name; newest first; nothing leaves the box
	_, b = e.get("/feeds/search?q=nas")
	if at(b, "kind") != "text" || at(b, "vulns", 0, "cve") != "CVE-2026-10001" || at(b, "vulns", 0, "display") != "Synology NAS (DSM)" {
		t.Errorf("text: %v", b)
	}
	if _, b = e.get("/feeds/search?q=zzzz"); len(at(b, "vulns").([]any)) != 0 {
		t.Errorf("text miss: %v", b)
	}
}

func TestContract_INV14_WeeklyAndIHaveIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	c, b := e.get("/feeds/weekly")
	if c != 200 || at(b, "items", 0, "id") != "synology|diskstation manager" || at(b, "items", 0, "answer") != nil || at(b, "items", 3) != nil {
		t.Fatalf("%d %v", c, b)
	}
	want := "Synology NAS (DSM) has a vulnerability that ransomware groups are exploiting (added to the CISA list on 3 Nov). If your company uses it, update it following Synology's advisory this week."
	if at(b, "items", 0, "text") != want || !strings.Contains(at(b, "items", 1, "text").(string), "being exploited in the wild") {
		t.Errorf("text: %v", at(b, "items", 0, "text"))
	}
	post := func(user, id, answer string) (int, map[string]any) {
		c, b, _ := e.do("POST", "/feeds/weekly/"+id, user, `{"answer":"`+answer+`"}`)
		return c, b
	}
	id := "synology%7Cdiskstation%20manager"
	// I have it: one manual device through the inventory, once
	c, b = post("operator", id, "have")
	if c != 200 || at(b, "items", 0, "answer") != "have" || len(e.inv.added) != 1 {
		t.Fatalf("%d %v %d devices", c, b, len(e.inv.added))
	}
	d := e.inv.added[0]
	if d.Kind != "nas" || d.Vendor != "Synology" || d.Display != "Synology NAS (DSM)" || d.Key != "synology|diskstation manager" {
		t.Errorf("device: %+v", d)
	}
	post("operator", id, "have")
	if len(e.inv.added) != 1 {
		t.Errorf("the second click added a device: %d", len(e.inv.added))
	}
	// Not relevant only stores the answer
	c, b = post("operator", "fortinet%7Cfortios", "not_relevant")
	if c != 200 || at(b, "items", 1, "answer") != "not_relevant" || len(e.inv.added) != 1 {
		t.Errorf("%d %v", c, b)
	}
	// Inventory off: the answer is stored, no device, no error
	e.gate.Set("inventory", false)
	c, b = post("operator", "qnap%7Cphoto%20station", "have")
	if c != 200 || at(b, "items", 2, "answer") != "have" || len(e.inv.added) != 1 {
		t.Errorf("%d %v %d", c, b, len(e.inv.added))
	}
	if c, b = post("operator", "nobody%7Cknown", "have"); c != 404 || code(b) != "not_found" {
		t.Errorf("unknown item: %d %v", c, b)
	}
	if c, _ = post("operator", id, "maybe"); c != 400 {
		t.Errorf("bad answer: %d", c)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_audit WHERE action = 'feeds.weekly_answer'`); n != 4 {
		t.Errorf("%d audit rows", n)
	}
	// The sentence needs no AI and no network: the failing transport saw nothing.
}

func TestStatusAndSourcesListing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c, b := e.get("/feeds/sources")
	if c != 200 || at(b, "items", 8, "id") != "hagezi-tif" || at(b, "items", 9) != nil {
		t.Fatalf("%d %v", c, b)
	}
	f := at(b, "items", 0)
	if at(f, "id") != "cisa-kev" || at(f, "builtin") != true || at(f, "status") != "never" || at(f, "last_fetch") != nil || at(f, "records") != nil || at(f, "parser") != nil ||
		at(f, "default_url") != at(f, "url") || at(f, "interval_hours") != 24.0 || at(f, "auth", "type") != "none" || at(f, "license") != "CC0" || at(b, "items", 3, "interval_hours") != 6.0 {
		t.Errorf("feed: %v", f)
	}
	_, s := e.get("/feeds/status")
	if at(s, "sources") == nil || len(at(s, "sources").([]any)) != 0 || at(s, "kev_catalog_version") != "" {
		t.Errorf("empty status: %v", s)
	}
	// after a successful KEV pull the status lists the sources with their time
	write(t, e.db, func(tx *sql.Tx) error {
		return recordOutcome(t.Context(), tx, "cisa-kev", outcome{Started: e.clock(), Finished: e.clock(), OK: true, Records: 3, CatalogVersion: "2026.11.04"})
	})
	_, s = e.get("/feeds/status")
	if at(s, "kev_catalog_version") != "2026.11.04" || at(s, "sources", 0, "name") != "CISA KEV" || at(s, "sources", 0, "fetched_at") != "2026-11-05T12:00:00Z" || at(s, "generated_at") != "2026-11-05T12:00:00Z" {
		t.Errorf("status: %v", s)
	}
}

func (e *env) put(id, body string) (int, map[string]any) {
	e.t.Helper()
	c, b, _ := e.do("PUT", "/feeds/sources/"+id, "admin", body)
	return c, b
}

func TestContract_INV4_BuiltinFeedsCanBeTunedButNotDeleted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c, b := e.put("ipsum", `{"enabled":false,"interval_hours":12,"url":"https://mirror.example.net/ipsum.txt"}`)
	if c != 200 || at(b, "enabled") != false || at(b, "interval_hours") != 12.0 || at(b, "url") != "https://mirror.example.net/ipsum.txt" || at(b, "default_url") == "https://mirror.example.net/ipsum.txt" {
		t.Fatalf("%d %v", c, b)
	}
	// url "" resets the default
	if c, b = e.put("ipsum", `{"url":""}`); c != 200 || at(b, "url") != at(b, "default_url") || at(b, "enabled") != false {
		t.Errorf("reset: %d %v", c, b)
	}
	for _, bad := range []string{`{"url":"http://example.com/x"}`, `{"url":"ftp://example.com/x"}`, `{"url":"https://u:p@example.com/x"}`} {
		if c, b = e.put("ipsum", bad); c != 400 || code(b) != "invalid_url" {
			t.Errorf("%s: %d %v", bad, c, b)
		}
	}
	if c, b = e.put("first-epss", `{"url":"https://mirror.example.net/epss?x=1"}`); c != 400 || code(b) != "invalid_url" {
		t.Errorf("epss query: %d %v", c, b)
	}
	if c, _ = e.put("ipsum", `{"url":"http://10.1.1.5/ipsum.txt"}`); c != 200 {
		t.Errorf("internal http: %d", c)
	}
	if c, b = e.put("nope", `{"enabled":true}`); c != 404 || code(b) != "not_found" {
		t.Errorf("unknown: %d %v", c, b)
	}
	if c, _ = e.put("ipsum", `{"interval_hours":0}`); c != 400 {
		t.Errorf("interval: %d", c)
	}
	if c, b, _ = e.do("DELETE", "/feeds/custom/ipsum", "admin", ""); c != 404 || code(b) != "not_found" {
		t.Errorf("delete built-in: %d %v", c, b)
	}
	if n := rowsOf(t, e.db, "feeds_source"); n != len(BuiltinSources()) {
		t.Errorf("%d feeds", n)
	}
	var detail string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'feeds.update' ORDER BY seq LIMIT 1`).Scan(&detail); err != nil || detail != "disabled, every 12 h, address changed" {
		t.Errorf("audit: %q %v", detail, err)
	}
}

const customBody = `{"name":"Partner C2 list","kind":"ioc","url":"https://threat-share.example.net/c2.csv","enabled":true,"interval_hours":6,
"auth":{"type":"bearer","header_name":null,"username":null,"secret":"s3cretTOKEN-x7Qk"},
"parser":{"format":"csv","records_path":"","delimiter":",","has_header":true,"fields":{"indicator":{"source":"dst_ip","regex":"","trim":true,"lowercase":false,"date_format":"auto"}}}}`

func (e *env) auditText() string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.t.Context(), `SELECT user || action || target || coalesce(detail, '') FROM core_audit`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var sb strings.Builder
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		sb.WriteString(s + "\n")
	}
	return sb.String()
}

func TestContract_INV6_SecretsViaCoreSecretsOnlyLast4Returned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c, b, raw := e.do("POST", "/feeds/custom", "admin", customBody)
	if c != 201 || !strings.HasPrefix(at(b, "id").(string), "cf-") || at(b, "builtin") != false || at(b, "auth", "secret_last4") != "x7Qk" || at(b, "status") != "never" || at(b, "parser", "format") != "csv" {
		t.Fatalf("%d %s", c, raw)
	}
	id := at(b, "id").(string)
	if strings.Contains(raw, "s3cretTOKEN") {
		t.Error("the response carries the secret")
	}
	var secretID, l4 string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT secret_id, secret_last4 FROM feeds_source WHERE id = ?`, id).Scan(&secretID, &l4); err != nil || l4 != "x7Qk" {
		t.Fatalf("%v %q", err, l4)
	}
	plain, err := e.svc.Secrets.Open(t.Context(), e.db.Reader(), secretID, secretPurpose)
	if err != nil || string(plain) != "s3cretTOKEN-x7Qk" {
		t.Fatalf("open: %q %v", plain, err)
	}
	// nowhere else: not in the listing, not in any feeds table, not in the audit log
	_, _, list := e.do("GET", "/feeds/sources", "viewer", "")
	if strings.Contains(list, "s3cretTOKEN") || !strings.Contains(list, `"secret_last4":"x7Qk"`) {
		t.Errorf("listing: %s", list)
	}
	var leaked int
	for _, tb := range []string{"feeds_source", "feeds_fetch_log"} {
		rows, _ := e.db.Reader().QueryContext(t.Context(), "SELECT * FROM "+tb)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			_ = rows.Scan(ptrs...)
			if strings.Contains(fmt.Sprint(vals...), "s3cretTOKEN") {
				leaked++
			}
		}
		_ = rows.Close()
	}
	if leaked != 0 || strings.Contains(e.auditText(), "s3cretTOKEN") {
		t.Errorf("secret leaked: %d rows, audit %q", leaked, e.auditText())
	}

	// editing with the secret left out, or empty, keeps the stored one
	edit := func(secretPart string) (int, map[string]any) {
		body := strings.Replace(customBody, `"secret":"s3cretTOKEN-x7Qk"`, secretPart, 1)
		c, b, _ := e.do("PUT", "/feeds/custom/"+id, "admin", body)
		return c, b
	}
	for _, part := range []string{`"header_name":null`, `"secret":""`} {
		c, b = edit(part)
		if c != 200 || at(b, "auth", "secret_last4") != "x7Qk" {
			t.Errorf("keep (%s): %d %v", part, c, b)
		}
	}
	if plain, _ := e.svc.Secrets.Open(t.Context(), e.db.Reader(), secretID, secretPurpose); string(plain) != "s3cretTOKEN-x7Qk" {
		t.Error("the stored secret changed")
	}
	// a new secret replaces it in place
	if c, b = edit(`"secret":"another-secret-ABCD"`); c != 200 || at(b, "auth", "secret_last4") != "ABCD" {
		t.Errorf("rotate: %d %v", c, b)
	}
	if plain, _ := e.svc.Secrets.Open(t.Context(), e.db.Reader(), secretID, secretPurpose); string(plain) != "another-secret-ABCD" {
		t.Error("the secret was not replaced")
	}
	// short or spaced secrets are refused
	for _, s := range []string{`"secret":"short"`, `"secret":"has some spaces in it"`} {
		if c, b = edit(s); c != 400 || code(b) != "invalid_auth" {
			t.Errorf("%s: %d %v", s, c, b)
		}
	}
	// switching the authentication off deletes the secret
	body := strings.Replace(customBody, `{"type":"bearer","header_name":null,"username":null,"secret":"s3cretTOKEN-x7Qk"}`, `{"type":"none","header_name":null,"username":null}`, 1)
	if c, b, _ = e.do("PUT", "/feeds/custom/"+id, "admin", body); c != 200 || at(b, "auth", "secret_last4") != nil || at(b, "auth", "type") != "none" {
		t.Errorf("none: %d %v", c, b)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_secret`); n != 0 {
		t.Errorf("%d secrets left", n)
	}
	// a feed that needs a secret and has none stored is refused
	body = strings.Replace(customBody, `"secret":"s3cretTOKEN-x7Qk"`, `"header_name":null`, 1)
	if c, b, _ = e.do("PUT", "/feeds/custom/"+id, "admin", body); c != 400 || code(b) != "invalid_auth" {
		t.Errorf("no secret: %d %v", c, b)
	}
}

func TestContract_PRE5_CustomFeedBoundaryAndAudit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	post := func(mut func(string) string) (int, map[string]any) {
		c, b, _ := e.do("POST", "/feeds/custom", "admin", mut(customBody))
		return c, b
	}
	sub := func(old, repl string) func(string) string {
		return func(s string) string { return strings.Replace(s, old, repl, 1) }
	}
	for _, c := range []struct {
		name string
		mut  func(string) string
		code string
	}{
		{"blank name", sub(`"Partner C2 list"`, `"   "`), "invalid_name"},
		{"built-in name", sub(`"Partner C2 list"`, `"ipsum"`), "duplicate_name"},
		{"http public", sub(`https://threat-share`, `http://threat-share`), "invalid_url"},
		{"no address", sub(`https://threat-share.example.net/c2.csv`, `not a url`), "invalid_url"},
		{"header auth without name", sub(`"type":"bearer","header_name":null`, `"type":"header","header_name":"Host"`), "invalid_auth"},
		{"basic without user", sub(`"type":"bearer"`, `"type":"basic"`), "invalid_auth"},
		{"unmapped required field", sub(`"source":"dst_ip"`, `"source":""`), "bad_config"},
		{"bad regex", sub(`"regex":""`, `"regex":"("`), "bad_config"},
	} {
		got, b := post(c.mut)
		if got != 400 || code(b) != c.code {
			t.Errorf("%s: %d %v, want %s", c.name, got, b, c.code)
		}
	}
	if got, b := post(sub(`"kind":"ioc"`, `"kind":"vulnerabilities"`)); got != 400 || code(b) != "bad_config" {
		// csv is valid for both kinds; the missing CVE mapping is a configuration error
		t.Errorf("vuln csv without cve: %d %v", got, b)
	}
	if got, b := post(func(s string) string {
		return sub(`"format":"csv"`, `"format":"stix"`)(sub(`"kind":"ioc"`, `"kind":"vulnerabilities"`)(s))
	}); got != 400 || code(b) != "invalid_format" {
		t.Errorf("stix: %d %v", got, b)
	}
	if n := rowsOf(t, e.db, "feeds_source"); n != len(BuiltinSources()) || count(t, e.db, `SELECT count(*) FROM core_audit`) != 0 {
		t.Errorf("a refused feed left %d feeds and audit rows", n)
	}
	if got, _ := post(func(s string) string { return s }); got != 201 {
		t.Fatal("create")
	}
	// the name is unique without regard to case, also on edit of another feed
	if got, b := post(sub(`"Partner C2 list"`, `"PARTNER c2 LIST"`)); got != 400 || code(b) != "duplicate_name" {
		t.Errorf("dup: %d %v", got, b)
	}
	if !strings.Contains(e.auditText(), "feeds.add_custom") || !strings.Contains(e.auditText(), "Partner C2 listioc, csv") {
		t.Errorf("audit: %q", e.auditText())
	}
	// a body that is not the contract is refused by the generated server (400, never 500)
	if got, _, _ := e.do("POST", "/feeds/custom", "admin", `{"name":"x"}`); got != 400 {
		t.Errorf("incomplete: %d", got)
	}
	if got, _, _ := e.do("PUT", "/feeds/custom/cf-nope", "admin", customBody); got != 404 {
		t.Errorf("edit unknown: %d", got)
	}
}

func TestContract_INV4_DeletingACustomFeedDeletesWhatItLoaded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, b, _ := e.do("POST", "/feeds/custom", "admin", customBody)
	id := at(b, "id").(string)
	applyI(t, e.db, e.clock(), id, []iocInput{{Kind: "ip", Value: "185.220.101.47"}, {Kind: "ip", Value: "45.148.10.95"}})
	applyI(t, e.db, e.clock(), "ipsum", []iocInput{{Kind: "ip", Value: "185.220.101.47"}})
	c, _, _ := e.do("DELETE", "/feeds/custom/"+id, "admin", "")
	if c != 204 || rowsOf(t, e.db, "feeds_ioc") != 1 || count(t, e.db, `SELECT count(*) FROM core_secret`) != 0 {
		t.Errorf("%d: %d indicators, secrets %d", c, rowsOf(t, e.db, "feeds_ioc"), count(t, e.db, `SELECT count(*) FROM core_secret`))
	}
	if c, b, _ = e.do("DELETE", "/feeds/custom/"+id, "admin", ""); c != 404 {
		t.Errorf("again: %d %v", c, b)
	}
	if !strings.Contains(e.auditText(), "feeds.delete_custom") {
		t.Error("not audited")
	}
}

func TestContract_INV7_ParseTestNeverWritesAndNeverFetches(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // its HTTP client fails the test on any request
	tables := []string{"feeds_source", "feeds_vuln", "feeds_ioc", "feeds_ioc_source", "feeds_fetch_log", "feeds_weekly_answer", "feeds_template", "core_audit", "core_secret"}
	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = rowsOf(t, e.db, tb)
	}
	parser := `{"format":"lines","records_path":"","delimiter":",","has_header":true,"fields":{"indicator":{"source":"","regex":"","trim":true,"lowercase":false,"date_format":"auto"}}}`
	// the built-in sample of the format
	c, b, raw := e.do("POST", "/feeds/parse-test", "admin", `{"kind":"ioc","parser":`+parser+`}`)
	if c != 200 || at(b, "sample_label") != "Plain list of addresses" || at(b, "accepted") != 3.0 || at(b, "rejected") != 2.0 || at(b, "truncated") != false ||
		at(b, "records", 0, "indicator") != "185.220.101.47" || at(b, "records", 0, "kind") != "ip" || at(b, "records", 0, "confidence") != nil ||
		at(b, "rejects", 0, "row") == nil || at(b, "reasons", 0, "count") == nil || len(at(b, "columns").([]any)) != 4 {
		t.Fatalf("%d %s", c, raw)
	}
	// the caller's own sample
	body, _ := json.Marshal(map[string]any{"kind": "ioc", "parser": json.RawMessage(parser), "sample": "8.8.4.4\n10.0.0.1\n"})
	c, b, _ = e.do("POST", "/feeds/parse-test", "admin", string(body))
	if c != 200 || at(b, "sample_label") != "Your sample" || at(b, "accepted") != 1.0 || at(b, "rejected") != 1.0 || at(b, "sample") != "8.8.4.4\n10.0.0.1\n" {
		t.Errorf("own sample: %d %v", c, b)
	}
	// errors: format of the other kind, bad rules, too large, unreadable
	for _, tc := range []struct {
		body   string
		status int
		code   string
	}{
		{`{"kind":"vulnerabilities","parser":` + strings.Replace(parser, `lines`, `stix`, 1) + `}`, 400, "invalid_format"},
		{`{"kind":"vulnerabilities","parser":` + strings.Replace(parser, `lines`, `csv`, 1) + `}`, 400, "bad_config"},
	} {
		if c, b, _ = e.do("POST", "/feeds/parse-test", "admin", tc.body); c != tc.status || code(b) != tc.code {
			t.Errorf("%s: %d %v", tc.body, c, b)
		}
	}
	// Over 5 MB the handler answers 413 too_large (the server's own 1 MiB body cap answers the same code earlier).
	huge := strings.Repeat("1.2.3.4\n", 700_000)
	req := &oas.FeedsPostFeedsParseTestReq{Kind: oas.FeedsPostFeedsParseTestReqKindIoc, Sample: oas.NewOptString(huge)}
	if err := json.Unmarshal([]byte(parser), &req.Parser); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHandlers(e.svc).FeedsPostFeedsParseTest(t.Context(), req); err == nil {
		t.Error("a 5.6 MB sample was parsed")
	} else if ae, ok := apierr.As(err); !ok || ae.Status != 413 || ae.Code != "too_large" {
		t.Errorf("too large: %v", err)
	}
	jp := `{"format":"json","records_path":"$.data[*]","delimiter":",","has_header":true,"fields":{"indicator":{"source":"$.ioc","regex":"","trim":true,"lowercase":false,"date_format":"auto"}}}`
	if c, b, _ = e.do("POST", "/feeds/parse-test", "admin", `{"kind":"ioc","parser":`+jp+`,"sample":"{not json"}`); c != 400 || code(b) != "bad_sample" {
		t.Errorf("bad sample: %d %v", c, b)
	}
	for _, tb := range tables {
		if got := rowsOf(t, e.db, tb); got != before[tb] {
			t.Errorf("%s: %d rows, was %d", tb, got, before[tb])
		}
	}
}

// The generated server checks the CVE id pattern, so a lower-case id is a generic 400 here; the GUI mock upper-cases it.
func TestCVEPathIsCheckedByTheGeneratedServer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if c, _ := e.get("/feeds/cve/cve-2026-10001"); c != 400 {
		t.Errorf("lower case id: %d", c)
	}
}

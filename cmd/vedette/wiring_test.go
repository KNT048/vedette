package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// stack is the binary's real wiring on a temp SQLite database and the real bus: every module the binary carries,
// built by buildServices, behind the generated server. Only sessions are the test stand-in. No network: the
// CISA list is stored with SQL (what a pull would have written), and the pull job never runs.
type stack struct {
	t   *testing.T
	d   *deps
	h   http.Handler
	got map[string]int // events seen on the bus, by name
}

func newStack(t *testing.T) *stack {
	t.Helper()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	wired := wiredModules()
	if err := migrateAll(ctx, db, wired); err != nil {
		t.Fatal(err)
	}
	aud := audit.New(nil)
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: aud, Manifests: modules.Manifests, Version: "test", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	d := &deps{Log: log, DB: db, Reg: reg, Secrets: sec, Audit: aud, Clock: time.Now, Bus: events.NewBus(log)}
	if err := buildServices(d); err != nil {
		t.Fatal(err)
	}
	api, err := server.New(server.Config{API: newHandler(*d), Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: reg, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	s := &stack{t: t, d: d, h: api, got: map[string]int{}}
	for _, name := range []string{inventory.EventAssetUpdated, inventory.EventMatchChanged, "findings.finding.created"} {
		d.Bus.Subscribe(name, func(_ context.Context, e events.Event) error { s.got[e.Name]++; return nil })
	}
	fs, err := feedsService(*d)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *stack) do(method, path, user, body string) (int, map[string]any) {
	s.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(s.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			s.t.Fatalf("%s %s: not JSON: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code, out
}

// kev stores a CISA-list row added today (the weekly and hot lists show it).
func (s *stack) kev(cve, vendor, product string) {
	s.t.Helper()
	now := time.Now().UTC()
	err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(s.t.Context(), `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, date_added, ransomware, source_id, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, 'cisa-kev', ?)`, cve, vendor, product, feeds.ProductKey(vendor, product), vendor+" "+product+" flaw", now.Format("2006-01-02"), store.FormatTS(now))
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
}

func (s *stack) count(query string, args ...any) int {
	s.t.Helper()
	var n int
	if err := s.d.DB.Reader().QueryRowContext(s.t.Context(), query, args...).Scan(&n); err != nil {
		s.t.Fatalf("%s: %v", query, err)
	}
	return n
}

// nf counts the findings of a device and CVE (either may be empty for any), read through findings' own API.
func (s *stack) nf(assetID, cve string) int {
	s.t.Helper()
	recs, err := s.d.Findings.List(s.t.Context(), assetID)
	if err != nil {
		s.t.Fatal(err)
	}
	n := 0
	for _, r := range recs {
		if cve == "" || r.CVE == cve {
			n++
		}
	}
	return n
}

func (s *stack) setModule(id string, on bool) {
	s.t.Helper()
	var ch modreg.Change
	err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) (err error) {
		if on {
			ch, err = s.d.Reg.Enable(s.t.Context(), tx, "admin@acme.example", id, false)
		} else {
			ch, err = s.d.Reg.Disable(s.t.Context(), tx, "admin@acme.example", id)
		}
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
	s.d.Reg.Publish(ch)
}

func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[k]
		case int:
			l, _ := v.([]any)
			if k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func (s *stack) addFortiGate() string {
	s.t.Helper()
	r, err := s.d.Inventory.AddDevice(s.t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "192.168.30.1"})
	if err != nil {
		s.t.Fatal(err)
	}
	return r.ID
}

// A device whose product is on the CISA list gets a finding through the events; deleting the device removes it
// (INV-7); the finding page carries the KEV entry and the generic guide of mitigation.
func TestWiringDeviceMatchesKEVAndDeleteRemovesTheFinding(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1003", "Synology", "DiskStation Manager")
	id := s.addFortiGate()

	if c, b := s.do("GET", "/findings", "viewer", ""); c != 200 || len(at(b, "items").([]any)) != 2 {
		t.Fatalf("GET /findings: %d %v", c, b)
	}
	if n := s.nf(id, ""); n != 2 || s.got["findings.finding.created"] != 2 || s.got[inventory.EventMatchChanged] != 2 {
		t.Fatalf("findings %d, events %v", n, s.got)
	}
	_, list := s.do("GET", "/findings", "viewer", "")
	fid := at(list, "items", 0, "id").(string)
	if at(list, "items", 0, "asset", "id") != id || at(list, "items", 0, "basis") != "product" || at(list, "items", 0, "kev", "name") == nil {
		t.Errorf("row: %v", at(list, "items", 0))
	}
	if c, b := s.do("GET", "/findings/"+fid, "viewer", ""); c != 200 || at(b, "id") != fid {
		t.Errorf("detail: %d %v", c, b)
	}
	// a repeated event creates nothing new (findings are one per device and CVE)
	if _, err := s.d.Findings.OnMatchChanged(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if n := s.nf("", ""); n != 2 {
		t.Errorf("%d findings after a repeat", n)
	}

	if c, b := s.do("DELETE", "/inventory/devices/"+id, "operator", ""); c != 204 {
		t.Fatalf("delete: %d %v", c, b)
	}
	if n := s.nf("", ""); n != 0 {
		t.Errorf("%d finding rows left after the device was deleted (INV-7)", n)
	}
}

// New CVEs of the CISA list reach the devices that run the product: one by one after a normal pull, once after a
// baseline pull (D-78).
func TestWiringFeedEventsRematchTheInventory(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	id := s.addFortiGate() // the list has nothing yet: no finding
	if n := s.nf("", ""); n != 0 {
		t.Fatalf("%d findings before any CVE", n)
	}
	s.kev("CVE-2026-2001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-2002", "Fortinet", "FortiOS")
	s.kev("CVE-2026-2003", "Mikrotik", "RouterOS")
	if err := s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventSyncBaseline, Data: feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 3}}); err != nil {
		t.Fatal(err)
	}
	if n := s.nf(id, ""); n != 2 {
		t.Fatalf("after the baseline: %d findings, want 2", n)
	}
	s.kev("CVE-2026-2004", "Fortinet", "FortiOS")
	if err := s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventNewKEV, Data: feeds.NewKEVEvent{CVE: "CVE-2026-2004", Vendor: "Fortinet", Product: "FortiOS"}}); err != nil {
		t.Fatal(err)
	}
	if n := s.nf(id, "CVE-2026-2004"); n != 1 {
		t.Errorf("new_kev: %d findings for the new CVE", n)
	}
	// a CVE of a product no device runs creates nothing
	s.kev("CVE-2026-2005", "Synology", "DiskStation Manager")
	_ = s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventNewKEV, Data: feeds.NewKEVEvent{CVE: "CVE-2026-2005", Vendor: "Synology", Product: "DiskStation Manager"}})
	if n := s.nf("", ""); n != 3 {
		t.Errorf("%d findings, want 3", n)
	}
}

// A module that is off does not react (SYS-5): no finding while findings is off, no re-match while inventory is off.
func TestWiringModuleOffNoReaction(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-3001", "Fortinet", "FortiOS")
	s.setModule("mitigation", false)
	s.setModule("findings", false)
	id := s.addFortiGate() // inventory announces the match; findings is off and ignores it
	if s.got[inventory.EventMatchChanged] != 1 || s.nf("", "") != 0 || s.got["findings.finding.created"] != 0 {
		t.Fatalf("findings off: match events %d, findings %d", s.got[inventory.EventMatchChanged], s.nf("", ""))
	}
	if c, _ := s.do("GET", "/findings", "viewer", ""); c != 404 {
		t.Errorf("GET /findings with findings off: %d", c)
	}
	// findings back on: the next match is handled (the matcher reads everything, so the missed one comes too)
	s.setModule("findings", true)
	s.kev("CVE-2026-3002", "Fortinet", "FortiOS")
	_ = s.d.Bus.Publish(t.Context(), events.Event{Name: inventory.EventMatchChanged, Data: inventory.MatchEvent{AssetID: id, CVE: "CVE-2026-3002", Basis: "product"}})
	if n := s.nf("", ""); n != 2 {
		t.Errorf("findings back on: %d findings, want 2", n)
	}
	// deleting a device while findings is off leaves its findings; the deletion event is ignored (reconcile is deferred)
	s.setModule("mitigation", false)
	s.setModule("findings", false)
	if err := s.d.Inventory.DeleteDevice(t.Context(), "it@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if n := s.nf("", ""); n != 2 {
		t.Errorf("findings off: %d findings after the delete, want the 2 left alone", n)
	}

	// inventory off: a new CVE on the bus makes no re-match
	s.setModule("inventory", false)
	before := s.got[inventory.EventMatchChanged]
	s.kev("CVE-2026-3003", "Fortinet", "FortiOS")
	_ = s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventNewKEV, Data: feeds.NewKEVEvent{CVE: "CVE-2026-3003", Vendor: "Fortinet", Product: "FortiOS"}})
	_ = s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventSyncBaseline, Data: feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 1}})
	if s.got[inventory.EventMatchChanged] != before {
		t.Errorf("inventory off: %d match events published", s.got[inventory.EventMatchChanged]-before)
	}
}

// feeds answers "Do you have it?" from the real inventory (INV-11), and "I have it" adds the device in the same
// transaction as the answer: when the answer cannot be stored, no device, audit row or event is left.
func TestWiringFeedsYouHaveAndIHaveItAreAtomic(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-4001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-4002", "Fortinet", "Multiple Products")
	s.kev("CVE-2026-4003", "Mikrotik", "RouterOS")
	s.kev("CVE-2026-4004", "Synology", "DiskStation Manager")
	id := s.addFortiGate()

	c, hot := s.do("GET", "/feeds/hot?window=7d", "viewer", "")
	if c != 200 {
		t.Fatalf("hot: %d %v", c, hot)
	}
	have := map[string]any{}
	for i := 0; at(hot, "rows", i) != nil; i++ {
		have[at(hot, "rows", i, "key").(string)] = at(hot, "rows", i, "you_have")
		if at(hot, "rows", i, "key") == "fortinet|fortios" && at(hot, "rows", i, "matched_assets", 0) != id {
			t.Errorf("matched_assets: %v", at(hot, "rows", i, "matched_assets"))
		}
	}
	if have["fortinet|fortios"] != "yes" || have["fortinet|multiple products"] != "maybe" || have["mikrotik|routeros"] != "no" || have["synology|diskstation manager"] != "no" { //nolint:misspell // RouterOS is the product name
		t.Fatalf("you_have: %v", have)
	}
	if c, b := s.do("GET", "/feeds/status", "viewer", ""); c != 200 || at(b, "inventory_on") != true {
		t.Errorf("status: %d %v", c, b)
	}

	devices := func() int {
		l, err := s.d.Inventory.Devices(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return len(l.Items)
	}
	before := devices()
	updated := s.got[inventory.EventAssetUpdated]
	manualAudit := func() int { return s.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.add_manual'`) }
	audited := manualAudit()
	// the answer cannot be stored: the whole transaction goes, including the device the inventory added in it
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER fail_answer BEFORE INSERT ON feeds_weekly_answer BEGIN SELECT RAISE(ABORT, 'no answers today'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	key := "synology%7Cdiskstation%20manager"
	if c, _ := s.do("POST", "/feeds/weekly/"+key, "operator", `{"answer":"have"}`); c != 500 {
		t.Fatalf("a failed answer: %d, want 500", c)
	}
	if devices() != before || manualAudit() != audited || s.got[inventory.EventAssetUpdated] != updated {
		t.Errorf("rollback left traces: %d devices (was %d), events %v", devices(), before, s.got)
	}
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DROP TRIGGER fail_answer`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// committed: the answer, the device, the audit row and the event are all there
	if c, b := s.do("POST", "/feeds/weekly/"+key, "operator", `{"answer":"have"}`); c != 200 {
		t.Fatalf("answer: %d %v", c, b)
	}
	if devices() != before+1 || s.count(`SELECT count(*) FROM feeds_weekly_answer WHERE key = 'synology|diskstation manager' AND device_added = 1`) != 1 ||
		manualAudit() != audited+1 || s.got[inventory.EventAssetUpdated] != updated+1 {
		t.Errorf("commit: %d devices (was %d), events %v", devices(), before, s.got)
	}
	// and the hot board now says yes for it; a second click adds no second device
	if c, _ := s.do("POST", "/feeds/weekly/"+key, "operator", `{"answer":"have"}`); c != 200 || devices() != before+1 {
		t.Errorf("second click: %d, %d devices", c, devices())
	}
	_, hot = s.do("GET", "/feeds/hot?window=7d", "viewer", "")
	for i := 0; at(hot, "rows", i) != nil; i++ {
		if at(hot, "rows", i, "key") == "synology|diskstation manager" && at(hot, "rows", i, "you_have") != "yes" {
			t.Errorf("after I have it: %v", at(hot, "rows", i))
		}
	}

	// inventory off: feeds answers with null and no devices
	s.setModule("mitigation", false)
	s.setModule("findings", false)
	s.setModule("inventory", false)
	_, hot = s.do("GET", "/feeds/hot?window=7d", "viewer", "")
	if at(hot, "rows", 0, "you_have") != nil {
		t.Errorf("inventory off: you_have %v", at(hot, "rows", 0, "you_have"))
	}
}

// The catalog and the CVE source of the inventory are the feeds data: an empty feeds table uses the product
// list shipped with the box, a pulled list replaces it.
func TestWiringInventoryUsesTheFeedsKEV(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	kev := feedsKEV{s.d}
	v0, list0, err := kev.Products(ctx)
	if err != nil || v0 != "embedded" || len(list0) < 100 {
		t.Fatalf("empty feeds table: %q, %d products, %v", v0, len(list0), err)
	}
	s.kev("CVE-2026-5001", "Acme", "Gateway")
	v1, list1, err := kev.Products(ctx)
	if err != nil || v1 == v0 || len(list1) != 1 || list1[0] != (inventory.KEVProduct{Vendor: "Acme", Product: "Gateway", Count: 1}) {
		t.Fatalf("after a pull: %q %v %v", v1, list1, err)
	}
	if cves, err := kev.CVEs(ctx, []string{"acme|gateway", "acme|other"}); err != nil || len(cves) != 1 || cves[0] != "CVE-2026-5001" {
		t.Errorf("CVEs: %v %v", cves, err)
	}
	// the catalog now offers the pulled product
	res, err := s.d.Inventory.SearchCatalog(ctx, "gateway")
	if err != nil || res.Total == 0 {
		t.Errorf("catalog: %+v %v", res, err)
	}
	// feeds off: the shipped list and no CVEs
	s.setModule("mitigation", false)
	s.setModule("findings", false)
	s.setModule("inventory", false)
	s.setModule("feeds", false)
	if v, _, _ := kev.Products(ctx); v != "embedded" {
		t.Errorf("feeds off: version %q", v)
	}
	if cves, _ := kev.CVEs(ctx, []string{"acme|gateway"}); len(cves) != 0 {
		t.Errorf("feeds off: %v", cves)
	}
}

// The module order in wiredModules is the dependency order the manifests declare (checked for all modules by
// TestWiredModulesFollowDependencies); this pins the four the wiring added together.
func TestWiredModulesIncludeFindingsAndMitigationInOrder(t *testing.T) {
	t.Parallel()
	got := strings.Join(ids(wiredModules()), ",")
	if got != "core,feeds,inventory,findings,mitigation" {
		t.Errorf("wired modules: %s", got)
	}
}

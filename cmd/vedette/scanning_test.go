package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/exec/exectest"
	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// Settings › Scanning (#850, core INV-40) over the binary's real wiring: every module's own reads and switches behind core's routes.

var engineModules = []string{"sensor-passive", "sensor-active", "agent-intake", "scan", "exposure", "honeypot"}

func (s *stack) engine(page map[string]any, id string) map[string]any {
	s.t.Helper()
	for _, x := range page["engines"].([]any) {
		if e := x.(map[string]any); e["id"] == id {
			return e
		}
	}
	s.t.Fatalf("no engine %s", id)
	return nil
}

func (s *stack) module(id string, on bool) {
	s.t.Helper()
	body := `{"enabled":false}`
	if on {
		body = `{"enabled":true,"with_dependencies":true}`
	}
	if code, out := s.do("PATCH", "/modules/"+id, "admin", body); code != http.StatusOK {
		s.t.Fatalf("PATCH /modules/%s: %d %v", id, code, out)
	}
}

func (s *stack) activeSetting() inventory.ActiveWindow {
	s.t.Helper()
	st, err := s.d.Inventory.Settings(s.t.Context())
	if err != nil {
		s.t.Fatal(err)
	}
	return st.Active
}

// The page answers a viewer with every engine module off and with them on, one card per engine of v1 in display order.
func TestScanningPageWithModulesOnAndOff(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, id := range engineModules {
		s.module(id, false)
	}
	code, page := s.do("GET", "/scanning", "viewer", "")
	if code != http.StatusOK {
		t.Fatalf("GET /scanning with every engine module off = %d %v", code, page)
	}
	var ids []string
	for _, x := range page["engines"].([]any) {
		e := x.(map[string]any)
		ids = append(ids, e["id"].(string))
		if e["enabled"] != false || (e["state"] != "off" && e["state"] != "unavailable") {
			t.Errorf("%s with its module off: enabled %v, state %v", e["id"], e["enabled"], e["state"])
		}
	}
	if want := []string{"passive", "nmap-discovery", "nmap-versions", "snmp", "osquery", "wazuh", "nuclei", "zap", "openvas", "honeypot"}; !slices.Equal(ids, want) {
		t.Fatalf("engines = %v", ids)
	}
	if r := page["box"].(map[string]any)["reserved_mb"]; r != 2048.0 {
		t.Fatalf("reserved_mb = %v with every engine off", r)
	}
	if w := page["safety"].(map[string]any)["window"].(map[string]any); w["time_zone"] != "Asia/Ho_Chi_Minh" {
		t.Fatalf("window = %v", w)
	}

	for _, id := range engineModules {
		s.module(id, true)
	}
	s.saveScope(t)
	_, page = s.do("GET", "/scanning", "viewer", "")
	want := map[string]string{
		"passive":        "needs_setup", // no sensor reported
		"nmap-discovery": "unavailable", // no scan container worker in a test
		"snmp":           "unavailable",
		"osquery":        "needs_setup", // no token
		"wazuh":          "needs_setup", // no server
		"nuclei":         "unavailable", // no scanner
		"zap":            "ready",
		"honeypot":       "needs_setup", // no Trap IP
	}
	for id, st := range want {
		if e := s.engine(page, id); e["enabled"] != true || e["state"] != st {
			t.Errorf("%s: enabled %v, state %v (%v), want %s", id, e["enabled"], e["state"], e["reason"], st)
		}
	}
	if e := s.engine(page, "nmap-discovery"); e["next_run_at"] == nil {
		t.Errorf("nmap-discovery has no next window: %v", e)
	}
	// core 2048, sensor 512, the scan container once (1024), the honeypot 256; OpenVAS is off, ZAP runs nothing
	if r := page["box"].(map[string]any)["reserved_mb"]; r != float64(2048+512+1024+256) {
		t.Fatalf("reserved_mb = %v", r)
	}
}

// PUT /scanning/safety is the one writer of the shared block, and the two older writers (PUT /scans/config, PUT /inventory/settings)
// write the same store: each change is seen by the other two and announced on the bus (sensor-active and the scheduler react).
func TestScanningSafetyIsOneStore(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.module("scan", true)
	s.saveScope(t)
	var changed int
	s.d.Bus.Subscribe(inventory.EventSettingsChanged, func(context.Context, events.Event) error { changed++; return nil })

	in := `{"scope":{"lan_ranges":["192.168.10.0/24"],"confirmed":true},"window":{"days":[1,2,3,4,5],"from":"21:00","to":"04:00"},
		"speed":{"packets_per_s":80,"requests_per_s":8},"exclusions":["192.168.10.99","192.168.10.64/28"],"fragile":{"kinds":["printer"],"regular_scan_kinds":[]},
		"version":"` + s.safetyVersion() + `"}`
	if code, out := s.do("PUT", "/scanning/safety", "viewer", in); code != http.StatusForbidden {
		t.Fatalf("a viewer saved: %d %v", code, out)
	}
	code, out := s.do("PUT", "/scanning/safety", "admin", in)
	if code != http.StatusOK || out["speed"].(map[string]any)["requests_per_s"] != 8.0 {
		t.Fatalf("PUT /scanning/safety = %d %v", code, out)
	}
	if a := s.activeSetting(); !a.Enabled || a.From != "21:00" || a.Rate != 80 || a.CheckRate != 8 || !slices.Equal(a.Exclusions, []string{"192.168.10.99", "192.168.10.64/28"}) {
		t.Fatalf("inventory active = %+v", a)
	}
	_, cfg := s.do("GET", "/scans/config", "admin", "")
	c := cfg["config"].(map[string]any)
	if w := c["window"].(map[string]any); w["from"] != "21:00" || w["to"] != "04:00" || c["rate"] != 8.0 || len(c["exclusions"].([]any)) != 2 {
		t.Fatalf("GET /scans/config = %v", c)
	}

	// the vulnerability scans page writes through (its window must hold its schedule time: Sunday 23:00 by default)
	code, out = s.do("PUT", "/scans/config", "admin", `{"window":{"days":[1,2,3,4,5,6,7],"from":"22:00","to":"06:00"},"rate":12,"exclusions":["192.168.10.5/30"]}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /scans/config = %d %v", code, out)
	}
	_, page := s.do("GET", "/scanning", "viewer", "")
	sf := page["safety"].(map[string]any)
	if w := sf["window"].(map[string]any); w["from"] != "22:00" || w["to"] != "06:00" || len(w["days"].([]any)) != 7 ||
		sf["speed"].(map[string]any)["requests_per_s"] != 12.0 || sf["speed"].(map[string]any)["packets_per_s"] != 80.0 {
		t.Fatalf("after PUT /scans/config: %v", sf)
	}
	if ex := sf["exclusions"].([]any); len(ex) != 1 || ex[0] != "192.168.10.4/30" { // host bits dropped: the same addresses
		t.Fatalf("exclusions = %v", ex)
	}

	// the discovery page's PUT keeps the check rate it does not carry
	if _, err := s.d.Inventory.SaveSettings(t.Context(), "admin@acme.example", inventory.SettingsInput{Settings: inventory.Settings{
		LANRanges: []string{"192.168.10.0/24"},
		Active:    inventory.ActiveWindow{Enabled: true, Days: []int{6, 7}, From: "20:00", To: "02:00", Rate: 60, Exclusions: []string{}},
	}, ScopeConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	_, page = s.do("GET", "/scanning", "viewer", "")
	sf = page["safety"].(map[string]any)
	if w := sf["window"].(map[string]any); w["from"] != "20:00" || sf["speed"].(map[string]any)["requests_per_s"] != 12.0 || len(sf["exclusions"].([]any)) != 0 {
		t.Fatalf("after PUT /inventory/settings: %v", sf)
	}
	if code, inv := s.do("GET", "/inventory/settings", "admin", ""); code != http.StatusOK || strings.Contains(strings.Join(keys(inv["active"].(map[string]any)), ","), "check_rate") {
		t.Fatalf("GET /inventory/settings = %d %v", code, inv)
	}
	if changed < 3 {
		t.Fatalf("inventory.settings.changed seen %d times, want one per save", changed)
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// PATCH /scanning/engines/{id} over the real switches: active discovery's own switch (with its scope check, its module turned on
// first), the module switches, the cards without a switch, and OpenVAS while External exposure is off.
func TestScanningEngineSwitchesOverRealModules(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.module("sensor-active", false)
	if code, out := s.do("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true,"with_dependencies":true}`); code != http.StatusBadRequest || errCodeOf(out) != "no_ranges" || s.d.Reg.Enabled("sensor-active") {
		t.Fatalf("no scope: %d %v", code, out)
	}
	// review #857 L9: a range but no day: refused before sensor-active is turned on, so nothing changes
	if _, err := s.d.Inventory.SaveSettings(t.Context(), "admin@acme.example", inventory.SettingsInput{Settings: inventory.Settings{
		LANRanges: []string{"192.168.10.0/24"}, Active: inventory.ActiveWindow{Days: []int{}, From: "01:00", To: "05:00", Rate: 100, Exclusions: []string{}},
	}, ScopeConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	if code, out := s.do("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true,"with_dependencies":true}`); code != http.StatusBadRequest || errCodeOf(out) != "no_days" || s.d.Reg.Enabled("sensor-active") {
		t.Fatalf("no day: %d %v, module on %v", code, out, s.d.Reg.Enabled("sensor-active"))
	}
	if _, err := s.d.Inventory.SaveSettings(t.Context(), "admin@acme.example", inventory.SettingsInput{Settings: inventory.Settings{
		LANRanges: []string{"192.168.10.0/24"}, Active: inventory.ActiveWindow{Days: []int{1}, From: "01:00", To: "05:00", Rate: 100, Exclusions: []string{}},
	}, ScopeConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	if code, out := s.do("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true}`); code != http.StatusConflict || errCodeOf(out) != "missing_dependencies" {
		t.Fatalf("module off, no with_dependencies: %d %v", code, out)
	}
	code, page := s.do("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true,"with_dependencies":true}`)
	if code != http.StatusOK || !s.d.Reg.Enabled("sensor-active") || !s.activeSetting().Enabled || s.engine(page, "nmap-discovery")["enabled"] != true {
		t.Fatalf("on: %d %v", code, page)
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail = 'active scanning on'`) != 1 ||
		s.count(`SELECT count(*) FROM core_audit WHERE action = 'module.enable' AND target = 'sensor-active'`) != 1 {
		t.Fatal("the switches did not write their own audit rows")
	}
	code, page = s.do("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":false}`)
	if code != http.StatusOK || !s.d.Reg.Enabled("sensor-active") || s.activeSetting().Enabled || s.engine(page, "nmap-versions")["enabled"] != false {
		t.Fatalf("off: %d, module %v", code, s.d.Reg.Enabled("sensor-active"))
	}
	for _, id := range []string{"nmap-versions", "snmp", "zap"} {
		if code, out := s.do("PATCH", "/scanning/engines/"+id, "admin", `{"enabled":true}`); code != http.StatusConflict || errCodeOf(out) != "not_toggleable" {
			t.Fatalf("%s: %d %v", id, code, out)
		}
	}
	if code, page := s.do("PATCH", "/scanning/engines/osquery", "admin", `{"enabled":true}`); code != http.StatusOK || !s.d.Reg.Enabled("agent-intake") || s.engine(page, "wazuh")["enabled"] != true {
		t.Fatalf("osquery on: %d", code)
	}
	if code, out := s.do("PATCH", "/scanning/engines/openvas", "admin", `{"enabled":true}`); code != http.StatusConflict || errCodeOf(out) != "module_off" {
		t.Fatalf("openvas with exposure off: %d %v", code, out)
	}
	if code, _ := s.do("PATCH", "/scanning/engines/nuclei", "operator", `{"enabled":true}`); code != http.StatusForbidden {
		t.Fatalf("an operator switched nuclei: %d", code)
	}
}

func errCodeOf(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

// The window, rate and exclusions have one home, the inventory's safety settings: the scan module keeps no copy, and what the
// vulnerability checks read and save is what Settings › Scanning shows.
func TestScanningSharedChecksHaveOneHome(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if s.count(`SELECT count(*) FROM pragma_table_info('scan_setting') WHERE name IN ('days', 'win_from', 'win_to', 'rate', 'exclusions')`) != 0 {
		t.Fatal("scan_setting still has a copy of the window, rate or exclusions")
	}
	if a := s.activeSetting(); a.Checks() != 5 {
		t.Fatalf("a fresh box checks at %d requests per second, want 5", a.Checks())
	}
	s.module("scan", true)
	code, out := s.do("PUT", "/scans/config", "admin", `{"rate":11,"exclusions":["192.168.10.9","192.168.10.40/28","192.168.10.32/28"]}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /scans/config: %d %v", code, out)
	}
	a := s.activeSetting()
	if a.CheckRate != 11 {
		t.Fatalf("the inventory holds rate %d, want 11", a.CheckRate)
	}
	if want := []string{"192.168.10.9", "192.168.10.32/28"}; !slices.Equal(a.Exclusions, want) { // .40/28 is .32/28: once
		t.Fatalf("exclusions = %v, want %v", a.Exclusions, want)
	}
	_, cfg := s.do("GET", "/scans/config", "admin", "")
	if c := cfg["config"].(map[string]any); c["rate"] != 11.0 || len(c["exclusions"].([]any)) != 2 {
		t.Fatalf("GET /scans/config = %v", c)
	}
}

// POST /scanning/engines/nmap-discovery/run over the real modules: who may start it, the refusals of the switches, the scope and the
// device's rules, and a run that shows in running[] with its progress until it ends, with the scan module off.
func TestScanningRunNow(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	run := func(user, body string) (int, map[string]any) {
		s.t.Helper()
		return s.do("POST", "/scanning/engines/nmap-discovery/run", user, body)
	}
	for _, who := range []string{"viewer", "operator"} {
		if code, _ := run(who, `{}`); code != http.StatusForbidden {
			t.Fatalf("%s started a run: %d", who, code)
		}
	}
	if code, out := run("admin", `{}`); code != http.StatusConflict || errCodeOf(out) != "engine_off" {
		t.Fatalf("discovery off: %d %v", code, out)
	}
	s.module("sensor-active", false)
	if code, out := run("admin", `{}`); code != http.StatusConflict || errCodeOf(out) != "module_off" {
		t.Fatalf("module off: %d %v", code, out)
	}
	s.module("sensor-active", true)
	s.saveScope(t) // 192.168.10.0/24 minus 192.168.10.99, discovery on, the window 01:00 to 05:00
	if code, out := run("admin", `{}`); code != http.StatusServiceUnavailable || errCodeOf(out) != "scanner_unavailable" {
		t.Fatalf("no scan container: %d %v", code, out)
	}
	// from here nmap is a script (the scan container's worker is not part of a test); first one that does not end by itself
	slow := filepath.Join(t.TempDir(), "nmap")
	exectest.WriteScript(t, slow, "#!/bin/sh\nsleep 30\n")
	inject := func(path string) *sensoractive.Service {
		t.Helper()
		svc, err := newLocalSensorActive(*s.d, path)
		if err != nil {
			t.Fatal(err)
		}
		saMu.Lock()
		saServices[s.d.DB] = svc
		saMu.Unlock()
		return svc
	}
	svc := inject(slow)

	web := s.seen(t, "192.168.10.20", "aa:bb:cc:00:00:20", "server")
	s.seen(t, "192.168.10.99", "aa:bb:cc:00:00:99", "server") // excluded
	far := s.seen(t, "10.20.0.5", "aa:bb:cc:00:00:05", "server")
	for _, c := range []struct{ target, code string }{
		{"192.168.10.77", "unknown_device"},
		{"192.168.10.99", "out_of_scope"},
		{far, "out_of_scope"},
	} {
		code, out := run("admin", `{"targets":["`+c.target+`"]}`)
		if code != http.StatusBadRequest || errCodeOf(out) != c.code || out["error"].(map[string]any)["target"] != c.target {
			t.Fatalf("%s: %d %v, want 400 %s", c.target, code, out, c.code)
		}
	}
	if svc.Manual(t.Context()) != nil || s.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatal("a refused run started something")
	}
	if s.d.Reg.Enabled("scan") {
		t.Fatal("the scan module is on: the run must not need it")
	}

	// Check this device now: 202, listed in running[] while it goes on, one run at a time, audited; the module off ends it
	code, out := run("admin", `{"targets":["192.168.10.20"]}`)
	if code != http.StatusAccepted || out["engine"] != "nmap-discovery" || out["target_id"] != web || out["label"] != "Check 192.168.10.20" {
		t.Fatalf("run = %d %v", code, out)
	}
	_, page := s.do("GET", "/scanning", "viewer", "")
	var listed map[string]any
	for _, x := range page["running"].([]any) {
		if r := x.(map[string]any); r["id"] == out["id"] {
			listed = r
		}
	}
	if listed == nil || listed["engine"] != "nmap-discovery" || listed["progress"] == nil || listed["target_id"] != web {
		t.Fatalf("running = %v, want the run %v with its progress", page["running"], out["id"])
	}
	if e := s.engine(page, "nmap-discovery"); e["state"] != "running" {
		t.Fatalf("nmap-discovery state = %v", e["state"])
	}
	// a second run while the check goes on is queued behind it and says so (never refused); both are listed
	code, again := run("admin", `{}`)
	if prog, _ := again["progress"].(map[string]any); code != http.StatusAccepted || prog == nil || !strings.HasPrefix(fmt.Sprint(prog["message"]), "Queued behind “Check of ") ||
		again["queued"] != true {
		t.Fatalf("a second run: %d %v", code, again)
	}
	_, page = s.do("GET", "/scanning", "viewer", "")
	queued := map[any]any{} // running[] says which runs go on and which wait
	for _, x := range page["running"].([]any) {
		queued[x.(map[string]any)["id"]] = x.(map[string]any)["queued"]
	}
	if len(queued) != 2 || queued[again["id"]] != true || queued[out["id"]] != false {
		t.Fatalf("running with a queued sweep = %v, want the check going and the sweep queued", page["running"])
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.run' AND target = ? AND detail LIKE 'check 192.168.10.20 (`+web+`) now%' AND user = 'admin@acme.example'`, out["id"]) != 1 {
		t.Fatal("the run is not audited")
	}
	s.module("sensor-active", false)
	if err := svc.WaitManual(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.module("sensor-active", true)
	_, page = s.do("GET", "/scanning", "viewer", "")
	if r := page["running"].([]any); len(r) != 0 {
		t.Fatalf("running after the run ended = %v", r)
	}
	// the module's switch stops the check's run whatever moment it is in (queued, starting, in nmap): it ends stopped, never done
	if s.count(`SELECT count(*) FROM core_run WHERE kind = 'device_check' AND status <> 'stopped'`) != 0 {
		t.Fatal("the check the module's switch stopped went on")
	}

	nm := newFakeNmap(t)
	svc = inject(nm.path)
	// Scan the LAN now: a sweep outside the window
	if code, out := run("admin", `{}`); code != http.StatusAccepted || out["label"] != "LAN sweep 192.168.10.0/24" || out["target_id"] != nil {
		t.Fatalf("sweep = %d %v", code, out)
	}
	if err := svc.WaitManual(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, c := range nm.calls(t) {
		if slices.Contains(c, "192.168.10.99") {
			t.Fatalf("an excluded address reached nmap: %q", c)
		}
	}
	if s.count(`SELECT count(*) FROM core_run WHERE kind = 'lan_sweep' AND status = 'done'`) != 1 {
		t.Fatal("no sweep ran")
	}
}

// shownConfirmedAt is `,"shown_confirmed_at":…` for a range dialog opened now: the confirmation GET /scanning shows.
func (s *stack) shownConfirmedAt() string {
	s.t.Helper()
	_, page := s.do("GET", "/scanning", "viewer", "")
	raw, err := json.Marshal(page["safety"].(map[string]any)["scope"].(map[string]any)["confirmed_at"])
	if err != nil {
		s.t.Fatal(err)
	}
	return `,"shown_confirmed_at":` + string(raw)
}

// safetyVersion is safety.version of GET /scanning: what a page that loads now holds.
func (s *stack) safetyVersion() string {
	s.t.Helper()
	code, page := s.do("GET", "/scanning", "viewer", "")
	v, _ := page["safety"].(map[string]any)["version"].(string)
	if code != http.StatusOK || v == "" {
		s.t.Fatalf("GET /scanning = %d, version %q", code, v)
	}
	return v
}

// "+ New range" and "+ New exclusion" (#842) over the real wiring: the inventory adds one entry in one transaction, the audit row
// names it, the bus announces it, the scan module reads the new exclusion, adds sent at once never overwrite each other, the tick
// confirms only the ranges the dialog showed (review #860 H1), and a full save from a page opened before the add is refused instead
// of dropping it (M1).
func TestScanningInlineAdds(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.module("scan", true)
	s.saveScope(t)
	var changed atomic.Int32
	s.d.Bus.Subscribe(inventory.EventSettingsChanged, func(context.Context, events.Event) error { changed.Add(1); return nil })
	opened := s.safetyVersion() // a Settings › Scanning page and a /scans/config page load now
	conf := s.shownConfirmedAt()
	_, oldCfg := s.do("GET", "/scans/config", "admin", "")
	if oldCfg["version"] != opened {
		t.Fatalf("GET /scans/config version %v, GET /scanning %s", oldCfg["version"], opened)
	}

	if code, out := s.do("POST", "/scanning/safety/ranges", "operator", `{"range":"192.168.20.0/24","confirm":true,"shown_ranges":["192.168.10.0/24"]`+conf+`}`); code != http.StatusForbidden {
		t.Fatalf("an operator added a range: %d %v", code, out)
	}
	if code, out := s.do("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.0/24","confirm":false,"shown_ranges":["192.168.10.0/24"]`+conf+`}`); code != http.StatusBadRequest || errCodeOf(out) != "scope_not_confirmed" {
		t.Fatalf("without the attestation: %d %v", code, out)
	}
	code, out := s.do("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.0/24","confirm":true,"shown_ranges":[]`+conf+`}`)
	if code != http.StatusConflict || errCodeOf(out) != "scope_changed" || len(out["error"].(map[string]any)["safety"].(map[string]any)["scope"].(map[string]any)["lan_ranges"].([]any)) != 1 {
		t.Fatalf("a dialog that showed no range: %d %v", code, out)
	}
	code, out = s.do("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.9/24","confirm":true,"shown_ranges":["192.168.10.0/24"]`+conf+`}`)
	if code != http.StatusOK || len(out["scope"].(map[string]any)["lan_ranges"].([]any)) != 2 || len(out["adjusted"].([]any)) != 1 || out["version"] == opened {
		t.Fatalf("add range = %d %v", code, out)
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail LIKE 'added range 192.168.20.0/24:%'`) != 1 {
		t.Fatal("no audit row naming the range")
	}
	code, out = s.do("POST", "/scanning/safety/exclusions", "admin", `{"entry":"192.168.20.77"}`)
	if code != http.StatusOK || !slices.Contains(out["exclusions"].([]any), any("192.168.20.77")) || out["version"] != s.safetyVersion() {
		t.Fatalf("add exclusion = %d %v", code, out)
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail LIKE 'added exclusion 192.168.20.77:%'`) != 1 {
		t.Fatal("no audit row naming the exclusion")
	}
	if n := changed.Load(); n != 2 {
		t.Fatalf("inventory.settings.changed = %d, want one per add", n)
	}
	if _, cfg := s.do("GET", "/scans/config", "admin", ""); !slices.Contains(cfg["config"].(map[string]any)["exclusions"].([]any), any("192.168.20.77")) {
		t.Fatalf("the vulnerability checks do not skip it: %v", cfg)
	}
	if code, again := s.do("POST", "/scanning/safety/exclusions", "admin", `{"entry":"192.168.20.77"}`); code != http.StatusOK || len(again["exclusions"].([]any)) != len(out["exclusions"].([]any)) || changed.Load() != 2 {
		t.Fatalf("the same exclusion again: %d %v", code, again)
	}

	// review #860 M1: the pages opened before the adds save their old lists: refused, the adds stay
	stale := `{"scope":{"lan_ranges":["192.168.10.0/24"],"confirmed":true},"window":{"days":[1,2,3,4,5,6,7],"from":"01:00","to":"06:00"},
		"speed":{"packets_per_s":100,"requests_per_s":5},"exclusions":["192.168.10.99"],"fragile":{"kinds":[],"regular_scan_kinds":[]},"version":"` + opened + `"}`
	code, out = s.do("PUT", "/scanning/safety", "admin", stale)
	if code != http.StatusConflict || errCodeOf(out) != "safety_changed" || !slices.Contains(out["error"].(map[string]any)["safety"].(map[string]any)["exclusions"].([]any), any("192.168.20.77")) {
		t.Fatalf("a stale PUT /scanning/safety: %d %v", code, out)
	}
	if code, out := s.do("PUT", "/scans/config", "admin", `{"window":{"from":"22:00","to":"06:00"},"exclusions":["192.168.10.99"],"version":"`+opened+`"}`); code != http.StatusConflict || errCodeOf(out) != "safety_changed" {
		t.Fatalf("a stale PUT /scans/config: %d %v", code, out)
	}
	if a := s.activeSetting(); !slices.Contains(a.Exclusions, "192.168.20.77") || a.To != "05:00" {
		t.Fatalf("a refused save stored something: %+v", a)
	}

	// people add at once, two ranges built on the same list and two exclusions: the exclusions land, one range lands and the other
	// is refused with the current list (its tick did not see the first one); nothing is overwritten
	shown := `["192.168.10.0/24","192.168.20.0/24"]` + s.shownConfirmedAt()
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i, c := range []struct{ path, body string }{
		{"/scanning/safety/ranges", `{"range":"10.20.0.0/16","confirm":true,"shown_ranges":` + shown + `}`},
		{"/scanning/safety/ranges", `{"range":"10.21.0.0/16","confirm":true,"shown_ranges":` + shown + `}`},
		{"/scanning/safety/exclusions", `{"entry":"192.168.10.200"}`},
		{"/scanning/safety/exclusions", `{"entry":"192.168.10.201"}`},
	} {
		wg.Go(func() { codes[i], _ = s.do("POST", c.path, "admin", c.body) })
	}
	wg.Wait()
	if codes[2] != http.StatusOK || codes[3] != http.StatusOK || codes[0]+codes[1] != http.StatusOK+http.StatusConflict {
		t.Fatalf("concurrent adds: %v", codes)
	}
	st, err := s.d.Inventory.Settings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.LANRanges) != 3 || !slices.Contains(st.LANRanges, "192.168.20.0/24") {
		t.Fatalf("ranges = %v", st.LANRanges)
	}
	for _, x := range []string{"192.168.10.99", "192.168.20.77", "192.168.10.200", "192.168.10.201"} {
		if !slices.Contains(st.Active.Exclusions, x) {
			t.Fatalf("exclusion %s was lost: %v", x, st.Active.Exclusions)
		}
	}
}

// review #860 L2: an exclusion added inline reaches sensor-active through inventory.settings.changed, which stops the scan of that
// device running now (ErrStopped). The nmap here is a script that sleeps; it never touches a network.
func TestScanningInlineExclusionStopsTheRunningScan(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.saveScope(t)
	target := s.seen(t, "192.168.10.20", "aa:bb:cc:00:05:01", "server")
	s.setModule("sensor-active", true)
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	nmap := filepath.Join(dir, "nmap")
	exectest.WriteScript(t, nmap, fmt.Sprintf("#!/bin/sh\ntouch %q\nexec sleep 30\n", started))
	d := *s.d
	d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) } // Monday 02:00, inside 01:00-05:00
	svc, err := newLocalSensorActive(d, nmap)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- svc.ScanDevice(t.Context(), target, "discovered") }()
	for deadline := time.Now().Add(10 * time.Second); ; <-time.After(20 * time.Millisecond) { // the state: nmap has started
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake nmap did not start")
		}
	}
	if code, out := s.do("POST", "/scanning/safety/exclusions", "admin", `{"entry":"192.168.10.16/29"}`); code != http.StatusOK {
		t.Fatalf("add exclusion = %d %v", code, out)
	}
	select {
	case err := <-done:
		if !errors.Is(err, sensoractive.ErrStopped) {
			t.Errorf("err = %v, want ErrStopped", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the scan of the device went on after it was excluded")
	}
}

// #861 (exposure INV-30): the zap and openvas cards take their last run from the external scans in which their step ran, through
// exposure's own read; nuclei's is the newer of its LAN runs and the external scans' template step. Those scans run on Scan now only,
// so zap and openvas have no next run. With no scan, every last run is null.
func TestScanningExternalLastRuns(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.module("scan", true)
	s.module("exposure", true)
	exec := func(q string, args ...any) {
		t.Helper()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	card := func(id string) map[string]any {
		t.Helper()
		code, page := s.do("GET", "/scanning", "viewer", "")
		if code != http.StatusOK {
			t.Fatalf("GET /scanning = %d %v", code, page)
		}
		return s.engine(page, id)
	}
	for _, id := range []string{"nuclei", "zap", "openvas"} {
		if e := card(id); e["last_run"] != nil || (id != "nuclei" && e["next_run_at"] != nil) {
			t.Fatalf("%s before any scan: last %v, next %v", id, e["last_run"], e["next_run_at"])
		}
	}

	// What an external deep scan of the box's IP records: its run with a step per engine; every step ran, ZAP lost a page, OpenVAS found 3.
	exec(`INSERT INTO exp_target (id, kind, value, origin, method, token, created_at) VALUES ('xt-ext', 'ip', '203.0.113.10', 'box', 'box_egress', '', '2026-11-16T06:00:00.000Z')`)
	exec(`INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, subject_label, status, queued_at, started_at, ended_at, updated_at)
		VALUES ('run-ext', 'exposure', 'exposure_scan', 'exposure', 'External scan of 203.0.113.10', 'manual', 'admin@acme.example', 'target', 'xt-ext', '203.0.113.10', 'done',
		'2026-11-16T06:00:00.000Z', '2026-11-16T06:00:00.000Z', '2026-11-16T07:55:00.000Z', '2026-11-16T07:55:00.000Z')`)
	exec(`INSERT INTO exp_scan (run_id, target_id, mode) VALUES ('run-ext', 'xt-ext', 'deep')`)
	const ins = `INSERT INTO core_run_step (run_id, seq, name, status, note, started_at, ended_at) VALUES ('run-ext', ?, ?, ?, ?, ?, ?)`
	exec(ins, 1, "Templates (nuclei)", "done", "External scan of 203.0.113.10: safe templates ran, 0 matched", "2026-11-16T06:30:00.000Z", "2026-11-16T06:30:00.000Z")
	exec(ins, 2, "Passive web scan (ZAP)", "partial", "External scan of 203.0.113.10: ZAP scanned 1 of 2 pages, 4 alerts", "2026-11-16T06:40:00.000Z", "2026-11-16T06:40:00.000Z")
	exec(ins, 3, "OpenVAS", "done", "External scan of 203.0.113.10: OpenVAS found 3 results", "2026-11-16T07:55:00.000Z", "2026-11-16T07:55:00.000Z")
	want := map[string]map[string]any{
		"nuclei":  {"at": "2026-11-16T06:30:00Z", "outcome": "ok", "text": "External scan of 203.0.113.10: safe templates ran, 0 matched"},
		"zap":     {"at": "2026-11-16T06:40:00Z", "outcome": "partial", "text": "External scan of 203.0.113.10: ZAP scanned 1 of 2 pages, 4 alerts"},
		"openvas": {"at": "2026-11-16T07:55:00Z", "outcome": "ok", "text": "External scan of 203.0.113.10: OpenVAS found 3 results"},
	}
	for id, w := range want {
		e := card(id)
		last, _ := e["last_run"].(map[string]any)
		if fmt.Sprint(last) != fmt.Sprint(w) || (id != "nuclei" && e["next_run_at"] != nil) {
			t.Errorf("%s: last %v, next %v; want last %v and no next run", id, e["last_run"], e["next_run_at"], w)
		}
	}

	// A LAN run of the vulnerability checks after the external scan is nuclei's last run; one before it is not.
	lan := func(id, ended string) {
		t.Helper()
		exec(`INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, status, total, done, queued_at, started_at, ended_at, updated_at)
VALUES (?1, 'scan', 'vuln_check', 'nuclei', 'Vulnerability check', 'manual', 'admin@acme.example', 'done', 1, 1, ?2, ?2, ?2, ?2)`, id, ended)
	}
	lan("run-old", "2026-11-16T05:00:00.000Z")
	if last, _ := card("nuclei")["last_run"].(map[string]any); last["at"] != "2026-11-16T06:30:00Z" {
		t.Fatalf("nuclei with an older LAN run: %v", last)
	}
	lan("run-new", "2026-11-16T08:18:00.000Z")
	if last, _ := card("nuclei")["last_run"].(map[string]any); last["at"] != "2026-11-16T08:18:00Z" || last["text"] != "Checked 1 of 1 devices, 0 confirmed" {
		t.Fatalf("nuclei with a newer LAN run: %v", last)
	}
}

// The fakes of a real exposure run in cmd/vedette (#863 r1 L5): the box's IP is 8.8.8.8, a web server with an exploited CVE on 80,
// one safe template that matches, and ZAP's report with one alert.
type extFakes struct{}

func (extFakes) Round(context.Context) (netip.Addr, error) {
	return netip.MustParseAddr("8.8.8.8"), nil
}
func (extFakes) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("no such host")
}
func (extFakes) Scan(context.Context, exposure.ScanTarget) (exposure.Content, error) {
	return exposure.Content{Ports: []exposure.PortRow{{IP: "8.8.8.8", Port: 80, Service: "http"}}}, nil
}
func (extFakes) ScanServices(context.Context, exposure.ScanTarget, netip.Addr) (exposure.ServiceScan, error) {
	return exposure.ServiceScan{Ports: 98, Services: []exposure.ServiceRow{{IP: "8.8.8.8", Port: 80, Name: "http", Method: "probed", Product: "Apache httpd", Version: "2.4.49"}}}, nil
}
func (extFakes) Match(context.Context, []exposure.ServiceRow) (exposure.Matches, error) {
	return exposure.Matches{Compared: 1, Listed: 1, Vulns: []exposure.VulnRow{{IP: "8.8.8.8", Port: 80, CVE: "CVE-2021-41773", Name: "Path traversal", Basis: "version", Summary: "In range."}}}, nil
}
func (extFakes) ScanTemplates(context.Context, exposure.ScanTarget, netip.Addr, []exposure.TemplateJob) (exposure.TemplateScan, error) {
	return exposure.TemplateScan{Results: []exposure.TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: exposure.OutcomeMatched}}}, nil
}
func (extFakes) RecordTemplateProbes(context.Context, []exposure.TemplateProbe) error { return nil }
func (extFakes) RecordWebProbe(context.Context, exposure.WebProbe) error              { return nil }
func (extFakes) Baseline(_ context.Context, _ exposure.ScanTarget, p exposure.WebPage) (exposure.WebScan, error) {
	return exposure.WebScan{Report: []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[{"pluginid":"10036","alert":"Server Leaks Version","riskcode":"1","confidence":"3","cweid":"200","instances":[{"uri":%q}]}]}]}`,
		strings.TrimSuffix(p.URL, "/"), p.URL))}, nil
}

// #863 r1 L5: a real exposure run (fake scanners, the box's own exposure service for this database) records its steps, and GET /scanning
// shows them on the nuclei and zap cards; OpenVAS, not on this box, stays null. With the External exposure module off the zap card
// still shows its last run.
func TestScanningShowsARealExternalRun(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.module("scan", true)
	s.module("exposure", true)
	f := extFakes{}
	runs, err := corerun.New(corerun.Config{DB: s.d.DB})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := exposure.NewService(exposure.Config{DB: s.d.DB, Audit: s.d.Audit, Log: s.d.Log, Resolver: f, Prober: f, Runner: f,
		Services: f, Matcher: f, Templates: f, Probes: f, Web: f, Location: time.UTC, Runs: runs,
		TwoStep: func(context.Context, string) (string, error) { return "app", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := runs.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runs.Close)
	exposureMu.Lock()
	exposureServices[s.d.DB] = svc // the service every exposureService(d) of this stack answers from now on
	exposureMu.Unlock()
	det, err := svc.Detect(ctx, "admin@acme.example", true)
	if err != nil || len(det.Items) != 1 {
		t.Fatalf("detect: %+v %v", det, err)
	}
	if _, err := svc.ScanNow(ctx, exposure.Actor{ID: "u-admin", Email: "admin@acme.example", Admin: true}, det.Items[0].ID, exposure.NoticeVersion); err != nil {
		t.Fatal(err)
	}
	card := func(id string) map[string]any {
		t.Helper()
		code, page := s.do("GET", "/scanning", "viewer", "")
		if code != http.StatusOK {
			t.Fatalf("GET /scanning = %d %v", code, page)
		}
		return s.engine(page, id)
	}
	want := map[string]string{
		"nuclei": "External scan of 8.8.8.8: safe templates ran, 1 matched",
		"zap":    "External scan of 8.8.8.8: ZAP scanned 1 page, 1 alert",
	}
	for id, text := range want {
		last, _ := card(id)["last_run"].(map[string]any)
		if last["outcome"] != "ok" || last["text"] != text || last["at"] == nil {
			t.Errorf("%s: last %v, want ok %q", id, last, text)
		}
	}
	if e := card("openvas"); e["last_run"] != nil {
		t.Errorf("openvas did not run: %v", e["last_run"])
	}
	s.module("exposure", false)
	if e := card("zap"); e["enabled"] != false || e["last_run"] == nil {
		t.Fatalf("zap with the module off: enabled %v, last %v", e["enabled"], e["last_run"])
	}
}

// #889: the honeypot card says "starting" while the traps wait for a start the host has not confirmed (a busy host right after an
// update), "error" only with the module's problem, and "ready" once a trap listens.
func TestScanningHoneypotStarting(t *testing.T) {
	t.Parallel()
	problem := "the honeypot container did not start"
	for name, c := range map[string]struct {
		o     honeypot.Overview
		state string
	}{
		"no Trap IP": {honeypot.Overview{}, core.EngineNeedsSetup},
		"starting": {honeypot.Overview{TrapIPs: honeypot.TrapIPCounts{Enabled: 1},
			Traps: []honeypot.Trap{{Enabled: true, State: honeypot.StateStarting}, {State: honeypot.StateOff}}}, core.EngineStarting},
		"failed": {honeypot.Overview{TrapIPs: honeypot.TrapIPCounts{Enabled: 1}, Problem: &problem,
			Traps: []honeypot.Trap{{Enabled: true, State: honeypot.StateFailed}}}, core.EngineError},
		"one listens, a new one starts": {honeypot.Overview{TrapIPs: honeypot.TrapIPCounts{Enabled: 2, Listening: 1},
			Traps: []honeypot.Trap{{Enabled: true, State: honeypot.StateListening}, {Enabled: true, State: honeypot.StateStarting}}}, core.EngineReady},
	} {
		if st, reason := honeypotState(c.o); st != c.state || (st != core.EngineReady) == (reason == "") {
			t.Errorf("%s: %s %q, want %s", name, st, reason, c.state)
		}
	}
}

// #889: the active-discovery cards say "starting", not "unavailable", while the box brings the scan container up and its worker
// has not reported yet (a busy host after an update).
func TestScanningScanContainerStarting(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 16, 18, 24, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	move := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	w := &startWatch{now: clock, busyOnly: true}
	s := newStackWith(t, func(d *deps) { d.ScanStart = w })
	s.module("sensor-active", true)
	s.saveScope(t)
	want := func(step, state string) {
		t.Helper()
		_, page := s.do("GET", "/scanning", "viewer", "")
		for _, id := range []string{"nmap-discovery", "nmap-versions", "snmp"} {
			if e := s.engine(page, id); e["state"] != state || (state == core.EngineStarting) != (e["reason"] == "The box is starting the scan container.") {
				t.Errorf("%s: %s: %v (%v), want %s", step, id, e["state"], e["reason"], state)
			}
		}
	}
	busy := fmt.Errorf("container.start: %w", errHostBusy)
	w.done(busy, false) // the guard's start is retried: the host is busy
	want("busy", core.EngineStarting)
	move(4 * time.Minute)
	w.done(busy, false)
	want("busy for 4 min", core.EngineStarting)
	move(time.Minute)
	want("busy for 5 min", core.EngineUnavailable) // the worker's own health message
	w.done(nil, false)                             // the host answered: the unit runs
	w.done(errors.New("scan: container.start refused (unit_unsafe)"), false)
	want("a refusal", core.EngineUnavailable)
	move(time.Minute)
	w.done(busy, false)
	want("busy after a refusal", core.EngineUnavailable) // does not hide the refusal
	w.done(nil, true)
	want("a confirmed start: the worker's health speaks", core.EngineUnavailable)
	w.done(busy, false)
	want("a new busy spell", core.EngineStarting)
}

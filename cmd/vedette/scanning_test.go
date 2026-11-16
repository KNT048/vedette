package main

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/exec/exectest"
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
		"speed":{"packets_per_s":80,"requests_per_s":8},"exclusions":["192.168.10.99","192.168.10.64/28"],"fragile":{"kinds":["printer"],"regular_scan_kinds":[]}}`
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

// The one-time merge at start on a box that has both copies: the scan module's window and exclusions saved by a person, discovery's
// own (the defaults here: every day 22:00 to 05:00, no exclusion).
func TestScanningMergeOfTheTwoCopies(t *testing.T) {
	t.Parallel()
	// a fresh box: merged at start, silently, at the scan module's default rate
	if s := newStack(t); s.activeSetting().CheckRate != 5 || s.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.safety.merged'`) != 0 {
		t.Fatalf("fresh box: %+v", s.activeSetting())
	}
	s := newStackWith(t, func(d *deps) {
		err := d.DB.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), `UPDATE scan_setting SET days = '[6,7]', win_from = '20:00', win_to = '06:00', rate = 11,
				exclusions = '["192.168.10.9","192.168.10.40/28","192.168.10.32/28"]', updated_by = 'it@acme.example', updated_at = '2026-11-01T00:00:00.000Z'`)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	a := s.activeSetting()
	if a.CheckRate != 11 || a.From != "22:00" || a.To != "05:00" || len(a.Days) != 7 {
		t.Fatalf("merged = %+v: the rate is the scan module's, the window discovery's", a)
	}
	if want := []string{"192.168.10.9", "192.168.10.32/28"}; !slices.Equal(a.Exclusions, want) { // .40/28 is .32/28: once
		t.Fatalf("exclusions = %v, want %v", a.Exclusions, want)
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.safety.merged' AND detail LIKE '%"from":"20:00"%' AND detail LIKE '%it@acme.example%'`) != 1 {
		t.Fatal("no audit row names the dropped window")
	}
	if s.count(`SELECT count(*) FROM pragma_table_info('scan_setting') WHERE name IN ('days', 'win_from', 'win_to', 'rate', 'exclusions')`) != 5 ||
		s.count(`SELECT count(*) FROM scan_setting WHERE win_from = '20:00' AND rate = 11`) != 1 {
		t.Fatal("scan_setting's columns or values are gone")
	}
	// the vulnerability checks read the merged values at once
	s.module("scan", true)
	_, cfg := s.do("GET", "/scans/config", "admin", "")
	if c := cfg["config"].(map[string]any); c["rate"] != 11.0 || c["window"].(map[string]any)["from"] != "22:00" || len(c["exclusions"].([]any)) != 2 {
		t.Fatalf("GET /scans/config = %v", c)
	}
	// at the next start nothing happens again
	mergeScanningSafety(t.Context(), s.d)
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.safety.merged'`) != 1 || s.activeSetting().CheckRate != 11 {
		t.Fatal("the merge ran twice")
	}
	// review #857 M1: a version before #850 after a rollback writes the copy again (a new exclusion): the scan module reads it at once,
	// and the next start takes it into the one store
	err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE scan_setting SET exclusions = '["192.168.10.9","192.168.10.50"]', updated_at = '2099-01-01T00:00:00.000Z'`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, cfg = s.do("GET", "/scans/config", "admin", "")
	if ex := cfg["config"].(map[string]any)["exclusions"].([]any); !slices.Contains(ex, any("192.168.10.50")) {
		t.Fatalf("before the next start nuclei skips %v, not the rollback's exclusion", ex)
	}
	mergeScanningSafety(t.Context(), s.d)
	if a := s.activeSetting(); !slices.Contains(a.Exclusions, "192.168.10.50") {
		t.Fatalf("after the next start: %v", a.Exclusions)
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
	if svc.Manual() != nil || s.count(`SELECT count(*) FROM sa_probe`) != 0 {
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
	if code, again := run("admin", `{}`); code != http.StatusConflict || errCodeOf(again) != "already_running" {
		t.Fatalf("a second run: %d %v", code, again)
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
	if s.count(`SELECT count(*) FROM sa_job WHERE kind = 'device' AND status <> 'stopped'`) != 0 { // stopped, or stopped before its row
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
	if s.count(`SELECT count(*) FROM sa_job WHERE kind = 'sweep' AND status = 'done'`) != 1 {
		t.Fatal("no sweep ran")
	}
}

// "+ New range" and "+ New exclusion" (#842) over the real wiring: the inventory adds one entry in one transaction, the audit row
// names it, the bus announces it, the scan module reads the new exclusion, and two adds sent at once both land.
func TestScanningInlineAdds(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.module("scan", true)
	s.saveScope(t)
	var changed atomic.Int32
	s.d.Bus.Subscribe(inventory.EventSettingsChanged, func(context.Context, events.Event) error { changed.Add(1); return nil })

	if code, out := s.do("POST", "/scanning/safety/ranges", "operator", `{"range":"192.168.20.0/24","confirm":true}`); code != http.StatusForbidden {
		t.Fatalf("an operator added a range: %d %v", code, out)
	}
	if code, out := s.do("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.0/24","confirm":false}`); code != http.StatusBadRequest || errCodeOf(out) != "scope_not_confirmed" {
		t.Fatalf("without the attestation: %d %v", code, out)
	}
	code, out := s.do("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.9/24","confirm":true}`)
	if code != http.StatusOK || len(out["scope"].(map[string]any)["lan_ranges"].([]any)) != 2 || len(out["adjusted"].([]any)) != 1 {
		t.Fatalf("add range = %d %v", code, out)
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail LIKE 'added range 192.168.20.0/24:%'`) != 1 {
		t.Fatal("no audit row naming the range")
	}
	code, out = s.do("POST", "/scanning/safety/exclusions", "admin", `{"entry":"192.168.20.77"}`)
	if code != http.StatusOK || !slices.Contains(out["exclusions"].([]any), any("192.168.20.77")) {
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

	// people add at once, two ranges and two exclusions: every one lands
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i, c := range []struct{ path, body string }{
		{"/scanning/safety/ranges", `{"range":"10.20.0.0/16","confirm":true}`},
		{"/scanning/safety/ranges", `{"range":"10.21.0.0/16","confirm":true}`},
		{"/scanning/safety/exclusions", `{"entry":"192.168.10.200"}`},
		{"/scanning/safety/exclusions", `{"entry":"192.168.10.201"}`},
	} {
		wg.Go(func() { codes[i], _ = s.do("POST", c.path, "admin", c.body) })
	}
	wg.Wait()
	if !slices.Equal(codes, []int{200, 200, 200, 200}) {
		t.Fatalf("concurrent adds: %v", codes)
	}
	st, err := s.d.Inventory.Settings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"192.168.10.0/24", "192.168.20.0/24", "10.20.0.0/16", "10.21.0.0/16"} {
		if !slices.Contains(st.LANRanges, r) {
			t.Fatalf("range %s was lost: %v", r, st.LANRanges)
		}
	}
	for _, x := range []string{"192.168.10.99", "192.168.20.77", "192.168.10.200", "192.168.10.201"} {
		if !slices.Contains(st.Active.Exclusions, x) {
			t.Fatalf("exclusion %s was lost: %v", x, st.Active.Exclusions)
		}
	}
}

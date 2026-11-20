package core_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// The tests of Settings › Scanning (#850, INV-40) at core's boundary: the ports are fakes here; cmd/vedette's scanning_test.go runs
// the same routes over the real modules.

type fakeSafety struct {
	st     core.Safety
	saved  []core.SafetyInput
	ranges []rangeAdd
	excl   []string
	err    error
}

func (f *fakeSafety) Safety(context.Context) (core.Safety, error) { return f.st, nil }

func (f *fakeSafety) SaveSafety(_ context.Context, _ string, in core.SafetyInput) (core.Safety, []core.Adjustment, error) {
	if f.err != nil {
		return core.Safety{}, nil, f.err
	}
	if in.Version != f.st.Version {
		return core.Safety{}, nil, &core.SafetyChanged{Code: "safety_changed", Message: "These safety settings changed.", Current: f.st}
	}
	f.st.Version += "+" // a save gives a new version
	f.saved = append(f.saved, in)
	f.st.LANRanges, f.st.Days, f.st.From, f.st.To = in.LANRanges, in.Days, in.From, in.To
	f.st.PacketsPerS, f.st.RequestsPerS, f.st.Exclusions = in.PacketsPerS, in.RequestsPerS, in.Exclusions
	return f.st, []core.Adjustment{{From: "192.168.18.5/24", To: "192.168.18.0/24"}}, nil
}

type rangeAdd struct {
	actor, rng, shown string
	confirmed         bool
}

// AddRange appends as the inventory does: refused without the attestation, nothing for a range already listed.
func (f *fakeSafety) AddRange(_ context.Context, actor string, in core.RangeAdd) (core.Safety, []core.Adjustment, error) {
	if f.err != nil {
		return core.Safety{}, nil, f.err
	}
	confirmedAt := "null"
	if in.ShownConfirmedAt != nil {
		confirmedAt = *in.ShownConfirmedAt
	}
	f.ranges = append(f.ranges, rangeAdd{actor, in.Range, strings.Join(in.Shown, ",") + " " + confirmedAt, in.Confirmed})
	if !in.Confirmed {
		return core.Safety{}, nil, apierr.New(http.StatusBadRequest, "scope_not_confirmed", "Tick the confirmation.")
	}
	if !slices.Equal(in.Shown, f.st.LANRanges) || in.ShownConfirmedAt == nil || *in.ShownConfirmedAt != *f.st.ConfirmedAt {
		return core.Safety{}, nil, &core.SafetyChanged{Code: "scope_changed", Message: "The network ranges changed.", Current: f.st}
	}
	f.st.Version += "+"
	if !slices.Contains(f.st.LANRanges, "192.168.20.0/24") {
		f.st.LANRanges = append(slices.Clone(f.st.LANRanges), "192.168.20.0/24")
	}
	return f.st, []core.Adjustment{{From: in.Range, To: "192.168.20.0/24"}}, nil
}

func (f *fakeSafety) AddExclusion(_ context.Context, actor, entry string) (core.Safety, error) {
	if f.err != nil {
		return core.Safety{}, f.err
	}
	f.excl = append(f.excl, actor+" "+entry)
	f.st.Version += "+"
	if !slices.Contains(f.st.Exclusions, entry) {
		f.st.Exclusions = append(slices.Clone(f.st.Exclusions), entry)
	}
	return f.st, nil
}

type fakeRunner struct {
	db      *store.DB // the record is written in the transaction that queues the run
	err     error
	targets [][]string
	started int // runs started: after their record
}

// Run records the run as sensor-active does, before it starts: a sweep of the scope, or the devices named.
func (f *fakeRunner) Run(ctx context.Context, _ string, targets []string, record func(*sql.Tx, core.RunConsent) error) (core.RunningJob, error) {
	f.targets = append(f.targets, targets)
	if f.err != nil {
		return core.RunningJob{}, f.err
	}
	c := core.RunConsent{ID: "sar-1", Until: time.Date(2026, 11, 16, 4, 0, 0, 0, time.UTC)}
	if len(targets) == 0 {
		c.Ranges = []string{"192.168.18.0/24"}
	}
	for _, t := range targets {
		c.Devices = append(c.Devices, t+" (a-1)")
	}
	if err := f.db.Write(ctx, func(tx *sql.Tx) error { return record(tx, c) }); err != nil {
		return core.RunningJob{}, err
	}
	f.started++
	return core.RunningJob{Engine: "nmap-discovery", ID: "sar-1", Label: "Check 192.168.18.20", TargetID: "a-1", StartedAt: time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC),
		Progress: &progress.View{Phase: progress.PhaseDiscovery, StartedAt: "2026-11-16T03:00:00.000Z", PhaseStartedAt: "2026-11-16T03:00:00.000Z", UpdatedAt: "2026-11-16T03:00:00.000Z"}}, nil
}

type scanningComposite struct {
	server.Fallback
	*core.ScanningHandlers
}

type scanningStack struct {
	*stack
	safety  *fakeSafety
	runner  *fakeRunner
	toggled []bool
	toggle  error
	broken  bool // the passive card's port fails
}

func ptr[T any](v T) *T { return &v }

func newScanningStack(t *testing.T) *scanningStack {
	t.Helper()
	db := migrated(t)
	log := slog.New(slog.DiscardHandler)
	reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: "test", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	s := &scanningStack{stack: &stack{t: t, db: db, reg: reg}, runner: &fakeRunner{db: db}, safety: &fakeSafety{st: core.Safety{
		LANRanges: []string{"192.168.18.0/24"}, ConfirmedAt: ptr("2026-11-01T00:00:00.000Z"), ConfirmedBy: ptr("admin@acme.example"),
		Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00", PacketsPerS: 50, RequestsPerS: 5, Exclusions: []string{"192.168.18.9"},
		FragileKinds: []string{"printer"}, RegularScanKinds: []string{}, FragileDevices: 3, Version: "v1",
	}}}
	moduleCard := func(module string, last *core.LastRun) func(context.Context) (core.EngineStatus, error) {
		return func(context.Context) (core.EngineStatus, error) {
			st := core.EngineStatus{Enabled: reg.Enabled(module), State: core.EngineOff, Last: last}
			if st.Enabled {
				st.State = core.EngineReady
			}
			return st, nil
		}
	}
	discoveryOn := false
	scanCost := core.EngineCost{RAMMB: ptr(1024), While: core.CostWhileOn, Container: "scan"}
	engines := []core.ScanEngine{
		{ID: "passive", Group: "discover", Module: "sensor-passive", Switch: core.SwitchModule, Cost: core.EngineCost{RAMMB: ptr(512), While: core.CostWhileOn},
			Status: func(ctx context.Context) (core.EngineStatus, error) {
				if s.broken {
					return core.EngineStatus{}, errors.New("the sensor table is gone")
				}
				return moduleCard("sensor-passive", nil)(ctx)
			}},
		{ID: "nmap-discovery", Group: "discover", Module: "sensor-active", Switch: core.SwitchOwn, Needs: "sensor-active", Affects: []string{"nmap-versions", "snmp"}, Cost: scanCost,
			Precheck: func(_ context.Context, on bool) error {
				if on && s.safety.st.ConfirmedAt == nil {
					return apierr.New(400, "scope_not_confirmed", "Confirm the scope.")
				}
				return nil
			},
			Toggle: func(_ context.Context, _ string, on bool) error {
				if s.toggle != nil {
					return s.toggle
				}
				s.toggled = append(s.toggled, on)
				discoveryOn = on
				return nil
			},
			Status: func(context.Context) (core.EngineStatus, error) {
				st := core.EngineStatus{Enabled: reg.Enabled("sensor-active") && discoveryOn, State: core.EngineOff}
				if st.Enabled {
					st.State, st.Running = core.EngineRunning, []core.RunningJob{{Engine: "nmap-discovery", ID: "saj-1", Label: "LAN sweep 192.168.18.0/24", StartedAt: time.Date(2026, 11, 16, 2, 0, 0, 0, time.UTC)}}
				}
				return st, nil
			}},
		{ID: "nmap-versions", Group: "identify", Module: "sensor-active", Follows: "nmap-discovery", Cost: scanCost, Status: moduleCard("sensor-active", nil)},
		{ID: "osquery", Group: "identify", Module: "agent-intake", Switch: core.SwitchModule, Affects: []string{"wazuh"}, Cost: core.EngineCost{RAMMB: ptr(0), While: core.CostWhileOn}, Status: moduleCard("agent-intake", nil)},
		{ID: "nuclei", Group: "vuln", Module: "scan", Preview: true, Switch: core.SwitchModule, Cost: scanCost,
			Status: moduleCard("scan", &core.LastRun{At: time.Date(2026, 11, 15, 23, 30, 0, 0, time.UTC), Outcome: "ok", Text: "Checked 4 of 4 devices, 1 confirmed"})},
		{ID: "zap", Group: "vuln", Module: "exposure", Cost: core.EngineCost{RAMMB: ptr(1024), While: core.CostWhileRunning}, Status: moduleCard("exposure", nil)},
		{ID: "openvas", Group: "vuln", Module: "exposure", Switch: core.SwitchOwn, Cost: core.EngineCost{While: core.CostWhileOn}, // RAM unknown: null
			Toggle: func(context.Context, string, bool) error {
				return apierr.New(http.StatusConflict, "low_memory", "This box has 5.9 GB of memory; OpenVAS needs at least 6.0 GB.")
			}, Status: moduleCard("exposure", nil)},
		{ID: "honeypot", Group: "traps", Module: "honeypot", Preview: true, Switch: core.SwitchModule, Cost: core.EngineCost{RAMMB: ptr(256), While: core.CostWhileOn}, Status: moduleCard("honeypot", nil)},
	}
	h, err := core.NewScanningHandlers(core.ScanningConfig{DB: db, Reg: reg, Audit: audit.New(nil), Log: log, Safety: s.safety, Engines: engines, Discovery: s.runner,
		TimeZone: func(context.Context) string { return "Asia/Ho_Chi_Minh" }, MemoryMB: func() (int, bool) { return 7680, true }})
	if err != nil {
		t.Fatal(err)
	}
	s.h, err = server.New(server.Config{API: scanningComposite{Fallback: server.Fallback{Log: log}, ScanningHandlers: h}, Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: reg, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func engineOf(t *testing.T, page map[string]any, id string) map[string]any {
	t.Helper()
	list, _ := page["engines"].([]any)
	for _, x := range list {
		if e, _ := x.(map[string]any); e["id"] == id {
			return e
		}
	}
	t.Fatalf("no engine %s in %v", id, page)
	return nil
}

// INV-40: GET /scanning answers a viewer with every engine module off (core serves it), every card in display order with its switch,
// cost and runs, the shared safety block, and the box's memory with what the engines on hold (a shared container once).
func TestContract_INV40_ScanningAnswersWithEveryModuleOff(t *testing.T) {
	t.Parallel()
	s := newScanningStack(t)
	turnOff(t, s.stack, "sensor-passive", "sensor-active", "agent-intake", "scan", "exposure", "honeypot")
	code, page := s.call("GET", "/scanning", "viewer", "")
	if code != http.StatusOK {
		t.Fatalf("GET /scanning = %d %v", code, page)
	}
	var ids []string
	for _, x := range page["engines"].([]any) {
		e := x.(map[string]any)
		ids = append(ids, e["id"].(string))
		if e["enabled"] != false || e["state"] != "off" {
			t.Errorf("%s: enabled %v state %v with its module off", e["id"], e["enabled"], e["state"])
		}
	}
	if want := []string{"passive", "nmap-discovery", "nmap-versions", "osquery", "nuclei", "zap", "openvas", "honeypot"}; !slices.Equal(ids, want) {
		t.Fatalf("engines = %v, want %v", ids, want)
	}
	if box := page["box"].(map[string]any); box["memory_mb"] != 7680.0 || box["reserved_mb"] != float64(core.CoreMemoryMB) {
		t.Fatalf("box = %v: only core holds memory with every engine off", box)
	}
	sf := page["safety"].(map[string]any)
	if w := sf["window"].(map[string]any); w["time_zone"] != "Asia/Ho_Chi_Minh" || w["from"] != "22:00" {
		t.Fatalf("window = %v", w)
	}
	if sp := sf["speed"].(map[string]any); sp["packets_per_s"] != 50.0 || sp["requests_per_s"] != 5.0 {
		t.Fatalf("speed = %v", sp)
	}
	if f := sf["fragile"].(map[string]any); f["devices"] != 3.0 {
		t.Fatalf("fragile = %v", f)
	}
	nuclei := engineOf(t, page, "nuclei")
	if lr, _ := nuclei["last_run"].(map[string]any); lr["outcome"] != "ok" || lr["at"] != "2026-11-15T23:30:00Z" || nuclei["preview"] != true || nuclei["can_toggle"] != true {
		t.Fatalf("nuclei = %v", nuclei)
	}
	if v := engineOf(t, page, "nmap-versions"); v["can_toggle"] != false || v["follows"] != "nmap-discovery" {
		t.Fatalf("nmap-versions = %v", v)
	}
	if o := engineOf(t, page, "openvas"); o["cost"].(map[string]any)["ram_mb"] != nil {
		t.Fatalf("openvas cost = %v: an unknown figure is null", o["cost"])
	}
	if r := page["running"].([]any); len(r) != 0 {
		t.Fatalf("running = %v", r)
	}

	// modules on: a container shared by three cards counts once, a "while running" one only while it runs
	turnOn(t, s.stack, "sensor-passive", "sensor-active", "scan", "exposure")
	if code, _ := s.call("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("nmap-discovery on = %d", code)
	}
	_, page = s.call("GET", "/scanning", "viewer", "")
	if got, want := page["box"].(map[string]any)["reserved_mb"], float64(core.CoreMemoryMB+512+1024); got != want {
		t.Fatalf("reserved_mb = %v, want %v (core + sensor + the scan container once; ZAP only while it runs)", got, want)
	}
	if r := page["running"].([]any); len(r) != 1 || r[0].(map[string]any)["id"] != "saj-1" || r[0].(map[string]any)["target_id"] != nil {
		t.Fatalf("running = %v", r)
	}

	// a card whose port fails says so; the page still answers
	s.broken = true
	code, page = s.call("GET", "/scanning", "viewer", "")
	if p := engineOf(t, page, "passive"); code != http.StatusOK || p["state"] != "error" || p["reason"] == nil {
		t.Fatalf("broken card: %d %v", code, p)
	}
}

func turnOff(t *testing.T, s *stack, ids ...string) { t.Helper(); setModules(t, s, false, ids...) }
func turnOn(t *testing.T, s *stack, ids ...string)  { t.Helper(); setModules(t, s, true, ids...) }

func setModules(t *testing.T, s *stack, on bool, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if s.reg.Enabled(id) == on {
			continue
		}
		var ch modreg.Change
		err := s.db.Write(t.Context(), func(tx *sql.Tx) error {
			var err error
			if on {
				ch, err = s.reg.Enable(t.Context(), tx, "admin@acme.example", id, true)
			} else {
				ch, err = s.reg.Disable(t.Context(), tx, "admin@acme.example", id)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		s.reg.Publish(ch)
	}
}

// INV-40: PATCH /scanning/engines/{id} moves the switch the engine maps to, audited by that switch, and answers the whole page;
// an engine without a switch answers 409 not_toggleable; a module the engine needs is turned on only with with_dependencies; the
// refusals of the switch (scope not confirmed, OpenVAS's preflight) reach the person as they are.
func TestContract_INV40_EngineSwitches(t *testing.T) {
	t.Parallel()
	s := newScanningStack(t)
	turnOff(t, s.stack, "sensor-passive", "sensor-active")
	for _, id := range []string{"nmap-versions", "zap"} {
		if code, body := s.call("PATCH", "/scanning/engines/"+id, "admin", `{"enabled":false}`); code != http.StatusConflict || errCode(body) != "not_toggleable" {
			t.Fatalf("%s: %d %v", id, code, body)
		}
	}
	if code, _ := s.call("PATCH", "/scanning/engines/passive", "viewer", `{"enabled":true}`); code != http.StatusForbidden {
		t.Fatalf("a viewer switched an engine: %d", code)
	}
	if code, _ := s.call("PATCH", "/scanning/engines/passive", "operator", `{"enabled":true}`); code != http.StatusForbidden {
		t.Fatalf("an operator switched an engine: %d", code)
	}

	// a module switch: the registry and its own audit row
	code, page := s.call("PATCH", "/scanning/engines/passive", "admin", `{"enabled":true}`)
	if code != http.StatusOK || !s.reg.Enabled("sensor-passive") || engineOf(t, page, "passive")["enabled"] != true {
		t.Fatalf("passive on: %d %v", code, page)
	}
	if n := count(t, s.db, `SELECT count(*) FROM core_audit WHERE action = 'module.enable' AND target = 'sensor-passive' AND user = 'admin@acme.example'`); n != 1 {
		t.Fatalf("module.enable rows = %d", n)
	}

	// active discovery needs sensor-active: refused without with_dependencies, nothing changed
	code, body := s.call("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true}`)
	if code != http.StatusConflict || errCode(body) != "missing_dependencies" || s.reg.Enabled("sensor-active") || len(s.toggled) != 0 {
		t.Fatalf("without with_dependencies: %d %v, module %v, toggled %v", code, body, s.reg.Enabled("sensor-active"), s.toggled)
	}
	code, page = s.call("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true,"with_dependencies":true}`)
	if code != http.StatusOK || !s.reg.Enabled("sensor-active") || !slices.Equal(s.toggled, []bool{true}) || engineOf(t, page, "nmap-discovery")["state"] != "running" {
		t.Fatalf("with_dependencies: %d, module %v, toggled %v, %v", code, s.reg.Enabled("sensor-active"), s.toggled, page)
	}
	// off never turns the module off
	if code, _ := s.call("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":false}`); code != http.StatusOK || !s.reg.Enabled("sensor-active") || !slices.Equal(s.toggled, []bool{true, false}) {
		t.Fatalf("off: %d, module %v, toggled %v", code, s.reg.Enabled("sensor-active"), s.toggled)
	}
	// the precheck refuses before anything moves
	s.safety.st.ConfirmedAt = nil
	if code, body := s.call("PATCH", "/scanning/engines/nmap-discovery", "admin", `{"enabled":true}`); code != http.StatusBadRequest || errCode(body) != "scope_not_confirmed" || len(s.toggled) != 2 {
		t.Fatalf("scope not confirmed: %d %v, toggled %v", code, body, s.toggled)
	}
	// OpenVAS's preflight passes through
	if code, body := s.call("PATCH", "/scanning/engines/openvas", "admin", `{"enabled":true}`); code != http.StatusConflict || errCode(body) != "low_memory" {
		t.Fatalf("openvas: %d %v", code, body)
	}
}

// INV-40: PUT /scanning/safety is the admin's one writer of the shared block: it reaches the inventory's store as typed, answers what
// was stored with the ranges it normalized, and the store's refusals pass through.
func TestContract_INV40_SafetyPut(t *testing.T) {
	t.Parallel()
	s := newScanningStack(t)
	in := `{"scope":{"lan_ranges":["192.168.18.5/24"],"confirmed":true},"window":{"days":[1,2,3],"from":"21:00","to":"04:00"},
		"speed":{"packets_per_s":80,"requests_per_s":8},"exclusions":["192.168.18.9","192.168.18.64/28"],"fragile":{"kinds":["printer","camera"],"regular_scan_kinds":["camera"]},"version":"v1"}`
	for _, who := range []string{"viewer", "operator"} {
		if code, _ := s.call("PUT", "/scanning/safety", who, in); code != http.StatusForbidden {
			t.Fatalf("%s saved the safety settings: %d", who, code)
		}
	}
	code, out := s.call("PUT", "/scanning/safety", "admin", in)
	if code != http.StatusOK || len(s.safety.saved) != 1 {
		t.Fatalf("PUT = %d %v", code, out)
	}
	got := s.safety.saved[0]
	if !got.Confirmed || !slices.Equal(got.LANRanges, []string{"192.168.18.5/24"}) || !slices.Equal(got.Days, []int{1, 2, 3}) || got.From != "21:00" || got.To != "04:00" ||
		got.PacketsPerS != 80 || got.RequestsPerS != 8 || !slices.Equal(got.Exclusions, []string{"192.168.18.9", "192.168.18.64/28"}) ||
		!slices.Equal(got.FragileKinds, []string{"printer", "camera"}) || !slices.Equal(got.RegularScanKinds, []string{"camera"}) {
		t.Fatalf("stored %+v", got)
	}
	if adj := out["adjusted"].([]any); len(adj) != 1 || adj[0].(map[string]any)["to"] != "192.168.18.0/24" {
		t.Fatalf("adjusted = %v", out["adjusted"])
	}
	if sp := out["speed"].(map[string]any); sp["requests_per_s"] != 8.0 || out["version"] != "v1+" {
		t.Fatalf("answer = %v", out)
	}
	// review #860 M1: the version is required, and a stale one is 409 safety_changed with the current block, nothing stored
	if code, body := s.call("PUT", "/scanning/safety", "admin", strings.Replace(in, `,"version":"v1"`, "", 1)); code != http.StatusBadRequest || len(s.safety.saved) != 1 {
		t.Fatalf("no version: %d %v", code, body)
	}
	code, body := s.call("PUT", "/scanning/safety", "admin", in)
	if code != http.StatusConflict || errCode(body) != "safety_changed" || len(s.safety.saved) != 1 {
		t.Fatalf("a stale version: %d %v", code, body)
	}
	if cur := body["error"].(map[string]any)["safety"].(map[string]any); cur["version"] != "v1+" || cur["window"].(map[string]any)["from"] != "21:00" {
		t.Fatalf("the refusal does not carry the current block: %v", cur)
	}
	in = strings.Replace(in, `"version":"v1"`, `"version":"v1+"`, 1)
	// the contract's own limits are checked at the edge
	if code, _ := s.call("PUT", "/scanning/safety", "admin", `{"scope":{"lan_ranges":[],"confirmed":false},"window":{"days":[],"from":"21:00","to":"04:00"},"speed":{"packets_per_s":80,"requests_per_s":8},"exclusions":[],"fragile":{"kinds":[],"regular_scan_kinds":[]},"version":"v1+"}`); code != http.StatusBadRequest {
		t.Fatalf("no day: %d", code)
	}
	s.safety.err = apierr.New(400, "bad_rate", "The vulnerability check rate is 1 to 20 requests per second.")
	if code, body := s.call("PUT", "/scanning/safety", "admin", in); code != http.StatusBadRequest || errCode(body) != "bad_rate" {
		t.Fatalf("a refusal of the store: %d %v", code, body)
	}
}

// INV-40: POST /scanning/engines/nmap-discovery/run is the admin's: 202 with the run, an audit row that names what will be scanned,
// and each refusal of the runner as its code.
func TestContract_INV40_RunNow(t *testing.T) {
	t.Parallel()
	s := newScanningStack(t)
	for _, who := range []string{"viewer", "operator"} {
		if code, _ := s.call("POST", "/scanning/engines/nmap-discovery/run", who, `{}`); code != http.StatusForbidden {
			t.Fatalf("%s started a run: %d", who, code)
		}
	}
	if len(s.runner.targets) != 0 {
		t.Fatal("a refused caller reached the runner")
	}
	code, run := s.call("POST", "/scanning/engines/nmap-discovery/run", "admin", `{"targets":["192.168.18.20"," 192.168.18.20 "]}`)
	if code != http.StatusAccepted || run["id"] != "sar-1" || run["engine"] != "nmap-discovery" || run["target_id"] != "a-1" || run["progress"].(map[string]any)["phase"] != "discovery" {
		t.Fatalf("run = %d %v", code, run)
	}
	if !slices.Equal(s.runner.targets[0], []string{"192.168.18.20"}) {
		t.Fatalf("targets = %v", s.runner.targets)
	}
	if n := count(t, s.db, `SELECT count(*) FROM core_audit WHERE action = 'scanning.run' AND user = 'admin@acme.example' AND target = 'sar-1' AND detail = 'check 192.168.18.20 (a-1) now, whatever the window'`); n != 1 {
		t.Fatalf("scanning.run rows = %d", n)
	}
	if code, _ := s.call("POST", "/scanning/engines/nmap-discovery/run", "admin", `{}`); code != http.StatusAccepted || len(s.runner.targets[1]) != 0 {
		t.Fatalf("Scan the LAN now: %d, targets %v", code, s.runner.targets)
	}
	if n := count(t, s.db, `SELECT count(*) FROM core_audit WHERE action = 'scanning.run' AND target = 'sar-1' AND detail LIKE 'sweep of 192.168.18.0/24 and the scans of the devices it finds now, whatever the window, until %'`); n != 1 {
		t.Fatalf("whole scope rows = %d", n)
	}
	if code, body := s.call("POST", "/scanning/engines/nmap-discovery/run", "admin", `{"targets":[" "]}`); code != http.StatusBadRequest || errCode(body) != "invalid" {
		t.Fatalf("blank target: %d %v", code, body)
	}
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{core.ErrDiscoveryModuleOff, 409, "module_off"},
		{core.ErrDiscoveryOff, 409, "engine_off"},
		{core.ErrScopeNotConfirmed, 400, "scope_not_confirmed"},
		{core.ErrRunBusy, 409, "already_running"},
		{core.ErrNmapBusy, 409, "busy"},
		{&core.RunTooSoon{RetryAfter: 7*time.Minute + 10*time.Second}, 409, "too_soon"},
		{core.ErrNmapUnavailable, 503, "scanner_unavailable"},
		{&core.RunRefusal{Target: "192.168.18.77", Code: "unknown_device", Detail: "no_device"}, 400, "unknown_device"},
		{&core.RunRefusal{Target: "10.0.0.1", Code: "out_of_scope", Detail: "out_of_scope"}, 400, "out_of_scope"},
		{&core.RunRefusal{Target: "a-2", Code: "not_scannable", Detail: "regular_scan_never"}, 400, "not_scannable"},
	} {
		s.runner.err = c.err
		code, body := s.call("POST", "/scanning/engines/nmap-discovery/run", "admin", `{"targets":["192.168.18.77"]}`)
		if code != c.status || errCode(body) != c.code {
			t.Errorf("%v: %d %v, want %d %s", c.err, code, body, c.status, c.code)
		}
		var rr *core.RunRefusal
		if errors.As(c.err, &rr) && body["error"].(map[string]any)["target"] != rr.Target {
			t.Errorf("%s: the answer does not name the target: %v", c.code, body)
		}
		if c.code == "too_soon" && body["error"].(map[string]any)["retry_after"] != 430.0 {
			t.Errorf("too_soon without retry_after: %v", body)
		}
	}
	if n := count(t, s.db, `SELECT count(*) FROM core_audit WHERE action = 'scanning.run'`); n != 2 || s.runner.started != 2 {
		t.Fatalf("a refused run was audited or started: %d rows, %d started", n, s.runner.started)
	}

	// review #857 M2: the audit row is written before anything starts; when it cannot be, nothing starts
	s.runner.err = nil
	if err := s.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER test_no_audit BEFORE INSERT ON core_audit BEGIN SELECT RAISE(ABORT, 'test: the audit log refuses'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, _ := s.call("POST", "/scanning/engines/nmap-discovery/run", "admin", `{}`); code != http.StatusInternalServerError || s.runner.started != 2 {
		t.Fatalf("an unwritable audit row: %d, %d started", code, s.runner.started)
	}
}

// INV-40 (#842): POST /scanning/safety/ranges and /exclusions are the admin's inline adds: they reach the inventory's store with the
// person and the attestation, answer the whole safety block (the range's with adjusted), and the store's refusals pass through.
func TestContract_INV40_SafetyInlineAdds(t *testing.T) {
	t.Parallel()
	s := newScanningStack(t)
	for _, who := range []string{"viewer", "operator"} {
		if code, _ := s.call("POST", "/scanning/safety/ranges", who, `{"range":"192.168.20.5/24","confirm":true,"shown_ranges":["192.168.18.0/24"],"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`); code != http.StatusForbidden {
			t.Fatalf("%s added a range: %d", who, code)
		}
		if code, _ := s.call("POST", "/scanning/safety/exclusions", who, `{"entry":"192.168.18.20"}`); code != http.StatusForbidden {
			t.Fatalf("%s added an exclusion: %d", who, code)
		}
	}
	if len(s.safety.ranges) != 0 || len(s.safety.excl) != 0 {
		t.Fatal("a refused caller reached the store")
	}
	for _, body := range []string{`{"range":"192.168.20.5/24","shown_ranges":[]` + `,"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`, `{"range":"192.168.20.5/24","confirm":true` + `,"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`, `{"range":"192.168.20.5/24","confirm":true,"shown_ranges":["192.168.18.0/24"]}`} {
		if code, out := s.call("POST", "/scanning/safety/ranges", "admin", body); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", body, code, out)
		}
	}
	if code, body := s.call("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.5/24","confirm":false,"shown_ranges":["192.168.18.0/24"],"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`); code != http.StatusBadRequest || errCode(body) != "scope_not_confirmed" {
		t.Fatalf("confirm false: %d %v", code, body)
	}
	// review #860 H1: a dialog that showed another list is 409 scope_changed with the current block
	code, body := s.call("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.5/24","confirm":true,"shown_ranges":[],"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`)
	if code != http.StatusConflict || errCode(body) != "scope_changed" {
		t.Fatalf("stale dialog: %d %v", code, body)
	}
	if cur := body["error"].(map[string]any)["safety"].(map[string]any); cur["version"] != "v1" || len(cur["scope"].(map[string]any)["lan_ranges"].([]any)) != 1 {
		t.Fatalf("the refusal does not carry the current block: %v", cur)
	}
	// review #860 r2 M1: a dialog that showed the scope unconfirmed reaches the store as such (null), and is refused here
	if code, body := s.call("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.5/24","confirm":true,"shown_ranges":["192.168.18.0/24"],"shown_confirmed_at":null}`); code != http.StatusConflict || errCode(body) != "scope_changed" || s.safety.ranges[2].shown != "192.168.18.0/24 null" {
		t.Fatalf("shown unconfirmed: %d %v %+v", code, body, s.safety.ranges)
	}
	code, out := s.call("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.20.5/24","confirm":true,"shown_ranges":["192.168.18.0/24"],"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`)
	if code != http.StatusOK || s.safety.ranges[3] != (rangeAdd{"admin@acme.example", "192.168.20.5/24", "192.168.18.0/24 2026-11-01T00:00:00.000Z", true}) || out["version"] != "v1+" {
		t.Fatalf("add range = %d %v, store got %+v", code, out, s.safety.ranges)
	}
	if r := out["scope"].(map[string]any)["lan_ranges"].([]any); len(r) != 2 || r[1] != "192.168.20.0/24" {
		t.Fatalf("lan_ranges = %v", r)
	}
	if adj := out["adjusted"].([]any); len(adj) != 1 || adj[0].(map[string]any)["to"] != "192.168.20.0/24" {
		t.Fatalf("adjusted = %v", out["adjusted"])
	}
	if out["window"].(map[string]any)["time_zone"] != "Asia/Ho_Chi_Minh" || out["fragile"].(map[string]any)["devices"] != 3.0 {
		t.Fatalf("not the whole block: %v", out)
	}
	code, out = s.call("POST", "/scanning/safety/exclusions", "admin", `{"entry":"192.168.18.20"}`)
	if code != http.StatusOK || !slices.Equal(s.safety.excl, []string{"admin@acme.example 192.168.18.20"}) {
		t.Fatalf("add exclusion = %d %v", code, out)
	}
	if x := out["exclusions"].([]any); len(x) != 2 || x[1] != "192.168.18.20" {
		t.Fatalf("exclusions = %v", x)
	}
	if _, has := out["adjusted"]; has || out["speed"] == nil || out["version"] != "v1++" {
		t.Fatalf("exclusion answer = %v", out)
	}
	if code, _ := s.call("POST", "/scanning/safety/exclusions", "admin", `{"entry":"`+strings.Repeat("1", 65)+`"}`); code != http.StatusBadRequest {
		t.Fatalf("a 65-character entry: %d", code)
	}
	s.safety.err = apierr.New(http.StatusBadRequest, "too_many_exclusions", "The exclusion list can have at most 200 lines.")
	if code, body := s.call("POST", "/scanning/safety/exclusions", "admin", `{"entry":"192.168.18.21"}`); code != http.StatusBadRequest || errCode(body) != "too_many_exclusions" {
		t.Fatalf("a refusal of the store: %d %v", code, body)
	}
	s.safety.err = apierr.New(http.StatusBadRequest, "overlap_range", "Range 192.168.0.0/16 overlaps 192.168.18.0/24.")
	if code, body := s.call("POST", "/scanning/safety/ranges", "admin", `{"range":"192.168.0.0/16","confirm":true,"shown_ranges":[],"shown_confirmed_at":"2026-11-01T00:00:00.000Z"}`); code != http.StatusBadRequest || errCode(body) != "overlap_range" {
		t.Fatalf("a refusal of the store: %d %v", code, body)
	}
}

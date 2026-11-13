package core_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	hostserver "github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
	"github.com/knt048/vedette/modules/core"
)

// The OS endpoints and the backup download through the real stack (server.New, sessions, SQLite) and a real
// host/client talking to an in-process vedette-host (host/server with the real host/ops commands on a fake
// machine: fake apt, systemctl and friends, a temporary root; nothing touches the real system and nothing runs
// as root). Time is TZ-independent: the host clock is fixed at 2026-11-09T12:00:00Z (a Monday) and the
// organization time zone is named explicitly where it matters.

type fullOSAPI struct {
	server.Fallback
	*core.ModuleHandlers
	*core.APIHandlers
	*core.OSHandlers
}

// gatedHost holds back GetRun while a test wants the install run to look "running" to core.
type gatedHost struct {
	core.Host
	on   atomic.Bool
	gate chan struct{}
}

func (g *gatedHost) GetRun(ctx context.Context, id string) (api.Run, error) {
	if g.on.Load() {
		select {
		case <-g.gate:
		case <-ctx.Done():
			return api.Run{}, ctx.Err()
		}
	}
	return g.Host.GetRun(ctx, id)
}

type osEnv struct {
	*world
	purgeGate *core.PurgeGate
	m         *opstest.Machine
	hh        *servertest.Harness
	clock     *servertest.Clock
	gate      *gatedHost
	lock      atomic.Bool // a dpkg lock is held
	free      atomic.Uint64
	handler   *core.OSHandlers
	admin     *client
	oper      *client
	viewer    *client
}

type osOpts struct {
	noHost    bool          // core.Host is nil: a container-only install
	coreClock time.Duration // how far behind the host clock core's clock is
	host      core.Host     // use this instead of the in-process host
	testBase  bool          // a -test. build with no ReleaseBase whose core_data/test-release-base names the release server (#469)
	wake      func()        // OSConfig.Wake
}

func newOSEnv(t *testing.T, o osOpts) *osEnv {
	t.Helper()
	e := &osEnv{world: newWorld(t), m: opstest.NewMachine(t), clock: servertest.NewClock(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))}
	e.free.Store(100 << 30)
	ho := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) {
		d.LockHeld = func(string) (bool, error) { return e.lock.Load(), nil }
		d.FreeBytes = func(string) (uint64, error) { return e.free.Load(), nil }
		d.AfterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } } // a scheduled reboot never fires here
	})
	e.hh = servertest.Start(t, ho.Commands(), func(op *hostserver.Options) {
		op.StateDir, op.Readers, op.Now, op.WriteGate = e.m.State, ho.Readers(), e.clock.Now, ho.WriteGate
	})
	e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	e.m.Rule("apt-get", "install", "", 0, "", "installed")
	e.m.Rule("apt-get", "dist-upgrade", "sim_after.txt", 0, "installed", "")
	e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
	e.m.Rule("apt-config", "dump", "aptconfig_on.txt", 0, "", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
	e.m.Rule("systemctl", "is-enabled", "enabled.txt", 0, "", "")

	var host core.Host
	switch {
	case o.noHost:
	case o.host != nil:
		host = o.host
	default:
		e.gate = &gatedHost{Host: e.hh.Client, gate: make(chan struct{})}
		host = e.gate
	}
	e.purgeGate = &core.PurgeGate{}
	e.handler = e.newHandlers(t, host, o.coreClock)
	e.admin, _ = e.signIn("admin@acme.example", "admin")
	e.oper, _ = e.signIn("operator@acme.example", "operator")
	e.viewer, _ = e.signIn("viewer@acme.example", "viewer")
	return e
}

// newHandlers builds OSHandlers on this world's database and mounts them on the HTTP stack (a second call is
// a restart of core: the same database, the same host, nothing in memory).
func (e *osEnv) newHandlers(t *testing.T, host core.Host, behind time.Duration) *core.OSHandlers {
	t.Helper()
	h, err := core.NewOSHandlers(core.OSConfig{
		DB: e.env.DB, Auth: e.env.Svc, Audit: e.env.Audit, Log: e.logger(), Host: host,
		DataDir: e.m.CoreData, KeyPath: filepath.Join(e.m.CoreData, "vedette.key"),
		Zone: e.h.OrgTimeZone, Clock: func() time.Time { return e.clock.Now().Add(-behind) }, Gate: e.purgeGate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	api, err := server.New(server.Config{
		API:  fullOSAPI{Fallback: server.Fallback{Log: e.logger()}, ModuleHandlers: core.NewModuleHandlers(e.env.DB, e.reg), APIHandlers: e.h, OSHandlers: h},
		Auth: e.env.Svc.Sessions, Modules: e.reg, Log: e.logger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.api = api
	return h
}

func (e *osEnv) logger() *slog.Logger { return slog.New(slog.NewTextHandler(e.logs, nil)) }

func (e *osEnv) snapshotDirs() []string {
	ents, _ := os.ReadDir(filepath.Join(e.m.CoreData, "snapshots"))
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	return out
}

func (e *osEnv) actions() []string {
	rows, err := e.env.DB.Reader().QueryContext(e.t.Context(), "SELECT action FROM core_audit ORDER BY seq")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func (e *osEnv) setting(key, value string) {
	e.t.Helper()
	err := e.env.DB.Write(e.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.t.Context(), `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES (?, ?, '2026-11-09T08:00:00.000Z', 'test')
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *osEnv) setZone(name string) {
	e.t.Helper()
	err := e.env.DB.Write(e.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.t.Context(), `INSERT INTO core_org (id, name, timezone, setup_complete, data_mode, install_id) VALUES (1, 'Acme', ?, 1, 'clean', 'ins-test')`, name)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// checked runs a first check, as the operator, so the host has a state to report.
func (e *osEnv) checked() {
	e.t.Helper()
	wantOK(e.t, e.oper.post("/core/updates/os/check", nil), 200)
}

func eventuallyOS(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		select {
		case <-t.Context().Done():
			t.Fatalf("test ended while waiting for %s", what)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (e *osEnv) waitRunDone(c *client) reply {
	e.t.Helper()
	var r reply
	eventuallyOS(e.t, "the install run to finish", func() bool {
		r = c.get("/core/updates/os/run")
		return r.Code == 200 && r.str("status") != "running"
	})
	return r
}

func getArr(r reply, path ...string) []any {
	var cur any = r.JSON
	for _, p := range path {
		m, _ := cur.(map[string]any)
		cur = m[p]
	}
	a, _ := cur.([]any)
	return a
}

func getVal(r reply, path ...string) any {
	var cur any = r.JSON
	for _, p := range path {
		m, _ := cur.(map[string]any)
		cur = m[p]
	}
	return cur
}

// ---- GET and check ----

func TestOSStateBeforeAndAfterTheFirstCheck(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	// Before the first check: 200 with os null and core's own part (D-407), not 409 no_check_yet.
	g0 := e.viewer.get("/core/updates/os")
	wantOK(t, g0, 200)
	if v, ok := g0.JSON["os"]; !ok || v != nil || len(getArr(g0, "pending")) != 0 || getVal(g0, "window", "mode") == nil || getVal(g0, "release_upgrade") != nil {
		t.Errorf("GET before the first check = %s", g0.Raw)
	}
	wantStatus(t, e.viewer.get("/core/updates/os/run").withNull(t), 200, "")

	r := e.oper.post("/core/updates/os/check", nil)
	wantOK(t, r, 200)
	if r.str("os", "distro") != "ubuntu" || r.str("os", "release") != "24.04" || r.str("os", "name") != "Ubuntu 24.04.3 LTS" {
		t.Errorf("os = %v", r.JSON["os"])
	}
	pending := getArr(r, "pending")
	if len(pending) != 2 || getVal(r, "busy") != false || getVal(r, "auto_security") != true || len(getArr(r, "pending")) == 0 {
		t.Fatalf("state = %s", r.Raw)
	}
	for _, p := range pending {
		m := p.(map[string]any)
		if _, ok := m["cves"].([]any); !ok {
			t.Errorf("package %v has no cves array", m)
		}
	}
	if w := getVal(r, "window").(map[string]any); w["mode"] != "always" || w["from"] != "02:00" || w["to"] != "05:00" {
		t.Errorf("default window = %v", w)
	}
	if r.str("release_upgrade", "to") != "Ubuntu 26.04 LTS" {
		t.Errorf("release_upgrade = %v", r.JSON["release_upgrade"])
	}
	if r.JSON["reboot_scheduled_at"] != nil {
		t.Errorf("reboot_scheduled_at = %v", r.JSON["reboot_scheduled_at"])
	}
	g := e.viewer.get("/core/updates/os")
	wantOK(t, g, 200)
	if getVal(g, "os", "kernel") == nil {
		t.Errorf("GET = %s", g.Raw)
	}
	if got := e.actions(); !slices.Contains(got, "os.check") {
		t.Errorf("no os.check row: %v", got)
	}
}

func (r reply) withNull(t *testing.T) reply {
	t.Helper()
	if r.Raw != "null" && strings.TrimSpace(r.Raw) != "null" {
		t.Errorf("body = %q, want null", r.Raw)
	}
	return r
}

func TestOSRolesAreEnforced(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	type call struct {
		method, path string
		body         any
		min          string
	}
	for _, c := range []call{
		{"GET", "/core/updates/os", nil, "viewer"},
		{"GET", "/core/updates/os/run", nil, "viewer"},
		{"POST", "/core/updates/os/check", nil, "operator"},
		{"POST", "/core/updates/os/install", map[string]any{"scope": "all"}, "admin"},
		{"PATCH", "/core/updates/os/settings", map[string]any{"auto_security": true}, "admin"},
		{"POST", "/core/updates/os/reboot", map[string]any{"when": "window"}, "admin"},
		{"DELETE", "/core/updates/os/reboot", nil, "admin"},
		{"GET", "/core/data/backup", nil, "admin"},
	} {
		for name, cl := range map[string]*client{"viewer": e.viewer, "operator": e.oper} {
			below := rankOfName(name) < rankOfName(c.min)
			r := cl.request(c.method, c.path, c.body)
			if below && (r.Code != 403 || r.code() != "forbidden") {
				t.Errorf("%s %s as %s = %d %s, want 403 forbidden", c.method, c.path, name, r.Code, r.Raw)
			}
			if !below && (r.Code == 401 || r.Code == 403) {
				t.Errorf("%s %s as %s = %d, want it allowed", c.method, c.path, name, r.Code)
			}
		}
	}
}

func rankOfName(n string) int { return map[string]int{"viewer": 1, "operator": 2, "admin": 3}[n] }

func TestOSCheckIsRefusedWhenUpdateChecksAreOffUnderPrivacy(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.setting("core_privacy", `{"update_check":false,"telemetry":true}`)
	wantStatus(t, e.oper.post("/core/updates/os/check", nil), 409, "check_off")
	if got := e.m.Calls("apt-get"); len(got) != 0 {
		t.Errorf("the box made a request although update checks are off: %q", got)
	}
	if slices.Contains(e.actions(), "os.check") {
		t.Error("a refused check left an audit row")
	}
	e.setting("core_privacy", `{"update_check":true}`)
	wantOK(t, e.oper.post("/core/updates/os/check", nil), 200)
}

// ---- install ----

func TestOSInstallRunsThroughTheHostAndCleansUp(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	r := e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"})
	wantOK(t, r, 202)
	if r.str("scope") != "all" || r.str("status") != "running" || !strings.HasPrefix(r.str("id"), "rn_") || r.str("user") != "admin@acme.example" || r.JSON["result"] != nil {
		t.Fatalf("accepted run = %s", r.Raw)
	}
	done := e.waitRunDone(e.viewer)
	res := getVal(done, "result").(map[string]any)
	if res["installed"] != float64(2) || res["security"] != float64(1) || res["backup"] == "" {
		t.Fatalf("result = %v", res)
	}
	h := res["health"].([]any)
	if len(h) != 1 || h[0].(map[string]any)["name"] != "vedette-core" || h[0].(map[string]any)["ok"] != true {
		t.Errorf("health = %v", h)
	}
	lines := getArr(done, "lines")
	if len(lines) == 0 || !strings.Contains(joinAny(lines), "Installing 2 packages") {
		t.Errorf("lines = %v", lines)
	}
	if done.JSON["finished_at"] == nil {
		t.Error("a finished run has no finished_at")
	}
	// The host holds a pre_os_update backup WITH the key: it never leaves the box.
	bl, err := e.hh.Client.StateBackups(t.Context())
	if err != nil || len(bl.Backups) != 1 || bl.Backups[0].Kind != "pre_os_update" || !bl.Backups[0].IncludesSecrets || bl.Backups[0].Downloadable || bl.Backups[0].BackupID != res["backup"] {
		t.Fatalf("backups = %+v %v", bl, err)
	}
	// core removes its snapshot directory once the run ended and audits the end, once.
	eventuallyOS(t, "the snapshot directory to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
	eventuallyOS(t, "the audit row of the end", func() bool { return slices.Contains(e.actions(), "os.install_done") })
	if got := e.actions(); !slices.Contains(got, "os.install") {
		t.Errorf("actions = %v", got)
	}
	// Nothing is pending any more: a second install has nothing to do, and the state is not busy.
	wantStatus(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 409, "nothing_to_install")
	st := e.viewer.get("/core/updates/os")
	wantOK(t, st, 200)
	if len(getArr(st, "pending")) != 0 || getVal(st, "busy") != false {
		t.Errorf("state after = %s", st.Raw)
	}
	// "Restart" core: a new OSHandlers rebuilds the run from the host's record, scope and user included.
	e.newHandlers(t, e.hh.Client, 0)
	again := e.viewer.get("/core/updates/os/run")
	wantOK(t, again, 200)
	if again.str("id") != r.str("id") || again.str("scope") != "all" || again.str("status") != "done" || again.str("user") != "admin@acme.example" ||
		getVal(again, "result", "installed") != float64(2) || len(getArr(again, "lines")) != len(lines) {
		t.Errorf("after a restart = %s", again.Raw)
	}
	n := 0
	for _, a := range e.actions() {
		if a == "os.install_done" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("os.install_done audited %d times", n)
	}
}

func joinAny(a []any) string {
	var b strings.Builder
	for _, x := range a {
		b.WriteString(x.(string))
		b.WriteByte('\n')
	}
	return b.String()
}

func TestOSInstallSecurityScopeAndValidation(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	wantStatus(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "nope"}), 400, "invalid") // the contract schema stops it at the door
	wantOK(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "security"}), 202)
	done := e.waitRunDone(e.admin)
	if done.str("scope") != "security" {
		t.Errorf("scope = %s", done.str("scope"))
	}
}

func TestOSInstallIsOneAtATimeAndBlocksCheckAndReboot(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	e.gate.on.Store(true) // the run ends in the host but core keeps seeing it as running
	wantOK(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 202)
	wantStatus(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 409, "busy")
	wantStatus(t, e.oper.post("/core/updates/os/check", nil), 409, "busy")
	wantStatus(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "now"}), 409, "busy")
	st := e.viewer.get("/core/updates/os")
	wantOK(t, st, 200)
	if getVal(st, "busy") != true {
		t.Errorf("state is not busy while the run is: %s", st.Raw)
	}
	if r := e.viewer.get("/core/updates/os/run"); r.str("status") != "running" {
		t.Errorf("run = %s", r.Raw)
	}
	close(e.gate.gate)
	e.waitRunDone(e.viewer)
	eventuallyOS(t, "busy to clear", func() bool { return getVal(e.viewer.get("/core/updates/os"), "busy") == false })
}

func TestOSInstallRunThatFailsSaysSoInItsLinesAndResult(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.m.ClearRules("apt-get")
	e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	e.m.Rule("apt-get", "install", "", 100, "", "")
	e.m.Rule("apt-get", "dist-upgrade", "sim_ubuntu.txt", 0, "", "")
	e.checked()
	wantOK(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 202)
	done := e.waitRunDone(e.admin)
	if !strings.Contains(joinAny(getArr(done, "lines")), "failed: apt_failed") {
		t.Errorf("the lines do not say why: %v", getArr(done, "lines"))
	}
	if getVal(done, "result", "installed") != float64(0) {
		t.Errorf("result = %v", done.JSON["result"])
	}
	// The page must not call a refused install "done" (issue #238): the run says failed, and why in words.
	if done.str("status") != "failed" || !strings.Contains(done.str("error"), "package manager failed") {
		t.Errorf("status %q, error %q", done.str("status"), done.str("error"))
	}
	eventuallyOS(t, "the snapshot directory to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
	eventuallyOS(t, "the audit row of the end", func() bool { return slices.Contains(e.actions(), "os.install_done") })
}

func TestOSHostRefusalsAreMappedAndTheSnapshotIsRemoved(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		arrange func(e *osEnv)
		behind  time.Duration
		status  int
		code    string
	}{
		{"dpkg lock held", func(e *osEnv) { e.lock.Store(true) }, 0, 409, "dpkg_locked"},
		{"low disk", func(e *osEnv) { e.free.Store(1<<30 - 1) }, 0, 409, "low_disk"},
		{"dpkg audit not clean", func(e *osEnv) { e.m.Rule("dpkg", "--audit", "dpkg_audit_bad.txt", 0, "", "") }, 0, 409, "dpkg_inconsistent"},
		{"snapshot too old for the host", func(*osEnv) {}, time.Hour, 502, "snapshot_rejected"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newOSEnv(t, osOpts{coreClock: c.behind})
			e.checked()
			c.arrange(e)
			r := e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"})
			wantStatus(t, r, c.status, c.code)
			if c.code == "dpkg_locked" {
				if e, _ := r.JSON["error"].(map[string]any); e["retry_after"] == nil {
					t.Errorf("no retry_after in %s", r.Raw)
				}
			}
			if d := e.snapshotDirs(); len(d) != 0 {
				t.Errorf("snapshot directories left: %v", d)
			}
			if got := e.actions(); !slices.Contains(got, "os.install") || !slices.Contains(got, "os.install_failed") {
				t.Errorf("a refused install must leave the intent and the failure in core_audit: %v", got)
			}
			if slices.ContainsFunc(e.m.Calls("apt-get"), func(c []string) bool { return slices.Contains(c, "install") }) {
				t.Error("apt install ran")
			}
			// The page is not stuck: a later run works once the cause is gone.
			wantStatus(t, e.viewer.get("/core/updates/os/run").withNull(t), 200, "")
		})
	}
}

// ---- settings ----

func TestOSSettingsWindowAndAutoSecurity(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	win := func(mode string, days []int, from, to string) map[string]any {
		return map[string]any{"window": map[string]any{"mode": mode, "days": days, "from": from, "to": to}}
	}
	for name, c := range map[string]struct {
		body map[string]any
		code string
	}{
		"no days":      {win("window", []int{}, "02:00", "05:00"), "no_days"},
		"day 8":        {win("window", []int{8}, "02:00", "05:00"), "invalid"}, // the contract schema stops these three at the door
		"bad time":     {win("window", []int{1}, "2am", "05:00"), "invalid"},
		"bad time 25h": {win("window", []int{1}, "02:00", "25:00"), "invalid"},
		"empty window": {win("window", []int{1}, "03:00", "03:00"), "empty_window"},
	} {
		r := e.admin.patch("/core/updates/os/settings", c.body)
		if r.Code != 400 || r.code() != c.code {
			t.Errorf("%s = %d %s, want 400 %s", name, r.Code, r.Raw, c.code)
		}
	}
	r := e.admin.patch("/core/updates/os/settings", win("window", []int{3, 1, 3}, "23:00", "02:00")) // crosses midnight: valid
	wantOK(t, r, 200)
	w := getVal(r, "window").(map[string]any)
	if w["mode"] != "window" || w["from"] != "23:00" || w["to"] != "02:00" || len(w["days"].([]any)) != 2 || w["days"].([]any)[0] != float64(1) {
		t.Errorf("window = %v", w)
	}
	// "always" keeps the days and hours for the next time the form is used.
	r = e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "always", "days": []int{}, "from": "00:00", "to": "00:00"}})
	wantOK(t, r, 200)
	if w := getVal(r, "window").(map[string]any); w["mode"] != "always" || w["from"] != "23:00" {
		t.Errorf("after always: %v", w)
	}
	// The window survives a restart of core (it is in core_setting).
	e.newHandlers(t, e.hh.Client, 0)
	if g := e.viewer.get("/core/updates/os"); getVal(g, "window", "from") != "23:00" {
		t.Errorf("window after a restart: %s", g.Raw)
	}
	// Auto security off: applied through the host and read back from the host.
	e.m.ClearRules("apt-config")
	e.m.Rule("apt-config", "dump", "aptconfig_off.txt", 0, "", "")
	e.m.ClearRules("systemctl")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
	e.m.Rule("systemctl", "is-enabled", "disabled.txt", 1, "", "")
	r = e.admin.patch("/core/updates/os/settings", map[string]any{"auto_security": false})
	wantOK(t, r, 200)
	if getVal(r, "auto_security") != false {
		t.Errorf("auto_security = %v", r.JSON["auto_security"])
	}
	runs, err := e.hh.Client.ListRuns(t.Context(), 20)
	if err != nil || !slices.ContainsFunc(runs, func(r api.Run) bool {
		return r.Command == api.CmdOSAutoSecuritySet && r.Status == api.StatusSucceeded && r.Actor == "admin@acme.example"
	}) {
		t.Errorf("no os.auto_security.set run by the admin: %+v %v", runs, err)
	}
	if n := countOf(e.actions(), "os.settings"); n != 3 {
		t.Errorf("os.settings audited %d times, want 3 (one per accepted change)", n)
	}
	// A failure on the box (the setting could not be verified) is a 502 and is not stored.
	e.m.ClearRules("apt-config")
	e.m.Rule("apt-config", "dump", "aptconfig_leaky.txt", 0, "", "")
	r = e.admin.patch("/core/updates/os/settings", map[string]any{"auto_security": true})
	if r.Code != 502 {
		t.Errorf("an unverified change = %d %s, want 502", r.Code, r.Raw)
	}
	if !slices.Contains(e.actions(), "os.settings_failed") {
		t.Error("the failure was not audited")
	}
}

func countOf(s []string, v string) (n int) {
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

// ---- reboot ----

func atOfHost(t *testing.T, e *osEnv) time.Time {
	t.Helper()
	st, err := e.hh.Client.StateOS(t.Context())
	if err != nil || st.RebootScheduledAt == nil {
		t.Fatalf("no reboot scheduled on the host: %+v %v", st, err)
	}
	return *st.RebootScheduledAt
}

func TestOSRebootWindowAndCustomAreReadInTheOrganizationTimeZone(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		zone         string
		window       string // from-to
		wantWindowAt time.Time
		customAt     string
		wantCustom   time.Time
		outside      string
	}{
		// Host clock: Mon 2026-11-09 12:00Z. Asia/Ho_Chi_Minh is UTC+7: 19:00 on Monday, so Tuesday 02:00 is 19:00Z.
		{"Asia/Ho_Chi_Minh", "02:00-05:00", time.Date(2026, 11, 9, 19, 0, 0, 0, time.UTC), "03:30", time.Date(2026, 11, 9, 20, 30, 0, 0, time.UTC), "12:00"},
		{"UTC", "02:00-05:00", time.Date(2026, 11, 10, 2, 0, 0, 0, time.UTC), "03:30", time.Date(2026, 11, 10, 3, 30, 0, 0, time.UTC), "12:00"},
		// America/New_York is UTC-5 in November: Monday 07:00, so Tuesday 02:00 is 07:00Z.
		{"America/New_York", "02:00-05:00", time.Date(2026, 11, 10, 7, 0, 0, 0, time.UTC), "03:30", time.Date(2026, 11, 10, 8, 30, 0, 0, time.UTC), "12:00"},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			t.Parallel()
			e := newOSEnv(t, osOpts{})
			e.setZone(tc.zone)
			e.checked()
			from, to, _ := strings.Cut(tc.window, "-")
			wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": []int{1, 2, 3, 4, 5, 6, 7}, "from": from, "to": to}}), 200)

			r := e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"})
			wantOK(t, r, 200)
			if got := atOfHost(t, e); !got.Equal(tc.wantWindowAt) {
				t.Errorf("window: host schedule %v, want %v", got, tc.wantWindowAt)
			}
			if r.str("reboot_scheduled_at") != tc.wantWindowAt.Format(time.RFC3339) {
				t.Errorf("answer reboot_scheduled_at = %q", r.str("reboot_scheduled_at"))
			}

			r = e.admin.post("/core/updates/os/reboot", map[string]any{"when": "custom", "at": tc.customAt})
			wantOK(t, r, 200)
			if got := atOfHost(t, e); !got.Equal(tc.wantCustom) {
				t.Errorf("custom: host schedule %v, want %v (a new schedule replaces the old one)", got, tc.wantCustom)
			}

			wantStatus(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "custom", "at": tc.outside}), 400, "outside_window")
			wantStatus(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "custom", "at": "25:99"}), 400, "invalid_time")
			wantStatus(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "custom"}), 400, "invalid_time")
			if got := atOfHost(t, e); !got.Equal(tc.wantCustom) {
				t.Errorf("a refused request changed the schedule: %v", got)
			}
		})
	}
}

func TestOSRebootWindowNeedsAWindowAndPicksTheDay(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.setZone("UTC")
	e.checked()
	wantStatus(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"}), 400, "no_window") // default: any time
	// Only Wednesday 01:00-04:00: from Monday noon the next start is Wednesday 01:00.
	wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": []int{3}, "from": "01:00", "to": "04:00"}}), 200)
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"}), 200)
	if got := atOfHost(t, e); !got.Equal(time.Date(2026, 11, 11, 1, 0, 0, 0, time.UTC)) {
		t.Errorf("schedule = %v", got)
	}
	// A custom time inside a window that crosses midnight belongs to the day it starts on: Wednesday 23:00-02:00
	// holds Thursday 01:00 but not Wednesday 01:00 before it started... and not Friday.
	wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": []int{3}, "from": "23:00", "to": "02:00"}}), 200)
	// The schedule above (Wed 01:00) is not inside the new window (it would need Tuesday 23:00 as start): dropped.
	if st, _ := e.hh.Client.StateOS(t.Context()); st.RebootScheduledAt != nil {
		t.Errorf("a schedule outside the new window stayed: %v", st.RebootScheduledAt)
	}
	if !slices.Contains(e.actions(), "os.reboot_cancel") {
		t.Error("the automatic cancel was not audited")
	}
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "custom", "at": "01:00"}), 200)
	if got := atOfHost(t, e); !got.Equal(time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)) {
		t.Errorf("custom across midnight = %v, want Thursday 01:00", got)
	}
}

func TestOSRebootNowAndCancel(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	wantStatus(t, e.admin.delete("/core/updates/os/reboot"), 409, "nothing_scheduled")
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "now"}), 200)
	eventuallyOS(t, "the host to run systemctl reboot", func() bool {
		return slices.ContainsFunc(e.m.Calls("systemctl"), func(c []string) bool { return slices.Equal(c, []string{"reboot"}) })
	})
	if !slices.Contains(e.actions(), "os.reboot") {
		t.Errorf("actions = %v", e.actions())
	}
}

func TestOSRebootCancel(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.setZone("UTC")
	e.checked()
	wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": []int{1, 2, 3, 4, 5, 6, 7}, "from": "02:00", "to": "05:00"}}), 200)
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"}), 200)
	r := e.admin.delete("/core/updates/os/reboot")
	wantOK(t, r, 200)
	if r.JSON["reboot_scheduled_at"] != nil {
		t.Errorf("still scheduled: %s", r.Raw)
	}
	if st, _ := e.hh.Client.StateOS(t.Context()); st.RebootScheduledAt != nil {
		t.Error("the host still has a schedule")
	}
	wantStatus(t, e.admin.delete("/core/updates/os/reboot"), 409, "nothing_scheduled")
}

func TestOSRebootLimitIsMapped(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	for i := range 3 {
		wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "now"}), 200)
		// The host refuses every write while it believes it is rebooting, until the boot id changes.
		e.m.SetBootID(fmt.Sprintf("%08d-2222-4333-8444-555555555555", i+2))
	}
	wantStatus(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "now"}), 409, "reboot_limit_reached")
}

// ---- not an appliance, unreachable ----

type osCall struct {
	method, path string
	body         any
	as           func(e *osEnv) *client
}

var osCalls = []osCall{
	{"GET", "/core/updates/os", nil, func(e *osEnv) *client { return e.viewer }},
	{"GET", "/core/updates/os/run", nil, func(e *osEnv) *client { return e.viewer }},
	{"POST", "/core/updates/os/check", nil, func(e *osEnv) *client { return e.oper }},
	{"POST", "/core/updates/os/install", map[string]any{"scope": "all"}, func(e *osEnv) *client { return e.admin }},
	{"PATCH", "/core/updates/os/settings", map[string]any{"auto_security": true}, func(e *osEnv) *client { return e.admin }},
	{"POST", "/core/updates/os/reboot", map[string]any{"when": "now"}, func(e *osEnv) *client { return e.admin }},
	{"DELETE", "/core/updates/os/reboot", nil, func(e *osEnv) *client { return e.admin }},
	{"GET", "/core/data/backup", nil, func(e *osEnv) *client { return e.admin }},
}

func TestOSWithoutAHostIsNotAnApplianceAndNeverA500(t *testing.T) {
	t.Parallel()
	absent := filepath.Join(os.TempDir(), "vedette-no-such-dir", "host.sock")
	for name, o := range map[string]osOpts{
		"no host configured":    {noHost: true},
		"socket file is absent": {host: hostclient.New(absent)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newOSEnv(t, o)
			before := len(e.actions())
			for _, c := range osCalls {
				r := c.as(e).request(c.method, c.path, c.body)
				if r.Code != 409 || r.code() != "not_appliance" {
					t.Errorf("%s %s = %d %s, want 409 not_appliance", c.method, c.path, r.Code, r.Raw)
				}
				if msg := r.str("error", "message"); !strings.Contains(msg, "container-only") {
					t.Errorf("%s %s: message %q does not say what is missing", c.method, c.path, msg)
				}
			}
			if after := len(e.actions()); after != before {
				t.Errorf("refused calls left %d audit rows", after-before)
			}
			if d := e.snapshotDirs(); len(d) != 0 {
				t.Errorf("snapshot directories: %v", d)
			}
		})
	}
}

func TestOSSocketThatDoesNotAnswerIs503HostUnreachable(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "vh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := new(net.ListenConfig).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close() // the file stays, nobody listens: connection refused
	e := newOSEnv(t, osOpts{host: hostclient.New(sock)})
	for _, c := range osCalls[:3] {
		r := c.as(e).request(c.method, c.path, c.body)
		if r.Code != 503 || r.code() != "host_unreachable" {
			t.Errorf("%s %s = %d %s, want 503 host_unreachable", c.method, c.path, r.Code, r.Raw)
		}
	}
}

// ---- backup download ----

func TestBackupDownloadStreamsTheHostsFileAndHoldsNoKey(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	before := len(e.actions())
	r := e.admin.get("/core/data/backup")
	if r.Code != 200 {
		t.Fatalf("backup = %d %s", r.Code, r.Raw)
	}
	if cd := r.Header.Get("Content-Disposition"); cd != `attachment; filename="vedette-backup-2026-11-09.tar.gz"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if cl := r.Header.Get("Content-Length"); cl == "" || cl != strconv.Itoa(len(r.Raw)) {
		t.Errorf("Content-Length %q, body %d bytes", cl, len(r.Raw))
	}
	members := map[string][]byte{}
	err := ops.ReadArchive(bytes.NewReader([]byte(r.Raw)), func(name string, data []byte) error {
		members[name] = append([]byte(nil), data...)
		return nil
	})
	if err != nil {
		t.Fatalf("the download is not a backup archive of the host: %v", err)
	}
	if _, ok := members["vedette.db"]; !ok || members["manifest.json"] == nil {
		t.Fatalf("members = %v", keysOf(members))
	}
	if _, ok := members["vedette.key"]; ok {
		t.Fatal("the downloadable backup holds the key file")
	}
	if !bytes.HasPrefix(members["vedette.db"], []byte("SQLite format 3\x00")) {
		t.Error("vedette.db is not a SQLite database")
	}
	for name, data := range members {
		if bytes.Contains(data, []byte(opstest.Key)) {
			t.Errorf("%s contains the master key", name)
		}
	}
	if !bytes.Contains(members["manifest.json"], []byte(`"db_schema":"core=11"`)) || !bytes.Contains(members["manifest.json"], []byte(`"includes_secrets":false`)) {
		t.Errorf("manifest = %s", members["manifest.json"])
	}
	bl, err := e.hh.Client.StateBackups(t.Context())
	if err != nil || len(bl.Backups) != 1 || bl.Backups[0].Kind != "manual" || bl.Backups[0].IncludesSecrets || !bl.Backups[0].Downloadable {
		t.Errorf("backups = %+v %v", bl, err)
	}
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot directories left after the call: %v", d)
	}
	if got := e.actions(); len(got) != before+1 || got[len(got)-1] != "data.backup" {
		t.Errorf("audit rows: %v", got)
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestBackupDownloadFailuresAreMappedAndTheSnapshotIsRemoved(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.free.Store(0)
	wantStatus(t, e.admin.get("/core/data/backup"), 409, "low_disk")
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot directories left after a failed backup: %v", d)
	}
	if got := e.actions(); !slices.Contains(got, "data.backup") || !slices.Contains(got, "data.backup_failed") {
		t.Errorf("audit rows: %v", got)
	}
	e2 := newOSEnv(t, osOpts{coreClock: time.Hour})
	wantStatus(t, e2.admin.get("/core/data/backup"), 502, "snapshot_rejected")
	if d := e2.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot directories left: %v", d)
	}
}

// A request as an anonymous browser never reaches the host.
func TestOSEndpointsNeedASession(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	anon := e.client()
	for _, c := range osCalls {
		if r := anon.request(c.method, c.path, c.body); r.Code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous = %d", c.method, c.path, r.Code)
		}
	}
	if got := e.m.AllCalls(); len(got) != 0 {
		t.Errorf("the host ran something for anonymous requests: %v", got)
	}
}

// The Privacy page and the OS code share one stored setting: turning update checks off through
// PATCH /core/privacy makes the OS check refuse, and turning them on again lets it run.
func TestOSCheckFollowsPatchCorePrivacy(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	wantOK(t, e.admin.patch("/core/privacy", map[string]any{"update_check": false}), 200)
	wantStatus(t, e.oper.post("/core/updates/os/check", nil), 409, "check_off")
	if got := e.m.Calls("apt-get"); len(got) != 0 {
		t.Errorf("the box made a request although update checks are off: %q", got)
	}
	wantOK(t, e.admin.patch("/core/privacy", map[string]any{"update_check": true}), 200)
	wantOK(t, e.oper.post("/core/updates/os/check", nil), 200)
}

package core_test

import (
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/core"
)

// The periodic check and the automatic mode (S-CORE-2, update-manifest §6, §12, D-388): UpdateTick is the core job
// cmd/vedette schedules every core.UpdateTickEvery.

// auditUsers lists the user of every audit row of action, oldest first.
func (e *osEnv) auditUsers(action string) []string {
	e.t.Helper()
	rows, err := e.env.DB.Reader().QueryContext(e.t.Context(), "SELECT user FROM core_audit WHERE action = ? ORDER BY seq", action)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// The job checks one tick after the process started when no check was ever made, then only 6 hours ± 30 minutes later,
// through the same check as the page (one update.check row, user system); with update checks off under Privacy it makes
// no request at all.
func TestUpdateCheckJobRunsEverySixHours(t *testing.T) {
	t.Parallel()
	e := newUpdEnv(t, osOpts{noHost: true})
	e.srv.standard(t, 5)
	index := "/index/index.json"

	if err := e.upd.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.srv.total(); n != 0 {
		t.Fatalf("the first tick of the process made %d requests, want none", n)
	}
	e.clock.Advance(core.UpdateTickEvery)
	if err := e.upd.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.srv.hit(index); n != 1 {
		t.Fatalf("index fetched %d times by the next tick, want 1", n)
	}
	if u := e.auditUsers("update.check"); !slices.Equal(u, []string{"system"}) {
		t.Fatalf("update.check rows = %q", u)
	}
	if g := e.viewer.get("/core/updates"); g.str("last_check") == "" || len(getArr(g, "available")) != 1 {
		t.Fatalf("after the job's check = %s", g.Raw)
	}
	e.clock.Advance(5*time.Hour + 29*time.Minute) // below 6 h - 30 min: not due
	if err := e.upd.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.srv.hit(index); n != 1 {
		t.Fatalf("index fetched %d times before 5 h 30 min, want 1", n)
	}
	e.clock.Advance(62 * time.Minute) // 6 h 31 min: past 6 h + 30 min, due
	if err := e.upd.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.srv.hit(index); n != 2 {
		t.Fatalf("index fetched %d times after 6 h 31 min, want 2", n)
	}

	e.setting("core_privacy", `{"update_check":false}`)
	e.clock.Advance(7 * time.Hour)
	n := e.srv.total()
	if err := e.upd.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if e.srv.total() != n || len(e.auditUsers("update.check")) != 2 {
		t.Errorf("update checks off: %d requests, %d check rows", e.srv.total()-n, len(e.auditUsers("update.check")))
	}
}

// Automatic mode installs the offer only inside the maintenance window with 30 minutes of it left, with no reboot
// scheduled, as system, never over a busy run, and does not try again a release whose last run failed (D-388). Manual
// mode never installs.
func TestUpdateAutoInstallsInTheWindowAsSystem(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	tick := func() {
		t.Helper()
		if err := e.handler.UpdateTick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	noRun := func(when string) {
		t.Helper()
		if run := getVal(e.admin.get("/core/updates"), "run"); run != nil || len(fh.callList()) != 0 {
			t.Fatalf("%s: run %v, calls %q", when, run, fh.callList())
		}
	}
	// The clock is Monday 2026-11-09 12:00 UTC (the organization's zone).
	e.setting("os.settings", `{"window":{"mode":"window","days":[1],"from":"02:00","to":"05:00"}}`)
	tick()
	noRun("manual mode")
	wantOK(t, e.admin.patch("/core/updates", map[string]any{"mode": "auto"}), 200)
	tick()
	noRun("automatic mode outside the window")

	e.setting("os.settings", `{"window":{"mode":"window","days":[1],"from":"11:00","to":"12:20"}}`)
	tick()
	noRun("20 minutes of the window left")

	e.setting("os.settings", `{"window":{"mode":"window","days":[1],"from":"11:00","to":"13:00"}}`)
	soon := e.clock.Now().Add(time.Hour)
	fh.mu.Lock()
	fh.rebootAt = &soon
	fh.mu.Unlock()
	tick()
	noRun("a reboot scheduled in an hour")
	fh.mu.Lock()
	fh.rebootAt = nil
	fh.mu.Unlock()
	e.clock.Advance(11 * time.Second) // the copy of state/os lives 10 s

	fh.hold["start core"] = true
	tick()
	waitCall(t, fh, "start core")
	run := runOf(t, e.admin.get("/core/updates"))
	if run["status"] != "running" || run["user"] != "system" || run["to"] != "1.4.0" {
		t.Fatalf("automatic run = %v", run)
	}
	calls := len(fh.callList())
	tick() // busy: nothing new
	if n := len(fh.callList()); n != calls {
		t.Fatalf("a tick during the run made %d more calls", n-calls)
	}
	fh.release("start core")
	if run := endedRun(t, e); run["status"] != "done" || run["user"] != "system" {
		t.Fatalf("automatic run at the end = %v", run)
	}
	if u := e.auditUsers("update.apply"); !slices.Equal(u, []string{"system"}) {
		t.Errorf("update.apply rows = %q", u)
	}
	if u := e.auditUsers("update.apply_done"); !slices.Equal(u, []string{"system"}) {
		t.Errorf("update.apply_done rows = %q", u)
	}
	if h0 := e.admin.get("/core/updates").JSON["history"].([]any)[0].(map[string]any); h0["user"] != "system" {
		t.Errorf("history = %v", h0)
	}
	// This process still runs 1.3.0 (core did not really restart): a run to 1.4.0 that ended done is not made again.
	calls = len(fh.callList())
	tick()
	if n := len(fh.callList()); n != calls {
		t.Errorf("a done release was installed again: calls %q", fh.callList())
	}
}

// A check that fails installs nothing, and while the last good check is older than one interval nothing installs either:
// a held-back index must not hide a revocation (§13).
func TestUpdateAutoNeedsAFreshGoodCheck(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	wantOK(t, e.admin.patch("/core/updates", map[string]any{"mode": "auto"}), 200)
	e.srv.put("/index/index.json.minisig", []byte("not a signature"))
	e.clock.Advance(7 * time.Hour) // the periodic check is due, and fails
	if err := e.handler.UpdateTick(t.Context()); err == nil {
		t.Fatal("a failed check was not reported by the job")
	}
	if err := e.handler.UpdateTick(t.Context()); err != nil { // not due again; the stored offer is too old to install
		t.Fatal(err)
	}
	if run := getVal(e.admin.get("/core/updates"), "run"); run != nil || len(fh.callList()) != 0 {
		t.Fatalf("installed without a fresh good check: run %v, calls %q", run, fh.callList())
	}
}

// A Check now that fails an hour after a good check stops the automatic mode too, though the good check is still young.
func TestUpdateAutoStopsAfterAFailedCheckNow(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	wantOK(t, e.admin.patch("/core/updates", map[string]any{"mode": "auto"}), 200)
	e.srv.put("/index/index.json.minisig", []byte("not a signature"))
	e.clock.Advance(time.Hour)
	wantStatus(t, e.oper.post("/core/updates/check", nil), 502, core.CodeUpdateCheckFailed)
	e.clock.Advance(core.UpdateTickEvery)
	if err := e.handler.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if run := getVal(e.admin.get("/core/updates"), "run"); run != nil || len(fh.callList()) != 0 {
		t.Fatalf("installed after a failed check: run %v, calls %q", run, fh.callList())
	}
}

func TestUpdateAutoDoesNotRetryAFailedRelease(t *testing.T) {
	t.Parallel()
	e, fh := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	wantOK(t, e.admin.patch("/core/updates", map[string]any{"mode": "auto"}), 200) // the window is "any time" by default
	fh.refuse["pull scan"] = api.CodeSignatureInvalid
	if err := e.handler.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if run := endedRun(t, e); run["status"] != "failed" || run["user"] != "system" {
		t.Fatalf("run = %v", run)
	}
	fh.mu.Lock()
	delete(fh.refuse, "pull scan")
	fh.mu.Unlock()
	calls := len(fh.callList())
	if err := e.handler.UpdateTick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(fh.callList()); n != calls {
		t.Fatalf("the failed release was tried again: calls %q", fh.callList())
	}
	// An administrator can still apply it.
	wantOK(t, e.admin.post("/core/updates/apply", map[string]any{"component": "software"}), 200)
	if run := endedRun(t, e); run["status"] != "done" || run["user"] != "admin@acme.example" {
		t.Fatalf("the administrator's run = %v", run)
	}
}

// Check now in automatic mode starts the run as system when the window allows (as the mock); applied stays 0.
func TestUpdateCheckNowInAutoModeStartsTheRun(t *testing.T) {
	t.Parallel()
	e, _ := newRunEnv(t, lockstep("1.3.0", "1.2.0"), "1.3.0", true)
	wantOK(t, e.admin.patch("/core/updates", map[string]any{"mode": "auto"}), 200)
	r := e.oper.post("/core/updates/check", nil)
	wantOK(t, r, 200)
	if getVal(r, "applied") != float64(0) {
		t.Errorf("applied = %v", getVal(r, "applied"))
	}
	if run := runOf(t, r); run["user"] != "system" || run["action"] != "update" {
		t.Fatalf("run = %v", run)
	}
	if run := endedRun(t, e); run["status"] != "done" {
		t.Fatalf("run = %v", run)
	}
}

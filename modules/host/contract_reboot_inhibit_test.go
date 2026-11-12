// Contract tests of D-453: os.reboot and logind's shutdown inhibitors (apt installing). The host never forces
// past a block lock: "now" is refused while one is held, a scheduled reboot waits for it, and a lock taken
// between the check and systemctl reboot is waited for (bounded) with the write gate still raised.
package host_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

const (
	// busctl --json=short's answer of ListInhibitors while apt installs (Ubuntu 26.04), and with only a delay lock.
	inhibitAPT  = `{"type":"a(ssssuu)","data":[[["shutdown:sleep","APT","APT is installing or removing packages","block",0,7781]]]}`
	inhibitNone = `{"type":"a(ssssuu)","data":[[["shutdown","Unattended Upgrades Shutdown","Stop ongoing upgrades","delay",0,5402]]]}`
)

var argvListInhibitors = []string{"--system", "--json=short", "call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListInhibitors"}

// inhibitWhile makes busctl report apt's block lock while the marker is set (or, with "!name", until it is).
func inhibitWhile(e *sysEnv, marker string) {
	e.m.RuleText("busctl", "ListInhibitors", inhibitAPT, 0, marker, "")
	e.m.RuleText("busctl", "ListInhibitors", inhibitNone, 0, "", "")
}

func rebootNotes(t *testing.T, e *sysEnv, code string) []api.AuditRecord {
	t.Helper()
	var out []api.AuditRecord
	for _, a := range audit(t, e.h) {
		if a.Command == "os.reboot" && a.Code != nil && *a.Code == code && a.Actor == "system" {
			out = append(out, a)
		}
	}
	return out
}

// retryTimers are the armed tries of a started reboot that a shutdown lock refused.
func retryTimers(e *sysEnv) []*fakeTimer {
	var out []*fakeTimer
	for _, tm := range e.timers.active() {
		if tm.d == 30*time.Second {
			out = append(out, tm)
		}
	}
	return out
}

func TestContract_Reboot_NowIsRefusedWhileAShutdownLockIsHeld(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	inhibitWhile(e, "!apt-done")
	ce := e.refusedWith(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "reboot_inhibited")
	if !strings.Contains(ce.Message, "APT holds a shutdown lock (APT is installing or removing packages)") {
		t.Errorf("the refusal does not name who and why: %q", ce.Message)
	}
	if rebootCalls(e) != 0 {
		t.Fatal("rebooted past a block inhibitor")
	}
	if c := e.m.Calls("busctl"); len(c) == 0 || !slices.Equal(c[0], argvListInhibitors) {
		t.Fatalf("busctl %q", c)
	}
	// A schedule is not refused: it waits for the lock when it fires.
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	e.ok(t, "os.reboot.cancel", nil)
	// apt finished: only the delay lock is left, which never refuses a reboot.
	e.m.Mark("apt-done", true)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
	for _, c := range e.m.Calls("systemctl") {
		if slices.ContainsFunc(c, func(a string) bool { return strings.Contains(a, "inhibit") || strings.Contains(a, "force") }) {
			t.Fatalf("systemctl %q", c)
		}
	}
}

// An unreadable list does not refuse: logind still refuses a locked reboot itself.
func TestContract_Reboot_AnUnreadableInhibitorListDoesNotRefuse(t *testing.T) {
	t.Parallel()
	for _, rule := range []struct {
		out  string
		code int
	}{{"", 1}, {"Failed to connect to bus", 1}, {`{"type":"a(ssssuu)","data":[[["shutdown","APT","x","block",null,1]]]}`, 0}} {
		e := startSys(t)
		e.m.RuleText("busctl", "ListInhibitors", rule.out, rule.code, "", "")
		e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
		eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
	}
}

func TestContract_Reboot_AScheduledRebootWaitsForAShutdownLock(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	inhibitWhile(e, "!apt-done")
	at := e.clock.Now().Add(2 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})
	for i := range 3 {
		if i == 0 {
			e.clock.Advance(2 * time.Hour)
		} else {
			e.clock.Advance(time.Minute)
		}
		act := e.timers.active()
		if len(act) != 1 {
			t.Fatalf("timers %+v", act)
		}
		act[0].fire()
		if rebootCalls(e) != 0 {
			t.Fatal("the scheduled reboot went past a block inhibitor")
		}
		if act = e.timers.active(); len(act) != 1 || act[0].d != time.Minute {
			t.Fatalf("not re-armed in a minute: %+v", act)
		}
		if r := e.o.WriteGate(); r != nil {
			t.Fatalf("writes are refused while the reboot only waits: %+v", r)
		}
		if raw, _ := os.ReadFile(filepath.Join(e.m.State, "os", "reboot.json")); !bytes.Contains(raw, []byte(`"schedule"`)) {
			t.Fatalf("the schedule is gone while it waits: %s", raw)
		}
	}
	waits := rebootNotes(t, e, "reboot_waiting_inhibitor")
	if len(waits) != 1 || !strings.Contains(string(waits[0].ArgsRedacted), `"who":"APT"`) || !strings.Contains(string(waits[0].ArgsRedacted), `"kind":"scheduled"`) {
		t.Fatalf("the wait is audited %d times: %+v", len(waits), waits)
	}
	e.m.Mark("apt-done", true)
	e.clock.Advance(time.Minute)
	e.timers.active()[0].fire()
	eventually(t, "the scheduled reboot after apt", func() bool { return rebootCalls(e) == 1 })
}

// fireRetry fires the one armed retry the way a real timer does: once fired, it is no longer armed.
func fireRetry(t *testing.T, e *sysEnv) {
	t.Helper()
	tms := retryTimers(e)
	if len(tms) != 1 {
		t.Fatalf("%d retries armed", len(tms))
	}
	e.timers.mu.Lock()
	tms[0].stopped = true
	e.timers.mu.Unlock()
	tms[0].fire()
}

// startRace starts a "now" reboot that logind refuses, as systemd 257 and later do: the check and the read
// before the call saw no lock, then apt took one just before systemctl reboot (the fake systemctl fails and sets
// the marker that makes busctl report apt's lock).
func startRace(t *testing.T) *sysEnv {
	t.Helper()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	inhibitWhile(e, "apt")
	e.m.RuleText("systemctl", "reboot", "Call to Reboot failed: Operation denied due to active block inhibitor\n", 1, "!apt-done", "apt")
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "the retry", func() bool { return len(retryTimers(e)) == 1 })
	return e
}

func TestContract_Reboot_ALockTakenAfterTheCheckIsWaitedForWithTheGateUp(t *testing.T) {
	t.Parallel()
	e := startRace(t)
	if rebootCalls(e) != 1 || len(rebootNotes(t, e, "reboot_failed")) != 0 {
		t.Fatalf("calls %d", rebootCalls(e))
	}
	// Past the gate's own 10 minutes, writes are still refused while the reboot waits.
	for range 2 {
		e.clock.Advance(9 * time.Minute)
		fireRetry(t, e)
	}
	e.clock.Advance(9 * time.Minute)
	if r := e.o.WriteGate(); r == nil || r.Code != api.CodeRebooting {
		t.Fatalf("the gate came down while the reboot waits: %+v", r)
	}
	if n := len(rebootNotes(t, e, "reboot_waiting_inhibitor")); n != 1 {
		t.Fatalf("the wait is audited %d times", n)
	}
	// While the list shows the lock, a try does not even call systemctl (systemd 255 would let root through).
	if len(retryTimers(e)) != 1 || rebootCalls(e) != 1 {
		t.Fatalf("timers %d, calls %d", len(retryTimers(e)), rebootCalls(e))
	}
	// apt is done: the next try reboots, and nothing more is armed.
	e.m.Mark("apt-done", true)
	e.m.Mark("apt", false)
	fireRetry(t, e)
	if rebootCalls(e) != 2 || len(retryTimers(e)) != 0 || len(rebootNotes(t, e, "reboot_failed")) != 0 {
		t.Fatalf("calls %d, timers %d", rebootCalls(e), len(retryTimers(e)))
	}
}

func TestContract_Reboot_AWaitForALockEndsInRebootFailedAfter30Minutes(t *testing.T) {
	t.Parallel()
	e := startRace(t)
	for range 3 {
		e.clock.Advance(10 * time.Minute)
		fireRetry(t, e)
	}
	if len(retryTimers(e)) != 0 {
		t.Fatal("still trying after 30 minutes")
	}
	f := rebootNotes(t, e, "reboot_failed")
	if len(f) != 1 || !strings.Contains(string(f[0].ArgsRedacted), `"reason":"inhibited"`) || !strings.Contains(string(f[0].ArgsRedacted), `"why":"APT is installing or removing packages"`) {
		t.Fatalf("reboot_failed %+v", f)
	}
	if r := e.o.WriteGate(); r != nil {
		t.Fatalf("the gate stays up after the reboot was given up: %+v", r)
	}
	e.ok(t, "os.reboot.cancel", nil) // writes run again
}

func TestContract_Reboot_AFailureWithoutALockIsReportedAtOnce(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	inhibitWhile(e, "never")
	e.m.RuleText("systemctl", "reboot", "", 1, "", "")
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "reboot_failed", func() bool { return len(rebootNotes(t, e, "reboot_failed")) == 1 })
	if f := rebootNotes(t, e, "reboot_failed"); !strings.Contains(string(f[0].ArgsRedacted), `"reason":"systemctl_failed"`) {
		t.Fatalf("%s", f[0].ArgsRedacted)
	}
	eventually(t, "the gate down", func() bool { return e.o.WriteGate() == nil }) // reboot_failed is written just before
	if len(retryTimers(e)) != 0 {
		t.Fatal("a failure without a lock is retried")
	}
}

func TestContract_Reboot_CloseStopsTheWaitForALock(t *testing.T) {
	t.Parallel()
	e := startRace(t)
	e.o.Close()
	if len(retryTimers(e)) != 0 {
		t.Fatal("the retry is still armed after Close")
	}
}

// Systemd 255 (Ubuntu 24.04) lets root reboot past apt's lock of uid 0, so the fake systemctl here always
// succeeds: only the host's own read just before the call stops a reboot whose lock was taken after the check.
func TestContract_Reboot_OnSystemd255TheReadBeforeTheCallIsTheGuard(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	// The first read (Check) sees no lock; every later one sees apt's, until apt is done.
	e.m.RuleText("busctl", "ListInhibitors", inhibitNone, 0, "!checked", "checked")
	inhibitWhile(e, "!apt-done")
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "the retry", func() bool { return len(retryTimers(e)) == 1 })
	if rebootCalls(e) != 0 {
		t.Fatal("systemctl reboot ran while the list showed apt's lock")
	}
	if r := e.o.WriteGate(); r == nil || r.Code != api.CodeRebooting {
		t.Fatalf("the gate is down while the reboot waits: %+v", r)
	}
	if n := len(rebootNotes(t, e, "reboot_waiting_inhibitor")); n != 1 {
		t.Fatalf("the wait is audited %d times", n)
	}
	e.clock.Advance(30 * time.Second)
	fireRetry(t, e)
	if rebootCalls(e) != 0 || len(retryTimers(e)) != 1 {
		t.Fatalf("calls %d, timers %d", rebootCalls(e), len(retryTimers(e)))
	}
	e.m.Mark("apt-done", true)
	e.clock.Advance(30 * time.Second)
	fireRetry(t, e)
	if rebootCalls(e) != 1 || len(retryTimers(e)) != 0 {
		t.Fatalf("calls %d, timers %d", rebootCalls(e), len(retryTimers(e)))
	}
}

// A scheduled reboot whose time comes with no lock goes ahead, then meets a lock taken just before systemctl
// reboot: it waits like a "now" reboot, with the gate up, and reboots once apt is done.
func TestContract_Reboot_AScheduledRebootThatGoesAheadThenMeetsTheRace(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	inhibitWhile(e, "apt")
	e.m.RuleText("systemctl", "reboot", "", 1, "!apt-done", "apt")
	at := e.clock.Now().Add(2 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})
	e.clock.Advance(2 * time.Hour)
	act := e.timers.active()
	if len(act) != 1 {
		t.Fatalf("timers %+v", act)
	}
	act[0].fire()
	if rebootCalls(e) != 1 || len(retryTimers(e)) != 1 {
		t.Fatalf("calls %d, retries %d", rebootCalls(e), len(retryTimers(e)))
	}
	if raw, _ := os.ReadFile(filepath.Join(e.m.State, "os", "reboot.json")); bytes.Contains(raw, []byte(`"schedule"`)) || !bytes.Contains(raw, []byte(`"kind":"scheduled"`)) {
		t.Fatalf("reboot.json %s", raw)
	}
	if r := e.o.WriteGate(); r == nil || r.Code != api.CodeRebooting {
		t.Fatalf("the gate is down while the started reboot waits: %+v", r)
	}
	w := rebootNotes(t, e, "reboot_waiting_inhibitor")
	if len(w) != 1 || !strings.Contains(string(w[0].ArgsRedacted), `"kind":"scheduled"`) {
		t.Fatalf("waits %+v", w)
	}
	e.m.Mark("apt-done", true)
	e.m.Mark("apt", false)
	e.clock.Advance(30 * time.Second)
	fireRetry(t, e)
	if rebootCalls(e) != 2 || len(retryTimers(e)) != 0 || len(rebootNotes(t, e, "reboot_failed")) != 0 {
		t.Fatalf("calls %d, retries %d", rebootCalls(e), len(retryTimers(e)))
	}
}

// A host restart while the reboot waits for a lock (same boot, not issued) is reported as reboot_failed
// host_restarted and not re-armed: no gate, no retry, and no reboot_completed after a later boot.
func TestContract_Reboot_AHostRestartDuringTheWaitIsReportedNotRearmed(t *testing.T) {
	t.Parallel()
	e := startRace(t)
	e.clock.Advance(2 * time.Minute) // well inside the gate's 10 minutes
	e.o.Close()
	timers2 := &fakeTimers{}
	o2 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = timers2.after })
	h2 := servertest.Start(t, o2.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, o2.Readers(), e.clock.Now
	})
	o2.Start(context.Background(), h2.Server)
	defer o2.Close()
	if r := o2.WriteGate(); r != nil {
		t.Fatalf("the restarted host keeps the gate of a reboot that will not come: %+v", r)
	}
	if len(timers2.active()) != 0 {
		t.Fatalf("the wait was re-armed: %+v", timers2.active())
	}
	var failed []api.AuditRecord
	for _, a := range audit(t, h2) {
		if a.Command == "os.reboot" && a.Code != nil && *a.Code == "reboot_failed" && a.Actor == "system" {
			failed = append(failed, a)
		}
	}
	if len(failed) != 1 || !strings.Contains(string(failed[0].ArgsRedacted), `"reason":"host_restarted"`) || !strings.Contains(string(failed[0].ArgsRedacted), `"issued":false`) {
		t.Fatalf("reboot_failed %+v", failed)
	}
	if raw, _ := os.ReadFile(filepath.Join(e.m.State, "os", "reboot.json")); bytes.Contains(raw, []byte(`"pending"`)) {
		t.Fatalf("the pending reboot is kept: %s", raw)
	}
	// A later boot claims nothing.
	e.m.SetBootID("99999999-8888-4777-8666-555555555555")
	o3 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = (&fakeTimers{}).after })
	h3 := servertest.Start(t, o3.Commands(), func(o *server.Options) {
		o.StateDir, o.AuditPath, o.Readers, o.Now = e.m.State, e.h.AuditPath, o3.Readers(), e.clock.Now
	})
	o3.Start(context.Background(), h3.Server)
	defer o3.Close()
	for _, a := range audit(t, h3) {
		if a.Code != nil && *a.Code == "reboot_completed" {
			t.Fatal("reboot_completed for a reboot the host never issued")
		}
	}
}

// An issued reboot keeps its gate across a host restart in the shutdown window (INV-15), and is marked issued.
func TestContract_Reboot_AnIssuedRebootIsRecordedAsIssued(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "issued", func() bool {
		raw, _ := os.ReadFile(filepath.Join(e.m.State, "os", "reboot.json"))
		return bytes.Contains(raw, []byte(`"issued":true`))
	})
}

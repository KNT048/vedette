package host_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
)

// container.start (the current image), container.stop and GET /v1/state/containers (WP-07b part 3, slice
// 3-6; spec 6.8, 6.9, D-105, D-123; host CONTRACT INV-17). The machine is the fake of opstest with a
// stateful systemctl and podman: restart copies the unit file as the container's own record, and the
// fake podman reports that record's digest. The tests assert the argv of every step, the unit text,
// the journal and the effect.

var (
	digA = opstest.Digest('a')
	digB = opstest.Digest('b')
)

type sleepLog struct {
	mu    sync.Mutex
	total time.Duration
	n     int
}

func (s *sleepLog) sleep(ctx context.Context, d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total += d
	s.n++
	return ctx.Err() == nil
}

func (s *sleepLog) get() (time.Duration, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total, s.n
}

type ctrEnv struct {
	*sysEnv
	sleeps *sleepLog
}

func startCtr(t *testing.T, muts ...mut) *ctrEnv {
	t.Helper()
	sl := &sleepLog{}
	e := startSys(t, append([]mut{func(_ *ops.Config, d *ops.Deps) { d.Sleep = sl.sleep }}, muts...)...)
	e.m.StatefulContainers()
	e.m.MakeUnitsDir()
	return &ctrEnv{sysEnv: e, sleeps: sl}
}

// ctl lists the systemctl calls that are not is-active looks, as "verb unit".
func (e *ctrEnv) ctl() []string {
	var out []string
	for _, c := range e.m.Calls("systemctl") {
		if c[0] == "is-active" {
			continue
		}
		out = append(out, strings.TrimSpace(strings.Join(c, " ")))
	}
	return out
}

func (e *ctrEnv) start(t *testing.T, svc string, restart bool) api.Run {
	t.Helper()
	r, err := e.call(t, api.CmdContainerStart, api.ContainerStartArgs{Service: svc, Restart: restart})
	if err != nil {
		t.Fatalf("start %s: %v", svc, err)
	}
	return r
}

func (e *ctrEnv) stop(t *testing.T, svc string, persist bool) api.Run {
	t.Helper()
	r, err := e.call(t, api.CmdContainerStop, api.ContainerStopArgs{Service: svc, Persist: persist})
	if err != nil {
		t.Fatalf("stop %s: %v", svc, err)
	}
	return r
}

func (e *ctrEnv) unit(t *testing.T, svc string) string {
	t.Helper()
	u, err := e.m.Unit(svc)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *ctrEnv) render(t *testing.T, svc, digest string, install bool) string {
	t.Helper()
	cfg := e.m.Config()
	b, err := ops.RenderUnitIn(svc, digest, install, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (e *ctrEnv) state(t *testing.T) map[string]api.ContainerState {
	t.Helper()
	st, err := e.h.Client.StateContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]api.ContainerState{}
	for _, s := range st.Services {
		m[s.Service] = s
	}
	return m
}

// --- container.start ------------------------------------------------------------------------------

func TestContract_Container_StartWritesTheUnitReloadsRestartsAndWaitsForHealth(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false) // stopped with persist: no [Install]
	old := e.unit(t, api.ServiceHoneypot)
	r := e.start(t, api.ServiceHoneypot, false)
	if r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	res := result[api.ContainerStartResult](t, r)
	if res.Service != api.ServiceHoneypot || res.Digest != digA || !res.Healthy || !res.Restarted || res.Version != nil {
		t.Fatalf("%+v", res)
	}
	if got := e.unit(t, api.ServiceHoneypot); got != e.render(t, api.ServiceHoneypot, digA, true) || !strings.HasSuffix(got, "\n[Install]\nWantedBy=multi-user.target\n") {
		t.Fatalf("the unit after the start:\n%s", got)
	}
	if prev, err := e.m.Prev(api.ServiceHoneypot); err != nil || prev != old {
		t.Fatalf("the previous bytes were not kept: %v", err)
	}
	if got, want := e.ctl(), []string{"daemon-reload", "restart vedette-honeypot.service"}; !slices.Equal(got, want) {
		t.Fatalf("systemctl calls %v, want %v", got, want)
	}
	if got := e.m.Calls("podman"); len(got) == 0 || !slices.Equal(got[0], []string{"container", "inspect", "vedette-honeypot"}) {
		t.Fatalf("podman calls %v", got)
	}
	if _, err := os.Stat(e.m.TransitionPath(api.ServiceHoneypot)); err == nil {
		t.Error("the journal was left behind")
	}
	// The journal existed while systemd was reloaded and restarted.
	if j := e.m.CallsWithJournal(); !slices.Equal(j, []string{"daemon-reload", "restart vedette-honeypot.service"}) {
		t.Errorf("calls made while the journal existed: %v", j)
	}
	if !e.m.IsRunning(api.ServiceHoneypot) {
		t.Error("the service is not running")
	}
}

func TestContract_Container_StartWorksForEveryServiceWithATemplate(t *testing.T) {
	t.Parallel()
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		e := startCtr(t)
		e.m.InstallUnit(svc, digB, true)
		r := e.start(t, svc, false)
		if r.Status != api.StatusSucceeded || result[api.ContainerStartResult](t, r).Digest != digB {
			t.Errorf("%s: %+v %+v", svc, r, r.Error)
		}
		if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload", "restart vedette-" + svc + ".service"}) {
			t.Errorf("%s: %v", svc, got)
		}
	}
}

func TestContract_Container_StartIsIdempotentAndRestartForcesIt(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.start(t, api.ServiceSensor, false)
	before := e.ctl()
	r := e.start(t, api.ServiceSensor, false)
	if res := result[api.ContainerStartResult](t, r); r.Status != api.StatusSucceeded || res.Restarted || !res.Healthy {
		t.Fatalf("%+v %+v", r, res)
	}
	if got := e.ctl(); !slices.Equal(got, before) {
		t.Fatalf("a start of a healthy service called systemctl: %v", got[len(before):])
	}
	r = e.start(t, api.ServiceSensor, true)
	if res := result[api.ContainerStartResult](t, r); r.Status != api.StatusSucceeded || !res.Restarted {
		t.Fatalf("%+v %+v", r, res)
	}
	if got := e.ctl()[len(before):]; !slices.Equal(got, []string{"daemon-reload", "restart vedette-sensor.service"}) {
		t.Fatalf("restart: %v", got)
	}
}

// A service stopped with persist and then found running again (someone started it by hand) gets its
// [Install] back and a reload, and the running container is left alone.
func TestContract_Container_StartPutsInstallBackWithoutRestartingAHealthyService(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	e.m.SetRunning(api.ServiceHoneypot, true)
	r := e.start(t, api.ServiceHoneypot, false)
	if res := result[api.ContainerStartResult](t, r); r.Status != api.StatusSucceeded || res.Restarted {
		t.Fatalf("%+v %+v", r, res)
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("%v", got)
	}
	if e.unit(t, api.ServiceHoneypot) != e.render(t, api.ServiceHoneypot, digA, true) {
		t.Fatal("the unit has no [Install]")
	}
}

func TestContract_Container_AnUnhealthyStartPutsTheOldUnitBack(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	old := e.unit(t, api.ServiceHoneypot)
	e.m.BadImage(digA)
	r := e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot}, api.StatusReverted, api.CodeUnitFailed)
	if res := result[api.ContainerStartResult](t, r); res.Healthy || res.Digest != digA {
		t.Fatalf("%+v", res)
	}
	if got := e.unit(t, api.ServiceHoneypot); got != old {
		t.Fatalf("the old unit was not put back:\n%s", got)
	}
	// The honeypot was stopped before: the revert stops it again instead of restarting it (M1).
	if got, want := e.ctl(), []string{"daemon-reload", "restart vedette-honeypot.service", "daemon-reload", "stop vedette-honeypot.service"}; !slices.Equal(got, want) {
		t.Fatalf("systemctl calls %v, want %v", got, want)
	}
	if _, err := os.Stat(e.m.TransitionPath(api.ServiceHoneypot)); err == nil {
		t.Error("the journal was left behind after the unit was put back")
	}
	if prev, _ := e.m.Prev(api.ServiceHoneypot); prev != old {
		t.Error("putting the old unit back must not replace .prev")
	}
}

// The health wait is 120 s counted in 2 s looks (61 looks of the container, 60 waits), on an injected clock.
func TestContract_Container_TheHealthWaitIs120SecondsOfLooks(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]func(*ctrEnv){
		"never healthy": func(e *ctrEnv) { e.m.SetHealth(api.ServiceCore, "starting") },
		"unhealthy":     func(e *ctrEnv) { e.m.SetHealth(api.ServiceCore, "unhealthy") },
		"another image": func(e *ctrEnv) {
			e.m.InspectRaw(api.ServiceCore, `[{"Name":"vedette-core","ImageDigest":"`+digB+`","State":{"Running":true,"Health":{"Status":"healthy"}}}]`)
		},
		"not running": func(e *ctrEnv) {
			e.m.InspectRaw(api.ServiceCore, `[{"Name":"vedette-core","ImageDigest":"`+digA+`","State":{"Running":false,"Health":{"Status":"healthy"}}}]`)
		},
	} {
		e := startCtr(t)
		e.m.InstallUnit(api.ServiceCore, digA, true)
		setup(e)
		e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceCore}, api.StatusReverted, api.CodeUnitFailed)
		total, n := e.sleeps.get()
		if total != 120*time.Second || n != 60 {
			t.Errorf("%s: waited %v in %d sleeps", name, total, n)
		}
		if got := len(e.m.Calls("podman")); got != 61 {
			t.Errorf("%s: %d looks at the container, want 61", name, got)
		}
	}
}

func TestContract_Container_StartSucceedsOnceTheContainerGetsHealthy(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.m.SetHealthSequence(api.ServiceSensor, "starting", "starting", "starting", "healthy")
	if r := e.start(t, api.ServiceSensor, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if total, n := e.sleeps.get(); n != 3 || total != 6*time.Second {
		t.Fatalf("waited %v in %d sleeps", total, n)
	}
}

func TestContract_Container_AFailedRestartPutsTheOldUnitBackAndAFailedPutBackLeavesTheJournal(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	old := e.unit(t, api.ServiceHoneypot)
	e.m.Mark("reload-fails", true)
	// systemd would not reload the new unit, nor the old one: the run fails, it does not claim a revert.
	r := e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot}, api.StatusFailed, api.CodeUnitFailed)
	if got := e.unit(t, api.ServiceHoneypot); got != old {
		t.Fatalf("the old unit text must be back even when the restart fails:\n%s", got)
	}
	if res := result[api.ContainerStartResult](t, r); res.Healthy {
		t.Fatalf("%+v", res)
	}
	b, err := os.ReadFile(e.m.TransitionPath(api.ServiceHoneypot))
	if err != nil {
		t.Fatalf("the journal must stay for the next start: %v", err)
	}
	if !strings.Contains(string(b), `"service":"honeypot"`) || !strings.Contains(string(b), `"op":"start"`) || !strings.Contains(string(b), `"phase":"pending"`) || !strings.Contains(string(b), `"was_active":false`) {
		t.Fatalf("%s", b)
	}
	if total, _ := e.sleeps.get(); total != 0 {
		t.Errorf("a restart that failed outright was waited for: %v", total)
	}
}

func TestContract_Container_NoJournalNoChange(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	old := e.unit(t, api.ServiceHoneypot)
	if err := os.Chmod(filepath.Join(e.m.State, "containers"), 0o500); err != nil { //nolint:gosec // test: make the journal unwritable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(e.m.State, "containers"), 0o700) }) //nolint:gosec // test cleanup
	e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot}, api.StatusFailed, api.CodeUnitUnwritable)
	if e.unit(t, api.ServiceHoneypot) != old || len(e.ctl()) != 0 {
		t.Fatal("the unit changed without a journal")
	}
}

func TestContract_Container_StartRefusals(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	start := func(a api.ContainerStartArgs, status int, code string) {
		t.Helper()
		e.refused(t, api.CmdContainerStart, a, status, code)
	}
	start(api.ContainerStartArgs{Service: "honeypot", Version: "1.2.3"}, 412, api.CodeNotPulled) // no pulled record of that version
	start(api.ContainerStartArgs{Service: "sensor"}, 412, api.CodeNotPulled)                     // no unit installed yet
	start(api.ContainerStartArgs{Service: "greenbone"}, 412, api.CodeUnitUnknown)
	start(api.ContainerStartArgs{Service: "nope"}, 400, api.CodeInvalidArgs)
	start(api.ContainerStartArgs{Service: "honeypot", Version: "latest"}, 400, api.CodeInvalidArgs)
	start(api.ContainerStartArgs{Service: "honeypot", Version: "1.2.3; id"}, 400, api.CodeInvalidArgs)
	start(api.ContainerStartArgs{Service: "honeypot", Snapshot: strings.Repeat("a", 32)}, 400, api.CodeInvalidArgs) // only core takes a snapshot
	start(api.ContainerStartArgs{Service: "core", Snapshot: "xyz"}, 400, api.CodeInvalidArgs)
	start(api.ContainerStartArgs{Service: "core", Version: "1.2.3"}, 400, api.CodeInvalidArgs) // core needs a snapshot with a version
	if len(e.ctl()) != 0 {
		t.Fatalf("a refused start called systemctl: %v", e.ctl())
	}
	// Refused runs still leave a run and an audit line.
	if a := audit(t, e.h); len(a) == 0 {
		t.Error("no audit")
	}
}

func TestContract_Container_AUnitTheHostDidNotWriteIsNotTouched(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	for name, setup := range map[string]func(){
		"foreign text": func() {
			e.m.WriteRoot("etc/containers/systemd/vedette-honeypot.container", "[Container]\nImage=docker.io/evil/x:latest\n")
		},
		"symlink": func() {
			victim := filepath.Join(e.m.Root, "victim")
			_ = os.WriteFile(victim, []byte("x"), 0o600)
			_ = os.Remove(filepath.Join(e.m.UnitsDir(), "vedette-honeypot.container"))
			if err := os.Symlink(victim, filepath.Join(e.m.UnitsDir(), "vedette-honeypot.container")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		_ = os.Remove(filepath.Join(e.m.UnitsDir(), "vedette-honeypot.container"))
		setup()
		e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeUnitUnsafe)
		e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "honeypot", Persist: true}, 412, api.CodeUnitUnsafe)
		_ = name
	}
}

func TestContract_Container_AnUnsafeQuadletDirectoryIsRefusedBeforeAnythingRuns(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	// A group-writable parent, then a link in place of the directory.
	if err := os.Chmod(filepath.Join(e.m.Root, "etc/containers"), 0o775); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeUnitUnsafe)
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "honeypot", Persist: true}, 412, api.CodeUnitUnsafe)
	// persist=false writes no unit, so it does not need the directory to be safe.
	e.m.SetRunning(api.ServiceHoneypot, true)
	if r := e.stop(t, "honeypot", false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if err := os.Chmod(filepath.Join(e.m.Root, "etc/containers"), 0o755); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	moved := filepath.Join(e.m.Root, "moved")
	if err := os.Rename(e.m.UnitsDir(), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, e.m.UnitsDir()); err != nil {
		t.Fatal(err)
	}
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeUnitUnsafe)
	if got := e.ctl(); !slices.Equal(got, []string{"stop vedette-honeypot.service"}) {
		t.Fatalf("systemctl calls %v", got)
	}
}

// L2: "ours" means identical bytes. A unit with one extra line, other ids, or an older template is read
// by nothing: the commands refuse it and the state does not call it installed.
func TestContract_Container_AUnitThatDiffersByOneByteIsNotOurs(t *testing.T) {
	t.Parallel()
	good := func(e *ctrEnv) string { return e.render(t, api.ServiceHoneypot, digA, true) }
	for name, mutate := range map[string]func(string) string{
		"extra line":     func(u string) string { return strings.Replace(u, "[Service]", "Environment=X=1\n[Service]", 1) },
		"extra mount":    func(u string) string { return strings.Replace(u, "ReadOnly=true", "ReadOnly=true\nVolume=/:/host", 1) },
		"trailing space": func(u string) string { return strings.Replace(u, "UserNS=auto", "UserNS=auto ", 1) },
		"other limits":   func(u string) string { return strings.Replace(u, "--cpus=0.5", "--cpus=64", 1) },
		"no newline":     func(u string) string { return strings.TrimSuffix(u, "\n") },
	} {
		e := startCtr(t)
		e.m.WriteRoot("etc/containers/systemd/vedette-honeypot.container", mutate(good(e)))
		e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeUnitUnsafe)
		e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "honeypot", Persist: true}, 412, api.CodeUnitUnsafe)
		if st := e.state(t)[api.ServiceHoneypot]; st.Installed {
			t.Errorf("%s: reported as installed", name)
		}
		if len(e.ctl()) != 0 {
			t.Errorf("%s: %v", name, e.ctl())
		}
	}
}

func TestContract_Container_HostConfWithoutTheSensorIdsRefusesTheUnitsThatNeedThem(t *testing.T) {
	t.Parallel()
	e := startCtr(t, func(c *ops.Config, _ *ops.Deps) { c.SensorUID, c.SensorGID = 0, 0 })
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceScan} {
		e.m.InstallUnit(svc, digA, true) // InstallUnit uses the machine's ids, not the ops config
		e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: svc}, 412, api.CodeHostConfIncomplete)
	}
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	if r := e.start(t, api.ServiceHoneypot, false); r.Status != api.StatusSucceeded {
		t.Fatalf("the honeypot needs no ids: %+v %+v", r, r.Error)
	}
}

func TestContract_Container_NotAnApplianceRefusesBoth(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.m.OSRelease("arch", "1", "Arch")
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeNotAppliance)
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "honeypot"}, 412, api.CodeNotAppliance)
}

// --- container.stop -------------------------------------------------------------------------------

func TestContract_Container_StopWithoutPersistKeepsInstallAndChecksIsActive(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.start(t, api.ServiceHoneypot, false)
	n := len(e.ctl())
	unit := e.unit(t, api.ServiceHoneypot)
	r := e.stop(t, api.ServiceHoneypot, false)
	if res := result[api.ContainerStopResult](t, r); r.Status != api.StatusSucceeded || !res.Changed || res.Persist {
		t.Fatalf("%+v %+v", r, res)
	}
	if got := e.ctl()[n:]; !slices.Equal(got, []string{"stop vedette-honeypot.service"}) {
		t.Fatalf("%v", got)
	}
	if e.unit(t, api.ServiceHoneypot) != unit || e.m.IsRunning(api.ServiceHoneypot) {
		t.Fatal("the unit changed or the service still runs")
	}
	last := e.m.Calls("systemctl")
	if c := last[len(last)-1]; c[0] != "is-active" || c[1] != "vedette-honeypot.service" {
		t.Fatalf("the last call was %v: the effect was not checked", c)
	}
}

func TestContract_Container_StopWithPersistDropsInstallBeforeStopping(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.start(t, api.ServiceHoneypot, false)
	n := len(e.ctl())
	with := e.unit(t, api.ServiceHoneypot)
	r := e.stop(t, api.ServiceHoneypot, true)
	if res := result[api.ContainerStopResult](t, r); r.Status != api.StatusSucceeded || !res.Changed || !res.Persist {
		t.Fatalf("%+v %+v", r, res)
	}
	if got, want := e.ctl()[n:], []string{"daemon-reload", "stop vedette-honeypot.service"}; !slices.Equal(got, want) {
		t.Fatalf("daemon-reload must come before the stop: %v", got)
	}
	got := e.unit(t, api.ServiceHoneypot)
	if got != e.render(t, api.ServiceHoneypot, digA, false) || strings.Contains(got, "[Install]") {
		t.Fatalf("the unit still has [Install]:\n%s", got)
	}
	if prev, _ := e.m.Prev(api.ServiceHoneypot); prev != with {
		t.Error(".prev does not hold the unit with [Install]")
	}
	if _, err := os.Stat(e.m.TransitionPath(api.ServiceHoneypot)); err == nil {
		t.Error("the journal was left behind")
	}
	if st := e.state(t)[api.ServiceHoneypot]; st.Enabled || st.UnitState != api.UnitInactive || !st.Installed {
		t.Fatalf("%+v", st)
	}
	// container.start builds the unit with [Install] again.
	if r := e.start(t, api.ServiceHoneypot, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if e.unit(t, api.ServiceHoneypot) != with || !e.state(t)[api.ServiceHoneypot].Enabled {
		t.Fatal("start did not put [Install] back")
	}
}

func TestContract_Container_StopIsIdempotent(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.start(t, api.ServiceSensor, false)
	e.stop(t, api.ServiceSensor, true)
	n := len(e.ctl())
	unit := e.unit(t, api.ServiceSensor)
	for _, persist := range []bool{true, false} {
		r := e.stop(t, api.ServiceSensor, persist)
		if res := result[api.ContainerStopResult](t, r); r.Status != api.StatusSucceeded || res.Changed {
			t.Fatalf("persist=%t: %+v %+v", persist, r, res)
		}
	}
	if got := e.ctl()[n:]; len(got) != 0 {
		t.Fatalf("a stop of a stopped service changed things: %v", got)
	}
	if e.unit(t, api.ServiceSensor) != unit {
		t.Fatal("the unit changed")
	}
	// A stopped service that still has [Install] and is stopped with persist: the unit is rewritten, nothing is stopped.
	e.m.InstallUnit(api.ServiceScan, digA, true)
	if r := e.stop(t, api.ServiceScan, true); r.Status != api.StatusSucceeded || !result[api.ContainerStopResult](t, r).Changed {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(e.unit(t, api.ServiceScan), "[Install]") {
		t.Fatal("[Install] stayed")
	}
	// A service with no unit at all: nothing to rewrite, and it is not running.
	if r := e.stop(t, api.ServiceHoneypot, true); r.Status != api.StatusSucceeded || result[api.ContainerStopResult](t, r).Changed {
		t.Fatalf("%+v", r)
	}
}

func TestContract_Container_CannotStopCore(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceCore, digA, true)
	e.start(t, api.ServiceCore, false)
	n := len(e.ctl())
	for _, persist := range []bool{false, true} {
		e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "core", Persist: persist}, 412, api.CodeCannotStopCore)
	}
	if len(e.ctl()) != n || !e.m.IsRunning(api.ServiceCore) {
		t.Fatal("core was touched")
	}
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "greenbone"}, 412, api.CodeUnitUnknown)
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "nope"}, 400, api.CodeInvalidArgs)
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: ""}, 400, api.CodeInvalidArgs)
}

// The effect of a stop is what is-active prints, not its exit code.
func TestContract_Container_StopIsJudgedByTheOutputOfIsActive(t *testing.T) {
	t.Parallel()
	// Prints "active" although it exits non-zero, and the service really stopped: not verified.
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.start(t, api.ServiceSensor, false)
	e.m.RuleText("systemctl", "is-active vedette-sensor.service", "active\n", 3, "", "")
	r := e.final(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "sensor"}, api.StatusFailed, api.CodeStopNotVerified)
	if res := result[api.ContainerStopResult](t, r); !res.Changed {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(string(r.Result), `"service":"sensor"`) {
		t.Fatalf("%s", r.Result)
	}

	// Garbage output, whatever the exit code, is not "inactive" either.
	for _, out := range []string{"", "deactivating\n", "inactiv\n", "inactive-ish\n", "\x00inactive", "unknown\n"} {
		e := startCtr(t)
		e.m.InstallUnit(api.ServiceSensor, digA, true)
		e.start(t, api.ServiceSensor, false)
		e.m.RuleText("systemctl", "is-active vedette-sensor.service", out, 0, "", "")
		e.final(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "sensor"}, api.StatusFailed, api.CodeStopNotVerified)
	}

	// Prints "inactive" although it exits 0: that is inactive. Nothing is stopped, the run is idempotent.
	e = startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.m.RuleText("systemctl", "is-active vedette-sensor.service", "inactive\n", 0, "", "")
	if r := e.stop(t, "sensor", false); r.Status != api.StatusSucceeded || result[api.ContainerStopResult](t, r).Changed {
		t.Fatalf("%+v", r)
	}
	if got := e.ctl(); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// --- GET /v1/state/containers ---------------------------------------------------------------------

func TestContract_Container_StateReportsEveryServiceFromTheUnitAndTheTools(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceCore, digA, true)
	e.m.InstallUnit(api.ServiceSensor, digB, false)
	e.m.InstallUnit(api.ServiceScan, digB, true)
	e.start(t, api.ServiceCore, false)
	e.m.SetRunning(api.ServiceScan, true)
	e.m.SetHealth(api.ServiceScan, "starting")
	st := e.state(t)
	if len(st) != 5 {
		t.Fatalf("%v", st)
	}
	core := st[api.ServiceCore]
	if !core.Installed || !core.Enabled || core.UnitState != api.UnitActive || core.Health != api.HealthHealthy ||
		core.Digest == nil || *core.Digest != digA || core.ConfiguredDigest == nil || *core.ConfiguredDigest != digA || core.Version != nil || core.Previous != nil || core.LatestPulled != nil {
		t.Fatalf("%+v", core)
	}
	if s := st[api.ServiceSensor]; !s.Installed || s.Enabled || s.UnitState != api.UnitInactive || s.Health != api.HealthNone || s.Digest != nil || *s.ConfiguredDigest != digB {
		t.Fatalf("%+v", s)
	}
	if s := st[api.ServiceScan]; s.UnitState != api.UnitActive || s.Health != api.HealthStarting {
		t.Fatalf("%+v", s)
	}
	for _, name := range []string{api.ServiceHoneypot, api.ServiceGreenbone} {
		if s := st[name]; s.Installed || s.Enabled || s.Digest != nil || s.ConfiguredDigest != nil || s.UnitState != api.UnitInactive || s.Health != api.HealthNone {
			t.Fatalf("%s: %+v", name, s)
		}
	}
	// The raw body has every field, nulls included, in a fixed order of services.
	code, body := rawGet(t, e.h, "/v1/state/containers")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var m struct {
		Services []map[string]any `json:"services"`
	}
	if err := json.Unmarshal(body, &m); err != nil || len(m.Services) != 5 {
		t.Fatalf("%v %s", err, body)
	}
	for i, svc := range api.Services {
		s := m.Services[i]
		if s["service"] != svc {
			t.Errorf("service %d is %v", i, s["service"])
		}
		for _, k := range []string{"installed", "version", "digest", "configured_digest", "previous", "latest_pulled", "enabled", "unit_state", "health"} {
			if _, ok := s[k]; !ok {
				t.Errorf("%s has no %q", svc, k)
			}
		}
	}
	if code, _ := rawGet(t, e.h, "/v1/state/containers?x=1"); code != 400 {
		t.Errorf("a query string answered %d", code)
	}
}

// What podman and systemctl print is data of the container, not trusted: anything that is not the
// strict shape reads as "unknown", a container is never reported healthy on hostile output, and the
// host does not fall over on a huge one.
func TestContract_Container_StateParsesHostileOutputStrictlyAndBounded(t *testing.T) {
	t.Parallel()
	good := `{"Name":"vedette-core","ImageDigest":"` + digA + `","State":{"Running":true,"Health":{"Status":"healthy"}}}`
	for name, raw := range map[string]string{
		"not json":       "<html>healthy</html>",
		"empty":          "",
		"two containers": "[" + good + "," + good + "]",
		"another one":    strings.Replace("["+good+"]", "vedette-core", "vedette-sensor", 1),
		"bad digest":     strings.Replace("["+good+"]", digA, "sha256:ZZ", 1),
		"no digest":      `[{"Name":"vedette-core","State":{"Running":true,"Health":{"Status":"healthy"}}}]`,
		"trailing":       "[" + good + "]\n{}",
		"wrong types":    `[{"Name":["vedette-core"],"ImageDigest":7,"State":"healthy"}]`,
		"nested":         strings.Repeat("[", 200000),
		"oversize":       "[" + good + "]" + strings.Repeat(" ", 3<<20),
	} {
		e := startCtr(t)
		e.m.InstallUnit(api.ServiceCore, digA, true)
		e.m.SetRunning(api.ServiceCore, true)
		e.m.InspectRaw(api.ServiceCore, raw)
		st := e.state(t)[api.ServiceCore]
		if st.Digest != nil || st.Health != api.HealthUnknown || st.UnitState != api.UnitActive {
			t.Errorf("%s: %+v", name, st)
		}
	}
	// A health word Podman does not use is "unknown", not "healthy".
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceCore, digA, true)
	e.m.SetRunning(api.ServiceCore, true)
	e.m.InspectRaw(api.ServiceCore, "["+strings.Replace(good, `"healthy"`, `"healthy; rm -rf /"`, 1)+"]")
	if st := e.state(t)[api.ServiceCore]; st.Health != api.HealthUnknown || st.Digest == nil {
		t.Fatalf("%+v", st)
	}
	// is-active output that is not a known word is "unknown".
	e = startCtr(t)
	e.m.InstallUnit(api.ServiceCore, digA, true)
	e.m.RuleText("systemctl", "is-active vedette-core.service", "ACTIVE and well\n", 0, "", "")
	if st := e.state(t)[api.ServiceCore]; st.UnitState != api.UnitUnknown || st.Digest != nil {
		t.Fatalf("%+v", st)
	}
	// A unit file that is not ours reads as not installed; a link reads as not installed.
	e = startCtr(t)
	e.m.WriteRoot("etc/containers/systemd/vedette-sensor.container", strings.Repeat("Image=x\n", 5))
	victim := filepath.Join(e.m.Root, "v")
	_ = os.WriteFile(victim, []byte(e.render(t, api.ServiceHoneypot, digA, true)), 0o600)
	if err := os.Symlink(victim, filepath.Join(e.m.UnitsDir(), "vedette-honeypot.container")); err != nil {
		t.Fatal(err)
	}
	st := e.state(t)
	if st[api.ServiceSensor].Installed || st[api.ServiceHoneypot].Installed {
		t.Fatalf("%+v %+v", st[api.ServiceSensor], st[api.ServiceHoneypot])
	}
}

// --- the journal at Start and after READY (D-123 H1, M1, M3, L7) ---------------------------------------

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type seed struct {
	op, svc, phase string
	oldText        string // the unit text before the change (what .prev holds)
	newText        string // the unit text the change wrote (what is on disk now)
	keepPrev       bool
	wasActive      bool
}

// seedTransition leaves what a host that died in the middle of a change leaves: the unit text of the
// phase in place, .prev holding the old one, and the journal.
func (e *ctrEnv) seedTransition(t *testing.T, sd seed) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-"+sd.svc+".container"), []byte(sd.newText), 0o644); err != nil { //nolint:gosec // test: a unit file of the fake root
		t.Fatal(err)
	}
	if sd.keepPrev {
		if err := os.WriteFile(filepath.Join(e.m.State, "containers", "units", sd.svc+".prev"), []byte(sd.oldText), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tr, _ := json.Marshal(map[string]any{
		"service": sd.svc, "op": sd.op, "phase": sd.phase, "digest": digA, "prev_sha256": shaOf(sd.oldText), "new_sha256": shaOf(sd.newText),
		"was_active": sd.wasActive, "at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef",
	})
	if err := os.WriteFile(e.m.TransitionPath(sd.svc), tr, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *ctrEnv) startHost(t *testing.T) *noteRecorder {
	t.Helper()
	rec := &noteRecorder{}
	e.o.Start(context.Background(), rec)
	t.Cleanup(e.o.Close)
	return rec
}

func (e *ctrEnv) journalExists(svc string) bool {
	_, err := os.Lstat(e.m.TransitionPath(svc))
	return err == nil
}

func (e *ctrEnv) hpTexts(t *testing.T) (oldText, newText string) {
	t.Helper()
	return e.render(t, api.ServiceHoneypot, digA, false), e.render(t, api.ServiceHoneypot, digA, true)
}

// H1: before READY the host only puts bytes back and reloads. The fake fails a synchronous restart of a
// unit that is After=vedette-host.service while the host's own start job is pending (a real one would
// wait for it forever), so a restart at Start shows up as a deadlock.
func TestContract_Container_StartRecoveryOnlyPutsBytesBackBeforeReadyAndTheStateAfterIt(t *testing.T) {
	t.Parallel()
	for _, wasActive := range []bool{true, false} {
		e := startCtr(t)
		oldText, newText := e.hpTexts(t)
		e.m.InstallUnit(api.ServiceHoneypot, digA, true)
		e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, keepPrev: true, wasActive: wasActive})
		e.m.Mark("host-starting", true)
		rec := e.startHost(t)

		// Before READY: bytes back, daemon-reload, nothing else; no look at health.
		if got := e.unit(t, api.ServiceHoneypot); got != oldText {
			t.Fatalf("wasActive=%t: the old unit was not put back:\n%s", wasActive, got)
		}
		if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
			t.Fatalf("wasActive=%t: before READY the host called %v, want only daemon-reload", wasActive, got)
		}
		if d := e.m.Deadlocked(); len(d) != 0 {
			t.Fatalf("a synchronous restart of an After=vedette-host unit while the host starts: %v", d)
		}
		if n := len(e.m.Calls("podman")); n != 0 {
			t.Errorf("the host looked at a container before READY (%d calls)", n)
		}
		if total, _ := e.sleeps.get(); total != 0 {
			t.Errorf("the host waited before READY: %v", total)
		}
		b, err := os.ReadFile(e.m.TransitionPath(api.ServiceHoneypot))
		if err != nil || !strings.Contains(string(b), `"phase":"restored"`) {
			t.Fatalf("the journal must be 'restored' until the state is back: %s %v", b, err)
		}
		// Container commands for the service wait for it; other services do not.
		e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeTransitionPending)
		e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "honeypot"}, 412, api.CodeTransitionPending)
		if !strings.Contains(rec.text(), `"action":"bytes_restored"`) {
			t.Fatalf("notes: %s", rec.text())
		}

		// READY: the host is active, a restart no longer waits on its own start job.
		e.m.Mark("host-starting", false)
		e.o.AfterReady(context.Background(), e.h.Server)
		ctl := e.ctl()
		if wasActive {
			if !slices.Contains(ctl, "restart vedette-honeypot.service") || !e.m.IsRunning(api.ServiceHoneypot) {
				t.Fatalf("an active service must be restarted after READY: %v", ctl)
			}
		} else if slices.Contains(ctl, "restart vedette-honeypot.service") || e.m.IsRunning(api.ServiceHoneypot) {
			t.Fatalf("a service that was stopped must stay stopped: %v", ctl)
		}
		if e.journalExists(api.ServiceHoneypot) || e.unit(t, api.ServiceHoneypot) != oldText {
			t.Fatal("the journal stayed or the unit changed")
		}
		if txt := rec.text(); !strings.Contains(txt, `"action":"reverted"`) || !strings.Contains(txt, "container.start transition_interrupted") {
			t.Fatalf("notes: %s", txt)
		}
		// The service can be commanded again.
		if r := e.start(t, api.ServiceHoneypot, false); r.Status != api.StatusSucceeded {
			t.Fatalf("%+v %+v", r, r.Error)
		}
	}
}

// The same step at boot: a unit that systemd is starting after READY is judged healthy once it is, and left alone.
func TestContract_Container_AfterReadyLeavesAnAlreadyHealthyServiceAlone(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.hpTexts(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, keepPrev: true, wasActive: true})
	e.startHost(t)
	e.m.SetRunning(api.ServiceHoneypot, true) // systemd started it after READY, from the restored text
	n := len(e.ctl())
	e.o.AfterReady(context.Background(), e.h.Server)
	if got := e.ctl()[n:]; !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("a healthy service was restarted: %v", got)
	}
	if e.journalExists(api.ServiceHoneypot) {
		t.Fatal("the journal stayed")
	}
}

// AfterReady waits for the write lock like a run does.
func TestContract_Container_AfterReadyTakesTheWriteLockAndWaitsWhileItIsBusy(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.hpTexts(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, keepPrev: true, wasActive: true})
	e.startHost(t)
	l := &busyThenFree{real: e.h.Server, busy: 3}
	e.o.AfterReady(context.Background(), l)
	if l.calls != 4 || l.ran != 1 || e.journalExists(api.ServiceHoneypot) {
		t.Fatalf("calls %d ran %d journal %t", l.calls, l.ran, e.journalExists(api.ServiceHoneypot))
	}
	// And the real lock is exclusive: while a command holds it, AfterReady's lock answers busy, not a second writer.
	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = e.h.Server.WithWriteLock(context.Background(), func(context.Context) { close(started); <-release })
	}()
	<-started
	if err := e.h.Server.WithWriteLock(context.Background(), func(context.Context) { t.Error("two holders of the write lock") }); err == nil {
		t.Error("the write lock was taken twice")
	}
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "sensor"}, 409, "busy")
	close(release)
}

type busyThenFree struct {
	real  *server.Server
	busy  int
	calls int
	ran   int
}

func (b *busyThenFree) WithWriteLock(ctx context.Context, fn func(context.Context)) error {
	b.calls++
	if b.calls <= b.busy {
		return server.ErrWriteBusy
	}
	return b.real.WithWriteLock(ctx, func(c context.Context) { b.ran++; fn(c) })
}

// A journal the effect of which was seen (verified) is only deleted: the change is kept, nothing reverts.
func TestContract_Container_AVerifiedJournalIsOnlyDeletedAtStart(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.hpTexts(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "verified", oldText: oldText, newText: newText, keepPrev: true, wasActive: true})
	rec := e.startHost(t)
	if e.unit(t, api.ServiceHoneypot) != newText || len(e.ctl()) != 0 || e.journalExists(api.ServiceHoneypot) {
		t.Fatalf("verified journal: unit changed %t, calls %v, journal %t", e.unit(t, api.ServiceHoneypot) != newText, e.ctl(), e.journalExists(api.ServiceHoneypot))
	}
	if !strings.Contains(rec.text(), `"action":"completed"`) {
		t.Fatalf("notes: %s", rec.text())
	}
}

// The host died before it wrote the unit: the bytes are the old ones already, nothing to put back, and the
// state is restored after READY.
func TestContract_Container_ACrashBeforeTheUnitWasWrittenRestoresOnlyTheState(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.hpTexts(t)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, keepPrev: false, wasActive: false})
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-honeypot.container"), []byte(oldText), 0o644); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	e.startHost(t)
	if e.unit(t, api.ServiceHoneypot) != oldText {
		t.Fatal("the unit changed")
	}
	e.o.AfterReady(context.Background(), e.h.Server)
	if e.journalExists(api.ServiceHoneypot) || e.m.IsRunning(api.ServiceHoneypot) {
		t.Fatal("the journal stayed or a stopped service was started")
	}
}

// A journal left in phase restored by a host that died again before AfterReady is finished by the next one.
func TestContract_Container_ARestoredJournalSurvivesAnotherCrash(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.hpTexts(t)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "restored", oldText: oldText, newText: oldText, keepPrev: true, wasActive: true})
	_ = newText
	e.startHost(t)
	e.o.AfterReady(context.Background(), e.h.Server)
	if e.journalExists(api.ServiceHoneypot) || !e.m.IsRunning(api.ServiceHoneypot) {
		t.Fatal("the restore was not finished")
	}
}

func TestContract_Container_AHalfDoneStopGetsItsUnitTextBackAndItsStateAfterReady(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.render(t, api.ServiceSensor, digA, true), e.render(t, api.ServiceSensor, digA, false)
	e.m.InstallUnit(api.ServiceSensor, digA, false)
	e.m.SetRunning(api.ServiceSensor, true)
	e.seedTransition(t, seed{op: "stop", svc: "sensor", phase: "pending", oldText: oldText, newText: newText, keepPrev: true, wasActive: true})
	rec := e.startHost(t)
	if e.unit(t, api.ServiceSensor) != oldText {
		t.Fatal("the unit text before the stop was not put back")
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) || !e.m.IsRunning(api.ServiceSensor) {
		t.Fatalf("systemctl calls %v", got)
	}
	e.o.AfterReady(context.Background(), e.h.Server)
	if e.journalExists(api.ServiceSensor) || !e.m.IsRunning(api.ServiceSensor) {
		t.Fatal("the service was not left running, or the journal stayed")
	}
	// The audit labels of an interrupted stop say container.stop.
	if txt := rec.text(); !strings.Contains(txt, "container.stop transition_interrupted") || strings.Contains(txt, "container.start transition_interrupted") {
		t.Fatalf("notes: %s", txt)
	}
}

func TestContract_Container_ARecoveryThatCannotPutBackKeepsTheJournalAndBlocksTheService(t *testing.T) {
	t.Parallel()
	for name, prepare := range map[string]func(*ctrEnv, string){
		"no prev": func(*ctrEnv, string) {},
		"stale prev": func(e *ctrEnv, _ string) {
			_ = os.WriteFile(filepath.Join(e.m.State, "containers", "units", "honeypot.prev"), []byte("something else"), 0o600)
		},
		"unit replaced": func(e *ctrEnv, _ string) {
			_ = os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-honeypot.container"), []byte("foreign"), 0o644) //nolint:gosec // test: a unit file of the fake root
		},
	} {
		e := startCtr(t)
		oldText, newText := e.hpTexts(t)
		e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, wasActive: true})
		prepare(e, oldText)
		rec := e.startHost(t)
		if !e.journalExists(api.ServiceHoneypot) {
			t.Errorf("%s: the journal was removed", name)
		}
		if !strings.Contains(rec.text(), "transition_recovery_failed") {
			t.Errorf("%s: notes: %s", name, rec.text())
		}
		if len(e.ctl()) != 0 {
			t.Errorf("%s: %v", name, e.ctl())
		}
		e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeTransitionPending)
		e.o.AfterReady(context.Background(), e.h.Server) // nothing pending: it must do nothing
		if len(e.ctl()) != 0 {
			t.Errorf("%s: AfterReady acted on a journal that was not restored: %v", name, e.ctl())
		}
	}
}

func TestContract_Container_AnInvalidJournalIsMovedAsideAtStartKeepingTheLastThree(t *testing.T) {
	t.Parallel()
	good := map[string]any{
		"service": "honeypot", "op": "start", "phase": "pending", "digest": digA, "prev_sha256": shaOf("a"), "new_sha256": shaOf("b"),
		"was_active": true, "at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef",
	}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	for name, content := range map[string][]byte{
		"not json":        []byte("start honeypot"),
		"unknown field":   mustJSONBytes(with("path", "/etc/passwd")),
		"another service": mustJSONBytes(with("service", "sensor")),
		"unknown service": mustJSONBytes(with("service", "sshd")),
		"unknown op":      mustJSONBytes(with("op", "delete")),
		"unknown phase":   mustJSONBytes(with("phase", "done")),
		"bad digest":      mustJSONBytes(with("digest", "latest")),
		"bad sha":         mustJSONBytes(with("new_sha256", "zz")),
		"bad run id":      mustJSONBytes(with("run_id", "../../x")),
		"trailing":        append(mustJSONBytes(good), []byte(" {}")...),
		"huge":            append(mustJSONBytes(good), []byte(strings.Repeat(" ", 5000))...),
	} {
		e := startCtr(t)
		e.m.InstallUnit(api.ServiceHoneypot, digA, true)
		dir := filepath.Join(e.m.State, "containers")
		for i := 1; i <= 4; i++ { // four earlier quarantined journals
			_ = os.WriteFile(filepath.Join(dir, "transition-honeypot.json.invalid-"+strings.Repeat("0", 18)+string(rune('0'+i))), []byte("x"), 0o600)
		}
		if err := os.WriteFile(e.m.TransitionPath(api.ServiceHoneypot), content, 0o600); err != nil {
			t.Fatal(err)
		}
		rec := e.startHost(t)
		if e.journalExists(api.ServiceHoneypot) {
			t.Errorf("%s: the journal stayed", name)
		}
		left, _ := filepath.Glob(filepath.Join(dir, "transition-honeypot.json.invalid-*"))
		if len(left) != 3 {
			t.Errorf("%s: %d quarantined files kept: %v", name, len(left), left)
		}
		if len(e.ctl()) != 0 || !strings.Contains(rec.text(), "transition_invalid") {
			t.Errorf("%s: %v %s", name, e.ctl(), rec.text())
		}
		// It no longer blocks the service.
		if r := e.start(t, api.ServiceHoneypot, false); r.Status != api.StatusSucceeded {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// A link in place of the journal is moved aside, never followed.
	e := startCtr(t)
	victim := filepath.Join(e.m.Root, "elsewhere")
	_ = os.WriteFile(victim, mustJSONBytes(good), 0o600)
	if err := os.Symlink(victim, e.m.TransitionPath(api.ServiceHoneypot)); err != nil {
		t.Fatal(err)
	}
	e.startHost(t)
	if e.journalExists(api.ServiceHoneypot) {
		t.Error("a symlinked journal stayed")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Error("the link target was removed")
	}
}

// An I/O error is not a verdict on the journal: it is left alone, said so, and the service waits.
func TestContract_Container_AnUnreadableJournalIsLeftAloneNotQuarantined(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can read a file with mode 0")
	}
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	oldText, newText := e.hpTexts(t)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, keepPrev: true, wasActive: true})
	if err := os.Chmod(e.m.TransitionPath(api.ServiceHoneypot), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.m.TransitionPath(api.ServiceHoneypot), 0o600) })
	rec := e.startHost(t)
	if !e.journalExists(api.ServiceHoneypot) {
		t.Fatal("the journal was moved or removed")
	}
	if left, _ := filepath.Glob(filepath.Join(e.m.State, "containers", "*.invalid-*")); len(left) != 0 {
		t.Fatalf("quarantined: %v", left)
	}
	if !strings.Contains(rec.text(), "transition_unreadable") || len(e.ctl()) != 0 {
		t.Fatalf("%s %v", rec.text(), e.ctl())
	}
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot"}, 412, api.CodeTransitionPending)
}

func mustJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// M3: a journal that has not been recovered blocks that service only, in both commands, and an
// old or overwritten journal is never silently reused by a new change.
func TestContract_Container_AJournalOfOneServiceRefusesItsCommandsOnly(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.hpTexts(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.seedTransition(t, seed{op: "start", svc: "honeypot", phase: "pending", oldText: oldText, newText: newText, keepPrev: true})
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "honeypot", Restart: true}, 412, api.CodeTransitionPending)
	e.refused(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "honeypot", Persist: true}, 412, api.CodeTransitionPending)
	if got := e.ctl(); len(got) != 0 {
		t.Fatalf("a refused command ran %v", got)
	}
	if r := e.start(t, api.ServiceSensor, false); r.Status != api.StatusSucceeded {
		t.Fatalf("another service is blocked: %+v %+v", r, r.Error)
	}
	if b, _ := os.ReadFile(e.m.TransitionPath(api.ServiceHoneypot)); !strings.Contains(string(b), `"phase":"pending"`) {
		t.Fatalf("the other service's journal was touched: %s", b)
	}
}

// M3: the fast path (a healthy service that only gets its [Install] back) is journaled too.
func TestContract_Container_TheFastPathWritesAJournalAndClearsIt(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	e.m.SetRunning(api.ServiceHoneypot, true)
	e.start(t, api.ServiceHoneypot, false)
	if j := e.m.CallsWithJournal(); !slices.Equal(j, []string{"daemon-reload"}) {
		// The calls say which look of runningHealthy did not see the healthy container (CI once took the restart path).
		t.Fatalf("the bytes changed without a journal: %v\nsystemctl %q\npodman %q", j, e.m.Calls("systemctl"), e.m.Calls("podman"))
	}
	if e.journalExists(api.ServiceHoneypot) {
		t.Fatal("the journal stayed")
	}
}

// M1: a persist-stopped service whose enabling fails stays stopped (SYS-5); one that was running is restarted.
func TestContract_Container_AFailedStartReturnsTheServiceToTheStateItHad(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceHoneypot, digA, false) // stopped with persist
	old := e.unit(t, api.ServiceHoneypot)
	e.m.Mark("restart-fails", true)
	e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot}, api.StatusReverted, api.CodeUnitFailed)
	if got, want := e.ctl(), []string{"daemon-reload", "restart vedette-honeypot.service", "daemon-reload", "stop vedette-honeypot.service"}; !slices.Equal(got, want) {
		t.Fatalf("systemctl calls %v, want %v: the revert must stop, not restart, a service that was stopped", got, want)
	}
	if e.m.IsRunning(api.ServiceHoneypot) || e.unit(t, api.ServiceHoneypot) != old || e.journalExists(api.ServiceHoneypot) {
		t.Fatal("the service runs, the unit changed or the journal stayed")
	}
	// An unhealthy start of a service that was running: the revert restarts it.
	e2 := startCtr(t)
	e2.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e2.m.SetRunning(api.ServiceHoneypot, true)
	e2.m.BadImage(digA)
	e2.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot, Restart: true}, api.StatusReverted, api.CodeUnitFailed)
	if got, want := e2.ctl(), []string{"daemon-reload", "restart vedette-honeypot.service", "daemon-reload", "restart vedette-honeypot.service"}; !slices.Equal(got, want) {
		t.Fatalf("systemctl calls %v, want %v", got, want)
	}
	if !e2.m.IsRunning(api.ServiceHoneypot) {
		t.Fatal("a service that was running is not running after the revert")
	}
}

// A run whose own context ends mid-way (a timeout) still puts the old unit back: the revert runs on a context of its own.
func TestContract_Container_ATimeoutIsFollowedByARevert(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := startCtr(t, func(_ *ops.Config, d *ops.Deps) {
		d.Sleep = func(context.Context, time.Duration) bool { cancel(); return false }
	})
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	old := e.unit(t, api.ServiceHoneypot)
	e.m.BadImage(digA)
	_, err := e.o.RunStart(ctx, api.ContainerStartArgs{Service: api.ServiceHoneypot})
	var rev *server.Reverted
	if !errors.As(err, &rev) || rev.Code != api.CodeUnitFailed {
		t.Fatalf("%v", err)
	}
	if e.unit(t, api.ServiceHoneypot) != old || e.journalExists(api.ServiceHoneypot) || e.m.IsRunning(api.ServiceHoneypot) {
		t.Fatal("the revert did not happen on a context of its own")
	}
	if got := e.ctl(); len(got) != 4 || got[2] != "daemon-reload" || got[3] != "stop vedette-honeypot.service" {
		t.Fatalf("%v", got)
	}
}

// M2: a unit that failed has nothing running: it counts as stopped, in the check and in the effect.
func TestContract_Container_AFailedUnitCountsAsStopped(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.m.RuleText("systemctl", "is-active vedette-sensor.service", "failed\n", 3, "", "")
	r := e.stop(t, "sensor", false)
	if res := result[api.ContainerStopResult](t, r); r.Status != api.StatusSucceeded || res.Changed {
		t.Fatalf("%+v %+v", r, res)
	}
	r = e.stop(t, "sensor", true)
	if res := result[api.ContainerStopResult](t, r); r.Status != api.StatusSucceeded || !res.Changed {
		t.Fatalf("%+v %+v", r, res)
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) {
		t.Fatalf("a failed unit was stopped again: %v", got)
	}
	if strings.Contains(e.unit(t, api.ServiceSensor), "[Install]") {
		t.Fatal("[Install] stayed")
	}
	// A unit that stays "deactivating" is not stopped: 20 s of looks (counted), then stop_not_verified.
	e2 := startCtr(t)
	e2.m.InstallUnit(api.ServiceSensor, digA, true)
	e2.m.RuleText("systemctl", "is-active vedette-sensor.service", "deactivating\n", 3, "", "")
	e2.final(t, api.CmdContainerStop, api.ContainerStopArgs{Service: "sensor"}, api.StatusFailed, api.CodeStopNotVerified)
	if total, n := e2.sleeps.get(); total != 20*time.Second || n != 10 {
		t.Fatalf("waited %v in %d sleeps", total, n)
	}
	// And the failed stop does not leave a journal that would block the retry.
	if e2.journalExists("sensor") {
		t.Fatal("a journal was left behind")
	}
}

// A stop with persist journals the unit change, and the journal is cleared when the stop was looked at.
func TestContract_Container_AStopWithPersistKeepsItsJournalUntilTheStopIsSeen(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.start(t, api.ServiceSensor, false)
	e.stop(t, "sensor", true)
	if j := e.m.CallsWithJournal(); !slices.Contains(j, "daemon-reload") || !slices.Contains(j, "stop vedette-sensor.service") {
		t.Fatalf("calls made while the journal existed: %v", j)
	}
	if e.journalExists("sensor") {
		t.Fatal("the journal stayed")
	}
}

// A journal for a service must never be created without the unit change: a refused or a no-op command leaves none.
func TestContract_Container_NoUnitChangeNoJournal(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, true)
	e.start(t, api.ServiceSensor, false) // a first start changes things: it is journaled
	before := len(e.m.CallsWithJournal())
	e.start(t, api.ServiceSensor, false) // already healthy, bytes equal
	e.stop(t, "sensor", false)           // no persist: no unit change
	if got := e.m.CallsWithJournal(); len(got) != before {
		t.Fatalf("a journal existed during %v", got[before:])
	}
}

// --- INV-17: the units that were built --------------------------------------------------------------

type unitLines map[string][]string // key -> values, in order (the [Unit]/[Container]/[Service]/[Install] sections flattened)

func parseBuilt(t *testing.T, text string) unitLines {
	t.Helper()
	out := unitLines{}
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		switch {
		case l == "" || (strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]")):
			continue
		case !regexp.MustCompile(`^[A-Za-z]+=.*$`).MatchString(l):
			t.Fatalf("a line that is not Key=value: %q", l)
		}
		k, v, _ := strings.Cut(l, "=")
		out[k] = append(out[k], v)
	}
	return out
}

// TestContract_INV17_BuiltUnitsFollowTheCapabilityAndNetworkTable scans the units the host builds, for every
// service, with and without [Install], and checks the table of DEPLOYMENT.md 2 and D-105 (6), D-114
// against the text, independently of the templates.
func TestContract_INV17_BuiltUnitsFollowTheCapabilityAndNetworkTable(t *testing.T) {
	t.Parallel()
	const cuid, cgid, suid, sgid = 10001, 10002, 10003, 10004
	type want struct {
		network   string
		addCaps   []string
		user      string   // "" = no User= line
		userns    string   // "" = no UserNS line
		volumes   []string // the exact Volume= lines, in order (L1)
		exec      string   // the exact Exec= line ("" = none)
		requires  []string
		wants     []string
		publishes []string
	}
	const keys = "vedette-creds-"
	table := map[string]want{
		api.ServiceCore: {network: "vedette-int.network", user: "10001:10002", publishes: []string{"8443:8443", "127.0.0.1:8444:8444", "514:5514/udp", "514:5514/tcp"},
			exec: "-listen :8443 -sensor-listen :8444 -sensor-creds /var/lib/vedette-creds -syslog-port 5514",
			volumes: []string{
				"/var/lib/vedette:/var/lib/vedette", // core_data bound: the database and the key core reads are the files the host backs up (D-142)
				"/var/lib/vedette-honeypot/config:/var/lib/vedette/honeypot/config",
				"vedette-hp-log.volume:/var/lib/vedette/honeypot/log:ro,noexec", // the size-capped tmpfs volume (D-318)
				"/run/vedette:/run/vedette",
				keys + "passive.volume:/var/lib/vedette-creds/passive",
				keys + "active.volume:/var/lib/vedette-creds/active",
			}},
		api.ServiceSensor: {network: "host", addCaps: []string{"NET_RAW"}, user: "10003:10004", wants: []string{"vedette-core.service"},
			volumes: []string{keys + "passive.volume:/var/lib/vedette-creds:ro"},
			exec:    "passive --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem"},
		api.ServiceScan: {network: "host", addCaps: []string{"NET_RAW"}, user: "10003:10004", wants: []string{"vedette-core.service"},
			volumes: []string{keys + "active.volume:/var/lib/vedette-creds:ro"},
			exec:    "active --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem"},
		// The image's user is 1000:0 from the start and the unit adds no capability (deploy/containers/honeypot/init.py, D-162). :U gives the
		// log volume to that user (UserNS=auto picks the range at start).
		api.ServiceHoneypot: {network: "ns:/run/netns/vedette-hp", userns: "auto", requires: []string{"vedette-host.service"},
			volumes: []string{
				"/var/lib/vedette-honeypot/config:/var/lib/vedette/honeypot/config:ro",
				"vedette-hp-log.volume:/var/lib/vedette/honeypot/log:U,noexec",
			}},
	}
	for svc, w := range table {
		for _, install := range []bool{true, false} {
			b, err := ops.RenderUnitIn(svc, digA, install, cuid, cgid, suid, sgid, "/var/lib/vedette")
			if err != nil {
				t.Fatal(err)
			}
			text := string(b)
			u := parseBuilt(t, text)
			one := func(k string) string {
				if len(u[k]) != 1 {
					t.Errorf("%s: %d %s lines", svc, len(u[k]), k)
					return ""
				}
				return u[k][0]
			}
			if strings.Contains(text, "--privileged") || strings.Contains(strings.ToLower(text), "privileged") {
				t.Errorf("%s: privileged", svc)
			}
			if one("Network") != w.network {
				t.Errorf("%s: Network=%v", svc, u["Network"])
			}
			if (w.network == "host") != (svc == api.ServiceSensor || svc == api.ServiceScan) {
				t.Fatal("the table itself breaks the rule: Network=host only for sensor and scan")
			}
			if one("DropCapability") != "ALL" {
				t.Errorf("%s: DropCapability=%v", svc, u["DropCapability"])
			}
			if !slices.Equal(u["AddCapability"], w.addCaps) {
				t.Errorf("%s: AddCapability=%v, want %v (never NET_BIND_SERVICE, never NET_ADMIN, never SYS_ADMIN)", svc, u["AddCapability"], w.addCaps)
			}
			if one("NoNewPrivileges") != "true" || one("ReadOnly") != "true" || one("LogDriver") != "journald" {
				t.Errorf("%s: hardening lines missing", svc)
			}
			// User= and UserNS=: core and sensor/scan run a fixed uid without UserNS; the honeypot runs UserNS=auto.
			if w.user == "" && len(u["User"]) != 0 || w.user != "" && one("User") != w.user {
				t.Errorf("%s: User=%v, want %q", svc, u["User"], w.user)
			}
			if w.userns == "" && (len(u["UserNS"]) != 0 || strings.Contains(text, "UserNS")) || w.userns != "" && one("UserNS") != w.userns {
				t.Errorf("%s: UserNS=%v", svc, u["UserNS"])
			}
			if (svc == api.ServiceCore || svc == api.ServiceSensor || svc == api.ServiceScan) && strings.Contains(text, "UserNS") {
				t.Errorf("%s runs without UserNS", svc)
			}
			// Published ports: only core, and only these (no IP of the box in the line).
			if !slices.Equal(u["PublishPort"], w.publishes) {
				t.Errorf("%s: PublishPort=%v", svc, u["PublishPort"])
			}
			// Image: a pinned digest of the service's repository.
			// The scan image is built on the box and has no registry digest: its unit pins the image ID (D-147).
			imageRE := `^ghcr\.io/knt048/vedette-` + svc + `@` + digA + `$`
			if svc == api.ServiceScan {
				imageRE = `^` + strings.TrimPrefix(digA, "sha256:") + `$`
			}
			if !regexp.MustCompile(imageRE).MatchString(one("Image")) {
				t.Errorf("%s: Image=%v", svc, u["Image"])
			}
			if one("ContainerName") != "vedette-"+svc {
				t.Errorf("%s: ContainerName=%v", svc, u["ContainerName"])
			}
			// Volumes: the exact list of the table, and a mode that is nothing but "ro" (no rshared, no Z, no suid).
			if !slices.Equal(u["Volume"], w.volumes) {
				t.Errorf("%s: Volume lines %v, want exactly %v", svc, u["Volume"], w.volumes)
			}
			for _, v := range u["Volume"] {
				parts := strings.Split(v, ":")
				// "U" (podman gives the volume to the container's user) is for the honeypot's log volume alone (D-162)
				honeypotLog := svc == api.ServiceHoneypot && v == "vedette-hp-log.volume:/var/lib/vedette/honeypot/log:U,noexec"
				coreLog := svc == api.ServiceCore && v == "vedette-hp-log.volume:/var/lib/vedette/honeypot/log:ro,noexec"
				if len(parts) < 2 || len(parts) > 3 || (len(parts) == 3 && parts[2] != "ro" && !honeypotLog && !coreLog) || strings.Contains(v, "shared") || strings.Contains(v, "slave") {
					t.Errorf("%s: odd Volume line %q", svc, v)
				}
				if strings.Contains(v, ".sock") && v != "/run/vedette:/run/vedette" {
					t.Errorf("%s mounts a socket file: %s", svc, v)
				}
			}
			if (svc == api.ServiceCore) != slices.Contains(u["Volume"], "/run/vedette:/run/vedette") {
				t.Errorf("%s: the host socket directory is for core only", svc)
			}
			wantTmpfs := "/tmp"
			if svc == api.ServiceCore {
				wantTmpfs = "/tmp:size=64m" // D-150: a bounded tmpfs, so a runaway temp file cannot eat the 2 GiB container memory
			}
			if !slices.Equal(u["Tmpfs"], []string{wantTmpfs}) {
				t.Errorf("%s: Tmpfs=%v", svc, u["Tmpfs"])
			}
			if w.exec == "" && len(u["Exec"]) != 0 || w.exec != "" && !slices.Equal(u["Exec"], []string{w.exec}) {
				t.Errorf("%s: Exec=%v, want %q", svc, u["Exec"], w.exec)
			}
			if !slices.Equal(u["Pull"], []string{"never"}) {
				t.Errorf("%s: Pull=%v (the host never lets Podman pull)", svc, u["Pull"])
			}
			// Ordering: sensor and scan want core, they do not require it (a restart of core must not restart them).
			if !slices.Equal(u["Requires"], w.requires) || !slices.Equal(u["Wants"], append(w.wants, wantsBase(svc)...)) {
				t.Errorf("%s: Requires=%v Wants=%v", svc, u["Requires"], u["Wants"])
			}
			// PodmanArgs: only memory/cpu/pids limits and core's --group-add of the sensor gid.
			for _, a := range strings.Fields(strings.Join(u["PodmanArgs"], " ")) {
				if !regexp.MustCompile(`^--(memory|memory-swap|cpus|pids-limit|cpu-shares)=[0-9.]+[mg]?$|^--group-add=` + "10004" + `$`).MatchString(a) {
					t.Errorf("%s: PodmanArgs has %q", svc, a)
				}
				if strings.HasPrefix(a, "--group-add") && svc != api.ServiceCore {
					t.Errorf("%s adds a group", svc)
				}
			}
			// [Install] present iff asked, and then only WantedBy=multi-user.target.
			if got := text[strings.LastIndex(text, "[Install]")+1:]; strings.Contains(text, "[Install]") != install || (install && !strings.HasSuffix(text, "[Install]\nWantedBy=multi-user.target\n")) {
				t.Errorf("%s: [Install] = %t, want %t (%q)", svc, strings.Contains(text, "[Install]"), install, got)
			}
			if len(u["Exec"]) > 1 || len(u["ExecStart"]) != 0 || len(u["ExecStartPre"]) != 0 || len(u["ExecStartPost"]) != 0 {
				t.Errorf("%s: extra commands", svc)
			}
			// No key outside the ones the templates use: a new key is a decision (add it here and to the table).
			known := []string{"Description", "After", "Wants", "Requires", "ContainerName", "Image", "Network", "PublishPort", "Volume", "ReadOnly", "Tmpfs",
				"NoNewPrivileges", "DropCapability", "AddCapability", "User", "UserNS", "LogDriver", "PodmanArgs", "HealthCmd", "HealthInterval",
				"HealthStartPeriod", "HealthRetries", "Exec", "Restart", "TimeoutStartSec", "WantedBy", "Pull", "RunInit", "Environment"}
			for k := range u {
				if !slices.Contains(known, k) {
					t.Errorf("%s has the key %s", svc, k)
				}
			}
			// D-150: the only environment variable is core's Go memory limit.
			if want := []string(nil); svc != api.ServiceCore && !slices.Equal(u["Environment"], want) || svc == api.ServiceCore && !slices.Equal(u["Environment"], []string{"GOMEMLIMIT=1800MiB"}) {
				t.Errorf("%s: Environment=%v (only core has GOMEMLIMIT=1800MiB, D-150)", svc, u["Environment"])
			}
			// D-146: only scan runs under an init (nmap can leave children that detach from the process group the worker kills).
			if _, has := u["RunInit"]; has != (svc == api.ServiceScan) {
				t.Errorf("%s: RunInit present = %t, only scan has it", svc, has)
			}
		}
	}
}

// Service units must not name another host path as a sensor id, and a unit has no drop-in: the host
// writes one file per service and nothing in a *.container.d directory.
// wantsBase is the Wants= line the core unit has besides what the table lists.
func wantsBase(svc string) []string {
	if svc == api.ServiceCore {
		return []string{"network-online.target"}
	}
	return nil
}

func TestContract_INV17_TheHostWritesNoDropIns(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	for _, svc := range []string{api.ServiceHoneypot, api.ServiceSensor} {
		e.m.InstallUnit(svc, digA, false)
		e.start(t, svc, false)
		e.stop(t, svc, true)
	}
	entries, err := os.ReadDir(e.m.UnitsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		isUnit := strings.HasSuffix(en.Name(), ".container") || slices.Contains([]string{"vedette-creds-passive.volume", "vedette-creds-active.volume", "vedette-hp-log.volume"}, en.Name())
		if en.IsDir() || !isUnit || strings.HasPrefix(en.Name(), ".") {
			t.Errorf("the host left %q in the Quadlet directory", en.Name())
		}
	}
}

// TestContract_INV17_CredentialVolumes: the two .volume units are written by the host from constant text with the host.conf ids, beside
// the first unit that mounts them; each is mounted read-write by core only and read-only by exactly one sensor role (passive in
// sensor, active in scan), and the honeypot mounts none (D-110 (4), D-114 (4), D-147).
func TestContract_INV17_CredentialVolumes(t *testing.T) {
	t.Parallel()
	const cuid, cgid, suid, sgid = 10001, 10002, 10003, 10004
	roleOf := map[string]string{api.ServiceSensor: "passive", api.ServiceScan: "active"}
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		b, err := ops.RenderUnitIn(svc, digA, true, cuid, cgid, suid, sgid, "/var/lib/vedette")
		if err != nil {
			t.Fatal(err)
		}
		var vols []string
		for _, v := range parseBuilt(t, string(b))["Volume"] {
			if strings.Contains(v, "vedette-creds-") {
				vols = append(vols, v)
			}
		}
		switch svc {
		case api.ServiceCore:
			// Read-write, and each role's folder separately: never one volume over the whole directory.
			if !slices.Equal(vols, []string{"vedette-creds-passive.volume:/var/lib/vedette-creds/passive", "vedette-creds-active.volume:/var/lib/vedette-creds/active"}) {
				t.Errorf("core mounts %v", vols)
			}
		case api.ServiceHoneypot:
			if len(vols) != 0 {
				t.Errorf("the honeypot mounts %v", vols)
			}
		default:
			if !slices.Equal(vols, []string{"vedette-creds-" + roleOf[svc] + ".volume:/var/lib/vedette-creds:ro"}) {
				t.Errorf("%s mounts %v, want only the %s volume, read-only", svc, vols, roleOf[svc])
			}
		}
	}
	for role, want := range map[string]string{ //nolint:gosec // "credentials" in a description is text, not a secret
		"passive": "[Unit]\nDescription=Vedette sensor credentials (passive role)\n\n[Volume]\nVolumeName=vedette-creds-passive\nUser=10001\nGroup=10004\n",
		"active":  "[Unit]\nDescription=Vedette sensor credentials (active role)\n\n[Volume]\nVolumeName=vedette-creds-active\nUser=10001\nGroup=10004\n",
	} {
		b, err := ops.RenderVolume(role, cuid, sgid)
		if err != nil || string(b) != want {
			t.Errorf("%s volume: %q, %v", role, b, err)
		}
		u := parseBuilt(t, string(b))
		for k := range u {
			if !slices.Contains([]string{"Description", "VolumeName", "User", "Group"}, k) {
				t.Errorf("the %s volume has the key %s", role, k)
			}
		}
	}
	for _, c := range []struct {
		role     string
		uid, gid int
	}{{"core", 1, 1}, {"passive", 0, 1}, {"passive", 1, 0}, {"active", 1, -1}} {
		if _, err := ops.RenderVolume(c.role, c.uid, c.gid); err == nil {
			t.Errorf("a volume for %+v was made", c)
		}
	}
	// Written by the host beside the first unit that is written, root-safe like the units, and idempotent.
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, false)
	e.start(t, api.ServiceSensor, false)
	cfg := e.m.Config()
	for _, role := range []string{"passive", "active"} {
		p := filepath.Join(e.m.UnitsDir(), "vedette-creds-"+role+".volume")
		want, _ := ops.RenderVolume(role, cfg.CoreUID, cfg.SensorGID)
		b, err := os.ReadFile(p) //nolint:gosec // test: a path under the fake root
		if err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s: %q, %v; want %q", p, b, err, want)
		}
		if st, err := os.Lstat(p); err != nil || st.Mode().Perm() != 0o644 || !st.Mode().IsRegular() {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	// A link planted at the name is refused, not followed (the writer of the units).
	e2 := startCtr(t)
	e2.m.MakeUnitsDir()
	target := filepath.Join(e2.m.Root, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(e2.m.UnitsDir(), "vedette-creds-active.volume")); err != nil {
		t.Fatal(err)
	}
	e2.m.InstallUnit(api.ServiceSensor, digA, false)
	if _, err := e2.call(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceSensor}); err == nil {
		// the start must not have followed the link
		if b, _ := os.ReadFile(target); string(b) != "x" { //nolint:gosec // test: a path under the fake root
			t.Errorf("the host wrote through a link: %q", b)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "x" { //nolint:gosec // test: a path under the fake root
		t.Errorf("the host wrote through a link: %q", b)
	}
}

// TestContract_INV17_HoneypotLogVolumeIsACappedTmpfs: log/ of the honeypot is a Quadlet volume of constant text, a tmpfs of at most 64 MiB
// and 1024 files with no suid, no device and no exec; the honeypot writes it, core reads it and nothing else mounts it. The host writes
// the file with the first start of core or honeypot, refuses a link at its name, and writes nothing through it (D-318).
func TestContract_INV17_HoneypotLogVolumeIsACappedTmpfs(t *testing.T) {
	t.Parallel()
	want := "[Unit]\nDescription=Vedette honeypot log (tmpfs, size-capped)\n\n[Volume]\nVolumeName=vedette-hp-log\nType=tmpfs\nDevice=tmpfs\nOptions=size=64m,nr_inodes=1024,nosuid,nodev,noexec\n"
	if got := string(ops.HpLogVolumeText()); got != want {
		t.Errorf("the log volume unit is %q, want %q", got, want)
	}
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		b, err := ops.RenderUnitIn(svc, digA, true, 10001, 10002, 10003, 10004, "/var/lib/vedette")
		if err != nil {
			t.Fatal(err)
		}
		var vols []string
		for _, v := range parseBuilt(t, string(b))["Volume"] {
			if strings.Contains(v, "vedette-hp-log") || strings.Contains(v, "/honeypot/log") {
				vols = append(vols, v)
			}
		}
		switch svc {
		case api.ServiceCore:
			if !slices.Equal(vols, []string{"vedette-hp-log.volume:/var/lib/vedette/honeypot/log:ro,noexec"}) {
				t.Errorf("core mounts %v, want the log volume read-only", vols)
			}
		case api.ServiceHoneypot:
			if !slices.Equal(vols, []string{"vedette-hp-log.volume:/var/lib/vedette/honeypot/log:U,noexec"}) {
				t.Errorf("the honeypot mounts %v, want the log volume", vols)
			}
		default:
			if len(vols) != 0 {
				t.Errorf("%s mounts %v", svc, vols)
			}
		}
	}
	// the honeypot's first start writes it, and core's does too
	for _, svc := range []string{api.ServiceHoneypot, api.ServiceCore} {
		e := startCtr(t)
		e.m.InstallUnit(svc, digA, false)
		e.start(t, svc, false)
		p := filepath.Join(e.m.UnitsDir(), "vedette-hp-log.volume")
		b, err := os.ReadFile(p) //nolint:gosec // test: a path under the fake root
		if err != nil || string(b) != want {
			t.Errorf("%s start: %s is %q, %v", svc, p, b, err)
		}
		if st, err := os.Lstat(p); err != nil || st.Mode().Perm() != 0o644 || !st.Mode().IsRegular() {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	// a start of sensor alone does not write it
	e := startCtr(t)
	e.m.InstallUnit(api.ServiceSensor, digA, false)
	e.start(t, api.ServiceSensor, false)
	if _, err := os.Lstat(filepath.Join(e.m.UnitsDir(), "vedette-hp-log.volume")); err == nil {
		t.Error("a sensor start wrote the honeypot log volume")
	}
	// a link at the name is not followed
	e2 := startCtr(t)
	target := filepath.Join(e2.m.Root, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(e2.m.UnitsDir(), "vedette-hp-log.volume")); err != nil {
		t.Fatal(err)
	}
	e2.m.InstallUnit(api.ServiceHoneypot, digA, false)
	before, _ := e2.m.Unit(api.ServiceHoneypot)
	e2.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot, Restart: true}, api.StatusFailed, api.CodeUnitUnsafe)
	if after, _ := e2.m.Unit(api.ServiceHoneypot); after != before {
		t.Errorf("the honeypot unit changed after the refusal:\n%s", after)
	}
	if b, _ := os.ReadFile(target); string(b) != "x" { //nolint:gosec // test: a path under the fake root
		t.Errorf("the host wrote through a link: %q", b)
	}
}

// A hostile digest cannot reach a unit: the only digest the host writes comes out of a unit it wrote
// or out of a verified manifest, and the renderer refuses anything else anyway.
func TestContract_INV17_ARenderedDigestIsAlwaysSha256Hex(t *testing.T) {
	t.Parallel()
	for _, d := range []string{"sha256:" + strings.Repeat("a", 64) + "\nExec=/bin/sh", "x", "", "sha256:" + strings.Repeat("g", 64)} {
		if _, err := ops.RenderUnit(api.ServiceHoneypot, d, true, 1, 1, 1, 1); err == nil {
			t.Errorf("%q was rendered", d)
		}
	}
}

// --- the systemctl and podman grammars through the contract package -----------------------------

func TestContract_INV2_ContainerArgvGrammars(t *testing.T) {
	t.Parallel()
	v := ops.ValidateSystemctl("vedette-core.service")
	for _, a := range [][]string{{"restart", "vedette-core.service"}, {"stop", "vedette-honeypot.service"}, {"daemon-reload"}, {"is-active", "vedette-scan.service"}} {
		if err := v(a); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	for _, a := range [][]string{{"restart", "sshd.service"}, {"restart", "vedette-host.service"}, {"enable", "vedette-core.service"}, {"restart", "vedette-core.service; id"}} {
		if err := v(a); err == nil {
			t.Errorf("%v accepted", a)
		}
	}
	if ops.ValidatePodman([]string{"container", "inspect", "vedette-core"}) != nil || ops.ValidatePodman([]string{"container", "rm", "vedette-core"}) == nil ||
		ops.ValidatePodman([]string{"run", "--privileged", "alpine"}) == nil {
		t.Error("the podman grammar")
	}
	// The unit text cannot be the argument of anything: the commands take a service name from the closed list only.
	e := startSys(t)
	for _, svc := range []string{"core; id", "$(id)", "../core", "core\n", "CORE", "vedette-core", "core.service", "core ", "--user"} {
		for _, cmd := range []string{api.CmdContainerStart, api.CmdContainerStop} {
			e.refused(t, cmd, map[string]any{"service": svc, "persist": false}, http.StatusBadRequest, api.CodeInvalidArgs)
		}
	}
	if got := e.m.AllCalls(); len(got) != 0 {
		t.Fatalf("a refused request ran %v", got)
	}
}

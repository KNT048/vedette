package host_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	b, err := ops.RenderUnit(svc, digest, install, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID)
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
	if _, err := os.Stat(e.m.TransitionPath()); err == nil {
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
	if got, want := e.ctl(), []string{"daemon-reload", "restart vedette-honeypot.service", "daemon-reload", "restart vedette-honeypot.service"}; !slices.Equal(got, want) {
		t.Fatalf("systemctl calls %v, want %v", got, want)
	}
	if _, err := os.Stat(e.m.TransitionPath()); err == nil {
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
	e.m.Mark("restart-fails", true)
	// systemd would not restart the new unit, nor the old one: the run fails, it does not claim a revert.
	r := e.final(t, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot}, api.StatusFailed, api.CodeUnitFailed)
	if got := e.unit(t, api.ServiceHoneypot); got != old {
		t.Fatalf("the old unit text must be back even when the restart fails:\n%s", got)
	}
	if res := result[api.ContainerStartResult](t, r); res.Healthy {
		t.Fatalf("%+v", res)
	}
	b, err := os.ReadFile(e.m.TransitionPath())
	if err != nil {
		t.Fatalf("the journal must stay for the next start: %v", err)
	}
	if !strings.Contains(string(b), `"service":"honeypot"`) || !strings.Contains(string(b), `"op":"start"`) {
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
	start(api.ContainerStartArgs{Service: "honeypot", Version: "1.2.3"}, 412, api.CodeNotPulled) // switching versions is slice 3-7/3-8
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
	if _, err := os.Stat(e.m.TransitionPath()); err == nil {
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
	for _, out := range []string{"", "deactivating\n", "inactiv\n", "inactive-ish\n", "failed\n", "\x00inactive"} {
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

// --- the journal at Start --------------------------------------------------------------------------

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// seedTransition leaves what a host that died in the middle of a change leaves: the new unit in
// place, .prev holding the old one, and the journal.
func (e *ctrEnv) seedTransition(t *testing.T, op, svc, oldText, newText string, keepPrev bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-"+svc+".container"), []byte(newText), 0o644); err != nil { //nolint:gosec // test: a unit file of the fake root
		t.Fatal(err)
	}
	if keepPrev {
		if err := os.WriteFile(filepath.Join(e.m.State, "containers", "units", svc+".prev"), []byte(oldText), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tr, _ := json.Marshal(map[string]any{
		"service": svc, "op": op, "digest": digA, "prev_sha256": shaOf(oldText), "new_sha256": shaOf(newText),
		"at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef",
	})
	if err := os.WriteFile(e.m.TransitionPath(), tr, 0o600); err != nil {
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

func TestContract_Container_AHalfDoneStartThatIsNotHealthyIsPutBackAtStart(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.render(t, api.ServiceHoneypot, digA, false), e.render(t, api.ServiceHoneypot, digA, true)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.m.BadImage(digA) // the new image does not get healthy
	e.seedTransition(t, "start", api.ServiceHoneypot, oldText, newText, true)
	rec := e.startHost(t)
	if got := e.unit(t, api.ServiceHoneypot); got != oldText {
		t.Fatalf("the old unit was not put back:\n%s", got)
	}
	ctl := e.ctl()
	if !slices.Contains(ctl, "daemon-reload") || !slices.Contains(ctl, "restart vedette-honeypot.service") {
		t.Fatalf("systemctl calls %v", ctl)
	}
	if _, err := os.Stat(e.m.TransitionPath()); err == nil {
		t.Error("the journal stayed")
	}
	if txt := rec.text(); !strings.Contains(txt, "container.start transition_interrupted") || !strings.Contains(txt, `"action":"reverted"`) || !strings.Contains(txt, `"service":"honeypot"`) {
		t.Fatalf("notes: %s", txt)
	}
	if total, _ := e.sleeps.get(); total != 30*time.Second {
		t.Errorf("the look for health at start is 30 s, waited %v", total)
	}
}

func TestContract_Container_AHalfDoneStartThatIsHealthyIsLeftAlone(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.render(t, api.ServiceHoneypot, digA, false), e.render(t, api.ServiceHoneypot, digA, true)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.m.SetRunning(api.ServiceHoneypot, true)
	e.seedTransition(t, "start", api.ServiceHoneypot, oldText, newText, true)
	rec := e.startHost(t)
	if e.unit(t, api.ServiceHoneypot) != newText || len(e.ctl()) != 0 {
		t.Fatalf("a healthy new unit was touched: %v", e.ctl())
	}
	if _, err := os.Stat(e.m.TransitionPath()); err == nil {
		t.Error("the journal stayed")
	}
	if !strings.Contains(rec.text(), `"action":"completed"`) {
		t.Fatalf("notes: %s", rec.text())
	}
}

func TestContract_Container_AHalfDoneStopGetsItsUnitTextBackAndNothingIsStoppedOrStarted(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.render(t, api.ServiceSensor, digA, true), e.render(t, api.ServiceSensor, digA, false)
	e.m.InstallUnit(api.ServiceSensor, digA, false)
	e.m.SetRunning(api.ServiceSensor, true)
	e.seedTransition(t, "stop", api.ServiceSensor, oldText, newText, true)
	rec := e.startHost(t)
	if e.unit(t, api.ServiceSensor) != oldText {
		t.Fatal("the unit text before the stop was not put back")
	}
	if got := e.ctl(); !slices.Equal(got, []string{"daemon-reload"}) || !e.m.IsRunning(api.ServiceSensor) {
		t.Fatalf("systemctl calls %v", got)
	}
	if !strings.Contains(rec.text(), `"action":"reverted"`) {
		t.Fatalf("notes: %s", rec.text())
	}
}

func TestContract_Container_ARecoveryThatCannotPutBackKeepsTheJournal(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	oldText, newText := e.render(t, api.ServiceHoneypot, digA, false), e.render(t, api.ServiceHoneypot, digA, true)
	e.m.InstallUnit(api.ServiceHoneypot, digA, true)
	e.m.BadImage(digA)
	// No .prev, and a .prev that does not match the journal.
	for name, keep := range map[string]func(){
		"no prev": func() {},
		"other prev": func() {
			_ = os.WriteFile(filepath.Join(e.m.State, "containers", "units", "honeypot.prev"), []byte("something else"), 0o600)
		},
	} {
		e.seedTransition(t, "start", api.ServiceHoneypot, oldText, newText, false)
		keep()
		rec := e.startHost(t)
		if _, err := os.Stat(e.m.TransitionPath()); err != nil {
			t.Errorf("%s: the journal was removed: %v", name, err)
		}
		if got := e.unit(t, api.ServiceHoneypot); got != newText {
			t.Errorf("%s: the unit changed", name)
		}
		if !strings.Contains(rec.text(), "transition_recovery_failed") {
			t.Errorf("%s: notes: %s", name, rec.text())
		}
		_ = os.Remove(filepath.Join(e.m.State, "containers", "units", "honeypot.prev"))
		e.o.Close()
	}
}

func TestContract_Container_AnInvalidJournalIsDroppedAtStart(t *testing.T) {
	t.Parallel()
	good := map[string]any{
		"service": "honeypot", "op": "start", "digest": digA, "prev_sha256": shaOf("a"), "new_sha256": shaOf("b"),
		"at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef",
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
		"unknown service": mustJSONBytes(with("service", "sshd")),
		"unknown op":      mustJSONBytes(with("op", "delete")),
		"bad digest":      mustJSONBytes(with("digest", "latest")),
		"bad sha":         mustJSONBytes(with("new_sha256", "zz")),
		"bad run id":      mustJSONBytes(with("run_id", "../../x")),
		"trailing":        append(mustJSONBytes(good), []byte(" {}")...),
		"huge":            append(mustJSONBytes(good), []byte(strings.Repeat(" ", 5000))...),
	} {
		e := startCtr(t)
		e.m.InstallUnit(api.ServiceHoneypot, digA, true)
		if err := os.WriteFile(e.m.TransitionPath(), content, 0o600); err != nil {
			t.Fatal(err)
		}
		rec := e.startHost(t)
		if _, err := os.Stat(e.m.TransitionPath()); err == nil {
			t.Errorf("%s: the journal stayed", name)
		}
		if len(e.ctl()) != 0 || !strings.Contains(rec.text(), "transition_invalid") {
			t.Errorf("%s: %v %s", name, e.ctl(), rec.text())
		}
	}
	// A link in place of the journal is dropped, never followed.
	e := startCtr(t)
	victim := filepath.Join(e.m.Root, "elsewhere")
	_ = os.WriteFile(victim, mustJSONBytes(good), 0o600)
	if err := os.Symlink(victim, e.m.TransitionPath()); err != nil {
		t.Fatal(err)
	}
	e.startHost(t)
	if _, err := os.Lstat(e.m.TransitionPath()); err == nil {
		t.Error("a symlinked journal stayed")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Error("the link target was removed")
	}
}

func mustJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
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
		user      string // "" = no User= line
		userns    string // "" = no UserNS line
		roVol     string // volume held read-only
		publishes []string
	}
	table := map[string]want{
		api.ServiceCore:     {network: "vedette-int.network", user: "10001:10002", publishes: []string{"8443:8443", "127.0.0.1:8444:8444"}},
		api.ServiceSensor:   {network: "host", addCaps: []string{"NET_RAW"}, user: "10003:10004", roVol: "vedette-creds-passive.volume"},
		api.ServiceScan:     {network: "host", addCaps: []string{"NET_RAW"}, user: "10003:10004", roVol: "vedette-creds-active.volume"},
		api.ServiceHoneypot: {network: "ns:/run/netns/vedette-hp", userns: "auto"},
	}
	for svc, w := range table {
		for _, install := range []bool{true, false} {
			b, err := ops.RenderUnit(svc, digA, install, cuid, cgid, suid, sgid)
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
			if !regexp.MustCompile(`^(ghcr\.io/knt048/vedette-` + svc + `|localhost/vedette-scan-nmap)@` + digA + `$`).MatchString(one("Image")) {
				t.Errorf("%s: Image=%v", svc, u["Image"])
			}
			if one("ContainerName") != "vedette-"+svc {
				t.Errorf("%s: ContainerName=%v", svc, u["ContainerName"])
			}
			// Volumes: no socket of a runtime, nothing of the host's root, creds only as the table says.
			for _, v := range u["Volume"] {
				if strings.Contains(v, "podman.sock") || strings.Contains(v, "docker.sock") || strings.HasPrefix(v, "/:") || strings.HasPrefix(v, "/etc:") || strings.HasPrefix(v, "/var:") || strings.HasPrefix(v, "/run:") {
					t.Errorf("%s mounts %s", svc, v)
				}
				if strings.Contains(v, "vedette-creds-") && svc != api.ServiceCore {
					wantRO := w.roVol + ":/var/lib/vedette-creds:ro"
					if v != wantRO {
						t.Errorf("%s mounts %s, want only %s", svc, v, wantRO)
					}
				}
				if svc == api.ServiceCore && strings.Contains(v, "vedette-creds-") && strings.HasSuffix(v, ":ro") {
					t.Errorf("core mounts the creds read-only: %s", v)
				}
				if strings.Contains(v, "host.sock") && svc != api.ServiceCore {
					t.Errorf("%s mounts the host socket", svc)
				}
			}
			if (svc == api.ServiceCore) != (len(u["Volume"]) > 0 && slices.ContainsFunc(u["Volume"], func(v string) bool { return strings.Contains(v, "host.sock") })) {
				t.Errorf("%s: the host socket is for core only", svc)
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
				"HealthStartPeriod", "HealthRetries", "Exec", "Restart", "TimeoutStartSec", "WantedBy"}
			for k := range u {
				if !slices.Contains(known, k) {
					t.Errorf("%s has the key %s", svc, k)
				}
			}
		}
	}
}

// Service units must not name another host path as a sensor id, and a unit has no drop-in: the host
// writes one file per service and nothing in a *.container.d directory.
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
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".container") || strings.HasPrefix(en.Name(), ".") {
			t.Errorf("the host left %q in the Quadlet directory", en.Name())
		}
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

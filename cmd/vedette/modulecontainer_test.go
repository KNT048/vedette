package main

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/modules"
)

// M3 (D-260): the sensor and scan containers follow their module, over the real host server and client (as the honeypot's
// tests do): on starts the unit and gives it [Install] back, off stops it with persist, the module is looked at again under
// the lock, and a host that fails to stop is an error for the guard to retry.

type flagReg struct{ on atomic.Bool }

func (f *flagReg) Enabled(string) bool { return f.on.Load() }

func (e *hpHost) follower(reg *flagReg, module, service string) *moduleContainer {
	return &moduleContainer{h: e.adapter(), reg: reg, module: module, service: service}
}

func (e *hpHost) state(t *testing.T, service string) string {
	t.Helper()
	st, err := e.h.Client.StateContainers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st.Services {
		if s.Service == service {
			return s.UnitState
		}
	}
	t.Fatalf("no %s in the state of the containers", service)
	return ""
}

// writes counts the systemctl calls that change something: what a container.start or container.stop run does.
func (e *hpHost) writes() int {
	n := 0
	for _, v := range []string{"restart", "start", "stop", "daemon-reload"} {
		n += e.systemctl(v)
	}
	return n
}

func (e *hpHost) hasInstall(t *testing.T, service string) bool {
	t.Helper()
	text, err := e.m.Unit(service)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(text, "[Install]")
}

func TestModuleContainerFollowsTheModule(t *testing.T) {
	t.Parallel()
	for _, c := range moduleContainers {
		t.Run(c.service, func(t *testing.T) {
			e := startHPHost(t, false)
			e.m.InstallUnit(c.service, opstest.Digest('b'), true)
			reg := &flagReg{}
			f := e.follower(reg, c.module, c.service)
			ctx := t.Context()

			// Off: the container is stopped and the unit has no [Install] (a reboot must not bring it back).
			if err := f.ensureOff(ctx); err != nil {
				t.Fatalf("ensureOff: %v", err)
			}
			if got := e.state(t, c.service); got != api.UnitInactive || e.hasInstall(t, c.service) {
				t.Fatalf("off: unit %s, [Install] %v", got, e.hasInstall(t, c.service))
			}
			if err := f.ensureOff(ctx); err != nil { // idempotent
				t.Fatalf("second ensureOff: %v", err)
			}

			// On: started, with [Install] back; a second call neither fails nor restarts.
			reg.on.Store(true)
			if err := f.ensureOn(ctx); err != nil {
				t.Fatalf("ensureOn: %v", err)
			}
			if got := e.state(t, c.service); got != api.UnitActive || !e.hasInstall(t, c.service) {
				t.Fatalf("on: unit %s, [Install] %v", got, e.hasInstall(t, c.service))
			}
			restarts := e.systemctl("restart")
			if err := f.ensureOn(ctx); err != nil || e.systemctl("restart") != restarts {
				t.Fatalf("second ensureOn: %v, restarts %d -> %d", err, restarts, e.systemctl("restart"))
			}
		})
	}
}

// A switch between the guard's check and the host call wins: each func re-reads the module under the lock and does
// nothing, not even a host call, when the module is already in the other state.
func TestModuleContainerLooksAtTheModuleAgain(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	e.m.InstallUnit(api.ServiceSensor, opstest.Digest('b'), true)
	reg := &flagReg{}
	f := e.follower(reg, "sensor-passive", api.ServiceSensor)
	before := len(e.m.Calls("systemctl"))
	if err := f.ensureOn(t.Context()); err != nil { // the module is off
		t.Fatal(err)
	}
	reg.on.Store(true)
	if err := f.ensureOff(t.Context()); err != nil { // the module is on
		t.Fatal(err)
	}
	if n := len(e.m.Calls("systemctl")); n != before {
		t.Fatalf("%d systemctl calls for a module that was in the other state", n-before)
	}
	if e.state(t, api.ServiceSensor) != api.UnitInactive {
		// ensureOn on an off module did not start it; ensureOff on an on module did not stop it
		t.Fatalf("the container is %s", e.state(t, api.ServiceSensor))
	}
}

// A host that cannot stop the container is an error (the OffGuard retries, the module is not "off" yet); a box with no unit for
// the service has nothing to start, which is done, not a retry loop.
func TestModuleContainerHostFailuresAndNoUnit(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	e.m.InstallUnit(api.ServiceScan, opstest.Digest('b'), true)
	reg := &flagReg{}
	reg.on.Store(true)
	f := e.follower(reg, "sensor-active", api.ServiceScan)
	if err := f.ensureOn(t.Context()); err != nil {
		t.Fatal(err)
	}
	reg.on.Store(false)
	e.m.Rule("systemctl", "stop vedette-scan", "", 1, "stopfail", "")
	e.m.Mark("stopfail", true)
	if err := f.ensureOff(t.Context()); err == nil {
		t.Fatal("ensureOff said done while the container still runs")
	}
	if e.state(t, api.ServiceScan) != api.UnitActive {
		t.Fatalf("the container is %s", e.state(t, api.ServiceScan))
	}
	e.m.Mark("stopfail", false)
	if err := f.ensureOff(t.Context()); err != nil {
		t.Fatalf("ensureOff after the host recovered: %v", err)
	}

	// Sensor has no unit in this host: starting is nothing to do.
	reg.on.Store(true)
	g := e.follower(reg, "sensor-passive", api.ServiceSensor)
	if err := g.ensureOn(t.Context()); err != nil {
		t.Fatalf("ensureOn with no unit: %v", err)
	}
}

// Without a host socket (dev, a bare box) nothing follows.
func TestNoModuleContainersWithoutAHost(t *testing.T) {
	t.Parallel()
	if m := newModuleContainers(deps{}); m != nil {
		t.Fatalf("followers without a host: %v", m)
	}
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		<-time.After(20 * time.Millisecond)
	}
}

// M3 (D-260), the wiring: startGuards, the function serve calls, over a real Registry and the fake host. Core starting with a
// module off stops its container and drops [Install]; a real Publish of a switch-on starts it with [Install]; a switch-off stops
// it again. Without the OnChange subscription or without addContainerGuards one of these steps never happens.
func TestSwitchingTheSensorModulesMovesTheirContainers(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := startHPHost(t, false)
	db := storetest.New(t)
	wired := wiredModules()
	if err := migrateAll(ctx, db, wired); err != nil {
		t.Fatal(err)
	}
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: version, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	toggle := func(id string, on bool) {
		t.Helper()
		var ch modreg.Change
		err := db.Write(ctx, func(tx *sql.Tx) error {
			var err error
			if on {
				ch, err = reg.Enable(ctx, tx, "admin@acme.example", id, true)
			} else {
				ch, err = reg.Disable(ctx, tx, "admin@acme.example", id)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		reg.Publish(ch)
	}
	for _, c := range moduleContainers {
		e.m.InstallUnit(c.service, opstest.Digest('b'), true) // as the bootstrap writes them: with [Install], not running
		toggle(c.module, false)
	}
	stop := startGuards(ctx, reg, slog.New(slog.DiscardHandler), deps{HostSocket: e.h.Socket, Reg: reg, Log: testLogger()}, wired)
	defer stop()
	for _, c := range moduleContainers {
		eventually(t, c.service+" stopped without [Install] at start with the module off", func() bool {
			return e.state(t, c.service) == api.UnitInactive && !e.hasInstall(t, c.service)
		})
		toggle(c.module, true)
		eventually(t, c.service+" started with [Install] after the switch-on", func() bool {
			return e.state(t, c.service) == api.UnitActive && e.hasInstall(t, c.service)
		})
		toggle(c.module, false)
		eventually(t, c.service+" stopped without [Install] after the switch-off", func() bool {
			return e.state(t, c.service) == api.UnitInactive && !e.hasInstall(t, c.service)
		})
	}
}

// A unit that is active with [Install] is left alone whatever its health (systemd just started it on boot, it is in its health
// start period): no restart, no write run. A unit that is stopped without [Install] is left alone by the stop.
func TestModuleContainerSkipsWhatIsAlreadyRight(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	e.m.InstallUnit(api.ServiceSensor, opstest.Digest('b'), true)
	reg := &flagReg{}
	f := e.follower(reg, "sensor-passive", api.ServiceSensor)
	ctx := t.Context()

	reg.on.Store(true)
	if err := f.ensureOn(ctx); err != nil { // the first start: the unit was not running
		t.Fatal(err)
	}
	e.m.SetHealth(api.ServiceSensor, "starting")
	restarts, runs := e.systemctl("restart"), e.writes()
	for range 2 {
		if err := f.ensureOn(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.systemctl("restart"); n != restarts {
		t.Fatalf("a unit in its health start period was restarted (%d -> %d)", restarts, n)
	}
	if n := e.writes(); n != runs {
		t.Fatalf("ensureOn sent %d write runs for a unit that was already right", n-runs)
	}

	reg.on.Store(false)
	if err := f.ensureOff(ctx); err != nil {
		t.Fatal(err)
	}
	runs = e.writes()
	if err := f.ensureOff(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.writes(); n != runs {
		t.Fatalf("ensureOff sent %d write runs for a unit that was already stopped without [Install]", n-runs)
	}
}

// MED-4: the skips take only what the host vouches for. A unit that is there but is not byte-for-byte the host's own (the host
// reports Installed=false) is not "nothing to stop": the stop goes out, is refused unit_unsafe, and the error makes the OffGuard retry.
func TestModuleContainerDoesNotSkipAUnitTheHostDoesNotTrust(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	e.m.InstallUnit(api.ServiceSensor, opstest.Digest('b'), true)
	reg := &flagReg{}
	reg.on.Store(true)
	f := e.follower(reg, "sensor-passive", api.ServiceSensor)
	ctx := t.Context()
	if err := f.ensureOn(ctx); err != nil {
		t.Fatal(err)
	}
	text, err := e.m.Unit(api.ServiceSensor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.m.UnitsDir(), "vedette-sensor.container"), []byte(text+"# edited by hand\n"), 0o644); err != nil { //nolint:gosec // a unit file of the fake root, 0644 like the real ones
		t.Fatal(err)
	}
	reg.on.Store(false)
	if err := f.ensureOff(ctx); err == nil {
		t.Fatal("ensureOff said done for a unit the host does not trust, while the container still runs")
	}
	if e.state(t, api.ServiceSensor) != api.UnitActive {
		t.Fatalf("the container is %s", e.state(t, api.ServiceSensor))
	}
	reg.on.Store(true) // the same for the start: the refusal is an error to retry, not a silent skip
	if err := f.ensureOn(ctx); err == nil {
		t.Fatal("ensureOn said done for a unit the host does not trust")
	}
}

// MED-4: a unit state the host cannot name ("unknown") is never taken for running: the module is on, the container is down,
// the start goes out.
func TestModuleContainerStartsWhenTheUnitStateIsUnknown(t *testing.T) {
	t.Parallel()
	e := startHPHost(t, false)
	e.m.InstallUnit(api.ServiceSensor, opstest.Digest('b'), true) // with [Install], not running
	e.m.Rule("systemctl", "is-active vedette-sensor", "weird\n", 3, "weird-state", "")
	e.m.Mark("weird-state", true)
	reg := &flagReg{}
	reg.on.Store(true)
	f := e.follower(reg, "sensor-passive", api.ServiceSensor)
	before := e.writes()
	_ = f.ensureOn(t.Context()) // the fake keeps printing "weird", so the host may not see it settle; what matters is that it tried
	if e.writes() == before {
		t.Fatal("ensureOn sent no write for a unit whose state is unknown")
	}
}

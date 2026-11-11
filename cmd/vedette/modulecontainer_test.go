package main

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops/opstest"
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

func (e *hpHost) hasInstall(t *testing.T, service string) bool {
	t.Helper()
	text, err := e.m.Unit(service)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(text, "[Install]")
}

func TestModuleContainerFollowsTheModule(t *testing.T) {
	t.Setenv("TZ", "UTC")
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
	t.Setenv("TZ", "UTC")
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
	t.Setenv("TZ", "UTC")
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

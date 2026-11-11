package main

import (
	"context"
	"sync"

	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/host/api"
)

// moduleContainer makes a module's container follow the module, the way the honeypot's does (M3, D-260): `sensor` runs
// exactly while sensor-passive is on and `scan` exactly while sensor-active is on. These two modules have no job that
// could do it (the packets and the probes run inside the container), so core's two guards do it, with the same host
// operations and the same retry as the honeypot's teardown (D-189):
//
//   - on (core starts with the module on, and after every switch-on): container.start of the current image, unless the
//     host's state says there is nothing to do: the unit has [Install] and is running or still coming up (its health start
//     period), whatever its health, so a container that systemd has just started on boot is never restarted and the host's one
//     write slot is not held for minutes. A unit that is down, or that lost its [Install], gets the start;
//   - off (core starts with the module off, and after every switch-off): container.stop with persist, so the unit loses
//     [Install] and a reboot does not bring it back, unless the state says it is already stopped and without [Install].
//
// The state is a read (GET /v1/state/containers: it counts against the host's request budget, not the 10 writes a minute);
// a failed read falls through to the write, so "unknown" is never taken for done. Both are idempotent, retried with backoff
// until the host has confirmed, cancelled by the opposite switch, and re-check the module under mu before they touch the
// host, so a quick off-on never ends with the container down while the module is on (or the reverse). A module's units
// keep [Install]: it is the guards, not boot, that decide, and core reconciles at its own start. An unknown outcome (a lost
// answer, a timeout, a busy host) is retried, never taken for done.
type moduleContainer struct {
	h       *honeypotHost // its do(): follows the run to its end and sorts the outcome, as for the honeypot
	reg     interface{ Enabled(id string) bool }
	module  string
	service string
	mu      sync.Mutex
}

// ensureOn is the func of the OnGuard.
func (c *moduleContainer) ensureOn(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.reg.Enabled(c.module) { // checked under the lock: a switch-off between the guard's check and the host call wins
		return nil
	}
	if st, ok := c.state(ctx); ok && (!st.Installed || (st.Enabled && !isDown(st.UnitState))) {
		return nil // no unit to start (see below), or running / coming up with [Install]: systemd's Restart= owns it
	}
	// not_pulled (this box has no unit for the service: not installed, or the scan build was skipped) is "nothing to
	// start": retrying it every few minutes would only fill the log. Any other refusal or unknown outcome is retried.
	return c.h.do(ctx, api.CmdContainerStart, api.ContainerStartArgs{Service: c.service}, api.CodeNotPulled)
}

// state is the host's look at the service; ok is false when it cannot be read (the caller then acts, it does not skip).
func (c *moduleContainer) state(ctx context.Context) (api.ContainerState, bool) {
	st, err := c.h.api.StateContainers(ctx)
	if err != nil {
		return api.ContainerState{}, false
	}
	for _, s := range st.Services {
		if s.Service == c.service {
			return s, true
		}
	}
	return api.ContainerState{}, false
}

func isDown(unitState string) bool {
	return unitState == api.UnitInactive || unitState == api.UnitFailed
}

// ensureOff is the Teardown of the OffGuard.
func (c *moduleContainer) ensureOff(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reg.Enabled(c.module) {
		return nil
	}
	if st, ok := c.state(ctx); ok && (!st.Installed || (!st.Enabled && isDown(st.UnitState))) {
		return nil // nothing to stop, or already stopped and without [Install]
	}
	return c.h.do(ctx, api.CmdContainerStop, api.ContainerStopArgs{Service: c.service, Persist: true}, "")
}

// moduleContainers are the modules whose container follows them, by the service they run.
var moduleContainers = []struct{ module, service string }{
	{"sensor-passive", api.ServiceSensor},
	{"sensor-active", api.ServiceScan},
}

// newModuleContainers builds one follower per entry of moduleContainers; nil without a host socket (dev and a bare box,
// D-55: there is no container to follow).
func newModuleContainers(d deps) map[string]*moduleContainer {
	if d.HostSocket == "" || d.Reg == nil {
		return nil
	}
	out := map[string]*moduleContainer{}
	for _, m := range moduleContainers {
		h, ok := newHoneypotHost(&d).(*honeypotHost) // one adapter each: its own name in the logs, its own warning rate limit
		if !ok {
			return nil
		}
		h.who = m.service
		out[m.module] = &moduleContainer{h: h, reg: d.Reg, module: m.module, service: m.service}
	}
	return out
}

// addContainerGuards hands each follower's two funcs to the guards (on: start, off: stop persist).
func addContainerGuards(on, off *modreg.OffGuard, d deps) {
	for id, c := range newModuleContainers(d) {
		off.Add(id, c.ensureOff)
		on.Add(id, c.ensureOn)
	}
}

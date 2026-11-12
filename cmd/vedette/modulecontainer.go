package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/host/api"
)

// moduleContainer makes a module's container follow the module, the way the honeypot's does (M3, D-260): `sensor` runs
// exactly while sensor-passive is on and `scan` exactly while sensor-active is on. These two modules have no job that
// could do it (the packets and the probes run inside the container), so core's two guards do it, with the same host
// operations and the same retry as the honeypot's teardown (D-189):
//
//   - on (core starts with the module on, and after every switch-on): container.start of the current image (of core's own
//     version when the host last pulled that for the service, D-342 (2), see startVersion), unless the
//     host's state says there is nothing to do: the host trusts the unit (Installed), it has [Install], and it is active or
//     coming up ("other"; its health start period, whatever its health), so a container that systemd has just started on boot
//     is never restarted and the host's one write slot is not held for minutes. Only a positive answer of the host leads to
//     the start: a unit that is down (inactive, failed), that lost its [Install], or that the host does not call its own
//     (missing: not_pulled, nothing to start; edited: refused unit_unsafe and retried). A read that fails (rate_limited, a
//     host that does not answer, a read that timed out) or a unit whose state systemd could not tell ("unknown") is an error
//     for the guard to retry, not a start: the start of a running container restarts it whenever the host does not see it
//     healthy, and the sensor is not healthy while core, which takes its heartbeats, is down. That is what an update did
//     (lab ubuntu2404, 2026-11-12: one extra restart of a running sensor after each update's core restart, none after a plain
//     restart of core). The wait is bounded: once the state has stayed unreadable (failed reads, a host answer that does not
//     list the service, "unknown") for unsureFor since the first such read, the start goes out anyway, so a box whose reads
//     are refused or fail fast, a host that does not list the service (a core/host version skew) or a unit_state that stays
//     unknown still gets a down container started, as before (a read that times out uses up the attempt's context, so the
//     start then fails too, as it did before). A good read resets the wait. Each start logs, at WARN and rate limited, which field of the host's answer
//     called for it, or "state unreadable for <how long>";
//   - off (core starts with the module off, and after every switch-off): container.stop with persist, so the unit loses
//     [Install] and a reboot does not bring it back, unless the host trusts the unit and says it is already stopped and
//     without [Install]. Here a failed read does go on to the stop: stopping is what "off" means (SYS-5) and costs a running
//     module nothing.
//
// The state is a read (GET /v1/state/containers: it counts against the host's request budget, 60 a minute for all of core,
// not the 10 writes a minute); "unknown" is never taken for done. Both are idempotent, retried with backoff
// until the host has confirmed, cancelled by the opposite switch, and re-check the module under mu before they touch the
// host, so a quick off-on never ends with the container down while the module is on (or the reverse). A module's units
// keep [Install]: it is the guards, not boot, that decide, and core reconciles at its own start. An unknown outcome (a lost
// answer, a timeout, a busy host) is retried, never taken for done.
type moduleContainer struct {
	h       *honeypotHost // its do(): follows the run to its end and sorts the outcome, as for the honeypot
	reg     interface{ Enabled(id string) bool }
	module  string
	service string
	version string           // the build version of core (main.version); see startVersion
	now     func() time.Time // nil: time.Now; a test moves it

	mu sync.Mutex
	// unsureSince is when ensureOn first found the state unreadable since the last good read (zero: it was readable). Reset
	// by a good read, a start the host confirmed and ensureOff, so a later switch-on waits its own unsureFor again.
	unsureSince time.Time
}

// unsureFor bounds how long ensureOn waits for a readable state before it starts the container anyway. The window it must
// ride out is an update's core restart (~35 s in the lab, a 60 s health start period); with modreg.OffBackoff (10 s, 30 s,
// 2 min, ...) the attempt at 2 min 40 s is the first past it. ponytail: one fixed bound, made a setting only if a box needs it.
const unsureFor = 2 * time.Minute

func (c *moduleContainer) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// ensureOn is the func of the OnGuard.
func (c *moduleContainer) ensureOn(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.reg.Enabled(c.module) { // checked under the lock: a switch-off between the guard's check and the host call wins
		c.unsureSince = time.Time{} // the next switch-on waits its own unsureFor
		return nil
	}
	// Skip only what the host vouches for: a unit it trusts (Installed), with [Install], that is active or coming up, running the
	// version pulled for it when that is core's own (D-342 (2)). Start only on what it positively says is wrong. Anything else
	// is unknown: an error, so the guard reads again after its backoff, until it has been unknown for unsureFor.
	st, err := c.state(ctx)
	v := c.startVersion(st, err == nil)
	why := ""
	if err == nil {
		why = startReason(st)
		if why == "" && v != "" && (st.Version == nil || *st.Version != v) { // a unit running another version than the one pulled for it is not done
			why = "version=" + versionOf(st.Version) + ", pulled " + v
		}
	}
	if err != nil || why == unitStateUnknown {
		now := c.clock()
		if c.unsureSince.IsZero() {
			c.unsureSince = now
		}
		waited := now.Sub(c.unsureSince)
		if waited < unsureFor {
			if err != nil {
				return fmt.Errorf("%w; will read again before any start", err)
			}
			return fmt.Errorf("%s: the host could not tell whether its unit runs (unit_state unknown); will read again before any start", c.service)
		}
		cause := why
		if err != nil {
			cause = err.Error()
		}
		why = "state unreadable for " + waited.Round(time.Second).String()
		if c.h.warnDue("start state unreadable") { // one key: the duration in why changes every attempt
			c.h.log.WarnContext(ctx, "container host: starting a module's container, its state has been unreadable too long", "service", c.service,
				"module", c.module, "reason", why, "cause", cause)
		}
	} else {
		c.unsureSince = time.Time{}
		if why == "" {
			return nil // running / coming up with [Install]: systemd's Restart= owns it
		}
		if c.h.warnDue("start " + why) {
			c.h.log.WarnContext(ctx, "container host: starting a module's container, the host's state calls for it", "service", c.service,
				"module", c.module, "reason", why, "unit_state", st.UnitState, "health", st.Health)
		}
	}
	if err := c.start(ctx, v); err != nil {
		return err
	}
	c.unsureSince = time.Time{}
	return nil
}

// start sends container.start: of version v first when it is set, then of the image the unit pins.
func (c *moduleContainer) start(ctx context.Context, v string) error {
	if v != "" {
		// The host judges a version more strictly than the current image (not_pulled, current_version_unknown, upgrade_path_required,
		// a revoked release...). Such a refusal must not leave the module without a container, so it falls back to the image the unit
		// pins, as before D-342 (2); a busy host or an unknown outcome is not a refusal and is retried.
		err := c.h.do(ctx, api.CmdContainerStart, api.ContainerStartArgs{Service: c.service, Version: v}, "")
		var re refusedError
		if !errors.As(err, &re) {
			return err
		}
	}
	// not_pulled (this box has no unit for the service: not installed, or the scan build was skipped) is "nothing to
	// start": retrying it every few minutes would only fill the log. Any other refusal or unknown outcome is retried.
	return c.h.do(ctx, api.CmdContainerStart, api.ContainerStartArgs{Service: c.service}, api.CodeNotPulled)
}

func versionOf(v *string) string {
	if v == nil {
		return "null"
	}
	return *v
}

const unitStateUnknown = "unit_state=" + api.UnitUnknown

// startReason names the field of the host's answer that calls for a start: "" when the host vouches that the unit is
// right (trusted, with [Install], active or coming up), unitStateUnknown when systemd could not tell (not a reason to
// start: a retry). A unit the host does not call its own goes to the start whatever its state: the host refuses it
// (not_pulled, unit_unsafe) before it touches systemd.
func startReason(st api.ContainerState) string {
	switch {
	case !st.Installed:
		return "installed=false"
	case st.UnitState == api.UnitUnknown:
		return unitStateUnknown
	case !st.Enabled:
		return "enabled=false"
	case st.UnitState == api.UnitActive || st.UnitState == api.UnitOther:
		return ""
	}
	return "unit_state=" + st.UnitState
}

// startVersion is the version core asks the host to start (D-342 (2)). An update pulls a service whose module is off but does
// not start it, so the unit still pins the old image; starting the unit as it is would run a sensor or scan that core answers
// 426 (protocol mismatch). When the host says the version it last pulled for the service is core's own, that is sent; the host
// repoints the unit, and only a pulled version is accepted (not_pulled otherwise, which would make a box that was never
// updated unable to start). Nothing pulled, another version pulled or a state that cannot be read: "" = the current image.
func (c *moduleContainer) startVersion(st api.ContainerState, ok bool) string {
	if ok && st.LatestPulled != nil && st.LatestPulled.Version != nil && *st.LatestPulled.Version == c.version {
		return c.version
	}
	return ""
}

// state is the host's look at the service; an error when it cannot be read (rate_limited, no answer, a read that timed
// out, a host that does not list the service).
func (c *moduleContainer) state(ctx context.Context) (api.ContainerState, error) {
	st, err := c.h.api.StateContainers(ctx)
	if err != nil {
		return api.ContainerState{}, fmt.Errorf("%s: the host's container state could not be read: %w", c.service, err)
	}
	for _, s := range st.Services {
		if s.Service == c.service {
			return s, nil
		}
	}
	return api.ContainerState{}, fmt.Errorf("%s: the host's container state does not list the service", c.service)
}

func isDown(unitState string) bool {
	return unitState == api.UnitInactive || unitState == api.UnitFailed
}

// ensureOff is the Teardown of the OffGuard.
func (c *moduleContainer) ensureOff(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unsureSince = time.Time{} // the next switch-on waits its own unsureFor, even after a quick off-on
	if c.reg.Enabled(c.module) {
		return nil
	}
	// Skip only a unit the host trusts that is already stopped and without [Install]; an untrusted or missing unit, or a
	// state that cannot be read, goes to the stop (a missing one succeeds at once, an edited one is refused unit_unsafe,
	// logged and retried).
	if st, err := c.state(ctx); err == nil && st.Installed && !st.Enabled && isDown(st.UnitState) {
		return nil // already stopped and without [Install]
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
		out[m.module] = &moduleContainer{h: h, reg: d.Reg, module: m.module, service: m.service, version: version}
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

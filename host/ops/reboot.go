package ops

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// Reboot limits (spec 6.4, section 10). Every reboot the host starts, immediate or scheduled,
// counts toward the limit, so a hijacked core cannot loop reboots by scheduling one a minute out.
const (
	rebootMinLead   = 60 * time.Second
	rebootMaxLead   = 7 * 24 * time.Hour
	rebootNowLimit  = 3
	rebootWindow    = 24 * time.Hour
	rebootStaleAt   = 5 * time.Minute // a schedule found this late after a host restart is dropped, not run
	rebootRetryBusy = time.Minute
	rebootGateTTL   = 10 * time.Minute // a started reboot that has not happened this long after is assumed not to be coming
	// A started reboot that logind refuses because of a block inhibitor (apt running, D-453) is tried again
	// this often, for this long, with the write gate raised again at every try; then it is given up.
	rebootInhibitRetry = 30 * time.Second
	rebootInhibitWait  = 30 * time.Minute
)

// rebootGate is set from the moment the host decides to reboot until the boot id changes: every
// write command is refused with 409 rebooting meanwhile, so core cannot interrupt dpkg (or a
// restore) by queueing work that the shutdown would kill halfway.
type rebootGate struct {
	BootID string
	At     time.Time
}

// WriteGate is the server's Options.WriteGate: a refusal while a reboot is under way, nil otherwise.
// It reads an atomic and the boot id, takes no lock, and never blocks.
func (o *Ops) WriteGate() *server.Refusal {
	if r := o.selfUpdateGate(); r != nil {
		return r
	}
	g := o.gate.Load()
	if g == nil {
		return nil
	}
	if cur := o.bootID(); cur != "" && g.BootID != "" && cur != g.BootID {
		o.gate.CompareAndSwap(g, nil) // the box rebooted: this is the new boot
		return nil
	}
	if el := o.d.Now().Sub(g.At); el >= rebootGateTTL || el <= -rebootGateTTL {
		o.gate.CompareAndSwap(g, nil) // the reboot did not happen
		return nil
	}
	return refuse409(api.CodeRebooting, "The box is about to reboot; commands that change it are refused until it is back.")
}

func (o *Ops) raiseGate(at time.Time) { o.gate.Store(&rebootGate{BootID: o.bootID(), At: at}) }

type rebootSchedule struct {
	At     time.Time `json:"at"`
	SetAt  time.Time `json:"set_at"`
	BootID string    `json:"boot_id"`
}

type rebootPending struct {
	BootID    string    `json:"boot_id"`
	StartedAt time.Time `json:"started_at"`
	Kind      string    `json:"kind"` // "now" | "scheduled"
	// Issued: systemctl reboot was accepted, so the box is going down (D-453). Until then the host may still be
	// waiting for a shutdown lock, and a host start on the same boot finds a reboot that will not come.
	Issued bool `json:"issued,omitempty"`
}

// rebootState is reboot.json: the one schedule, the reboots the host started in the last 24 hours,
// and the reboot it is waiting to see complete.
type rebootState struct {
	Schedule *rebootSchedule `json:"schedule,omitempty"`
	Started  []time.Time     `json:"started"`
	Pending  *rebootPending  `json:"pending,omitempty"`
}

func (o *Ops) rebootPath() string { return o.stateFile("os", "reboot.json") }

// loadRebootLocked reads reboot.json (a missing or unreadable file is the empty state; the host
// must not refuse to work because of it). Caller holds rbMu.
func (o *Ops) loadRebootLocked() rebootState {
	var st rebootState
	if err := readJSONFile(o.rebootPath(), &st); err != nil && !errors.Is(err, os.ErrNotExist) {
		o.log.Warn("reboot state is unreadable; starting empty")
		return rebootState{}
	}
	return st
}

func (o *Ops) saveRebootLocked(st rebootState) error {
	if st.Started == nil {
		st.Started = []time.Time{}
	}
	return writeJSONAtomic(o.rebootPath(), st)
}

func recentStarts(st rebootState, now time.Time) int {
	n := 0
	for _, t := range st.Started {
		// A start dated in the future (the clock went back) still counts: setting the clock back
		// must not reset the limit.
		if now.Sub(t) < rebootWindow {
			n++
		}
	}
	return n
}

func pruneStarts(st *rebootState, now time.Time) {
	kept := st.Started[:0]
	for _, t := range st.Started {
		if now.Sub(t) < rebootWindow {
			kept = append(kept, t)
		}
	}
	st.Started = kept
}

// scheduledAt is the time of the scheduled reboot, nil when none.
func (o *Ops) scheduledAt() *time.Time {
	o.rbMu.Lock()
	defer o.rbMu.Unlock()
	if st := o.loadRebootLocked(); st.Schedule != nil {
		t := st.Schedule.At
		return &t
	}
	return nil
}

// cmdReboot is os.reboot (spec 6.4).
func (o *Ops) cmdReboot() server.Command {
	return server.Define(server.Spec[api.OSRebootArgs]{
		Name: api.CmdOSReboot, Write: true, Timeout: 30 * time.Second,
		Validate: func(a *api.OSRebootArgs) error {
			switch a.When {
			case "now":
				if a.At != "" {
					return server.Invalid("at", "must be empty when when is now")
				}
			case "at":
				t, err := time.Parse(time.RFC3339, a.At)
				if err != nil {
					return server.Invalid("at", "must be an RFC 3339 time")
				}
				a.At = t.UTC().Format(time.RFC3339)
			default:
				return server.Invalid("when", "must be now or at")
			}
			return nil
		},
		Check: func(ctx context.Context, a api.OSRebootArgs) error {
			if o.installing.Load() {
				return refuse409(api.CodeInstallInProgress, "An operating system install is running; reboot after it ends.")
			}
			if o.netPending() {
				return refuse409(api.CodeNetPendingConfirm, "A network change is waiting for confirmation; do not reboot until it is confirmed or reverted.")
			}
			now := o.d.Now()
			if a.When == "at" {
				at, _ := time.Parse(time.RFC3339, a.At)
				switch {
				case at.Before(now.Add(rebootMinLead)):
					return refuse412(api.CodeAtInPast, "The reboot time must be at least 60 seconds from now.")
				case at.After(now.Add(rebootMaxLead)):
					return refuse412(api.CodeAtTooFar, "The reboot time must be within 7 days.")
				}
				return nil
			}
			o.rbMu.Lock()
			n := recentStarts(o.loadRebootLocked(), now)
			o.rbMu.Unlock()
			if n >= rebootNowLimit {
				return refuse409(api.CodeRebootLimit, "The box already rebooted 3 times in the last 24 hours.")
			}
			// A block inhibitor (apt installing) refuses now (D-453). An unknown list does not (logged once):
			// doReboot reads it again before systemctl reboot, and systemd 257 and later also refuse a locked
			// reboot themselves (255 does not, for root).
			bl, err := o.shutdownBlockers(ctx, inhibitReadCheck)
			if err != nil {
				return nil
			}
			if len(bl) > 0 {
				return refuse409(api.CodeRebootInhibited, inhibitedMessage(bl))
			}
			return nil
		},
		Run: func(_ context.Context, rc *server.RunContext, a api.OSRebootArgs) (any, error) {
			if a.When == "at" {
				at, _ := time.Parse(time.RFC3339, a.At)
				if err := o.setSchedule(at); err != nil {
					return nil, fail("state_unwritable", "The reboot schedule could not be saved.")
				}
				rc.Log("Reboot scheduled")
				return api.OSRebootResult{When: "at", At: &at}, nil
			}
			if err := o.markRebootStarted("now"); err != nil {
				return nil, fail("state_unwritable", "The reboot could not be recorded, so it was not started.")
			}
			rc.Log("Rebooting after this run is recorded")
			// The run must be recorded as succeeded before the machine goes down (spec 6.4).
			rc.AfterFinish(func(ctx context.Context, st api.Status) {
				if st == api.StatusSucceeded {
					o.doReboot(ctx, "now")
					return
				}
				o.clearPending()
			})
			return api.OSRebootResult{When: "now"}, nil
		},
	})
}

// cmdRebootCancel is os.reboot.cancel: no schedule is a success that does nothing.
func (o *Ops) cmdRebootCancel() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdOSRebootCancel, Write: true, Timeout: 30 * time.Second,
		Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			o.rbMu.Lock()
			defer o.rbMu.Unlock()
			st := o.loadRebootLocked()
			if st.Schedule == nil {
				return nil, nil
			}
			st.Schedule = nil
			if o.stopTick != nil {
				o.stopTick()
				o.stopTick = nil
			}
			if err := o.saveRebootLocked(st); err != nil {
				return nil, fail("state_unwritable", "The reboot schedule could not be cleared.")
			}
			rc.Log("Scheduled reboot cancelled")
			return nil, nil
		},
	})
}

// setSchedule replaces the one schedule and arms the timer.
func (o *Ops) setSchedule(at time.Time) error {
	o.rbMu.Lock()
	defer o.rbMu.Unlock()
	st := o.loadRebootLocked()
	st.Schedule = &rebootSchedule{At: at, SetAt: o.d.Now().UTC(), BootID: o.bootID()}
	if err := o.saveRebootLocked(st); err != nil {
		return err
	}
	o.rbWaitNoted = false // a new schedule audits its own wait for a shutdown lock
	o.armRebootLocked(at)
	return nil
}

// armRebootLocked (re)arms the timer for at. Caller holds rbMu.
func (o *Ops) armRebootLocked(at time.Time) {
	if o.stopTick != nil {
		o.stopTick()
	}
	d := max(at.Sub(o.d.Now()), 0)
	o.stopTick = o.d.AfterFunc(d, o.fireScheduled)
}

// markRebootStarted records a reboot the host is about to start: the count toward the 24 hour
// limit and the boot id to compare after the next boot.
func (o *Ops) markRebootStarted(kind string) error {
	o.rbMu.Lock()
	defer o.rbMu.Unlock()
	return o.markStartedLocked(o.loadRebootLocked(), kind)
}

func (o *Ops) markStartedLocked(st rebootState, kind string) error {
	now := o.d.Now().UTC()
	pruneStarts(&st, now)
	st.Started = append(st.Started, now)
	st.Pending = &rebootPending{BootID: o.bootID(), StartedAt: now, Kind: kind}
	if err := o.saveRebootLocked(st); err != nil {
		return err
	}
	o.raiseGate(now) // durable first (reboot.json), then refuse writes
	return nil
}

func (o *Ops) clearPending() {
	o.rbMu.Lock()
	defer o.rbMu.Unlock()
	st := o.loadRebootLocked()
	st.Pending = nil
	o.gate.Store(nil)
	if err := o.saveRebootLocked(st); err != nil {
		o.log.Error("could not clear the pending reboot")
	}
}

// doReboot audits and runs systemctl reboot. It is the only place the host reboots the machine. It never
// passes --check-inhibitors=no or --force (D-453): rebooting while dpkg configures can leave packages broken.
func (o *Ops) doReboot(ctx context.Context, kind string) {
	o.note("os.reboot", "reboot_started", map[string]any{"kind": kind})
	o.tryReboot(ctx, kind, o.d.Now().Add(rebootInhibitWait), false)
}

// tryReboot reads logind's list and, when no block inhibitor is held, runs systemctl reboot once. The read
// comes first on every try because systemd 255 (Ubuntu 24.04) lets root reboot past a block lock of uid 0,
// which APT's is: there the host's own read is the only guard (D-453). A lock in the list before the call, or
// in the list read again after a failed call (systemd 257 and later refuse; systemctl's text is never parsed),
// raises the write gate again and tries again in rebootInhibitRetry until deadline; the wait is audited once
// (reboot_waiting_inhibitor). Any other failure, an unknown list after a failure, or the deadline:
// reboot_failed with the reason, and the gate comes down. An unknown list before the call does not stop it.
func (o *Ops) tryReboot(ctx context.Context, kind string, deadline time.Time, waitNoted bool) {
	bl, lerr := o.shutdownBlockers(ctx, inhibitReadWait)
	inhibited := lerr == nil && len(bl) > 0
	code := 0
	if !inhibited {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var err error
		_, code, err = o.exec(rctx, binSystemctl, "reboot")
		cancel()
		if err == nil && code == 0 {
			o.markIssued()
			return
		}
		bl, lerr = o.shutdownBlockers(ctx, inhibitReadWait)
		inhibited = lerr == nil && len(bl) > 0
	}
	if now := o.d.Now(); inhibited && now.Before(deadline) {
		if !waitNoted {
			o.log.WarnContext(ctx, "the reboot waits for a shutdown lock", "kind", kind, "who", bl[0].Who, "why", bl[0].Why)
			o.note("os.reboot", "reboot_waiting_inhibitor", inhibitDetail(kind, bl))
		}
		o.raiseGate(now.UTC()) // keep refusing writes past the gate's 10 minutes while the reboot waits
		o.rbMu.Lock()
		if o.stopRetry != nil {
			o.stopRetry() // the try that is running now (a fired timer; stopping it does nothing more)
		}
		o.stopRetry = o.d.AfterFunc(rebootInhibitRetry, func() {
			if o.isClosed() {
				return // the host is stopping; the next start drops the pending reboot (startReboot)
			}
			o.tryReboot(ctx, kind, deadline, true) // AfterFinish's context is never cancelled; the scheduled path's is Background
		})
		o.rbMu.Unlock()
		return
	}
	reason := "systemctl_failed"
	if inhibited {
		reason = "inhibited"
	}
	o.log.ErrorContext(ctx, "systemctl reboot failed", "kind", kind, "exit_code", code, "reason", reason)
	d := inhibitDetail(kind, bl)
	d["reason"] = reason
	o.note("os.reboot", "reboot_failed", d)
	o.clearPending()
}

// markIssued records that systemctl reboot was accepted (rebootPending.Issued).
func (o *Ops) markIssued() {
	o.rbMu.Lock()
	defer o.rbMu.Unlock()
	st := o.loadRebootLocked()
	if st.Pending == nil {
		return
	}
	st.Pending.Issued = true
	if err := o.saveRebootLocked(st); err != nil {
		o.log.Error("could not record that the reboot was issued")
	}
}

func (o *Ops) isClosed() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed
}

// gateThenBusy raises the write gate and only then asks whether a command is running. The server
// checks the gate and claims its write lock in one locked section, so a write is either already
// running here (the gate is lifted and the caller postpones) or refused by the gate; none can be
// accepted between the check and the gate. When it returns false the gate stays raised and the
// caller must lower it again if it then decides not to reboot.
func (o *Ops) gateThenBusy() bool {
	o.raiseGate(o.d.Now().UTC())
	if o.writeActive() || o.installing.Load() {
		o.gate.Store(nil)
		return true
	}
	return false
}

// fireScheduled runs when the timer of the scheduled reboot goes off.
func (o *Ops) fireScheduled() {
	// A block inhibitor (apt installing) postpones a due scheduled reboot like a running command does (D-453):
	// the schedule stays (reboot_scheduled_at), the wait is audited once, and the 24 hour expiry bounds it. The
	// list is read first, outside rbMu and before the write gate goes up, so the minute-by-minute waits never
	// hold either. An unknown list goes on; doReboot reads it again before systemctl reboot.
	var bl []inhibitor
	if at := o.scheduledAt(); at != nil && !o.d.Now().Before(*at) {
		bl, _ = o.shutdownBlockers(context.Background(), inhibitReadWait)
	}
	o.rbMu.Lock()
	st := o.loadRebootLocked()
	sch := st.Schedule
	if sch == nil {
		o.rbMu.Unlock()
		return
	}
	now := o.d.Now()
	switch {
	case now.Before(sch.At):
		o.armRebootLocked(sch.At) // the clock moved or the timer fired early
		o.rbMu.Unlock()
		return
	case now.Sub(sch.At) > 24*time.Hour:
		st.Schedule = nil
		_ = o.saveRebootLocked(st)
		o.rbMu.Unlock()
		o.note("os.reboot", "reboot_schedule_expired", map[string]any{"at": sch.At.Format(time.RFC3339)})
		return
	case len(bl) > 0:
		if o.stopTick != nil {
			o.stopTick()
		}
		o.stopTick = o.d.AfterFunc(rebootRetryBusy, o.fireScheduled)
		first := !o.rbWaitNoted
		o.rbWaitNoted = true
		o.rbMu.Unlock()
		if first {
			o.log.Warn("the scheduled reboot waits for a shutdown lock", "who", bl[0].Who, "why", bl[0].Why)
			o.note("os.reboot", "reboot_waiting_inhibitor", inhibitDetail("scheduled", bl))
		}
		return
	case o.gateThenBusy():
		if o.stopTick != nil {
			o.stopTick()
		}
		o.stopTick = o.d.AfterFunc(rebootRetryBusy, o.fireScheduled) // a command is running: wait for it
		o.rbMu.Unlock()
		return
	case recentStarts(st, now) >= rebootNowLimit:
		o.gate.Store(nil)
		st.Schedule = nil
		_ = o.saveRebootLocked(st)
		o.rbMu.Unlock()
		o.note("os.reboot", "reboot_skipped_limit", map[string]any{"at": sch.At.Format(time.RFC3339)})
		return
	}
	o.rbWaitNoted = false
	st.Schedule = nil
	o.stopTick = nil
	err := o.markStartedLocked(st, "scheduled")
	o.rbMu.Unlock()
	if err != nil {
		o.gate.Store(nil)
		o.log.Error("could not record the scheduled reboot; not rebooting")
		return
	}
	o.doReboot(context.Background(), "scheduled")
}

// startReboot runs at host start-up: it notices that a reboot the host started has completed (the
// kernel's boot id changed), and re-arms or drops the schedule.
func (o *Ops) startReboot() {
	o.rbMu.Lock()
	st := o.loadRebootLocked()
	cur := o.bootID()
	var notes []func()
	if p := st.Pending; p != nil {
		if cur != "" && p.BootID != "" && p.BootID != cur {
			kind, started := p.Kind, p.StartedAt.Format(time.RFC3339)
			notes = append(notes, func() {
				o.note("os.reboot", "reboot_completed", map[string]any{"kind": kind, "started_at": started})
			})
		}
		switch {
		case cur != "" && p.BootID == cur && p.Issued && o.d.Now().Sub(p.StartedAt) < rebootGateTTL && o.d.Now().Sub(p.StartedAt) > -rebootGateTTL:
			// The host restarted while the box was shutting down: keep refusing writes.
			o.gate.Store(&rebootGate{BootID: p.BootID, At: p.StartedAt})
		case cur != "" && p.BootID == cur:
			// Same boot: the reboot never happened (it was not issued yet, e.g. waiting for a shutdown lock, or it
			// was issued long ago). Nothing re-arms it; say so instead of dropping it silently (D-453).
			st.Pending = nil
			kind, started, issued := p.Kind, p.StartedAt.Format(time.RFC3339), p.Issued
			notes = append(notes, func() {
				o.note("os.reboot", "reboot_failed", map[string]any{"kind": kind, "reason": "host_restarted", "started_at": started, "issued": issued})
			})
		default:
			st.Pending = nil // a new boot (reboot_completed above), or a boot id that cannot be read
		}
	}
	if sch := st.Schedule; sch != nil {
		now := o.d.Now()
		switch {
		case cur != "" && sch.BootID != "" && sch.BootID != cur:
			st.Schedule = nil // the box rebooted since: the reason for the reboot is gone
			notes = append(notes, func() { o.note("os.reboot", "reboot_schedule_dropped", map[string]any{"reason": "new_boot"}) })
		case now.Sub(sch.At) > rebootStaleAt:
			st.Schedule = nil
			at := sch.At.Format(time.RFC3339)
			notes = append(notes, func() { o.note("os.reboot", "reboot_schedule_expired", map[string]any{"at": at}) })
		default:
			o.armRebootLocked(sch.At)
		}
	}
	if err := o.saveRebootLocked(st); err != nil {
		o.log.Error("could not save the reboot state at start-up")
	}
	o.rbMu.Unlock()
	for _, n := range notes {
		n()
	}
}

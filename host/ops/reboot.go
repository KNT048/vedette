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
)

type rebootSchedule struct {
	At     time.Time `json:"at"`
	SetAt  time.Time `json:"set_at"`
	BootID string    `json:"boot_id"`
}

type rebootPending struct {
	BootID    string    `json:"boot_id"`
	StartedAt time.Time `json:"started_at"`
	Kind      string    `json:"kind"` // "now" | "scheduled"
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
		if now.Sub(t) < rebootWindow && !t.After(now.Add(time.Minute)) {
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
		Check: func(_ context.Context, a api.OSRebootArgs) error {
			if o.installing.Load() {
				return refuse409(api.CodeInstallInProgress, "An operating system install is running; reboot after it ends.")
			}
			if o.d.NetPending() {
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
	return o.saveRebootLocked(st)
}

func (o *Ops) clearPending() {
	o.rbMu.Lock()
	defer o.rbMu.Unlock()
	st := o.loadRebootLocked()
	st.Pending = nil
	if err := o.saveRebootLocked(st); err != nil {
		o.log.Error("could not clear the pending reboot")
	}
}

// doReboot audits and runs systemctl reboot. It is the only place the host reboots the machine.
func (o *Ops) doReboot(ctx context.Context, kind string) {
	o.note("os.reboot", "reboot_started", map[string]any{"kind": kind})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, code, err := o.exec(ctx, binSystemctl, "reboot")
	if err != nil || code != 0 {
		o.log.ErrorContext(ctx, "systemctl reboot failed", "kind", kind, "exit_code", code)
		o.note("os.reboot", "reboot_failed", map[string]any{"kind": kind})
		o.clearPending()
	}
}

// fireScheduled runs when the timer of the scheduled reboot goes off.
func (o *Ops) fireScheduled() {
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
	case o.writeActive() || o.installing.Load():
		if o.stopTick != nil {
			o.stopTick()
		}
		o.stopTick = o.d.AfterFunc(rebootRetryBusy, o.fireScheduled) // a command is running: wait for it
		o.rbMu.Unlock()
		return
	case recentStarts(st, now) >= rebootNowLimit:
		st.Schedule = nil
		_ = o.saveRebootLocked(st)
		o.rbMu.Unlock()
		o.note("os.reboot", "reboot_skipped_limit", map[string]any{"at": sch.At.Format(time.RFC3339)})
		return
	}
	st.Schedule = nil
	o.stopTick = nil
	err := o.markStartedLocked(st, "scheduled")
	o.rbMu.Unlock()
	if err != nil {
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
		st.Pending = nil // same boot: the reboot never happened
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

package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
)

// The scan schedule of a target is the shared schedule ScheduleKey(id) (core/schedule): the shared editor sets it (how often, the
// window, a pause), its ticker starts a scan when it comes due, and "Run once now" starts one at once. Every target gets the default
// schedule when it is added (weekly, inside the box's scan window, as the testing terms say) and loses it when it is deleted.
//
// A due scan is queued like Scan now, as a run of the exposure lane, and checked again right before it starts (the proof, the box's
// own IP, the safety block: runScan). What the box starts by itself needs more than a person's press: the testing terms of the current
// version, which say the box also scans the target on its schedule; and it never runs the disruptive checks (ModeNow, execute).

// The schedule's owner limits: an external scan of a target takes minutes to hours and loads its services, so it runs at most every
// MinScheduleMinutes, and only an administrator changes it (it decides what the box sends on its own).
const (
	MinScheduleMinutes = 6 * 60
	scheduleLimitWhy   = "An external scan can take hours and loads the target's services, so it runs at most every 6 hours."
)

// DefaultSchedule is the schedule a target gets when it is added: weekly, Monday at 02:30, inside the box's scan window.
func DefaultSchedule() schedule.Rule { return schedule.WeeklyAt("02:30", 1).InWindow() }

// registerSchedules registers the owner of the targets' schedules. Without a schedule service no target is scanned by itself.
func (s *Service) registerSchedules() error {
	if s.cfg.Schedules == nil {
		return nil
	}
	return s.cfg.Schedules.Register(schedule.Owner{
		Module: ModuleID, Key: ScheduleOwner, PerSubject: true, AdminOnly: true, Default: DefaultSchedule(),
		Limits: schedule.Limits{MinEveryMinutes: MinScheduleMinutes, Reason: scheduleLimitWhy},
		Subject: func(ctx context.Context, id string) (bool, error) {
			_, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
			if errors.Is(err, ErrNotFound) {
				return false, nil
			}
			return err == nil, err
		},
		Start: s.startScheduled,
	})
}

// ensureSchedule gives target id its default schedule in tx unless it has one.
func (s *Service) ensureSchedule(ctx context.Context, tx *sql.Tx, id string) error {
	if s.cfg.Schedules == nil {
		return nil
	}
	if err := s.cfg.Schedules.EnsureTx(ctx, tx, ScheduleKey(id), DefaultSchedule(), corerun.System); err != nil {
		return fmt.Errorf("the schedule of target %s: %w", id, err)
	}
	return nil
}

// dropSchedule deletes the schedule of target id in tx (its runs stay).
func (s *Service) dropSchedule(ctx context.Context, tx *sql.Tx, id string) error {
	if s.cfg.Schedules == nil {
		return nil
	}
	return schedule.DeleteTx(ctx, tx, ScheduleKey(id))
}

// EnsureSchedules gives every target that has no schedule the default one: the targets of a box that ran before the schedules were
// shared. The box calls it once at start, before the schedules' ticker starts.
func (s *Service) EnsureSchedules(ctx context.Context) error {
	if s.cfg.Schedules == nil {
		return nil
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		ids, err := idsOf(ctx, tx, `SELECT t.id FROM exp_target t WHERE NOT EXISTS (SELECT 1 FROM core_schedule c WHERE c.owner_key = ? || ':' || t.id)`, ScheduleOwner)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := s.ensureSchedule(ctx, tx, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("exposure: the targets' schedules: %w", err)
	}
	return nil
}

// startScheduled is the Start of the targets' schedules, inside the schedule's transaction: it queues a scan of the target as a run
// (trigger schedule, by the system; or manual, by the person who pressed Run once now) after the checks of the stored state, or skips
// with the reason the person reads in the editor. The checks that ask the network run when the scan starts, never here.
func (s *Service) startScheduled(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
	t, err := loadTarget(ctx, tx, f.Subject)
	if errors.Is(err, ErrNotFound) {
		return "", schedule.Skip("The target was deleted.")
	}
	if err != nil {
		return "", err
	}
	if s.scanRunner() == nil || s.cfg.Runs == nil {
		return "", schedule.Skip("Scanning is not set up on this box.")
	}
	s.runMu.Lock()
	off := s.off || s.closed
	s.runMu.Unlock()
	if off {
		return "", schedule.Skip("Its module is off.")
	}
	now := s.clock()
	if !t.Enabled {
		return "", schedule.Skip(t.Value + " is switched off, so it is not scanned.")
	}
	if r := t.blocked(now); r != "" {
		var ae *APIError
		if errors.As(s.refusal(t, r, now), &ae) {
			return "", schedule.Skip(ae.Message)
		}
		return "", schedule.Skip(t.Value + " cannot be scanned now.")
	}
	if f.Trigger == corerun.Schedule && !t.Terms.current() {
		return "", schedule.Skip("The testing terms of " + t.Value + " are not accepted in their current version; they are what lets the box scan it on its schedule. An administrator accepts them on its page.")
	}
	if _, live := s.activeRunTx(ctx, tx, t.ID); live {
		return "", schedule.Skip("A scan of " + t.Value + " was already queued or running.")
	}
	if last, ok := s.lastAsked(ctx, tx, t.ID); ok && now.Sub(last) < ScanEvery && !last.After(now) {
		return "", schedule.Skip(fmt.Sprintf("%s was scanned at %s, less than %d minutes before.", t.Value, s.momentText(last), int(ScanEvery.Minutes())))
	}
	by := f.By
	if f.Trigger == corerun.Schedule {
		by = corerun.System
	}
	return s.createScanRun(ctx, tx, t, f.Trigger, by, f.ScheduleID)
}

// createScanRun creates, in tx, the run of a scan of t with its exp_scan row; the run starts when the lane is free.
func (s *Service) createScanRun(ctx context.Context, tx *sql.Tx, t Target, trigger corerun.Trigger, by, scheduleID string) (string, error) {
	runID, err := s.cfg.Runs.CreateTx(ctx, tx, corerun.Spec{Module: ModuleID, Kind: RunKind, Title: "External scan of " + t.Value,
		Trigger: trigger, RequestedBy: by, ScheduleID: scheduleID, Subject: &corerun.Subject{Kind: "target", ID: t.ID, Label: t.Value}})
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO exp_scan (run_id, target_id, mode) VALUES (?, ?, ?)`, runID, t.ID, modeWord(t.mode())); err != nil {
		return "", fmt.Errorf("recording the scan: %w", err)
	}
	return runID, nil
}

// boxMode is the mode of a scan the box runs by itself (actor SystemUser, a scheduled scan): never the disruptive checks, whatever the
// terms allow. A person's Scan now and Run once now keep what the terms allow.
func boxMode(actor string, m ScanMode) ScanMode {
	if actor == SystemUser {
		m.Disruptive = false
	}
	return m
}

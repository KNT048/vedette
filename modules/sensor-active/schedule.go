package sensoractive

import (
	"context"
	"database/sql"
	"errors"

	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
)

// ScheduleKey is the owner key of the LAN sweep in core/schedule.
const ScheduleKey = "inventory.sweep"

// ScheduleOwner is what the LAN sweep registers with core/schedule: the person's rule decides when a pass of the confirmed ranges
// is queued (by default every day at 22:00, held until the scan window is open); the window stays the safety limit of the pass,
// which waits for the next window when one closes on it and goes on from its cursor.
func (s *Service) ScheduleOwner() schedule.Owner {
	return schedule.Owner{Module: ModuleID, Key: ScheduleKey, AdminOnly: true, Default: schedule.DailyAt("22:00").InWindow(), DefaultOn: true, Start: s.startSweep}
}

// startSweep queues a pass of the ranges inside the schedule's transaction. Nothing is queued, and the reason is said, while active
// scanning is off, the scope is not confirmed, the ranges are empty, the scanner is not available or a pass is already going on (it
// goes on from its cursor in the next window, so the due time adds nothing).
func (s *Service) startSweep(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
	if s.off.Load() {
		return "", schedule.Skip("Active scanning is stopped.")
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return "", err
	}
	if err := st.allowed(); err != nil {
		return "", schedule.Skip(sweepRefusal(err))
	}
	if err := s.available(ctx); err != nil {
		return "", schedule.Skip("The scanner is not available: " + err.Error())
	}
	if sw, err := s.liveRun(ctx, RunSweep); err != nil {
		return "", err
	} else if sw != nil {
		return "", schedule.Skip("The pass that is going on is not finished; it goes on from where it stopped.")
	}
	spec := run.Spec{Trigger: run.Schedule, RequestedBy: run.System, ScheduleID: f.ScheduleID}
	if f.Trigger == run.Manual {
		if err := s.sweepGap(ctx); err != nil {
			var soon *TooSoonError
			if errors.As(err, &soon) {
				return "", schedule.Skip("A sweep ran a few minutes ago; try again in a few minutes.")
			}
			return "", err
		}
		spec.Trigger, spec.RequestedBy = run.Manual, f.By
	}
	spec, err = s.sweepSpec(ctx, st, spec)
	if err != nil {
		return "", err
	}
	return s.submitTx(ctx, tx, spec, nil, nil)
}

// sweepRefusal says why the settings do not allow a sweep.
func sweepRefusal(err error) string {
	switch {
	case errors.Is(err, ErrScanningOff):
		return "Active scanning is off (Settings, Scanning)."
	case errors.Is(err, ErrScopeNotConfirmed):
		return "The network ranges are not confirmed yet (Settings, Scanning)."
	case errors.Is(err, ErrNoRanges):
		return "No network range is set to scan."
	}
	return err.Error()
}

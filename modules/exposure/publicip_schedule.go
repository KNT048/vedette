package exposure

import (
	"context"
	"database/sql"
	"time"

	"github.com/knt048/vedette/core/run"
	coreschedule "github.com/knt048/vedette/core/schedule"
)

// PublicIPScheduleKey is the owner key of the public IP detection in core/schedule.
const PublicIPScheduleKey = "exposure.public_ip"

// SchedulePort is the part of core/schedule the module uses: it keeps the schedule in step with the box-ip form.
type SchedulePort interface {
	SaveTx(ctx context.Context, tx *sql.Tx, key string, st coreschedule.Setting, by string) error
}

// publicIPLimits is what the detection's schedule allows: an interval from 5 minutes to 24 hours.
var publicIPLimits = coreschedule.Limits{Freqs: []coreschedule.Freq{coreschedule.Interval}, MinEveryMinutes: MinIntervalMin, MaxEveryMinutes: MaxIntervalMin,
	Windows: []coreschedule.WindowMode{coreschedule.WindowNone}, Reason: "The lookup services rate-limit; a change is found at the next check."}

// PublicIPScheduleOwner is what the public IP detection registers with core/schedule. When it comes due nothing starts here: the
// detection job checks at its next tick (autoDue reads the schedule), because a check asks the Internet and must not hold the
// schedule's transaction. A person's "run once now" is the page's Detect now button.
func (s *Service) PublicIPScheduleOwner() coreschedule.Owner {
	return coreschedule.Owner{Module: ModuleID, Key: PublicIPScheduleKey, AdminOnly: true, Limits: publicIPLimits,
		Default: coreschedule.Every(DefaultIntervalMin), DefaultOn: true,
		Start: func(_ context.Context, _ *sql.Tx, f coreschedule.Fire) (string, error) {
			if f.Trigger == run.Manual {
				return "", coreschedule.Skip("Use Detect now on the Public IPs card to check the box's public IPs now.")
			}
			return "", nil
		}}
}

// autoSetting reads the detection's schedule: on or off, and every how many minutes; the defaults before anyone saved one.
func autoSetting(ctx context.Context, q coreschedule.Querier) (auto bool, minutes int, lastDue *time.Time, err error) {
	e, ok, err := coreschedule.Lookup(ctx, q, PublicIPScheduleKey)
	if err != nil {
		return false, 0, nil, err
	}
	if !ok {
		return true, DefaultIntervalMin, nil, nil
	}
	minutes = DefaultIntervalMin
	if e.Rule.Freq == coreschedule.Interval && e.Rule.EveryMinutes != nil {
		minutes = *e.Rule.EveryMinutes
	}
	return e.Enabled, minutes, e.LastDueAt, nil
}

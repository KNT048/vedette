package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	coreschedule "github.com/knt048/vedette/core/schedule"
)

// DefaultCustomHours is how often a new custom feed pulls until someone changes it.
const DefaultCustomHours = 6

const scheduleKeyPrefix = "feeds.source:"

func scheduleKey(id string) string { return scheduleKeyPrefix + id }

// SchedulePort is the part of core/schedule the module uses to give a source its schedule.
type SchedulePort interface {
	EnsureTx(ctx context.Context, tx *sql.Tx, key string, rule coreschedule.Rule, by string) error
}

// scheduleLimits is what a source's schedule allows: an interval from an hour to a week. Sources ask their clients not to poll more
// often than that, and a feed older than a week is stale for good.
var scheduleLimits = coreschedule.Limits{Freqs: []coreschedule.Freq{coreschedule.Interval}, MinEveryMinutes: 60, MaxEveryMinutes: 168 * 60,
	Windows: []coreschedule.WindowMode{coreschedule.WindowNone}, Reason: "Sources ask clients not to poll more often."}

// ScheduleOwner is what the sources register with core/schedule: one schedule per source (feeds.source:<id>), an interval only. When
// it comes due nothing starts here: the pull job pulls the source at its next tick (State.Due reads when the schedule last came due),
// because a pull asks the Internet and must not hold the schedule's transaction.
func (s *Service) ScheduleOwner() coreschedule.Owner {
	return coreschedule.Owner{Module: "feeds", Key: "feeds.source", PerSubject: true, AdminOnly: true, Limits: scheduleLimits,
		Default: coreschedule.Every(60), DefaultOn: false,
		Subject: func(ctx context.Context, id string) (bool, error) {
			var n int
			if err := s.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_source WHERE id = ?`, id).Scan(&n); err != nil {
				return false, fmt.Errorf("feeds: read source: %w", err)
			}
			return n > 0, nil
		},
		Start: func(ctx context.Context, _ *sql.Tx, f coreschedule.Fire) (string, error) {
			r, err := s.st.source(ctx, f.Subject)
			if err != nil {
				return "", err
			}
			if !r.Enabled {
				return "", coreschedule.Skip("The source is turned off.")
			}
			if f.Trigger == corerun.Manual {
				return "", coreschedule.Skip("Use Fetch now on the source to pull it now.")
			}
			return "", nil
		}}
}

// ensureSchedule gives a source its schedule, an interval of hours, unless it has one.
func (s *Service) ensureSchedule(ctx context.Context, tx *sql.Tx, id string, hours int, by string) error {
	if s.Schedules == nil {
		return nil
	}
	return s.Schedules.EnsureTx(ctx, tx, scheduleKey(id), coreschedule.Every(hours*60), by)
}

// scheduledDue is when each source's schedule last came due, by source id: what the pull job compares with each source's last pull.
func (s *Service) scheduledDue(ctx context.Context) (map[string]*time.Time, error) {
	all, err := coreschedule.LookupAll(ctx, s.DB.Reader(), scheduleKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*time.Time, len(all))
	for key, e := range all {
		out[key[len(scheduleKeyPrefix):]] = e.LastDueAt
	}
	return out, nil
}

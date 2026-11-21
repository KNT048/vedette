package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// View is a schedule as the editor shows it (GET /schedules/{owner_key}).
type View struct {
	OwnerKey    string     `json:"owner_key"`
	Module      string     `json:"module"`
	Saved       bool       `json:"saved"` // false: nobody saved it; Rule and Enabled are the owner's default
	Enabled     bool       `json:"enabled"`
	PausedUntil *time.Time `json:"paused_until"`
	Rule        Rule       `json:"rule"`
	Zone        string     `json:"zone"` // the IANA zone the rule is read in (the organization's for tz "org")
	NextDueAt   *time.Time `json:"next_due_at"`
	// Upcoming are the next start times: the due times, moved into the scan window for a schedule that uses it.
	Upcoming       []time.Time `json:"upcoming"`
	WaitingFor     *string     `json:"waiting_for"` // due, and held: what it waits for
	LastDueAt      *time.Time  `json:"last_due_at"`
	LastRunID      *string     `json:"last_run_id"`
	LastSkipReason *string     `json:"last_skip_reason"`
	LastSkipAt     *time.Time  `json:"last_skip_at"`
	UpdatedBy      *string     `json:"updated_by"`
	UpdatedAt      *time.Time  `json:"updated_at"`
	Limits         Limits      `json:"limits"`
	EditRole       string      `json:"edit_role"` // operator or admin: who may change it and run it once
}

// Setting is what a person saves (PUT /schedules/{owner_key}).
type Setting struct {
	Enabled     bool
	PausedUntil *time.Time // nil, or a time in the past: not paused
	Rule        Rule
}

func (o Owner) editRole() string {
	if o.AdminOnly {
		return "admin"
	}
	return "operator"
}

// Get returns the schedule of a key: the saved one, or the owner's default. ErrUnknownOwner for a key no owner has, or a
// subject that does not exist.
func (s *Service) Get(ctx context.Context, key string) (View, error) {
	o, _, err := s.lookup(ctx, key)
	if err != nil {
		return View{}, err
	}
	q := s.cfg.DB.Reader()
	org, err := orgZoneName(ctx, q)
	if err != nil {
		return View{}, err
	}
	now := s.now()
	r, err := getRow(ctx, q, key)
	if errors.Is(err, errNoRow) {
		r = row{OwnerModule: o.Module, OwnerKey: key, Enabled: o.DefaultOn, Rule: o.Default, UpdatedAt: now}
		r.NextDueAt = r.due(org)
		return s.view(ctx, o, r, false, org, now), nil
	}
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, o, r, true, org, now), nil
}

// future refuses a once rule whose time has passed: it would be saved on and never run.
func future(r Rule, now time.Time) error {
	if r.Freq == Once && r.OnceAt != nil && !r.OnceAt.After(now) {
		return ruleErr("once_at", "Choose a date and time in the future.")
	}
	return nil
}

func (s *Service) view(ctx context.Context, o Owner, r row, saved bool, org string, now time.Time) View {
	loc := zoneOf(r.Rule.TZ, org)
	if r.PausedUntil != nil && !r.PausedUntil.After(now) {
		r.PausedUntil = nil // a pause that has ended is no pause
	}
	v := View{
		OwnerKey: r.OwnerKey, Module: o.Module, Saved: saved, Enabled: r.Enabled, PausedUntil: r.PausedUntil, Rule: r.Rule,
		Zone: loc.String(), NextDueAt: r.NextDueAt, Upcoming: []time.Time{}, LastDueAt: r.LastDueAt, LastRunID: r.LastRunID,
		LastSkipReason: r.LastSkipReason, LastSkipAt: r.LastSkipAt, Limits: o.Limits.normalized(), EditRole: o.editRole(),
	}
	if saved {
		v.UpdatedBy, v.UpdatedAt = &r.UpdatedBy, &r.UpdatedAt
	}
	if r.NextDueAt != nil {
		v.Upcoming = s.upcoming(ctx, r.Rule, *r.NextDueAt, now, loc)
		if !r.NextDueAt.After(now) && r.Rule.Window == WindowGlobal && len(v.Upcoming) > 0 && v.Upcoming[0].After(now) {
			w := "The scan window to open"
			v.WaitingFor = &w
		}
	}
	return v
}

// upcoming are the next start times from the due time first, as the ticker would start them: a past due time starts now, a
// schedule in the scan window starts when it opens, and a start later than LateAfter counts the next due time from the start.
func (s *Service) upcoming(ctx context.Context, r Rule, first, now time.Time, loc *time.Location) []time.Time {
	var w *Window
	var wloc *time.Location
	if r.Window == WindowGlobal {
		var err error
		if w, wloc, err = s.scanWindow(ctx); err != nil {
			s.cfg.Log.WarnContext(ctx, "schedules: the next start times leave out the scan window", "error", err)
		}
	}
	out := []time.Time{}
	for d := first; len(out) < Upcoming && !d.IsZero(); {
		start := d
		if start.Before(now) {
			start = now
		}
		if w != nil {
			start = w.OpenAt(start, wloc).UTC()
		}
		out = append(out, start)
		from := d
		if start.Sub(d) > LateAfter {
			from = start
		}
		d = Next(r, from, loc)
	}
	return out
}

// Preview returns the next start times of a rule as if it were saved now, and the zone it is read in. With a key, the owner's
// limits apply (ErrUnknownOwner for a key no owner has). The error of a rule that cannot be saved is a *RuleError.
func (s *Service) Preview(ctx context.Context, key string, rl Rule, pausedUntil *time.Time) ([]time.Time, string, error) {
	rl, err := Validate(rl)
	if err != nil {
		return nil, "", err
	}
	if key != "" {
		o, _, err := s.lookup(ctx, key)
		if err != nil {
			return nil, "", err
		}
		if err := o.Limits.Check(rl); err != nil {
			return nil, "", err
		}
	}
	org, err := orgZoneName(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	if err := future(rl, now); err != nil {
		return nil, "", err
	}
	loc := zoneOf(rl.TZ, org)
	first := Due(rl, nil, now, pausedUntil, loc)
	return s.upcoming(ctx, rl, first, now, loc), loc.String(), nil
}

// Save stores a person's setting of a schedule (audited schedule.save) and returns it. ErrUnknownOwner; a *RuleError for a rule
// that cannot be saved or that the owner does not allow.
func (s *Service) Save(ctx context.Context, key string, st Setting, by string) (View, error) {
	o, _, err := s.lookup(ctx, key)
	if err != nil {
		return View{}, err
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := s.saveTx(ctx, tx, o, key, st, by); err != nil {
			return err
		}
		if by != run.System && s.cfg.Audit != nil {
			detail := "off"
			if st.Enabled {
				detail = string(st.Rule.Freq)
			}
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: by, Action: "schedule.save", Target: key, Detail: detail})
		}
		return nil
	})
	if err != nil {
		return View{}, err
	}
	s.Kick()
	return s.Get(ctx, key)
}

// SaveTx stores a setting of a schedule inside the caller's transaction, without an audit row: for an owner that keeps the
// schedule in step with its own form. ErrUnknownOwner; a *RuleError.
func (s *Service) SaveTx(ctx context.Context, tx *sql.Tx, key string, st Setting, by string) error {
	o, _, ok := s.owner(key)
	if !ok {
		return ErrUnknownOwner
	}
	if err := s.saveTx(ctx, tx, o, key, st, by); err != nil {
		return err
	}
	s.Kick()
	return nil
}

func (s *Service) saveTx(ctx context.Context, tx *sql.Tx, o Owner, key string, st Setting, by string) error {
	rl, err := Validate(st.Rule)
	if err != nil {
		return err
	}
	if err := o.Limits.Check(rl); err != nil {
		return err
	}
	now := s.now()
	if st.Enabled {
		if err := future(rl, now); err != nil {
			return err
		}
	}
	r, err := getRow(ctx, tx, key)
	if errors.Is(err, errNoRow) {
		r = row{ID: store.NewID("sch"), OwnerModule: o.Module, OwnerKey: key}
	} else if err != nil {
		return err
	}
	r.Enabled, r.Rule, r.UpdatedBy, r.UpdatedAt = st.Enabled, rl, clip(by, 320), now
	r.PausedUntil = nil
	if st.PausedUntil != nil && st.PausedUntil.After(now) {
		p := st.PausedUntil.UTC().Truncate(time.Millisecond)
		r.PausedUntil = &p
	}
	org, err := orgZoneName(ctx, tx)
	if err != nil {
		return err
	}
	return upsert(ctx, tx, r, org)
}

// EnsureTx saves a schedule with rule (on) inside the caller's transaction unless one is saved already: an owner with subjects
// calls it when it creates a subject. ErrUnknownOwner; a *RuleError.
func (s *Service) EnsureTx(ctx context.Context, tx *sql.Tx, key string, rule Rule, by string) error {
	o, _, ok := s.owner(key)
	if !ok {
		return ErrUnknownOwner
	}
	if _, err := getRow(ctx, tx, key); !errors.Is(err, errNoRow) {
		return err
	}
	return s.saveTx(ctx, tx, o, key, Setting{Enabled: true, Rule: rule}, by)
}

// DeleteTx deletes the schedule of a key inside the caller's transaction (the owner deletes the subject); its runs stay.
func DeleteTx(ctx context.Context, tx *sql.Tx, key string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM core_schedule WHERE owner_key = ?`, key); err != nil {
		return fmt.Errorf("schedule: delete %s: %w", key, err)
	}
	return nil
}

// RunNow starts a schedule's work once, now (trigger manual), without changing when it is next due: audited schedule.run_now.
// It returns the run's id ("" for work that is not a run). ErrUnknownOwner; ErrBusy while the run the schedule last started has
// not ended; a *SkipError when the owner does not start (its reason says why).
func (s *Service) RunNow(ctx context.Context, key, by string) (string, error) {
	o, subject, err := s.lookup(ctx, key)
	if err != nil {
		return "", err
	}
	var runID string
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		r, err := getRow(ctx, tx, key)
		saved := err == nil
		if err != nil && !errors.Is(err, errNoRow) {
			return err
		}
		if saved {
			since, err := liveRun(ctx, tx, r.LastRunID)
			if err != nil {
				return err
			}
			if since != nil {
				return ErrBusy
			}
		}
		if s.cfg.Gate != nil && !s.cfg.Gate.Enabled(o.Module) {
			return &SkipError{Reason: "Its module is off."}
		}
		rl := r.Rule
		if !saved {
			rl = o.Default
		}
		id, skip, _, err := s.start(ctx, tx, o, Fire{ScheduleID: r.ID, OwnerKey: key, Subject: subject, Trigger: run.Manual, By: by, DueAt: s.now(), Rule: rl})
		if err != nil {
			return err
		}
		if skip != "" {
			return &SkipError{Reason: skip}
		}
		runID = id
		if saved && id != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE core_schedule SET last_run_id = ? WHERE id = ?`, id, r.ID); err != nil {
				return fmt.Errorf("schedule: record the run: %w", err)
			}
		}
		if by != run.System && s.cfg.Audit != nil {
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: by, Action: "schedule.run_now", Target: key, Detail: runID})
		}
		return nil
	})
	return runID, err
}

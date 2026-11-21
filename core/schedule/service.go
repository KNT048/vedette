// Package schedule is the one model of every schedule a person can set: an exposure target's scans, the vulnerability checks,
// the LAN sweep, a report, a feed source's refresh, public IP detection, the Wazuh pull. A schedule is a core_schedule row keyed
// by its owner_key; the module that owns it registers in code what it allows (Limits) and what starts when it comes due (Start).
//
// When a schedule comes due the one ticker of this package calls its owner's Start inside the transaction that records the due
// time, so a run (core/run, trigger schedule) and the schedule's last_run_id are written together. Next is a pure function, and
// next_due_at is always Next of the rule from Reference: the self-check recomputes it.
//
// Firing rules:
//   - a schedule fired within LateAfter of its due time counts from that due time, so an interval does not drift; one fired later
//     (the box was off, the scan window was closed) counts from the moment it fired, so missed times start one run, not a burst;
//   - a late start whose rule has a regular time within MergeWithin gives way to it, so the work runs once;
//   - an interval paused until a time starts at that time; a pause that has ended is cleared at the next due time;
//   - a schedule whose last run has not ended (queued, running or waiting) skips the due time and says why;
//   - a schedule of a module that is off skips the due time and says why;
//   - a schedule in the scan window (WindowGlobal) is held while the window is closed and starts when it opens.
package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// Timing of the ticker.
const (
	TickEvery = 30 * time.Second // how often the ticker looks for due schedules without being kicked
	LateAfter = 2 * time.Minute  // a due time fired later than this counts as missed (see the package comment)
	// MergeWithin: a missed due time whose rule has a regular time this close after the late start waits for that time
	// instead of starting now, so the box coming back at 01:59 runs the daily 02:00 work once, not twice.
	MergeWithin = time.Hour
	Upcoming    = 3 // how many next start times the API shows
)

// The errors of the Service. The API maps them to answers (modules/core handlers_schedules.go).
var (
	ErrUnknownOwner = errors.New("schedule: nothing in this version has a schedule with that key")
	ErrBusy         = errors.New("schedule: the last run has not ended")
	ErrClosed       = errors.New("schedule: the service is closed")
)

// SkipError is an owner's refusal to start: Reason says why, for the person ("Scanning is off").
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "schedule: skipped: " + e.Reason }

// Skip returns the error an owner's Start gives when it does not start this time.
func Skip(reason string) error { return &SkipError{Reason: reason} }

// Gate says whether a module is on. modreg.Registry satisfies it.
type Gate interface {
	Enabled(id string) bool
}

// Fire is a start of a schedule: it came due (trigger schedule) or a person asked to run it once now (trigger manual).
type Fire struct {
	ScheduleID string // "" when a person runs once a schedule nobody has saved
	OwnerKey   string
	Subject    string // the part of the key after ":" for an owner with one schedule per subject
	Trigger    run.Trigger
	By         string    // run.System, or the person's email
	DueAt      time.Time // when it came due; the moment asked for a run once
	// Rule is the rule the schedule has now (the owner's default for a schedule nobody saved): an owner reads its window from it.
	Rule Rule
}

// Owner is a kind of schedule a module offers.
type Owner struct {
	Module string // the owning module: its schedules start only while it is on
	// Key is the owner_key, or with PerSubject its prefix: the keys are Key + ":" + the subject's id (exposure.target:<id>).
	Key        string
	PerSubject bool
	Limits     Limits
	AdminOnly  bool // changing it or running it once needs an administrator (an operator otherwise)
	// Default is the rule before anyone saves one. With DefaultOn a schedule of an owner without subjects is saved with it at
	// start; an owner with subjects saves one with EnsureTx when it creates a subject.
	Default   Rule
	DefaultOn bool
	// Subject says whether a subject exists (PerSubject only); nil accepts any id.
	Subject func(ctx context.Context, id string) (bool, error)
	// Start starts what the schedule starts, inside the schedule's transaction: usually run.Manager.CreateTx with f.Trigger,
	// f.By and f.ScheduleID. It returns the run's id ("" for work that is not a run) or an error; Skip(reason) skips this time.
	// It must be quick: the work itself belongs in the run.
	Start func(ctx context.Context, tx *sql.Tx, f Fire) (runID string, err error)
}

// Config wires a Service. DB is required.
type Config struct {
	DB    *store.DB
	Audit *audit.Log // the audit rows of a person's change and run once; nil writes none (tests)
	Gate  Gate       // nil: every module is on
	// ScanWindow reads the box's scan window, in the organization's zone. nil: always open. An error holds the schedules that
	// use it (no start outside a window that cannot be read).
	ScanWindow func(ctx context.Context) (Window, error)
	Log        *slog.Logger
	Clock      func() time.Time
}

// Service keeps the schedules: the API's reads and writes, and the ticker that starts what comes due.
type Service struct {
	cfg Config

	mu      sync.Mutex
	owners  map[string]Owner
	started bool
	closed  bool
	stop    context.CancelFunc
	kick    chan struct{}
	loop    sync.WaitGroup
}

// New returns a Service. Register the owners, then Start it.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil {
		return nil, errors.New("schedule: DB is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Service{cfg: cfg, owners: map[string]Owner{}, kick: make(chan struct{}, 1)}, nil
}

var (
	ownerKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$`)
	subjectRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,96}$`)
)

// ValidKey reports whether key has the shape of an owner_key: a dotted name, and for a subject ":" and its id.
func ValidKey(key string) bool {
	if len(key) > 160 {
		return false
	}
	name, subject, has := strings.Cut(key, ":")
	return ownerKeyRE.MatchString(name) && (!has || subjectRE.MatchString(subject))
}

// Register adds an owner. Call it before Start.
func (s *Service) Register(o Owner) error {
	if o.Module == "" || len(o.Module) > 32 || !ownerKeyRE.MatchString(o.Key) || o.Start == nil {
		return fmt.Errorf("schedule: owner %q of %q needs a module, a dotted key and a Start", o.Key, o.Module)
	}
	def, err := Validate(o.Default)
	if err != nil {
		return fmt.Errorf("schedule: owner %s: default: %w", o.Key, err)
	}
	if err := o.Limits.Check(def); err != nil {
		return fmt.Errorf("schedule: owner %s: its default breaks its limits: %w", o.Key, err)
	}
	o.Default = def
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.owners[o.Key]; ok {
		return fmt.Errorf("schedule: owner %s registered twice", o.Key)
	}
	s.owners[o.Key] = o
	return nil
}

// owner returns the owner of a key and the subject's id.
func (s *Service) owner(key string) (Owner, string, bool) {
	if !ValidKey(key) {
		return Owner{}, "", false
	}
	name, subject, has := strings.Cut(key, ":")
	s.mu.Lock()
	o, ok := s.owners[name]
	s.mu.Unlock()
	if !ok || o.PerSubject != has {
		return Owner{}, "", false
	}
	return o, subject, true
}

// lookup is owner, plus the check that the subject exists.
func (s *Service) lookup(ctx context.Context, key string) (Owner, string, error) {
	o, subject, ok := s.owner(key)
	if !ok {
		return Owner{}, "", ErrUnknownOwner
	}
	if o.PerSubject && o.Subject != nil {
		exists, err := o.Subject(ctx, subject)
		if err != nil {
			return Owner{}, "", err
		}
		if !exists {
			return Owner{}, "", ErrUnknownOwner
		}
	}
	return o, subject, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock().UTC().Truncate(time.Millisecond) }

// Start saves the default schedules of the owners without subjects that nobody saved yet, brings every next due time up to date
// (Recompute), then starts the ticker. ctx carries values only: the ticker ends with Close.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return errors.New("schedule: Start called twice or after Close")
	}
	s.started = true
	var defaults []Owner
	for _, o := range s.owners {
		if !o.PerSubject && o.DefaultOn {
			defaults = append(defaults, o)
		}
	}
	s.mu.Unlock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, o := range defaults {
			if err := s.EnsureTx(ctx, tx, o.Key, o.Default, run.System); err != nil {
				return err
			}
		}
		_, err := Recompute(ctx, tx)
		return err
	})
	if err != nil {
		return err
	}
	base, stop := context.WithCancel(context.WithoutCancel(ctx))
	s.mu.Lock()
	s.stop = stop
	s.mu.Unlock()
	s.loop.Add(1)
	go s.tickLoop(base)
	return nil
}

// Kick asks the ticker to look now. It never blocks.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Close stops the ticker and waits for it.
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	stop := s.stop
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	s.loop.Wait()
}

func (s *Service) tickLoop(ctx context.Context) {
	defer s.loop.Done()
	t := time.NewTicker(TickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Log.ErrorContext(ctx, "schedules: could not start what came due", "error", err)
		}
	}
}

// Tick starts every schedule that is due now and returns how many it handled (started or skipped). The ticker calls it; tests
// call it with their own clock.
func (s *Service) Tick(ctx context.Context) (int, error) {
	now := s.now()
	due, err := listRows(ctx, s.cfg.DB.Reader(), `WHERE enabled = 1 AND next_due_at <= ? ORDER BY next_due_at, id`, store.FormatTS(now))
	if err != nil {
		return 0, err
	}
	var (
		read   bool
		isOpen bool
		errs   []error
	)
	open := func() bool { // read once per tick; a window that cannot be read is closed
		if read {
			return isOpen
		}
		read = true
		w, loc, err := s.scanWindow(ctx)
		if err != nil {
			errs = append(errs, err)
			return false
		}
		isOpen = w == nil || w.Contains(now, loc)
		return isOpen
	}
	n := 0
	for _, r := range due {
		if r.Rule.Window == WindowGlobal && !open() {
			continue // held until the scan window opens
		}
		if err := s.fire(ctx, r.OwnerKey, now); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.OwnerKey, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// scanWindow reads the box's scan window and the organization's zone it is read in; nil without a ScanWindow (always open).
func (s *Service) scanWindow(ctx context.Context) (*Window, *time.Location, error) {
	if s.cfg.ScanWindow == nil {
		return nil, nil, nil
	}
	w, err := s.cfg.ScanWindow(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("schedule: read the scan window: %w", err)
	}
	name, err := orgZoneName(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, nil, err
	}
	return &w, zoneOf(OrgZone, name), nil
}

// fire starts one due schedule and records its due time.
func (s *Service) fire(ctx context.Context, key string, now time.Time) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		r, err := getRow(ctx, tx, key)
		if errors.Is(err, errNoRow) {
			return nil
		}
		if err != nil {
			return err
		}
		if !r.Enabled || r.NextDueAt == nil || r.NextDueAt.After(now) {
			return nil // changed since the list was read
		}
		org, err := orgZoneName(ctx, tx)
		if err != nil {
			return err
		}
		last := *r.NextDueAt
		late := now.Sub(last) > LateAfter
		if late {
			last = now
		}
		if r.PausedUntil != nil && !r.PausedUntil.After(now) {
			r.PausedUntil = nil // the pause has ended; the new last due time is after it, so the next due time is the same
		}
		skip, runID := "", ""
		o, subject, ok := s.owner(key)
		switch {
		case late && mergesLate(r.Rule) && within(Next(r.Rule, now, zoneOf(r.Rule.TZ, org)), now, MergeWithin):
			// The regular time just after starts the work: count from now, start nothing, skip nothing.
		case !ok:
			skip = "Nothing in this version of Vedette starts this schedule."
		case s.cfg.Gate != nil && !s.cfg.Gate.Enabled(o.Module):
			skip = "Its module is off."
		default:
			var since *time.Time
			if since, err = liveRun(ctx, tx, r.LastRunID); err != nil {
				return err
			}
			if since != nil {
				skip = "The run it started at " + orgtime.Stamp(*since, zoneOf(OrgZone, org)) + " had not ended."
				break
			}
			runID, skip, err = s.start(ctx, tx, o, Fire{ScheduleID: r.ID, OwnerKey: key, Subject: subject, Trigger: run.Schedule, By: run.System, DueAt: *r.NextDueAt, Rule: r.Rule})
			if err != nil {
				return err
			}
		}
		r.LastDueAt = &last
		if runID != "" {
			r.LastRunID = &runID
		}
		r.LastSkipReason, r.LastSkipAt = nil, nil
		if skip != "" {
			skip = clip(skip, 300)
			r.LastSkipReason, r.LastSkipAt = &skip, &now
			s.cfg.Log.InfoContext(ctx, "schedules: a due time was skipped", "schedule", key, "reason", skip)
		}
		return upsert(ctx, tx, r, org)
	})
}

// mergesLate reports whether a late start of r gives way to its next regular time: every rule but an elapsed interval (whose next
// time is a whole interval away by definition).
func mergesLate(r Rule) bool { return r.Freq != Interval || r.At != nil }

func within(t, now time.Time, d time.Duration) bool { return !t.IsZero() && t.Sub(now) <= d }

// liveRun returns when the run started (or was queued) while it has not ended; nil otherwise or when there is no such run.
func liveRun(ctx context.Context, tx *sql.Tx, id *string) (*time.Time, error) {
	if id == nil {
		return nil, nil //nolint:nilnil // no run
	}
	var st, at string
	err := tx.QueryRowContext(ctx, `SELECT status, COALESCE(started_at, queued_at) FROM core_run WHERE id = ?`, *id).Scan(&st, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // pruned
	}
	if err != nil {
		return nil, fmt.Errorf("schedule: read the last run: %w", err)
	}
	if run.Status(st).Ended() {
		return nil, nil //nolint:nilnil // ended
	}
	t, err := parseTS(at)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// start calls an owner's Start inside a savepoint, so a failed start leaves nothing behind. A Skip comes back as the reason; any
// other error is logged and recorded as a skip that says the start failed.
func (s *Service) start(ctx context.Context, tx *sql.Tx, o Owner, f Fire) (runID, skip string, err error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT schedule_start`); err != nil {
		return "", "", fmt.Errorf("schedule: savepoint: %w", err)
	}
	id, serr := o.Start(ctx, tx, f)
	if serr != nil {
		if _, err := tx.ExecContext(ctx, `ROLLBACK TO schedule_start`); err != nil {
			return "", "", fmt.Errorf("schedule: roll back a failed start: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `RELEASE schedule_start`); err != nil {
			return "", "", fmt.Errorf("schedule: release: %w", err)
		}
		var sk *SkipError
		if errors.As(serr, &sk) {
			return "", sk.Reason, nil
		}
		s.cfg.Log.ErrorContext(ctx, "schedules: could not start", "schedule", f.OwnerKey, "error", serr)
		return "", "It could not start; the box log has the error.", nil
	}
	if _, err := tx.ExecContext(ctx, `RELEASE schedule_start`); err != nil {
		return "", "", fmt.Errorf("schedule: release: %w", err)
	}
	return id, "", nil
}

// clip cuts s to at most n characters.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

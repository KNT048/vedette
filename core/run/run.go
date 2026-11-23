// Package run is the one model of every piece of scanning work a person can see: a LAN sweep, a device check, an SNMP read, the
// vulnerability checks, an exposure scan and its engine steps. A run is a core_run row with its steps (the cursor a resumed run
// continues from), the devices it touched (items) and a capped log.
//
// The queue is the rows in status queued, so it survives a restart. Each run occupies a lane (nmap, nuclei, exposure, ...) and
// the database holds one live run per lane: the partial unique index core_run_live refuses a second running row, so two starts
// in one lane cannot both succeed whatever the code does. The Manager starts the oldest queued run of every free lane, gives it
// to the Run function its module registered, and records how it ended.
//
// A restart never loses a run: a queued run stays queued, a running one is marked stopped with the reason "Vedette restarted",
// and when its kind is resumable and it has work left it is queued again and continues from its steps.
package run

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Retention and caps (core/run Prune and Exec.Log).
const (
	KeepRuns    = 400 * 24 * time.Hour // an ended run is deleted with its steps, items and log this long after it ended
	KeepLog     = 30 * 24 * time.Hour  // a log line is deleted this long after it was written
	MaxLogLines = 2000                 // log lines kept per run; the oldest go first
	PruneEvery  = 24 * time.Hour       // how often the core job "run-prune" runs
)

// The reasons the box itself writes.
const (
	RestartReason   = "Vedette restarted"
	ModuleOffReason = "Its module was turned off"
	// System is the requested_by of a run nobody asked for, and the actor of a stop or resume the box makes itself.
	System = "system"
)

// The errors of the Manager. The API maps them to answers (modules/core handlers_runs.go).
var (
	ErrNotFound     = errors.New("run: no such run")
	ErrUnknownKind  = errors.New("run: no such kind of run")
	ErrInvalid      = errors.New("run: invalid run")
	ErrEnded        = errors.New("run: the run has already ended")
	ErrNotResumable = errors.New("run: the run cannot be resumed")
	ErrNotLive      = errors.New("run: the run is not running")
	ErrStopped      = errors.New("run: the manager is closed")
)

// The causes of a run's context ending.
var (
	errStopAsked = errors.New("run: a stop was asked")
	errShutdown  = errors.New("run: Vedette is stopping")
)

// Gate says whether a module is on. modreg.Registry satisfies it.
type Gate interface {
	Enabled(id string) bool
}

// Kind is a kind of run a module registers: where it runs (Lane) and what does the work (Run).
type Kind struct {
	Module string // the owning module: its runs start only while it is on
	Name   string // core_run.kind, e.g. lan_sweep, device_check, vuln_check
	Lane   string // what a run occupies, e.g. nmap, nuclei, exposure: one live run per lane
	// Resumable says a stopped run with work left can go on from its steps: after a restart it is queued again, and a person
	// can resume it. Its Run must then skip the steps that are done (Exec.Steps).
	Resumable bool
	// AdminResume makes Resume an administrator's, for a kind whose start is one (a LAN sweep only an admin may start);
	// otherwise an operator may resume it.
	AdminResume bool
	// Unit names the units a run of this kind counts in its steps (plural, e.g. "addresses", "devices"): the summary says "6,272 of
	// 65,792 addresses". Empty: "6,272 of 65,792".
	Unit string
	// Estimate, when set, adds the time a running or waiting run has left to its summary, in words ("about 9 more nights at 50
	// packets/s"); "" when it cannot tell. It is called while the runs are read, so it must be cheap.
	Estimate func(ctx context.Context, r Run) string
	// Hold, when set, is how long a run of this kind keeps its lane from the runs queued behind it: a running one until it lets the
	// lane go (its end, or the end of its current batch for a kind that gives way between batches), a queued one how long it will
	// keep the lane once it starts. ok is false when it cannot tell. A queued run's summary adds up the run in its way and the runs
	// queued ahead of it ("it starts in about 25 minutes"). It is called while the runs are read, so it must be cheap.
	Hold func(ctx context.Context, r Run) (d time.Duration, ok bool)
	// GiveWay, when set, is told that a run of another kind is queued behind run id of this kind, which holds the lane: it should let
	// the lane go soon. The dispatcher calls it after the transaction that saw the queued run, so that run is committed and every check
	// the holder makes from then on sees it. It is called again at every dispatch while both stay so: it must be cheap and safe to repeat.
	GiveWay func(ctx context.Context, id string)
	// Run does the work. It ends when ctx ends (a stop, or the box stopping) and returns how the run ended. An error makes
	// the run failed with the error's text, so the text must be fit for the person who reads the run page.
	Run func(ctx context.Context, x *Exec) (Result, error)
}

func (k Kind) key() string { return k.Module + "/" + k.Name }

// Result is how a Run ended.
type Result struct {
	Status     Status // Done (the zero value means Done), Partial, Failed or Waiting
	WaitingFor string // with Waiting: what it waits for, e.g. "the scan window (opens 23:00)"
	Error      string // with Failed or Partial: what went wrong, in words
}

// Subject is what a run is about: a device, an exposure target, a scope.
type Subject struct {
	Kind  string `json:"kind"`  // device | target | scope | ...
	ID    string `json:"id"`    // its id in its module
	Label string `json:"label"` // a snapshot of its name, kept when the subject goes
}

// StepPlan is a step known when the run is created (the ranges of a sweep): it starts queued.
type StepPlan struct {
	Name  string
	Total int
}

// Spec is a run to create.
type Spec struct {
	Module, Kind string // a registered Kind
	Title        string // what the run does, e.g. "LAN sweep of 192.0.2.0/24"
	Trigger      Trigger
	TriggerNote  string // optional words on the trigger, e.g. "a new device appeared"
	RequestedBy  string // an email, or System
	ScheduleID   string // optional: the schedule that came due
	Subject      *Subject
	ParentID     string // optional: the run this one is a step of
	Steps        []StepPlan
	// WaitingFor, when set, creates the run waiting for what it names (e.g. "the scan window (opens 23:00)") instead of queued: it
	// holds no place in its lane's queue until it is resumed (Resume).
	WaitingFor string
}

// Config wires a Manager. DB is required.
type Config struct {
	DB    *store.DB
	Audit *audit.Log // the audit rows of a person's stop and resume; nil writes none (tests)
	Gate  Gate       // nil: every module is on
	Log   *slog.Logger
	Clock func() time.Time
}

// Manager creates, queues, starts and records runs.
type Manager struct {
	cfg Config

	mu      sync.Mutex
	kinds   map[string]Kind
	live    map[string]context.CancelCauseFunc // the runs this process executes, by id
	started bool
	closed  bool
	base    context.Context
	stop    context.CancelCauseFunc
	kick    chan struct{}
	loop    sync.WaitGroup  // the dispatcher
	runs    sync.WaitGroup  // the executing runs
	bg      sync.WaitGroup  // the stops of a module turned off
	ended   func(id string) // test hook: called after a run's end is recorded
}

// New returns a Manager. Register the kinds, then Start it.
func New(cfg Config) (*Manager, error) {
	if cfg.DB == nil {
		return nil, errors.New("run: DB is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Manager{cfg: cfg, kinds: map[string]Kind{}, live: map[string]context.CancelCauseFunc{}, kick: make(chan struct{}, 1)}, nil
}

// Register adds a kind of run. Call it before Start: the restart recovery resumes only the kinds it knows.
func (m *Manager) Register(k Kind) error {
	if k.Module == "" || len(k.Module) > 32 || !wordRE.MatchString(k.Name) || !wordRE.MatchString(k.Lane) || k.Run == nil {
		return fmt.Errorf("%w: kind %q of %q needs a module, a name and a lane of [a-z0-9_]{1,40} and a Run", ErrInvalid, k.Name, k.Module)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.kinds[k.key()]; ok {
		return fmt.Errorf("%w: kind %s registered twice", ErrInvalid, k.key())
	}
	m.kinds[k.key()] = k
	return nil
}

func (m *Manager) kind(module, name string) (Kind, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.kinds[module+"/"+name]
	return k, ok
}

func (m *Manager) now() string { return store.FormatTS(m.cfg.Clock()) }

// Start recovers the runs a previous process left (Recover), then starts the queued runs and keeps starting them as lanes free
// up, until Close. ctx carries values only: the runs end with Close, not with ctx.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started || m.closed {
		m.mu.Unlock()
		return errors.New("run: Start called twice or after Close")
	}
	m.started = true
	m.base, m.stop = context.WithCancelCause(context.WithoutCancel(ctx))
	m.mu.Unlock()
	if err := m.Recover(ctx); err != nil {
		return err
	}
	m.loop.Add(1)
	go m.dispatchLoop()
	m.Kick()
	return nil
}

// Kick asks the dispatcher to look at the queue now. It never blocks. Calling it inside the write transaction that queued a
// run is safe: the dispatcher's own transaction waits for the writer, so it sees the run once that transaction commits.
func (m *Manager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Close ends every executing run and waits for them, then stops the dispatcher. The rows of the runs it ends are left as they
// are (running): the next start records them as stopped by the restart and resumes those that can go on, the same as after a
// crash. Close the Manager before the database.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	started := m.started
	m.mu.Unlock()
	m.bg.Wait() // no Add after closed is set: ModuleChanged checks it under mu
	if !started {
		return
	}
	m.stop(errShutdown)
	m.runs.Wait()
	m.loop.Wait()
}

// Create queues a run in its own transaction and returns its id.
func (m *Manager) Create(ctx context.Context, s Spec) (string, error) {
	var id string
	err := m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = m.CreateTx(ctx, tx, s)
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// CreateTx queues a run inside the caller's transaction (with the module's own rows keyed by its id) and returns its id. The
// run starts once the transaction commits and its lane is free; a rollback leaves nothing.
func (m *Manager) CreateTx(ctx context.Context, tx *sql.Tx, s Spec) (string, error) {
	k, ok := m.kind(s.Module, s.Kind)
	if !ok {
		return "", fmt.Errorf("%w: %s/%s", ErrUnknownKind, s.Module, s.Kind)
	}
	title := clip(s.Title, 200)
	by := clip(s.RequestedBy, 320)
	if title == "" || by == "" || !s.Trigger.Valid() {
		return "", fmt.Errorf("%w: a run needs a title, who asked and a trigger", ErrInvalid)
	}
	var subKind, subID, subLabel *string
	if s.Subject != nil {
		if !wordRE.MatchString(s.Subject.Kind) || s.Subject.ID == "" || len(s.Subject.ID) > 96 {
			return "", fmt.Errorf("%w: subject %q %q", ErrInvalid, s.Subject.Kind, s.Subject.ID)
		}
		subKind, subID, subLabel = &s.Subject.Kind, &s.Subject.ID, nullable(s.Subject.Label, 200)
	}
	id := store.NewID("run")
	now := m.now()
	st, waitingFor := Queued, nullable(s.WaitingFor, 200)
	if waitingFor != nil {
		st = Waiting
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO core_run (id, module, kind, lane, title, trigger, trigger_note, requested_by, schedule_id,
		subject_kind, subject_id, subject_label, parent_id, status, waiting_for, queued_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, k.Module, k.Name, k.Lane, title, string(s.Trigger), nullable(s.TriggerNote, 200), by, nullable(s.ScheduleID, 96),
		subKind, subID, subLabel, nullable(s.ParentID, 96), string(st), waitingFor, now, now)
	if err != nil {
		return "", fmt.Errorf("run: create: %w", err)
	}
	for i, p := range s.Steps {
		name := clip(p.Name, 200)
		if name == "" || p.Total < 0 {
			return "", fmt.Errorf("%w: step %d needs a name and a total of 0 or more", ErrInvalid, i+1)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_run_step (run_id, seq, name, status, total) VALUES (?, ?, ?, ?, ?)`,
			id, i+1, name, string(Queued), p.Total); err != nil {
			return "", fmt.Errorf("run: create step: %w", err)
		}
	}
	if err := rollup(ctx, tx, id, now); err != nil {
		return "", err
	}
	if waitingFor != nil {
		if err := logTx(ctx, tx, id, now, Info, "Waiting for "+*waitingFor); err != nil {
			return "", err
		}
		return id, nil
	}
	m.Kick()
	return id, nil
}

// rollup sets a run's total and done to the sums of its steps': the one writer of those two columns once a run has steps.
func rollup(ctx context.Context, tx *sql.Tx, id, now string) error {
	_, err := tx.ExecContext(ctx, `UPDATE core_run SET
		total = COALESCE((SELECT sum(total) FROM core_run_step WHERE run_id = ?1), 0),
		done  = COALESCE((SELECT sum(done)  FROM core_run_step WHERE run_id = ?1), 0),
		updated_at = ?2
		WHERE id = ?1`, id, now)
	if err != nil {
		return fmt.Errorf("run: progress: %w", err)
	}
	return nil
}

// logTx appends a line to a run's log and drops the lines past MaxLogLines.
func logTx(ctx context.Context, tx *sql.Tx, id, now string, lvl Level, text string) error {
	text = clip(text, 1000)
	if text == "" || !lvl.Valid() {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO core_run_log (run_id, ts, level, text) VALUES (?, ?, ?, ?)`, id, now, string(lvl), text); err != nil {
		return fmt.Errorf("run: log: %w", err)
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM core_run_log WHERE run_id = ?1 AND id <= (
		SELECT id FROM core_run_log WHERE run_id = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)`, id, MaxLogLines)
	if err != nil {
		return fmt.Errorf("run: log cap: %w", err)
	}
	return nil
}

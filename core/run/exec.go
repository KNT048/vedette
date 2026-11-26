package run

import (
	"context"
	"database/sql"
	"fmt"
)

// Exec is what a kind's Run reports through while it executes: its steps, the devices it touches and its log. Every write
// checks that the run is still running (or stopping), so a run that was recorded as ended cannot be changed by late work.
type Exec struct {
	m  *Manager
	id string
	// Resumed says the run ran before (it was stopped by a restart or a person, or waited): skip the steps that are done.
	Resumed bool
}

// ID is the run's id: the key of the module's own rows about it.
func (x *Exec) ID() string { return x.id }

// Run reads the run as stored now.
func (x *Exec) Run(ctx context.Context) (Detail, error) { return x.m.Get(ctx, x.id) }

// write runs fn in a write transaction once it checked that the run is live.
func (x *Exec) write(ctx context.Context, fn func(tx *sql.Tx, now string) error) error {
	return x.m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, _, err := statusOf(ctx, tx, x.id)
		if err != nil {
			return err
		}
		if !st.Live() {
			return ErrNotLive
		}
		return fn(tx, x.m.now())
	})
}

// AddStep appends a step (queued) and returns its number.
func (x *Exec) AddStep(ctx context.Context, name string, total int) (int, error) {
	name = clip(name, 200)
	if name == "" || total < 0 {
		return 0, fmt.Errorf("%w: a step needs a name and a total of 0 or more", ErrInvalid)
	}
	var seq int
	err := x.write(ctx, func(tx *sql.Tx, now string) error {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(seq), 0) + 1 FROM core_run_step WHERE run_id = ?`, x.id).Scan(&seq); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_run_step (run_id, seq, name, status, total) VALUES (?, ?, ?, ?, ?)`,
			x.id, seq, name, string(Queued), total); err != nil {
			return err
		}
		return rollup(ctx, tx, x.id, now)
	})
	return seq, err
}

// StartStep marks a step running.
func (x *Exec) StartStep(ctx context.Context, seq int) error {
	return x.write(ctx, func(tx *sql.Tx, now string) error {
		return x.updateStep(ctx, tx, seq, `UPDATE core_run_step SET status = ?, started_at = COALESCE(started_at, ?), ended_at = NULL
			WHERE run_id = ? AND seq = ?`, string(Running), now, x.id, seq)
	})
}

// Progress sets a step's units of work: done of total (addresses, devices, templates). The run's own done and total are the
// sums over its steps.
func (x *Exec) Progress(ctx context.Context, seq, done, total int) error {
	if done < 0 || total < 0 {
		return fmt.Errorf("%w: progress %d of %d", ErrInvalid, done, total)
	}
	return x.write(ctx, func(tx *sql.Tx, now string) error {
		if err := x.updateStep(ctx, tx, seq, `UPDATE core_run_step SET done = ?, total = ? WHERE run_id = ? AND seq = ?`, done, total, x.id, seq); err != nil {
			return err
		}
		return rollup(ctx, tx, x.id, now)
	})
}

// EndStep records how a step ended (Done, Partial, Failed or Stopped) with an optional note.
func (x *Exec) EndStep(ctx context.Context, seq int, st Status, note string) error {
	if !st.Ended() {
		return fmt.Errorf("%w: a step ends done, partial, failed or stopped, not %q", ErrInvalid, st)
	}
	return x.write(ctx, func(tx *sql.Tx, now string) error {
		return x.updateStep(ctx, tx, seq, `UPDATE core_run_step SET status = ?, note = ?, ended_at = ? WHERE run_id = ? AND seq = ?`,
			string(st), nullable(note, 500), now, x.id, seq)
	})
}

// SkipStep records that a step did not run, with why in note (an engine turned off, nothing for it to check, the run ended before
// it). Its done is left as it is: a step skipped because there was nothing to do can be counted as done first (Progress), one the run
// never reached is not.
func (x *Exec) SkipStep(ctx context.Context, seq int, note string) error {
	return x.write(ctx, func(tx *sql.Tx, now string) error {
		return x.updateStep(ctx, tx, seq, `UPDATE core_run_step SET status = ?, note = ?, ended_at = ? WHERE run_id = ? AND seq = ?`,
			string(Skipped), nullable(note, 500), now, x.id, seq)
	})
}

// StepNote sets the note of a running step: where it is now ("finding open ports: 41%, about 9 minutes left"). A step that is not
// running is left as it is, so a late report never overwrites how a step ended.
func (x *Exec) StepNote(ctx context.Context, seq int, note string) error {
	return x.write(ctx, func(tx *sql.Tx, now string) error {
		_, err := tx.ExecContext(ctx, `UPDATE core_run_step SET note = ? WHERE run_id = ? AND seq = ? AND status = ?`, nullable(note, 500), x.id, seq, string(Running))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE core_run SET updated_at = ? WHERE id = ?`, now, x.id)
		return err
	})
}

// FillNote gives a step that ended without a note its note, once: what it found when that was only known after it ended (the open
// ports of a port scan, read once the service scan that followed it answers). Its state and times are left as they are; a step that
// has a note or has not ended is left as it is.
func (x *Exec) FillNote(ctx context.Context, seq int, note string) error {
	n := nullable(note, 500)
	if n == nil {
		return nil
	}
	return x.write(ctx, func(tx *sql.Tx, now string) error {
		_, err := tx.ExecContext(ctx, `UPDATE core_run_step SET note = ? WHERE run_id = ? AND seq = ? AND note IS NULL AND ended_at IS NOT NULL
			AND status IN (?, ?, ?, ?, ?)`, n, x.id, seq, string(Done), string(Partial), string(Failed), string(Stopped), string(Skipped))
		return err
	})
}

func (x *Exec) updateStep(ctx context.Context, tx *sql.Tx, seq int, q string, args ...any) error {
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: run %s has no step %d", ErrInvalid, x.id, seq)
	}
	return nil
}

// Item is a device or host a run touched.
type Item struct {
	SubjectKind string `json:"subject_kind"` // device | host | target | ...
	SubjectID   string `json:"subject_id"`   // its id; empty for an address no device has yet
	Label       string `json:"label"`        // what the page shows, e.g. "192.0.2.10 (printer)"
	Outcome     string `json:"outcome"`      // found | new | checked | unreachable | failed | skipped | ...
	Note        string `json:"note"`
}

// AddItem records a device or host the run touched, as it comes.
func (x *Exec) AddItem(ctx context.Context, it Item) error { return x.AddItems(ctx, it) }

// AddItems records several items in one transaction, in the order given: items that belong together (a row and what follows it)
// are never separated by another writer's item.
func (x *Exec) AddItems(ctx context.Context, its ...Item) error {
	for _, it := range its {
		if !wordRE.MatchString(it.SubjectKind) || !wordRE.MatchString(it.Outcome) || clip(it.Label, 200) == "" || len(it.SubjectID) > 96 {
			return fmt.Errorf("%w: item %q %q %q", ErrInvalid, it.SubjectKind, it.Outcome, it.Label)
		}
	}
	return x.write(ctx, func(tx *sql.Tx, _ string) error {
		for _, it := range its {
			_, err := tx.ExecContext(ctx, `INSERT INTO core_run_item (run_id, seq, subject_kind, subject_id, label, outcome, note)
				VALUES (?1, (SELECT COALESCE(max(seq), 0) + 1 FROM core_run_item WHERE run_id = ?1), ?2, ?3, ?4, ?5, ?6)`,
				x.id, it.SubjectKind, nullable(it.SubjectID, 96), clip(it.Label, 200), it.Outcome, nullable(it.Note, 500))
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Log appends a line to the run's log (at most MaxLogLines are kept; the oldest go first).
func (x *Exec) Log(ctx context.Context, lvl Level, text string) error {
	if !lvl.Valid() {
		return fmt.Errorf("%w: log level %q", ErrInvalid, lvl)
	}
	return x.write(ctx, func(tx *sql.Tx, now string) error { return logTx(ctx, tx, x.id, now, lvl, text) })
}

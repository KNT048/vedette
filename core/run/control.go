package run

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Stop stops a run and the runs under it: a queued or waiting run is stopped at once, a running one becomes stopping until its
// work ends. by is the person (an email) or System; reason is what the run page says ("Stopped by ann@example.com" when
// empty). A person's stop is audited (scanning.run_stop) in the same transaction. ErrNotFound, or ErrEnded for a run that has
// already ended; a run that is already stopping is left as it is.
func (m *Manager) Stop(ctx context.Context, id, by, reason string) error {
	if reason == "" {
		reason = "Stopped by " + by
	}
	var cancel []string
	err := m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cancel = cancel[:0]
		st, title, err := statusOf(ctx, tx, id)
		if err != nil {
			return err
		}
		if st.Ended() {
			return ErrEnded
		}
		ids, err := tree(ctx, tx, id)
		if err != nil {
			return err
		}
		now := m.now()
		for _, rid := range ids {
			c, err := m.stopTx(ctx, tx, rid, reason, now)
			if err != nil {
				return err
			}
			if c {
				cancel = append(cancel, rid)
			}
		}
		if by != System && m.cfg.Audit != nil {
			return m.cfg.Audit.Append(ctx, tx, audit.Entry{User: by, Action: "scanning.run_stop", Target: id, Detail: clip(title, 500)})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, rid := range cancel {
		m.mu.Lock()
		c, ok := m.live[rid]
		m.mu.Unlock()
		if ok {
			c(errStopAsked)
			continue
		}
		// Nothing in this process executes it (its kind is not registered here): it ends now.
		if err := m.finish(context.WithoutCancel(ctx), rid, Result{}, nil, true); err != nil {
			return err
		}
	}
	return nil
}

// stopTx stops one run and says whether it was running (its executor must be told).
func (m *Manager) stopTx(ctx context.Context, tx *sql.Tx, id, reason, now string) (bool, error) {
	st, _, err := statusOf(ctx, tx, id)
	if err != nil || st.Ended() || st == Stopping {
		return false, err
	}
	reason = clip(reason, 500)
	if st == Running {
		_, err := tx.ExecContext(ctx, `UPDATE core_run SET status = ?, stop_reason = ?, updated_at = ? WHERE id = ?`, string(Stopping), reason, now, id)
		if err != nil {
			return false, err
		}
		return true, logTx(ctx, tx, id, now, Warn, "Stopping: "+reason)
	}
	_, err = tx.ExecContext(ctx, `UPDATE core_run SET status = ?, stop_reason = ?, waiting_for = NULL, ended_at = ?, updated_at = ? WHERE id = ?`,
		string(Stopped), reason, now, now, id)
	if err != nil {
		return false, err
	}
	return false, logTx(ctx, tx, id, now, Warn, "Stopped: "+reason)
}

// Resume queues again a run that is waiting, or that was stopped with work left when its kind can go on from its steps
// (CanResume). A person's resume is audited (scanning.run_resume). ErrNotFound or ErrNotResumable.
func (m *Manager) Resume(ctx context.Context, id, by string) error {
	err := m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		r, err := m.getTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if !r.CanResume {
			return ErrNotResumable
		}
		now := m.now()
		if err := m.requeue(ctx, tx, id, now); err != nil {
			return err
		}
		text := "Resumed by " + by
		if by == System {
			text = "Resumed"
		}
		if err := logTx(ctx, tx, id, now, Info, text); err != nil {
			return err
		}
		if by != System && m.cfg.Audit != nil {
			return m.cfg.Audit.Append(ctx, tx, audit.Entry{User: by, Action: "scanning.run_resume", Target: id, Detail: clip(r.Title, 500)})
		}
		return nil
	})
	if err != nil {
		return err
	}
	m.Kick()
	return nil
}

// Rewait changes what the waiting runs ids wait for, when the reason changed while they wait (the window opened while the scan
// worker is not ready yet, the window closed before their turn came). A run that is not waiting, that already waits for that, or
// that does not exist is left as it is; each run it changes logs the new reason. waitingFor must not be empty.
func (m *Manager) Rewait(ctx context.Context, waitingFor string, ids ...string) error {
	w := nullable(waitingFor, 200)
	if w == nil {
		return fmt.Errorf("%w: a waiting run needs to say what it waits for", ErrInvalid)
	}
	if len(ids) == 0 {
		return nil
	}
	return m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		now := m.now()
		for _, id := range ids {
			res, err := tx.ExecContext(ctx, `UPDATE core_run SET waiting_for = ?, updated_at = ? WHERE id = ? AND status = ? AND waiting_for IS NOT ?`,
				*w, now, id, string(Waiting), *w)
			if err != nil {
				return fmt.Errorf("run: rewait %s: %w", id, err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			if err := logTx(ctx, tx, id, now, Info, "Waiting for "+*w); err != nil {
				return err
			}
		}
		return nil
	})
}

// requeue puts a run back in the queue; its steps that are not done start again (stopped, failed and waiting steps queue).
func (m *Manager) requeue(ctx context.Context, tx *sql.Tx, id, now string) error {
	_, err := tx.ExecContext(ctx, `UPDATE core_run SET status = ?, waiting_for = NULL, stop_reason = NULL, error = NULL, ended_at = NULL,
		updated_at = ? WHERE id = ?`, string(Queued), now, id)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE core_run_step SET status = ?, ended_at = NULL WHERE run_id = ? AND status IN (?, ?, ?, ?)`,
		string(Queued), id, string(Running), string(Stopped), string(Failed), string(Waiting))
	return err
}

// Recover records what a previous process left: a queued or waiting run stays as it is; a running one becomes stopped with
// the reason RestartReason, and is queued again when its kind is resumable and it has work left; a stopping one becomes
// stopped with the reason the person gave. Start calls it before any run starts; after it no run is running or stopping.
func (m *Manager) Recover(ctx context.Context) error {
	var resumed int
	err := m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		resumed = 0
		type left struct {
			id, module, kind, reason string
			st                       Status
		}
		var ls []left
		rows, err := tx.QueryContext(ctx, `SELECT id, module, kind, status, COALESCE(stop_reason, '') FROM core_run WHERE status IN (?, ?) ORDER BY queued_at, rowid`, string(Running), string(Stopping))
		if err != nil {
			return err
		}
		for rows.Next() {
			var l left
			if err := rows.Scan(&l.id, &l.module, &l.kind, &l.st, &l.reason); err != nil {
				_ = rows.Close()
				return err
			}
			ls = append(ls, l)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		now := m.now()
		for _, l := range ls {
			reason := RestartReason
			if l.st == Stopping {
				reason = "" // keep the person's
			}
			_, err := tx.ExecContext(ctx, `UPDATE core_run SET status = ?, stop_reason = COALESCE(?, stop_reason, ?), ended_at = ?, updated_at = ? WHERE id = ?`,
				string(Stopped), nullable(reason, 500), RestartReason, now, now, l.id)
			if err != nil {
				return fmt.Errorf("run: recover %s: %w", l.id, err)
			}
			if err := settleSteps(ctx, tx, l.id, Stopped, now); err != nil {
				return err
			}
			logReason := RestartReason
			if l.st == Stopping && l.reason != "" {
				logReason = l.reason
			}
			if err := logTx(ctx, tx, l.id, now, Warn, "Stopped: "+logReason); err != nil {
				return err
			}
			if l.st != Running {
				continue
			}
			r, err := m.getTx(ctx, tx, l.id)
			if err != nil {
				return err
			}
			if !r.CanResume {
				continue
			}
			if err := m.requeue(ctx, tx, l.id, now); err != nil {
				return err
			}
			if err := logTx(ctx, tx, l.id, now, Info, "Queued again to continue after the restart"); err != nil {
				return err
			}
			resumed++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("run: recover: %w", err)
	}
	if resumed > 0 {
		m.cfg.Log.InfoContext(ctx, "runs: queued again the runs a restart stopped", "runs", resumed)
	}
	return nil
}

// ModuleChanged is the modreg.OnChange subscriber: turning a module off stops its runs that have not ended (reason
// ModuleOffReason); turning one on starts its queued runs. It never blocks the goroutine that publishes the change: the stops
// run on their own goroutine, which reads the switch again (Gate) before each one, so an off quickly followed by an on stops
// nothing of a module that is on.
func (m *Manager) ModuleChanged(id string, enabled bool) {
	if enabled {
		m.Kick()
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.bg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.bg.Done()
		m.stopModule(context.Background(), id)
	}()
}

// moduleOn reads a module's switch now.
func (m *Manager) moduleOn(id string) bool { return m.cfg.Gate != nil && m.cfg.Gate.Enabled(id) }

// stopModule stops the runs of a module that is off, as long as it stays off.
func (m *Manager) stopModule(ctx context.Context, id string) {
	if m.moduleOn(id) {
		return
	}
	rows, err := m.cfg.DB.Reader().QueryContext(ctx, `SELECT id FROM core_run WHERE module = ? AND status IN (?, ?, ?, ?)`,
		id, string(Queued), string(Waiting), string(Running), string(Stopping))
	if err != nil {
		m.cfg.Log.ErrorContext(ctx, "runs: could not read the runs of a module turned off", "module", id, "error", err)
		return
	}
	var ids []string
	for rows.Next() {
		var rid string
		if rows.Scan(&rid) == nil {
			ids = append(ids, rid)
		}
	}
	_ = rows.Close()
	for _, rid := range ids {
		if m.moduleOn(id) {
			return // turned on again meanwhile: its runs go on
		}
		if err := m.Stop(ctx, rid, System, ModuleOffReason); err != nil && !errors.Is(err, ErrEnded) {
			m.cfg.Log.ErrorContext(ctx, "runs: could not stop a run of a module turned off", "run", rid, "error", err)
		}
	}
}

// Prune deletes the runs that ended more than KeepRuns ago (with their steps, items, log and child runs) and the log lines
// older than KeepLog. It returns the number of runs and lines it deleted.
func (m *Manager) Prune(ctx context.Context) (runs, lines int64, err error) {
	now := m.cfg.Clock()
	err = m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM core_run WHERE parent_id IS NULL AND ended_at IS NOT NULL AND ended_at < ?`, store.FormatTS(now.Add(-KeepRuns)))
		if err != nil {
			return err
		}
		runs, _ = res.RowsAffected()
		res, err = tx.ExecContext(ctx, `DELETE FROM core_run_log WHERE ts < ?`, store.FormatTS(now.Add(-KeepLog)))
		if err != nil {
			return err
		}
		lines, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("run: prune: %w", err)
	}
	return runs, lines, nil
}

// statusOf reads a run's status and title.
func statusOf(ctx context.Context, tx *sql.Tx, id string) (Status, string, error) {
	var st, title string
	err := tx.QueryRowContext(ctx, `SELECT status, title FROM core_run WHERE id = ?`, id).Scan(&st, &title)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return Status(st), title, err
}

// tree lists a run and every run under it, parents first.
func tree(ctx context.Context, tx *sql.Tx, id string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `WITH RECURSIVE t(id, depth) AS (
		SELECT ?, 0 UNION ALL SELECT r.id, t.depth + 1 FROM core_run r JOIN t ON r.parent_id = t.id WHERE t.depth < 8)
		SELECT id FROM t ORDER BY depth`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		ids = append(ids, rid)
	}
	return ids, rows.Err()
}

// SubjectMovedTx gives the runs of module whose subject is device from to device into, inside the caller's transaction (a merge of
// two devices that were one machine: the runs of the one that goes are the history of the one that stays). The label snapshot stays.
func (m *Manager) SubjectMovedTx(ctx context.Context, tx *sql.Tx, module, subjectKind, from, into string) error {
	_, err := tx.ExecContext(ctx, `UPDATE core_run SET subject_id = ?, updated_at = ? WHERE module = ? AND subject_kind = ? AND subject_id = ?`,
		into, m.now(), module, subjectKind, from)
	if err != nil {
		return fmt.Errorf("run: move subject: %w", err)
	}
	return nil
}

// SubjectGoneTx stops, inside the caller's transaction, the runs of module about subject that have not started or wait (queued,
// waiting) with reason: their subject is gone (a deleted device). A running one is the module's to stop.
func (m *Manager) SubjectGoneTx(ctx context.Context, tx *sql.Tx, module, subjectKind, subjectID, reason string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM core_run WHERE module = ? AND subject_kind = ? AND subject_id = ? AND status IN (?, ?)`,
		module, subjectKind, subjectID, string(Queued), string(Waiting))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	now := m.now()
	for _, id := range ids {
		if _, err := m.stopTx(ctx, tx, id, reason, now); err != nil {
			return fmt.Errorf("run: stop for a gone subject: %w", err)
		}
	}
	return nil
}

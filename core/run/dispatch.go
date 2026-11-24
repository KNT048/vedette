package run

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/knt048/vedette/core/store"
)

// retryEvery is how often the dispatcher looks at the queue without being kicked.
const retryEvery = time.Minute

// dispatchLoop starts queued runs whenever it is kicked, until Close.
func (m *Manager) dispatchLoop() {
	defer m.loop.Done()
	tick := time.NewTicker(retryEvery) // a dispatch that failed (a busy or failed write) is tried again without waiting for a kick
	defer tick.Stop()
	for {
		select {
		case <-m.base.Done():
			return
		case <-tick.C:
			m.Kick()
		case <-m.kick:
			if err := m.dispatch(m.base); err != nil && m.base.Err() == nil {
				m.cfg.Log.Error("runs: could not start the queued runs", "error", err)
			}
		}
	}
}

type idKey struct{}

// IDFrom is the id of the run whose work ctx belongs to: the context a Kind's Run is called with carries it, so the work another
// module does for that run (a scan of a device inside a vulnerability check) is recorded against it. "" when ctx is no run's.
func IDFrom(ctx context.Context) string {
	id, _ := ctx.Value(idKey{}).(string)
	return id
}

// ShuttingDown says the work of ctx ends because Vedette is stopping, not because the run was stopped: the run is left running and the
// next start records it as stopped by the restart (Recover), so the work writes no stop line of its own.
func ShuttingDown(ctx context.Context) bool { return errors.Is(context.Cause(ctx), errShutdown) }

// starting is a run the dispatcher moved to running, to hand to its Kind.
type starting struct {
	id      string
	kind    Kind
	resumed bool
}

// holder is the running run that holds a lane, for its kind's GiveWay.
type holder struct {
	id   string
	kind Kind
}

// dispatch starts the oldest queued run of every free lane whose module is on and whose kind is registered, and tells the running
// run of a lane whose kind gives way (Kind.GiveWay) that a run of another kind is queued behind it.
func (m *Manager) dispatch(ctx context.Context) error {
	var start []starting
	var giveWay map[string]holder
	err := m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		start, giveWay = start[:0], map[string]holder{}
		busy := map[string]bool{}
		holders := map[string]holder{} // by lane: the running run whose kind gives way
		rows, err := tx.QueryContext(ctx, `SELECT id, module, kind, lane, status FROM core_run WHERE status IN (?, ?)`, string(Running), string(Stopping))
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, module, kind, lane string
			var st Status
			if err := rows.Scan(&id, &module, &kind, &lane, &st); err != nil {
				_ = rows.Close()
				return err
			}
			busy[lane] = true
			if k, ok := m.kind(module, kind); ok && k.GiveWay != nil && st == Running {
				holders[lane] = holder{id: id, kind: k}
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		type queued struct {
			id, module, kind, lane string
			resumed                bool
		}
		var qs []queued
		rows, err = tx.QueryContext(ctx, `SELECT id, module, kind, lane, started_at IS NOT NULL FROM core_run WHERE status = ? ORDER BY queued_at, rowid`, string(Queued))
		if err != nil {
			return err
		}
		for rows.Next() {
			var q queued
			if err := rows.Scan(&q.id, &q.module, &q.kind, &q.lane, &q.resumed); err != nil {
				_ = rows.Close()
				return err
			}
			qs = append(qs, q)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		now := m.now()
		for _, q := range qs {
			k, ok := m.kind(q.module, q.kind)
			if !ok || (m.cfg.Gate != nil && !m.cfg.Gate.Enabled(q.module)) {
				continue // it waits in the queue for its module
			}
			if busy[q.lane] {
				if h, ok := holders[q.lane]; ok && h.kind.key() != k.key() {
					giveWay[h.id] = h // told after the commit, so every check the holder makes sees this run
				}
				continue
			}
			res, err := tx.ExecContext(ctx, `UPDATE core_run SET status = ?, started_at = COALESCE(started_at, ?), updated_at = ?,
				waiting_for = NULL, stop_reason = NULL, error = NULL, ended_at = NULL WHERE id = ? AND status = ?`,
				string(Running), now, now, q.id, string(Queued))
			if store.IsUniqueViolation(err) { // another run holds the lane: the database says so, whatever this map believed
				busy[q.lane] = true
				continue
			}
			if err != nil {
				return fmt.Errorf("start %s: %w", q.id, err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			busy[q.lane] = true
			if k.GiveWay != nil {
				holders[q.lane] = holder{id: q.id, kind: k}
			}
			text := LineStarted
			if q.resumed {
				text = LineResumed
			}
			if err := logTx(ctx, tx, q.id, now, Info, text); err != nil {
				return err
			}
			start = append(start, starting{id: q.id, kind: k, resumed: q.resumed})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, s := range start {
		m.launch(s) //nolint:contextcheck // a run outlives this dispatch call: it runs under the manager's own base context
	}
	for id, h := range giveWay {
		h.kind.GiveWay(m.base, id) //nolint:contextcheck // the holder runs under the manager's own base context
	}
	return nil
}

// launch executes a run that dispatch moved to running.
func (m *Manager) launch(s starting) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return // the row stays running: the next start recovers it
	}
	ctx, cancel := context.WithCancelCause(context.WithValue(m.base, idKey{}, s.id))
	m.live[s.id] = cancel
	m.runs.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.runs.Done()
		defer cancel(nil)
		// A stop that came between the start and this point found no executor and recorded the end itself.
		var st Status
		if err := m.cfg.DB.Reader().QueryRowContext(ctx, `SELECT status FROM core_run WHERE id = ?`, s.id).Scan(&st); err == nil && !st.Live() {
			cancel(errStopAsked)
		}
		x := &Exec{m: m, id: s.id, Resumed: s.resumed}
		res, err := m.execute(ctx, s.kind, x)
		res.NotBegun = res.NotBegun && !s.resumed // a run that began before keeps its start
		// The executor leaves the live map only once its end is recorded: a stop in between finds it (and its stopping row is
		// then ended by finish) instead of recording a stop over work that finished.
		defer func() {
			m.mu.Lock()
			delete(m.live, s.id)
			m.mu.Unlock()
		}()
		if errors.Is(context.Cause(ctx), errShutdown) {
			return // left running on purpose: Recover records it at the next start
		}
		if ferr := m.finish(context.WithoutCancel(ctx), s.id, res, err, errors.Is(context.Cause(ctx), errStopAsked)); ferr != nil {
			m.cfg.Log.Error("runs: could not record the end of a run", "run", s.id, "error", ferr)
		}
		if m.ended != nil {
			m.ended(s.id)
		}
		m.Kick()
	}()
}

// execute calls the kind's Run and turns a panic into a failure.
func (m *Manager) execute(ctx context.Context, k Kind, x *Exec) (res Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			m.cfg.Log.ErrorContext(ctx, "runs: a run panicked", "run", x.id, "kind", k.key(), "panic", p, "stack", string(debug.Stack()))
			res, err = Result{}, errors.New("the run stopped on an internal error")
		}
	}()
	return k.Run(ctx, x)
}

// finish records how a run ended. A stop asked while it ran makes it stopped unless it finished all its work anyway.
func (m *Manager) finish(ctx context.Context, id string, res Result, runErr error, stopAsked bool) error {
	st := res.Status
	if st == "" {
		st = Done
	}
	errText := res.Error
	switch {
	case stopAsked && st != Done:
		st = Stopped
	case runErr != nil:
		st, errText = Failed, runErr.Error()
	case st != Done && st != Partial && st != Failed && st != Waiting:
		st, errText = Failed, fmt.Sprintf("the run ended with the state %q, which a run cannot end in", st)
	}
	waitingFor := ""
	if st == Waiting {
		waitingFor = clip(res.WaitingFor, 200)
		if waitingFor == "" {
			waitingFor = "a person to resume it"
		}
	}
	return m.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		now := m.now()
		var ended any
		if st.Ended() {
			ended = now
		}
		up, err := tx.ExecContext(ctx, `UPDATE core_run SET status = ?, waiting_for = ?, error = ?, ended_at = ?, updated_at = ?,
			stop_reason = CASE WHEN ? THEN stop_reason ELSE NULL END
			WHERE id = ? AND status IN (?, ?)`,
			string(st), nullable(waitingFor, 200), nullable(errText, 1000), ended, now, st == Stopped, id, string(Running), string(Stopping))
		if err != nil {
			return err
		}
		if n, _ := up.RowsAffected(); n == 0 {
			return nil // already recorded (a stop of a run this process did not execute)
		}
		if err := settleSteps(ctx, tx, id, st, now); err != nil {
			return err
		}
		if st == Waiting && res.NotBegun {
			if err := unstart(ctx, tx, id); err != nil {
				return err
			}
		}
		return logTx(ctx, tx, id, now, levelOf(st), endText(st, waitingFor, errText))
	})
}

// unstart takes back the start of a run whose first turn waited before it did any work (Result.NotBegun): it has not started, so it
// has no started time and its log has no "Started" line; the next turn that really works starts it. Its steps lose the start of that
// turn too.
func unstart(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE core_run SET started_at = NULL WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE core_run_step SET started_at = NULL WHERE run_id = ? AND done = 0`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM core_run_log WHERE id = (SELECT max(id) FROM core_run_log WHERE run_id = ? AND text = ?)`, id, LineStarted)
	return err
}

// settleSteps gives the steps still running when the run leaves running the run's new state.
func settleSteps(ctx context.Context, tx *sql.Tx, id string, st Status, now string) error {
	var ended any
	if st.Ended() {
		ended = now
	}
	_, err := tx.ExecContext(ctx, `UPDATE core_run_step SET status = ?, ended_at = ? WHERE run_id = ? AND status = ?`, string(st), ended, id, string(Running))
	return err
}

func levelOf(st Status) Level {
	switch st {
	case Failed:
		return Error
	case Partial, Stopped:
		return Warn
	}
	return Info
}

// endText is the log line of a run's end.
func endText(st Status, waitingFor, errText string) string {
	switch st {
	case Waiting:
		return "Waiting for " + waitingFor
	case Failed:
		if errText == "" {
			return "Failed"
		}
		return "Failed: " + errText
	case Partial:
		if errText == "" {
			return "Partly done"
		}
		return "Partly done: " + errText
	case Stopped:
		return "Stopped"
	}
	return "Done"
}

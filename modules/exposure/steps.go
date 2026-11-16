package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The engine steps of an external scan as Settings › Scanning shows them (#861, INV-30): nuclei (the safe and the deep templates), ZAP
// (the passive web scan) and OpenVAS. Their cards take their last run from here.
const (
	StepNuclei  = "nuclei"
	StepZAP     = "zap"
	StepOpenVAS = "openvas"
)

// How a step of a run ended (exp_engine_run.outcome), as Settings › Scanning's last_run.outcome names it.
const (
	StepOK      = "ok"
	StepPartial = "partial"
	StepFailed  = "failed"
	StepStopped = "stopped"
)

var stepEngines = []string{StepNuclei, StepZAP, StepOpenVAS}

// EngineRun is the newest run of an external scan in which an engine step actually ran (exp_engine_run, INV-30): a run that skipped
// the step (OpenVAS off, no web port for ZAP, no template needed) leaves the earlier one. At is when the step ended (RFC 3339 UTC).
type EngineRun struct {
	Engine  string
	RunID   string
	Target  string
	At      string
	Outcome string
	Text    string
}

// EngineRuns reads the newest run of each engine step; an engine that never ran is not in the map.
func (s *Service) EngineRuns(ctx context.Context) (map[string]EngineRun, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT engine, run_id, target, at, outcome, text FROM exp_engine_run`)
	if err != nil {
		return nil, fmt.Errorf("exposure: reading the engines' last runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]EngineRun{}
	for rows.Next() {
		var r EngineRun
		if err := rows.Scan(&r.Engine, &r.RunID, &r.Target, &r.At, &r.Outcome, &r.Text); err != nil {
			return nil, fmt.Errorf("exposure: reading the engines' last runs: %w", err)
		}
		out[r.Engine] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("exposure: reading the engines' last runs: %w", err)
	}
	return out, nil
}

// stepLog is what the engine steps of one run did (INV-30). nuclei and ZAP count their calls as they make them (one call per address,
// one per page); OpenVAS's outcome is the step's own state. A nil *stepLog records nothing (a step called outside a run).
type stepLog struct {
	mu sync.Mutex
	m  map[string]*stepTally
}

type stepTally struct {
	running, ok, failed, found int
	at                         time.Time // when a call last ended
	outcome, text              string    // set when the step names its own outcome (OpenVAS)
	saved                      bool
}

type stepsKey struct{}

func withSteps(ctx context.Context, l *stepLog) context.Context {
	return context.WithValue(ctx, stepsKey{}, l)
}

func stepsOf(ctx context.Context) *stepLog {
	l, _ := ctx.Value(stepsKey{}).(*stepLog)
	return l
}

func (l *stepLog) tally(engine string) *stepTally {
	if l.m == nil {
		l.m = map[string]*stepTally{}
	}
	t := l.m[engine]
	if t == nil {
		t = &stepTally{}
		l.m[engine] = t
	}
	return t
}

// begin is called right before the engine is asked; every begin is followed by end, unless the run is stopped while it runs.
func (l *stepLog) begin(engine string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tally(engine).running++
}

// The results of one call of an engine (stepLog.end).
const (
	callRan     = iota // the engine ran and answered
	callFailed         // it was asked and failed (an error, its cap, an answer that could not be read, unavailable)
	callSkipped        // it was not asked after all (a page that was skipped): the call does not count
)

// end records how one call ended and what it found (alerts, matched templates).
func (l *stepLog) end(engine string, result, found int, at time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.tally(engine)
	t.running--
	switch result {
	case callRan:
		t.ok++
	case callFailed:
		t.failed++
	default:
		return
	}
	t.found += found
	t.at = at
}

// set records a step that names its own outcome (OpenVAS); "" outcome means it did not run and the run does not count.
func (l *stepLog) set(engine, outcome, text string, at time.Time) {
	if l == nil || outcome == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.tally(engine)
	t.outcome, t.text, t.at = outcome, text, at
}

// rows takes the steps that ended and were not saved yet; final takes a step still running too, as stopped at now (the run ends).
func (l *stepLog) rows(runID, target string, now time.Time, final bool) []EngineRun {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []EngineRun
	for _, engine := range stepEngines {
		t := l.m[engine]
		if t == nil || t.saved || (t.running > 0 && !final) {
			continue
		}
		outcome, text, at := t.outcome, t.text, t.at
		if outcome == "" {
			switch {
			case t.running > 0:
				outcome, at = StepStopped, now
			case t.ok+t.failed == 0: // every call was skipped: the step did not run
				continue
			case t.failed == 0:
				outcome = StepOK
			case t.ok == 0:
				outcome = StepFailed
			default:
				outcome = StepPartial
			}
			text = stepText(engine, outcome, t)
		}
		t.saved = true
		out = append(out, EngineRun{Engine: engine, RunID: runID, Target: target, At: store.FormatTS(at), Outcome: outcome,
			Text: clipText("External scan of "+target+": "+text, maxLineText)})
	}
	return out
}

func stepText(engine, outcome string, t *stepTally) string {
	if outcome == StepStopped {
		return map[string]string{StepNuclei: "stopped while the templates ran", StepZAP: "stopped while ZAP ran"}[engine]
	}
	switch engine {
	case StepZAP:
		switch outcome {
		case StepOK:
			return fmt.Sprintf("ZAP scanned %s, %s", plural(t.ok, "page"), plural(t.found, "alert"))
		case StepPartial:
			return fmt.Sprintf("ZAP scanned %d of %d pages, %s", t.ok, t.ok+t.failed, plural(t.found, "alert"))
		}
		return "ZAP could not scan " + plural(t.failed, "page")
	default:
		switch outcome {
		case StepOK:
			return fmt.Sprintf("safe templates ran, %d matched", t.found)
		case StepPartial:
			return fmt.Sprintf("templates ran on %d of %d addresses, %d matched", t.ok, t.ok+t.failed, t.found)
		}
		return "the templates did not finish"
	}
}

// openVASStep is the outcome and text of the OpenVAS step from its state (GreenboneRun.State) and its rows; "" when it did not run.
func openVASStep(state string, results int) (string, string) {
	switch state {
	case GBRunDone:
		return StepOK, "OpenVAS found " + plural(results, "result")
	case GBRunPartial:
		return StepPartial, "OpenVAS stopped at its 90-minute limit, " + plural(results, "result")
	case GBRunEnded:
		return StepPartial, "OpenVAS ended the task before it finished, " + plural(results, "result")
	case GBRunFailed:
		return StepFailed, "OpenVAS failed (the scan's Not checked list says why)"
	case GBRunStopped:
		return StepStopped, "stopped while OpenVAS ran"
	}
	return "", ""
}

// saveSteps stores the steps of the run that ended and were not stored yet (INV-30): before the OpenVAS step starts (nuclei and ZAP
// are done by then), and when the run ends. It runs on its own context, so a stop or a shutdown still records it; a failure is logged.
func (s *Service) saveSteps(ctx context.Context, run *scanRun, final bool) {
	rows := run.steps.rows(run.view.ID, run.view.TargetValue, s.clock(), final)
	if len(rows) == 0 {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		for _, r := range rows {
			if _, err := tx.ExecContext(wctx, `INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (engine) DO UPDATE SET run_id = excluded.run_id, target = excluded.target, at = excluded.at, outcome = excluded.outcome, text = excluded.text`,
				r.Engine, r.RunID, r.Target, r.At, r.Outcome, r.Text); err != nil {
				return fmt.Errorf("exposure: storing the last run of %s: %w", r.Engine, err)
			}
		}
		return nil
	})
	if err != nil {
		s.cfg.Log.ErrorContext(wctx, "exposure: storing the engines' last runs failed", "run", run.view.ID, "error", err)
	}
}

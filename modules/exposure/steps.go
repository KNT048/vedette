package exposure

import (
	"context"
	"database/sql"
	"errors"
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
	running, ok, empty, failed, found int
	at                                time.Time // when a call last ended
	outcome, text                     string    // set when the step names its own outcome (OpenVAS)
	deep                              bool      // nuclei ran the deep templates (testing terms accepted)
	closed                            bool      // the run is past the step: no more calls come
	saved                             bool
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

// begin is called right before the engine is asked; every begin is followed by end, unless the run is stopped while it runs. deep
// says the call runs the deep templates (nuclei of a target whose testing terms are accepted).
func (l *stepLog) begin(engine string, deep bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.tally(engine)
	t.running++
	t.deep = t.deep || deep
}

// The results of one call of an engine (stepLog.end).
const (
	callRan     = iota // the engine ran and answered
	callEmpty          // ZAP ran and found no page at the address: answered, but nothing was scanned
	callFailed         // it ran and failed (an error, its cap, an answer that could not be read)
	callSkipped        // it did not run after all (a skipped page, the engine unavailable or off): the call does not count
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
	case callEmpty:
		t.empty++
	case callFailed:
		t.failed++
	default:
		return
	}
	t.found += found
	t.at = at
}

// close says the run is past the step: a stop or an error after it does not change how the step ended.
func (l *stepLog) close(engine string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tally(engine).closed = true
}

// set records a step that names its own outcome (OpenVAS); "" outcome means it did not run and the run does not count.
func (l *stepLog) set(engine, outcome, text string, at time.Time) {
	if l == nil || outcome == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.tally(engine)
	t.outcome, t.text, t.at, t.closed = outcome, text, at, true
}

// How a run ended, for rows: runOn (not ended: only the closed steps are taken), runEnded (done, or failed with an error the steps
// reported themselves), runStopped (a Stop, the module switched off, the box shutting down), runPanicked (an error of the box).
const (
	runOn = iota
	runEnded
	runStopped
	runPanicked
)

// rows takes the steps that ended and were not saved yet. Once the run ended (end != runOn), a step it cut, in a call or between two
// calls, is stopped at now, or failed when the box's error ended the run.
func (l *stepLog) rows(runID, target string, now time.Time, end int) []EngineRun {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []EngineRun
	for _, engine := range stepEngines {
		t := l.m[engine]
		if t == nil || t.saved || (end == runOn && (!t.closed || t.running > 0)) {
			continue
		}
		outcome, text, at := t.outcome, t.text, t.at
		if outcome == "" {
			cut := t.running > 0 || (!t.closed && (end == runStopped || end == runPanicked))
			switch {
			case t.running == 0 && t.ok+t.empty+t.failed == 0: // every call was skipped: the step did not run
				continue
			case cut && end == runPanicked:
				outcome, at = StepFailed, now
				text = map[string]string{StepNuclei: "the scan stopped because of an error on the box while the templates ran",
					StepZAP: "the scan stopped because of an error on the box while ZAP ran"}[engine]
			case cut:
				outcome, at = StepStopped, now
				text = map[string]string{StepNuclei: "stopped while the templates ran", StepZAP: "stopped while ZAP ran"}[engine]
			default:
				switch {
				case t.failed == 0:
					outcome = StepOK
				case t.ok+t.empty == 0:
					outcome = StepFailed
				default:
					outcome = StepPartial
				}
				text = stepText(engine, outcome, t)
			}
		}
		t.saved = true
		out = append(out, EngineRun{Engine: engine, RunID: runID, Target: target, At: store.FormatTS(at), Outcome: outcome,
			Text: clipText("External scan of "+target+": "+text, maxLineText)})
	}
	return out
}

func stepText(engine, outcome string, t *stepTally) string {
	if engine == StepZAP {
		total := t.ok + t.empty + t.failed
		switch {
		case outcome == StepFailed:
			return "ZAP could not scan " + plural(t.failed, "page")
		case t.ok == 0: // every page it answered for had no page there
			return "ZAP found no page to scan at " + plural(t.empty, "web port")
		case outcome == StepPartial || t.empty > 0:
			return fmt.Sprintf("ZAP scanned %d of %d pages, %s", t.ok, total, plural(t.found, "alert"))
		}
		return fmt.Sprintf("ZAP scanned %s, %s", plural(t.ok, "page"), plural(t.found, "alert"))
	}
	kind := "safe templates"
	if t.deep {
		kind = "deep templates"
	}
	switch outcome {
	case StepOK:
		return fmt.Sprintf("%s ran, %d matched", kind, t.found)
	case StepPartial:
		return fmt.Sprintf("%s ran on %d of %d addresses, %d matched", kind, t.ok, t.ok+t.failed, t.found)
	}
	return "the " + kind + " did not finish"
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
// are done by then, end runOn), and when the run ends. A target deleted meanwhile gets no row. It runs on its own context, so a stop or a shutdown still records it; a failure is logged.
func (s *Service) saveSteps(ctx context.Context, run *scanRun, end int) {
	rows := run.steps.rows(run.view.ID, run.view.TargetValue, s.clock(), end)
	if len(rows) == 0 {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		if _, err := loadTarget(wctx, tx, run.view.TargetID); errors.Is(err, ErrNotFound) { // deleted while it ran (L4 of #863 r1)
			return nil
		} else if err != nil {
			return err
		}
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

package exposure

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/knt048/vedette/core/store"
)

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
// calls, is stopped at now (why says why, stopWhy), or failed when the box's error ended the run.
func (l *stepLog) rows(runID, target string, now time.Time, end int, why string) []EngineRun {
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
					StepZAP: "the scan stopped because of an error on the box while ZAP ran", StepZAPActive: "the scan stopped because of an error on the box while ZAP's active scan ran"}[engine]
			case cut:
				outcome, at = StepStopped, now
				text = map[string]string{StepNuclei: "stopped while the templates ran", StepZAP: "stopped while ZAP ran", StepZAPActive: "stopped while ZAP's active scan ran (its container was removed)"}[engine] + whyNote(why)
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
	if engine == StepZAPActive {
		rules := "without the disruptive rules"
		if t.deep {
			rules = "with the disruptive rules"
		}
		total := t.ok + t.empty + t.failed
		switch {
		case outcome == StepFailed:
			return "ZAP's active scan could not attack " + plural(t.failed, "page")
		case outcome == StepPartial:
			return fmt.Sprintf("ZAP's active scan attacked %d of %d pages %s, %s", t.ok, total, rules, plural(t.found, "alert"))
		}
		return fmt.Sprintf("ZAP's active scan attacked %s %s, %s", plural(t.ok, "page"), rules, plural(t.found, "alert"))
	}
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

// whyNote is why, as the end of a stopped step's text: " (Vedette shut down while it ran …)"; "" when not known.
func whyNote(why string) string {
	if why == "" {
		return ""
	}
	return " (" + why + ")"
}

// openVASStep is the outcome and text of the OpenVAS step from its state (GreenboneRun.State), its rows and, when stopped, why;
// "" when it did not run.
func openVASStep(state string, results int, stop *GreenboneStop) (string, string) {
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
		return StepStopped, "stopped while OpenVAS ran" + whyNote(stopWhy(stop))
	}
	return "", ""
}

// ran says the engine answered at least one call in this run: its issues of this run replace the earlier ones.
func (l *stepLog) ran(engine string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.m[engine]
	return t != nil && (t.ok > 0 || t.outcome == StepOK || t.outcome == StepPartial)
}

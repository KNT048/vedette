package exposure

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/progress"
	corerun "github.com/knt048/vedette/core/run"
)

// The steps of a scan as its run page lists them (INV-29, INV-30). Every step of the plan is added queued as soon as the plan is
// known, so the page lists the whole scan from its first moments; each one then runs, ends (done, partial, failed, stopped) or is
// skipped with why in plain words. A step counts as one unit of the run (total 1), so the run reads "3 of 8 steps"; where a running
// step is (nmap's percent, the template checks, the page ZAP is on, OpenVAS's percent) is its note, written at most every
// liveEvery. Each start and end is a line of the run's log.

// The keys of the steps. stepSurface (the old single step) is only read: runs stored before the steps were split have it.
const (
	stepKeyCheck    = "check"    // the gate, right before the scan: proof, commitment, terms, safety rules
	stepKeySurface  = "surface"  // the runner: an IP's common ports, pages and certificates, or a domain's names and their pages
	stepKeyPorts    = "ports"    // nmap's port discovery (every TCP port in a deep scan, the 1,000 most common otherwise)
	stepKeyServices = "services" // nmap -sV on the open ports, with nmap's scripts in a deep scan
	stepKeyNuclei   = StepNuclei
	stepKeyZAP      = StepZAP
	// stepKeyZAPActive is ZAP's active scan (INV-24a), right after the passive one, in a deep scan's plan only: skipped with why in a
	// scheduled scan, its note says the pages attacked, the rules, the alerts and a page cut short at its limit.
	stepKeyZAPActive = StepZAPActive
	stepKeySave      = "save" // the comparison with the exploited CVEs, then the rows written
	stepKeyOpenVAS   = StepOpenVAS
	// stepKeyDisruptive is nmap's disruptive scripts (password guessing, denial of service and crash checks), the last step of a deep
	// scan's plan: only when the run allows the disruptive checks, on the open ports the scan found; skipped with why otherwise.
	stepKeyDisruptive = "nmap_disruptive"
	stepKeyWaiting    = "waiting" // a domain's addresses left for the next scans (the deep scan's cap)
)

// The names of the steps that are not engine steps. The engine steps keep their names (stepNames), which Settings › Scanning reads.
const (
	stepNameCheck       = "Check ownership, terms and safety rules"
	stepNameSurfaceIP   = "Common ports, web pages and certificates"
	stepNameSurfaceDom  = "Find names and check their web pages"
	stepNamePortsDeep   = "Find open ports (every TCP port)"
	stepNamePorts       = "Find open ports (nmap's 1,000 most common)"
	stepNameServiceDeep = "Identify services and run nmap's safe scripts"
	stepNameServices    = "Identify services (nmap -sV)"
	stepNameSave        = "Compare with exploited CVEs and save the results"
	stepNameWaiting     = "Addresses left for the next scans"
	stepNameDisruptive  = "nmap's disruptive scripts (password guessing, crash checks)"
)

// liveEvery is how often where a running step is gets written to its note.
const liveEvery = 3 * time.Second

// The notes of the steps the run ends before they run.
const (
	notReachedStopped = "Not reached: the scan was stopped before this step."
	notReachedFailed  = "Not reached: the scan ended before this step."
)

type stepDef struct{ key, name string }

// scanPlan is the steps of a scan of a target of kind k at mode m, in the order they run. The steps of a domain's addresses (deep
// scan) are added between its surface step and the rest as they come (runSteps.addAddress), so the rest is added after them.
// A step added later (an engine of its own) goes here, in the place it runs.
//
// The order of a deep scan puts the light checks before the heavy ones: nmap's sweep of every port with service identification and
// its safe scripts (the later steps need the ports and the services), the templates, ZAP's passive then active scan, the results
// written, OpenVAS, and nmap's disruptive scripts last, so a ban or an overloaded firewall in front of the target costs only the
// last steps. Before each engine step the scan checks that the ports seen open earlier still answer (probes.go).
func scanPlan(k Kind, m ScanMode) (head, tail []stepDef) {
	if k == KindDomain {
		head = []stepDef{{stepKeySurface, stepNameSurfaceDom}}
	} else {
		ports, services := stepNamePorts, stepNameServices
		if m.Full {
			ports, services = stepNamePortsDeep, stepNameServiceDeep
		}
		head = []stepDef{{stepKeySurface, stepNameSurfaceIP}, {stepKeyPorts, ports}, {stepKeyServices, services}}
	}
	tail = []stepDef{{stepKeyNuclei, stepNameNuclei}, {stepKeyZAP, stepNameZAP}}
	if m.Full {
		tail = append(tail, stepDef{stepKeyZAPActive, stepNameZAPAct})
	}
	tail = append(tail, stepDef{stepKeySave, stepNameSave}, stepDef{stepKeyOpenVAS, stepNameOpenVAS})
	if m.Full {
		tail = append(tail, stepDef{stepKeyDisruptive, stepNameDisruptive})
	}
	return head, tail
}

// runStep is one step of the run as this process knows it.
type runStep struct {
	key, name string
	seq       int
	state     corerun.Status
	started   time.Time
	live      string // the note written while it runs
	noted     bool   // it ended with a note
}

// runSteps writes the steps of one scan's run. A nil *runSteps writes nothing (a scan's code called outside a run, or inside the
// step of one of a domain's addresses, whose engine phases are that step's). Safe for concurrent use: progress reports come from the
// readers of the engines' output.
type runSteps struct {
	x     *corerun.Exec
	log   *slog.Logger
	clock func() time.Time
	l     *stepLog

	mu    sync.Mutex // the steps, and every write: one order of writes
	steps []*runStep
	byKey map[string]*runStep
	tail  []stepDef // the steps of the plan not added yet

	// incomplete is, for a step, why its results are incomplete (a port that stopped answering before or while it ran): a step that
	// ends done with one ends partly done, the reason after its note. problems are what the run did not do that it should have (a
	// target that stopped answering, an engine image not on the box yet): a run with one ends partly done, never done. Both under mu.
	incomplete map[string]string
	problems   []string

	pmu      sync.Mutex
	pending  map[string]string // the newest note of each running step, not written yet
	services bool              // nmap reported its service phase: the port discovery is over
	only     string            // while set, every progress report is the note of this step (nmap's disruptive scripts)
	stop     chan struct{}
	stopped  chan struct{}
}

func (s *Service) newRunSteps(x *corerun.Exec, l *stepLog) *runSteps {
	return &runSteps{x: x, log: s.cfg.Log, clock: s.clock, l: l, byKey: map[string]*runStep{}, pending: map[string]string{}, incomplete: map[string]string{}}
}

// incompleteOn says the results of step key are incomplete, and why (each reason once, in the order given).
func (rs *runSteps) incompleteOn(key, why string) {
	if rs == nil || why == "" {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !strings.Contains(rs.incomplete[key], why) {
		rs.incomplete[key] = strings.TrimSpace(rs.incomplete[key] + " " + why)
	}
}

// problem records something the run did not do that it should have; the run then ends partly done with the first one as its reason.
func (rs *runSteps) problem(why string) {
	if rs == nil || why == "" {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !slices.Contains(rs.problems, why) {
		rs.problems = append(rs.problems, why)
	}
}

// result is res with the run's problems: a run that would end done with one ends partly done, its first problem (and how many more)
// as its reason; a run that already ends partly done adds them to its own reason.
func (rs *runSteps) result(res corerun.Result) corerun.Result {
	if rs == nil {
		return res
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.problems) == 0 || (res.Status != "" && res.Status != corerun.Done && res.Status != corerun.Partial) {
		return res
	}
	why := rs.problems[0]
	if n := len(rs.problems) - 1; n > 0 {
		why = fmt.Sprintf("%s (and %s)", strings.TrimSuffix(why, "."), plural(n, "more problem"))
	}
	if res.Error != "" {
		why = res.Error + "; " + why
	}
	return corerun.Result{Status: corerun.Partial, Error: clipText(why, 1000)}
}

// logLine writes a line of the run's log.
func (rs *runSteps) logLine(ctx context.Context, level corerun.Level, text string) {
	if rs == nil {
		return
	}
	c, cancel := wctx(ctx)
	defer cancel()
	rs.warn(ctx, "log", rs.x.Log(c, level, clipText(text, 1000)))
}

type runStepsKey struct{}

type scanRunKey struct{}

// RunIDOf is the core_run id of the exposure scan whose work ctx carries, "" outside one: the probe log links each probe to its run.
func RunIDOf(ctx context.Context) string {
	id, _ := ctx.Value(scanRunKey{}).(string)
	return id
}

// WithRunID is ctx for the work of the exposure scan whose run is id (RunIDOf).
func WithRunID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, scanRunKey{}, id)
}

func withRunSteps(ctx context.Context, rs *runSteps) context.Context {
	return context.WithValue(ctx, runStepsKey{}, rs)
}

// runStepsOf is the steps of ctx's run; nil inside the step of one of a domain's addresses (withinAddress).
func runStepsOf(ctx context.Context) *runSteps {
	rs, _ := ctx.Value(runStepsKey{}).(*runSteps)
	return rs
}

// wctx is a context for one write that outlives a stop of the run: the step must say how it ended.
func wctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}

func (rs *runSteps) warn(ctx context.Context, what string, err error) {
	if err != nil {
		rs.log.WarnContext(ctx, "exposure: writing a step of the scan's run failed", "run", rs.x.ID(), "write", what, "error", err)
	}
}

// add appends the steps defs, queued. The caller holds mu.
func (rs *runSteps) addLocked(ctx context.Context, defs ...stepDef) {
	c, cancel := wctx(ctx)
	defer cancel()
	for _, d := range defs {
		if rs.byKey[d.key] != nil {
			continue
		}
		seq, err := rs.x.AddStep(c, d.name, 1)
		if err != nil {
			rs.warn(ctx, "add "+d.key, err)
			continue
		}
		st := &runStep{key: d.key, name: d.name, seq: seq, state: corerun.Queued}
		rs.steps = append(rs.steps, st)
		rs.byKey[d.key] = st
	}
}

// add appends steps now, queued.
func (rs *runSteps) add(ctx context.Context, defs ...stepDef) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.addLocked(ctx, defs...)
}

// plan adds the head of the plan now and keeps the tail for addTail (an IP scan adds both at once).
func (rs *runSteps) plan(ctx context.Context, head, tail []stepDef, now bool) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.addLocked(ctx, head...)
	rs.tail = tail
	if now {
		rs.addLocked(ctx, rs.tail...)
		rs.tail = nil
	}
}

// addTail adds the rest of the plan (after a domain's addresses).
func (rs *runSteps) addTail(ctx context.Context) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.addLocked(ctx, rs.tail...)
	rs.tail = nil
}

// addressKey is the key of the step of one of a domain's addresses.
func addressKey(ip string) string { return "address:" + ip }

// start marks a queued step running and logs it; a step that runs or has ended is left as it is.
func (rs *runSteps) start(ctx context.Context, key string) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.startLocked(ctx, key)
}

func (rs *runSteps) startLocked(ctx context.Context, key string) {
	st := rs.byKey[key]
	if st == nil || st.state != corerun.Queued {
		return
	}
	c, cancel := wctx(ctx)
	defer cancel()
	if err := rs.x.StartStep(c, st.seq); err != nil {
		rs.warn(ctx, "start "+key, err)
		return
	}
	st.state, st.started = corerun.Running, rs.clock()
	rs.warn(ctx, "log", rs.x.Log(c, corerun.Info, "Started: "+st.name))
}

// end records how a step ended (done, partial, failed or stopped) with note, and logs it with how long it took. A queued step is
// started first, so it has a start time; a step that has ended is left as it is. A stopped step does not count as done.
func (rs *runSteps) end(ctx context.Context, key string, how corerun.Status, note string) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.endLocked(ctx, key, how, note)
}

func (rs *runSteps) endLocked(ctx context.Context, key string, how corerun.Status, note string) {
	st := rs.byKey[key]
	if st == nil {
		return
	}
	if st.state != corerun.Queued && st.state != corerun.Running {
		rs.fillLocked(ctx, st, how, note)
		return
	}
	rs.startLocked(ctx, key)
	if st.state != corerun.Running {
		return
	}
	if why := rs.incomplete[key]; why != "" && (how == corerun.Done || how == corerun.Partial) { // a port stopped answering: never "done"
		how = corerun.Partial
		note = strings.TrimSpace(note + " " + why)
	}
	c, cancel := wctx(ctx)
	defer cancel()
	if how != corerun.Stopped {
		rs.warn(ctx, "count "+key, rs.x.Progress(c, st.seq, 1, 1))
	}
	note = clipText(note, 500)
	if err := rs.x.EndStep(c, st.seq, how, note); err != nil {
		rs.warn(ctx, "end "+key, err)
		return
	}
	st.state, st.noted = how, note != ""
	rs.dropPending(key)
	word := map[corerun.Status]string{corerun.Done: "Done", corerun.Partial: "Partly done", corerun.Failed: "Failed", corerun.Stopped: "Stopped"}[how]
	level := map[corerun.Status]corerun.Level{corerun.Done: corerun.Info, corerun.Partial: corerun.Warn, corerun.Failed: corerun.Error, corerun.Stopped: corerun.Warn}[how]
	line := word + ": " + st.name + " (" + tookText(rs.clock().Sub(st.started)) + ")"
	if note != "" {
		line += ". " + note
	}
	rs.warn(ctx, "log", rs.x.Log(c, level, clipText(line, 1000)))
}

// fillLocked gives a step that ended as how without a note the note of that same end, once: the port discovery ends when nmap's
// service scan starts, and how many open ports it found is known only when nmap answers. Its state and end time stay as they are.
func (rs *runSteps) fillLocked(ctx context.Context, st *runStep, how corerun.Status, note string) {
	note = clipText(note, 500)
	if st.state != how || st.noted || note == "" {
		return
	}
	c, cancel := wctx(ctx)
	defer cancel()
	if err := rs.x.FillNote(c, st.seq, note); err != nil {
		rs.warn(ctx, "note of "+st.key, err)
		return
	}
	st.noted = true
	rs.warn(ctx, "log", rs.x.Log(c, corerun.Info, clipText(st.name+": "+note, 1000)))
}

// skip records that a step did not run, with why, while the scan goes on: the scan is complete without it (an engine turned off,
// nothing for it to check), so it counts as done in the run's "3 of 8 steps". A step the run never reached is skipped by close, and
// does not count.
func (rs *runSteps) skip(ctx context.Context, key, note string) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.skipLocked(ctx, key, note, true)
}

func (rs *runSteps) skipLocked(ctx context.Context, key, note string, counts bool) {
	st := rs.byKey[key]
	if st == nil || (st.state != corerun.Queued && st.state != corerun.Running) { // a step that started may find it cannot run
		return
	}
	rs.dropPending(key)
	c, cancel := wctx(ctx)
	defer cancel()
	if counts {
		rs.warn(ctx, "count "+key, rs.x.Progress(c, st.seq, 1, 1))
	}
	note = clipText(note, 500)
	if err := rs.x.SkipStep(c, st.seq, note); err != nil {
		rs.warn(ctx, "skip "+key, err)
		return
	}
	st.state, st.noted = corerun.Skipped, note != ""
	line := "Skipped: " + st.name
	if note != "" {
		line += ". " + note
	}
	rs.warn(ctx, "log", rs.x.Log(c, corerun.Info, clipText(line, 1000)))
}

// state is the state of a step as this process wrote it; "" for a step that is not in the run.
func (rs *runSteps) state(key string) corerun.Status {
	if rs == nil {
		return ""
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if st := rs.byKey[key]; st != nil {
		return st.state
	}
	return ""
}

// endFirstOpen ends the first of keys that has not ended with how and note, and skips the ones after it as not reached because of
// it (counted: the scan is as complete as it can be without them).
func (rs *runSteps) endFirstOpen(ctx context.Context, how corerun.Status, note string, keys ...string) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var failed *runStep
	for _, k := range keys {
		st := rs.byKey[k]
		if st == nil || (st.state != corerun.Queued && st.state != corerun.Running) {
			continue
		}
		if failed == nil {
			failed = st
			rs.endLocked(ctx, k, how, note)
			continue
		}
		rs.skipLocked(ctx, k, "Not run: "+failed.name+" did not finish.", true)
	}
}

// settle ends an engine step from what its calls did (stepLog, INV-30) once the run is past it; a step none of whose calls ran is
// done with its Checked line, or skipped with its first Not checked line (kinds: the lines of that step).
func (rs *runSteps) settle(ctx context.Context, key string, c Content, kinds ...string) {
	if rs == nil {
		return
	}
	rs.record(ctx, "", runOn, "")
	switch rs.state(key) {
	case corerun.Queued, corerun.Running:
	default:
		return
	}
	if text, ok := checkedLine(c, kinds...); ok {
		rs.end(ctx, key, corerun.Done, text)
		return
	}
	rs.skip(ctx, key, firstNotChecked(c, "Not needed in this scan.", kinds...))
}

// record ends the engine steps whose calls are over (stepLog.rows), with the outcome and the sentence Settings › Scanning shows.
func (rs *runSteps) record(ctx context.Context, target string, end int, why string) {
	if rs == nil {
		return
	}
	for _, r := range rs.l.rows(rs.x.ID(), target, rs.clock(), end, why) {
		rs.end(ctx, r.Engine, stepStatus[r.Outcome], stepNote(r.Text))
	}
}

// stepNote is a step sentence of stepLog without the "External scan of <target>: " that Settings › Scanning puts in front.
func stepNote(text string) string {
	if strings.HasPrefix(text, "External scan of ") {
		if i := strings.Index(text, ": "); i > 0 {
			return text[i+2:]
		}
	}
	return text
}

// checkedLine is the first Checked line of kinds.
func checkedLine(c Content, kinds ...string) (string, bool) {
	for _, r := range c.Checks {
		for _, k := range kinds {
			if r.Kind == k {
				return r.Text, true
			}
		}
	}
	return "", false
}

// firstNotChecked is the first Not checked line of kinds, with how many more there are; or else.
func firstNotChecked(c Content, or string, kinds ...string) string {
	var lines []string
	for _, r := range c.NotChecked {
		for _, k := range kinds {
			if r.Kind == k {
				lines = append(lines, r.Text)
			}
		}
	}
	switch len(lines) {
	case 0:
		return or
	case 1:
		return lines[0]
	}
	return fmt.Sprintf("%s (and %s in the scan's Not checked list)", lines[0], plural(len(lines)-1, "more line"))
}

// close ends what is left when the run ends: the engine steps from their calls, a running step stopped (with why) or failed (with
// failNote), and every step not reached skipped as such. The rest of a domain's plan is added first, so the page lists it.
func (rs *runSteps) close(ctx context.Context, end int, why, failNote string) {
	if rs == nil {
		return
	}
	rs.stopLive()
	rs.addTail(ctx)
	rs.record(ctx, "", end, why)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, st := range rs.steps {
		switch st.state {
		case corerun.Running:
			switch {
			case end == runStopped:
				rs.endLocked(ctx, st.key, corerun.Stopped, "Stopped"+whyNote(why)+".")
			case failNote != "":
				rs.endLocked(ctx, st.key, corerun.Failed, failNote)
			default:
				rs.endLocked(ctx, st.key, corerun.Done, "")
			}
		case corerun.Queued:
			note := notReachedFailed
			if end == runStopped {
				note = notReachedStopped
			}
			if end == runEnded && failNote == "" {
				note = "Not needed in this scan."
			}
			rs.skipLocked(ctx, st.key, note, end == runEnded && failNote == "")
		}
	}
}

// ---- where a running step is ----

// say sets the note of a running step (written within liveEvery).
func (rs *runSteps) say(key, note string) {
	if rs == nil {
		return
	}
	rs.pmu.Lock()
	defer rs.pmu.Unlock()
	rs.pending[key] = note
}

func (rs *runSteps) dropPending(key string) {
	rs.pmu.Lock()
	defer rs.pmu.Unlock()
	delete(rs.pending, key)
}

// phaseStep is the step of an IP scan each phase of the engines' progress reports belongs to.
var phaseStep = map[string]string{progress.PhaseDiscovery: stepKeyPorts, progress.PhasePorts: stepKeyPorts, progress.PhaseServices: stepKeyServices,
	progress.PhaseScripts: stepKeyServices, progress.PhaseVulns: stepKeyNuclei, progress.PhaseWeb: stepKeyZAP, progress.PhaseOpenVAS: stepKeyOpenVAS}

// Report implements progress.Sink for an IP scan: each report becomes the note of the step its phase belongs to. Quick and never
// blocking: it is called from the reader of an engine's output, and the note is written by the live loop.
func (rs *runSteps) Report(u progress.Update) {
	rs.pmu.Lock()
	only := rs.only
	rs.pmu.Unlock()
	key := cmp.Or(only, phaseStep[u.Phase])
	if key == "" {
		return
	}
	note := liveNote(u, key == stepKeyServices || key == only)
	rs.pmu.Lock()
	defer rs.pmu.Unlock()
	if key == stepKeyServices && only == "" {
		rs.services = true
	}
	if note != "" {
		rs.pending[key] = note
	}
}

// addressSink is the progress.Sink of the step of one of a domain's addresses: every phase is that step's, named in its note.
type addressSink struct {
	rs  *runSteps
	key string
}

func (a addressSink) Report(u progress.Update) {
	if note := liveNote(u, true); note != "" {
		a.rs.say(a.key, note)
	}
}

// withinAddress is ctx for the work of the step of one of a domain's addresses: its engine phases are that step's, so runStepsOf
// is nil inside it and every progress report is that step's note.
func withinAddress(ctx context.Context, rs *runSteps, key string) context.Context {
	if rs == nil {
		return ctx
	}
	return progress.WithSink(context.WithValue(withRunSteps(ctx, nil), addressStepKey{}, addressSink{rs: rs, key: key}), addressSink{rs: rs, key: key})
}

type addressStepKey struct{}

// incomplete says the results of step key are incomplete, and why, and the run is partly done; inside the step of one of a domain's
// addresses it is that step's results that are incomplete.
func incomplete(ctx context.Context, key, why string) {
	if rs := runStepsOf(ctx); rs != nil {
		rs.incompleteOn(key, why)
		rs.problem(why)
		return
	}
	if a, ok := ctx.Value(addressStepKey{}).(addressSink); ok {
		a.rs.incompleteOn(a.key, why)
		a.rs.problem(why)
	}
}

// The words of the phases, in a note.
var phaseWords = map[string]string{progress.PhaseDiscovery: "looking for the address", progress.PhasePorts: "finding open ports",
	progress.PhaseServices: "reading service versions", progress.PhaseScripts: "running nmap's scripts", progress.PhaseVulns: "template checks",
	progress.PhaseWeb: "web pages", progress.PhaseOpenVAS: "OpenVAS", progress.PhaseSaving: "saving"}

// liveNote is a report in words: "finding open ports: 41%, about 9 minutes left", "1,240 of 3,600 template checks". The numbers come
// from tools' output: out of range is left out.
func liveNote(u progress.Update, named bool) string {
	var parts []string
	switch {
	case u.Total > 0 && u.Total <= progress.MaxCount && u.Done >= 0 && u.Done <= u.Total:
		unit := "done"
		switch {
		case u.Phase == progress.PhaseVulns:
			unit = "template checks"
		case u.Unit == progress.UnitHosts:
			unit = "addresses"
		}
		parts = append(parts, corerun.Number(int(u.Done))+" of "+corerun.Number(int(u.Total))+" "+unit)
	case u.Percent >= 0 && u.Percent <= 100 && !math.IsNaN(u.Percent):
		parts = append(parts, fmt.Sprintf("%d%%", int(u.Percent)))
	}
	if u.Remaining >= time.Minute && u.Remaining <= progress.MaxRemaining {
		parts = append(parts, leftText(u.Remaining))
	}
	head := strings.Join(parts, ", ")
	if !named || phaseWords[u.Phase] == "" || (u.Phase == progress.PhaseVulns && head != "") {
		return head
	}
	if head == "" {
		return phaseWords[u.Phase]
	}
	return phaseWords[u.Phase] + ": " + head
}

// reportTo makes every progress report the note of step key until reportTo(""): the disruptive scripts' nmap run reports the phases
// of a port scan, which are not the earlier steps'.
func (rs *runSteps) reportTo(key string) {
	if rs == nil {
		return
	}
	rs.pmu.Lock()
	defer rs.pmu.Unlock()
	rs.only = key
}

// startLive starts the loop that writes where the running steps are, until stopLive.
func (rs *runSteps) startLive(ctx context.Context) {
	if rs == nil {
		return
	}
	rs.stop, rs.stopped = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(rs.stopped)
		t := time.NewTicker(liveEvery)
		defer t.Stop()
		for {
			select {
			case <-rs.stop:
				return
			case <-t.C:
				rs.flush(ctx)
			}
		}
	}()
}

func (rs *runSteps) stopLive() {
	if rs.stop == nil {
		return
	}
	select {
	case <-rs.stop:
	default:
		close(rs.stop)
	}
	<-rs.stopped
}

// flush writes the newest note of each running step, and ends the port discovery once nmap reports its service phase.
func (rs *runSteps) flush(ctx context.Context) {
	rs.pmu.Lock()
	notes := rs.pending
	rs.pending = map[string]string{}
	services := rs.services
	rs.pmu.Unlock()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if services {
		if p := rs.byKey[stepKeyPorts]; p != nil && p.state == corerun.Running {
			rs.endLocked(ctx, stepKeyPorts, corerun.Done, "")
			rs.startLocked(ctx, stepKeyServices)
		}
	}
	c, cancel := wctx(ctx)
	defer cancel()
	for key, note := range notes {
		st := rs.byKey[key]
		if st == nil || st.state != corerun.Running || note == st.live {
			continue
		}
		if err := rs.x.StepNote(c, st.seq, note); err != nil {
			rs.warn(ctx, "note "+key, err)
			continue
		}
		st.live = note
	}
}

// ---- words ----

// tookText is how long a step took: "less than a second", "12 s", "2 min 10 s", "1 h 5 min".
func tookText(d time.Duration) string {
	switch {
	case d < time.Second:
		return "less than a second"
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d/time.Second))
	case d < time.Hour:
		m, s := int(d/time.Minute), int(d%time.Minute/time.Second)
		if s == 0 {
			return fmt.Sprintf("%d min", m)
		}
		return fmt.Sprintf("%d min %d s", m, s)
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	if m == 0 {
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

// leftText is a tool's estimate of the time left: "about 9 minutes left".
func leftText(d time.Duration) string {
	m := int(math.Round(d.Minutes()))
	switch {
	case m <= 1:
		return "about a minute left"
	case m < 90:
		return fmt.Sprintf("about %d minutes left", m)
	}
	return fmt.Sprintf("about %d hours left", int(math.Round(d.Hours())))
}

// modeNote is the note of the check step of t: how deep the scan goes, by the terms as they are now. The disruptive checks go only to
// the box's own public IP (deepGate): a domain's run says so instead of claiming them, and a typed IP never gets them.
func modeNote(t Target, m ScanMode) string {
	switch {
	case m.Full && m.Disruptive && t.Kind == KindDomain:
		return "Deep scan: the testing terms are accepted. The disruptive checks run only on an address of this domain that is this box's own public IP; the other addresses get the deep scan without them."
	case m.Full && m.Disruptive && t.Typed:
		return "Deep scan: the testing terms are accepted. The disruptive checks run only on this box's own public IP, so this typed-in address gets the deep scan without them."
	case m.Full && m.Disruptive:
		return "Deep scan with the disruptive checks: the testing terms are accepted."
	case m.Full:
		return "Deep scan: the testing terms are accepted."
	}
	return "Standard scan: the testing terms are not accepted, so the deep steps do not run."
}

// nouns is n with the noun of its number, for a noun plural cannot make ("1 address", "2 addresses").
func nouns(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return corerun.Number(n) + " " + many
}

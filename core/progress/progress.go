// Package progress is the one shape of "how far is it" for the long jobs a customer waits on (#830): a scan of a device, the
// scan of a public IP, its OpenVAS step. A job owns a Tracker; the code that does the work reports to the Sink it finds in its
// context, so the modules between the two (scan, exposure, sensor-active's Dispatcher, the adapters of cmd/vedette) need no new
// parameter. Only the latest state is kept, in memory: no history, no table, and it goes with the job (the owner drops the
// Tracker when the job ends).
//
// What a Sink receives can come from a tool's output that a device or a compromised worker shaped (the scan worker's nmap and
// nuclei): Report checks every field and drops what is out of range, so a View is always well formed.
//
// Standard library only.
package progress

import (
	"context"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Phases of a job (contract: web/src/lib/progress.ts JobProgress.phase).
const (
	PhaseDiscovery = "discovery" // is the host up (nmap ping or ARP scan)
	PhasePorts     = "ports"     // port scan
	PhaseServices  = "services"  // service and version detection (nmap -sV)
	PhaseScripts   = "scripts"   // nmap's scripts (titles, certificates, NTLM answers)
	PhaseVulns     = "vulns"     // vulnerability checks (nuclei templates)
	PhaseWeb       = "web"       // the passive web checks of a public address (ZAP)
	PhaseOpenVAS   = "openvas"   // the optional OpenVAS deep scan (Greenbone)
	PhaseSaving    = "saving"    // the result is being stored
)

// Phases is every phase a View can name.
var Phases = []string{PhaseDiscovery, PhasePorts, PhaseServices, PhaseScripts, PhaseVulns, PhaseWeb, PhaseOpenVAS, PhaseSaving}

// Units of Done and Total.
const (
	UnitChecks = "checks" // template x target pairs of nuclei
	UnitHosts  = "hosts"  // addresses of a discovery batch
)

// Units is every unit a View can name.
var Units = []string{UnitChecks, UnitHosts}

// Limits of what a View may hold.
const (
	MaxCount     = 1_000_000_000
	MaxRemaining = 48 * time.Hour
	MaxMessage   = 120 // runes
	// etaAfter is how long a phase must have run, and minPercent how far it must be, before Tracker estimates an end itself.
	etaAfter   = 10 * time.Second
	minPercent = 1.0
	// restartDrop is how far the percent of the same phase must fall to count as a new pass of it (the second nmap run of a device).
	restartDrop = 20.0
)

// Update is one report. Percent < 0 means unknown; Total 0 means there is no count (Done and Unit are then ignored); Remaining 0
// means the tool gave no estimate.
type Update struct {
	Phase     string
	Percent   float64
	Done      int64
	Total     int64
	Unit      string
	Remaining time.Duration
	Message   string
	// EndsBy is the latest time the phase ends, when its owner enforces one (OpenVAS's cap and its stop budget); zero: none.
	EndsBy time.Time
	// NewPass starts a new pass of the phase whatever came before it (the first report of a Series): its time and pace start
	// again, and the percent may start again from 0.
	NewPass bool
}

// Phase is an Update that names a phase only (no percent, no count).
func Phase(phase, message string) Update { return Update{Phase: phase, Percent: -1, Message: message} }

// Sink receives the reports of a job. Report must be quick and must not block: it is called from the reader of a process's output.
type Sink interface{ Report(Update) }

type sinkKey struct{}

// WithSink returns ctx carrying s.
func WithSink(ctx context.Context, s Sink) context.Context {
	return context.WithValue(ctx, sinkKey{}, s)
}

// SinkFrom is the Sink ctx carries, or nil.
func SinkFrom(ctx context.Context) Sink {
	s, _ := ctx.Value(sinkKey{}).(Sink)
	return s
}

// Report sends u to the Sink of ctx; nothing when there is none.
func Report(ctx context.Context, u Update) {
	if s := SinkFrom(ctx); s != nil {
		s.Report(u)
	}
}

// View is the API shape (contract JobProgress). Times are UTC, millisecond ISO 8601 like every other time of the API.
type View struct {
	Phase          string   `json:"phase"`
	Percent        *float64 `json:"percent"`
	Done           *int64   `json:"done"`
	Total          *int64   `json:"total"`
	Unit           *string  `json:"unit"`
	StartedAt      string   `json:"started_at"`
	PhaseStartedAt string   `json:"phase_started_at"`
	UpdatedAt      string   `json:"updated_at"`
	ETA            *string  `json:"eta"`
	Message        *string  `json:"message"`
	EndsBy         *string  `json:"ends_by"`
}

// Tracker keeps the latest state of one job. The zero value is not usable; make it with NewTracker. Safe for concurrent use.
type Tracker struct {
	mu      sync.Mutex
	now     func() time.Time
	started time.Time
	has     bool
	cur     Update
	phaseAt time.Time // when the current phase (or pass of it) began
	done0   int64     // Done when the phase began, for the rate estimate
	updated time.Time
	eta     time.Time // zero: unknown
}

// NewTracker starts a job now. now nil means time.Now.
func NewTracker(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{now: now, started: now()}
}

// Report implements Sink: it checks u and keeps it as the latest state. A report with an unknown phase is dropped whole; an
// out-of-range number is dropped alone.
//
// Within a pass of a phase the bar never goes back (#830 FAIL 2: the page read 85 % → 39 % → 82 %): a report with a lower percent
// keeps the state shown before whole (percent, count, estimate, message); only updated_at moves. Only a new pass starts lower: a report that says so (NewPass), another phase, or a percent
// without a count that falls by more than restartDrop (the second nmap run of a device: that tool's percent restarts on its own).
// A count never starts a pass by falling: the jobs of one pass are added up by a Series.
func (t *Tracker) Report(u Update) {
	u, ok := clean(u)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	pass := !t.has || u.Phase != t.cur.Phase || u.NewPass
	if !pass && u.Percent >= 0 && t.cur.Percent >= 0 && u.Percent < t.cur.Percent {
		if u.Total == 0 && t.cur.Total == 0 && u.Percent < t.cur.Percent-restartDrop {
			pass = true
		} else { // the state shown stays whole, its estimate and note too (review r1 #3): only the time of the last word moves
			t.updated = now
			return
		}
	}
	if pass {
		t.phaseAt, t.done0 = now, u.Done
	}
	t.has, t.cur, t.updated = true, u, now
	t.eta = t.estimate(now)
}

// estimate is the end of the current phase: the tool's own estimate when it gave one, else the pace of the phase so far once it
// has run etaAfter and passed minPercent; zero when neither. The caller holds mu.
func (t *Tracker) estimate(now time.Time) time.Time {
	u := t.cur
	if u.Remaining > 0 {
		return now.Add(u.Remaining)
	}
	elapsed := now.Sub(t.phaseAt)
	if elapsed < etaAfter || u.Percent < minPercent || u.Percent >= 100 {
		return time.Time{}
	}
	if u.Total > 0 {
		if gained := u.Done - t.done0; gained > 0 {
			left := min(float64(u.Total-u.Done)/float64(gained)*float64(elapsed), float64(MaxRemaining)) // review r1 #7: no overflow
			return now.Add(time.Duration(left))
		}
		return time.Time{}
	}
	left := min(float64(elapsed)*(100-u.Percent)/u.Percent, float64(MaxRemaining))
	return now.Add(time.Duration(left))
}

// View is the latest state, nil before the first report.
func (t *Tracker) View() *View {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.has {
		return nil
	}
	u := t.cur
	v := &View{Phase: u.Phase, StartedAt: ts(t.started), PhaseStartedAt: ts(t.phaseAt), UpdatedAt: ts(t.updated)}
	if u.Percent >= 0 {
		p := math.Round(u.Percent*10) / 10
		v.Percent = &p
	}
	if u.Total > 0 {
		d, n, unit := u.Done, u.Total, u.Unit
		v.Done, v.Total, v.Unit = &d, &n, &unit
	}
	if !t.eta.IsZero() {
		e := ts(t.eta)
		v.ETA = &e
	}
	if !u.EndsBy.IsZero() {
		e := ts(u.EndsBy)
		v.EndsBy = &e
	}
	if u.Message != "" {
		m := u.Message
		v.Message = &m
	}
	return v
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// clean checks an Update. The phase must be known; a count needs a known unit and 0 <= Done <= Total <= MaxCount (Done over Total
// is cut to Total); a percent outside 0..100 or not a number is unknown; a count gives the percent; a remaining time outside
// 0..MaxRemaining is unknown; a message keeps its first MaxMessage printable runes.
func clean(u Update) (Update, bool) {
	if !slices.Contains(Phases, u.Phase) {
		return Update{}, false
	}
	if math.IsNaN(u.Percent) || math.IsInf(u.Percent, 0) || u.Percent < 0 {
		u.Percent = -1
	} else if u.Percent > 100 {
		u.Percent = 100
	}
	switch {
	case u.Total <= 0 || u.Total > MaxCount || u.Done < 0 || !slices.Contains(Units, u.Unit):
		u.Done, u.Total, u.Unit = 0, 0, ""
	default:
		u.Done = min(u.Done, u.Total)
		u.Percent = float64(u.Done) * 100 / float64(u.Total)
	}
	if u.Remaining < 0 || u.Remaining > MaxRemaining {
		u.Remaining = 0
	}
	u.Message = text(u.Message)
	return u, true
}

// text keeps the printable runes of s, spaces folded, at most MaxMessage of them.
func text(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == MaxMessage {
			break
		}
		if unicode.IsSpace(r) {
			r = ' '
		}
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Series is one count of checks over the jobs of a pass of a phase that run one after another (#830 FAIL 2). The deep scan of a
// public IP hands its templates to nuclei as many jobs, each reporting its own 0..N, and passed on as they came the page read
// 85 % → 39 % → 82 %. A Series adds the checks of the jobs that ended to the running job's count, against the total its owner plans
// for the pass, so the count only grows, the estimate of the end follows the whole pass, and a job's report never stands for the
// pass. The owner makes it with NewSeries, runs each job with the context of Job and calls the end function Job returns when the job
// is over. Safe for concurrent use; nothing happens when the context carries no Sink.
type Series struct {
	sink  Sink
	phase string

	mu    sync.Mutex
	plan  int64 // the checks the owner plans for the pass
	ended int64 // the checks of the jobs that ended
	done  int64 // of the running job: its count
	total int64 // of the running job: its total
	job   int   // the running job; a report of another one is dropped
}

// NewSeries starts a pass of phase with plan checks planned (an upper bound is fine: Plan lowers it when the owner knows better) and
// reports its 0 at once.
func NewSeries(ctx context.Context, phase string, plan int64) *Series {
	s := &Series{sink: SinkFrom(ctx), phase: phase, plan: max(plan, 0)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reportLocked(true)
	return s
}

// Plan sets the total the owner plans for the pass, the jobs that ended included (the templates of a port once its technologies
// are known).
func (s *Series) Plan(plan int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plan = max(plan, 0)
	s.reportLocked(false)
}

// Job returns the context the next job of the series runs with, and the function that ends that job with the number of checks it
// stood for: they count as done whether the tool ran them all or not (a target it gave up, a template it did not load), and the
// job's later reports are dropped.
func (s *Series) Job(ctx context.Context) (context.Context, func(checks int64)) {
	s.mu.Lock()
	s.job++
	s.done, s.total = 0, 0
	id := s.job
	s.mu.Unlock()
	end := func(checks int64) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.job != id {
			return
		}
		s.job++
		s.ended += max(checks, s.done, 0)
		s.done, s.total = 0, 0
		s.reportLocked(false)
	}
	return WithSink(ctx, seriesJob{s: s, id: id}), end
}

// reportLocked reports the count of the pass. The caller holds mu.
func (s *Series) reportLocked(first bool) {
	if s.sink == nil {
		return
	}
	total := max(s.plan, s.ended+s.total, s.ended+s.done)
	if total <= 0 {
		s.sink.Report(Update{Phase: s.phase, Percent: -1, NewPass: first})
		return
	}
	s.sink.Report(Update{Phase: s.phase, Percent: -1, Done: s.ended + s.done, Total: total, Unit: UnitChecks, NewPass: first})
}

// seriesJob is the Sink of one job of a Series.
type seriesJob struct {
	s  *Series
	id int
}

// Report takes the job's count of its own checks into the pass; a report of another phase, or without a count, goes on as it is.
func (j seriesJob) Report(u Update) {
	s := j.s
	if u.Phase != s.phase || u.Total <= 0 || u.Done < 0 {
		if s.sink != nil {
			s.sink.Report(u)
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != j.id {
		return
	}
	s.done, s.total = max(s.done, min(u.Done, MaxCount)), min(u.Total, MaxCount)
	s.reportLocked(false)
}

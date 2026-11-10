// Package worker is the nmap worker of the scan container (`vedette-sensor active`, D-113, sensor-protocol.md section 6.4).
// It long-polls core for one job at a time, builds the command line itself from the job's shape, rate and targets
// (nmapargv, the same code core used before it handed the job over), runs the OS package's nmap through core/exec in its
// own process group and posts the result. It holds no scope and no consent: core decided before it dispatched; the worker
// only refuses what the grammar forbids, and it kills nmap whenever core can no longer be listening for the answer.
//
// The package is linked into the sensor binary: standard library, core/exec, core/sensorlink and nmapargv only, never the
// database or the generated API (TestBinaryDependencies).
package worker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

const (
	// Lease is how long the worker keeps nmap running without one successful poll of core (sensor-protocol.md 6.4).
	Lease = 60 * time.Second
	// MaxTimeout is the longest job it accepts.
	MaxTimeout = 7200
	// HeartbeatEvery is the heartbeat period.
	HeartbeatEvery = 30 * time.Second
	moduleOffEvery = 60 * time.Second

	versionBin = "nmap-version"
)

// Why nmap was killed; context.Cause of the job's context says which.
// jobIDRE is the form of every job id core makes (spec section 5).
var jobIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

var (
	errCancelled = errors.New("cancelled by core")
	errLease     = errors.New("lease lost")
	errInstance  = errors.New("core restarted")
	errModuleOff = errors.New("module off")
	errShutdown  = errors.New("worker stopping")
)

// Link is the sensor side of the protocol; *sensorlink.Client implements it.
type Link interface {
	Jobs(ctx context.Context, running string, wait time.Duration) (sensorlink.JobsReply, error)
	ActiveHeartbeat(ctx context.Context, hb *sensorlink.ActiveHeartbeat) (string, error)
	PostResult(ctx context.Context, id string, res *sensorlink.JobResult) error
}

// Config configures a Worker. The time fields are for tests; zero means the protocol's value.
type Config struct {
	Link     Link
	NmapPath string // absolute path of the OS package's nmap
	Version  string // SemVer of this binary, for the heartbeat
	Log      *slog.Logger

	Now       func() time.Time // the clock of the lease
	Sleep     func(ctx context.Context, d time.Duration) error
	Wait      time.Duration // long-poll wait (default 25 s)
	Heartbeat time.Duration // default 30 s
	Tick      time.Duration // how often the lease is looked at (default 1 s)
}

// Worker runs jobs. Create it with New and call Run.
type Worker struct {
	link      Link
	runner    *exec.Runner
	nmapPath  string
	version   string
	log       *slog.Logger
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error
	wait      time.Duration
	heartbeat time.Duration
	tick      time.Duration

	mu     sync.Mutex
	lastOK time.Time  // the latest successful poll
	cur    *activeJob // the job in hand, from the poll that delivered it until its result is posted or dropped
	wg     sync.WaitGroup
}

type activeJob struct {
	job      sensorlink.Job
	instance string
	kill     context.CancelCauseFunc // ends the job's context with a cause; the context itself is passed around
	posting  atomic.Bool             // the result is being sent: the poll loop waits for it before it polls again
	postDone chan struct{}           // closed when the job is over and the worker is free
}

// New builds a Worker.
func New(c Config) (*Worker, error) {
	if c.Link == nil {
		return nil, errors.New("worker: a Link is required")
	}
	w := &Worker{link: c.Link, nmapPath: c.NmapPath, version: c.Version, log: c.Log, now: c.Now, sleep: c.Sleep, wait: c.Wait, heartbeat: c.Heartbeat, tick: c.Tick}
	if w.log == nil {
		w.log = slog.New(slog.DiscardHandler)
	}
	if w.now == nil {
		w.now = time.Now
	}
	if w.sleep == nil {
		w.sleep = sleepCtx
	}
	if w.wait <= 0 {
		w.wait = sensorlink.DefaultWait
	}
	w.wait = max(w.wait, time.Second) // the wire carries whole seconds: less would be wait=0, a poll that returns at once and loops
	if w.heartbeat <= 0 {
		w.heartbeat = HeartbeatEvery
	}
	if w.tick <= 0 {
		w.tick = time.Second
	}
	r, err := exec.NewRunner(w.log,
		exec.Binary{Name: "nmap", Path: c.NmapPath, Validate: nmapargv.Validate, MaxOutput: nmapargv.MaxOutput},
		exec.Binary{Name: versionBin, Path: c.NmapPath, Validate: validVersionArgs, MaxOutput: 64 << 10},
	)
	if err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	w.runner = r
	return w, nil
}

func validVersionArgs(args []string) error {
	if len(args) != 1 || args[0] != "--version" {
		return errors.New("only --version")
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run serves core until ctx ends. When it ends, a running nmap is killed and Run returns after it is gone.
func (w *Worker) Run(ctx context.Context) error {
	var hb sync.WaitGroup
	hb.Add(1)
	go func() { defer hb.Done(); w.heartbeats(ctx) }()
	defer func() {
		w.killCurrent(errShutdown)
		w.wg.Wait()
		hb.Wait()
	}()

	bo := sensorlink.NewBackoff(nil)
	for ctx.Err() == nil {
		w.waitPost(ctx)
		rep, err := w.link.Jobs(ctx, w.runningID(), w.wait)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			var e *sensorlink.Error
			if errors.As(err, &e) && e.Code == sensorlink.CodeModuleOff {
				// Stop at once, no last result, ask again later (SYS-5, D-80 (4)).
				w.killCurrent(errModuleOff)
				w.log.InfoContext(ctx, "sensor_active_module_off")
				_ = w.sleep(ctx, moduleOffEvery)
				continue
			}
			if errors.As(err, &e) && e.Code == sensorlink.CodeForbiddenRoute {
				w.log.ErrorContext(ctx, "sensor_active_forbidden_route") // a programming error, not worth retrying quickly
			} else {
				w.log.WarnContext(ctx, "sensor_active_poll_failed", "error", err)
			}
			_ = w.sleep(ctx, bo.Next())
			continue
		}
		bo.Reset()
		w.apply(ctx, rep)
	}
	return ctx.Err()
}

// waitPost holds the poll loop while the result of the job in hand is being sent: a poll that names a job whose result is on
// its way is a poll core may answer before the result is in (L1). The wait ends with the post, which is bounded by the lease.
func (w *Worker) waitPost(ctx context.Context) {
	w.mu.Lock()
	cur := w.cur
	w.mu.Unlock()
	if cur == nil || !cur.posting.Load() {
		return
	}
	select {
	case <-cur.postDone:
	case <-ctx.Done():
	}
}

func (w *Worker) runningID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil {
		return ""
	}
	return w.cur.job.ID
}

// killCurrent kills nmap of the job in hand, if any, for cause.
func (w *Worker) killCurrent(cause error) {
	w.mu.Lock()
	cur := w.cur
	w.mu.Unlock()
	if cur != nil {
		cur.kill(cause)
	}
}

// noteInstance records the nonce of core. A change while a job is in hand means core restarted: whoever was waiting for the
// result is gone, so nmap stops now and its result is dropped (D-113 (4)).
func (w *Worker) noteInstance(inst string) {
	w.mu.Lock()
	cur := w.cur
	w.mu.Unlock()
	if cur != nil && cur.instance != inst {
		cur.kill(errInstance)
	}
}

// apply handles one successful poll reply: the lease, the instance, the cancels, then the job.
func (w *Worker) apply(ctx context.Context, rep sensorlink.JobsReply) {
	w.mu.Lock()
	w.lastOK = w.now()
	w.mu.Unlock()
	w.noteInstance(rep.Instance)

	cancelled := map[string]bool{}
	for _, id := range rep.Cancel {
		cancelled[id] = true
		w.mu.Lock()
		cur := w.cur
		w.mu.Unlock()
		if cur != nil && cur.job.ID == id {
			cur.kill(errCancelled)
		}
	}
	for i, job := range rep.Jobs {
		if !jobIDRE.MatchString(job.ID) {
			// Nothing about it is used: not in a URL, not in a log, not in a result. Core's own ids are 32 hex digits.
			w.log.ErrorContext(ctx, "sensor_active_job_with_a_bad_id_ignored")
			continue
		}
		if i > 0 {
			w.log.ErrorContext(ctx, "sensor_active_extra_job_ignored", "id", job.ID) // the protocol carries at most one
			continue
		}
		w.mu.Lock()
		if w.cur != nil {
			w.mu.Unlock()
			w.post(ctx, job.ID, &sensorlink.JobResult{Status: "refused", Reason: "busy", ExitCode: -1})
			continue
		}
		jctx, kill := context.WithCancelCause(ctx)
		cur := &activeJob{job: job, instance: rep.Instance, kill: kill, postDone: make(chan struct{})}
		w.cur = cur
		w.mu.Unlock()
		if cancelled[job.ID] {
			kill(errCancelled) // cancel racing start: the cancel came in the same reply
		}
		w.wg.Add(2)
		go func() { defer w.wg.Done(); w.watchLease(jctx, cur) }()
		go func() { defer w.wg.Done(); w.run(ctx, jctx, cur) }()
	}
}

// watchLease kills the job when no poll has succeeded for the lease.
func (w *Worker) watchLease(jctx context.Context, cur *activeJob) {
	t := time.NewTicker(w.tick)
	defer t.Stop()
	for {
		select {
		case <-jctx.Done():
			return
		case <-t.C:
			w.mu.Lock()
			lost := w.now().Sub(w.lastOK) > Lease
			w.mu.Unlock()
			if lost {
				cur.kill(errLease)
				return
			}
		}
	}
}

// run is one job from the delivery to the result. A kill for the lease, a new core instance, the module being off or our own
// shutdown drops the result: nobody is listening for it.
func (w *Worker) run(ctx, jctx context.Context, cur *activeJob) {
	defer cur.kill(nil) // frees the watcher and the context
	defer close(cur.postDone)
	res := w.execute(ctx, jctx, cur)
	cur.posting.Store(true)
	if cause := context.Cause(jctx); errors.Is(cause, errLease) || errors.Is(cause, errInstance) || errors.Is(cause, errModuleOff) || errors.Is(cause, errShutdown) || errors.Is(cause, context.Canceled) {
		w.log.WarnContext(ctx, "sensor_active_job_dropped", "id", cur.job.ID, "cause", cause)
	} else {
		w.post(ctx, cur.job.ID, res)
	}
	w.mu.Lock()
	w.cur = nil
	w.mu.Unlock()
}

// execute re-checks the job and runs it and returns the result to post.
func (w *Worker) execute(ctx, jctx context.Context, cur *activeJob) *sensorlink.JobResult {
	argv, err := argvOf(cur.job)
	if err != nil {
		w.log.ErrorContext(ctx, "sensor_active_job_refused", "id", cur.job.ID, "error", err) // core and worker disagree on the grammar
		return &sensorlink.JobResult{Status: "refused", Reason: "invalid_job", ExitCode: -1}
	}
	if context.Cause(jctx) != nil { // cancelled (or core gone) before nmap started
		return stopped()
	}
	rctx, cancel := context.WithTimeout(jctx, time.Duration(cur.job.TimeoutS)*time.Second)
	defer cancel()
	out, err := w.runner.Run(rctx, "nmap", argv, nil)
	cause := context.Cause(jctx)
	switch {
	case cause != nil:
		return stopped()
	case rctx.Err() != nil: // the job's own deadline
		return &sensorlink.JobResult{Status: "stopped", Reason: "deadline", ExitCode: -1}
	case err == nil:
		r := &sensorlink.JobResult{Status: "done", ExitCode: 0, Truncated: out.Truncated}
		r.SetXML(out.Stdout)
		return r
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return &sensorlink.JobResult{Status: "failed", ExitCode: min(ee.ExitCode, 255), Truncated: out.Truncated}
	case errors.Is(err, fs.ErrNotExist):
		return &sensorlink.JobResult{Status: "failed", Reason: "nmap_missing", ExitCode: -1}
	}
	w.log.WarnContext(ctx, "sensor_active_exec_failed", "id", cur.job.ID, "error", err)
	return &sensorlink.JobResult{Status: "failed", Reason: "exec_failed", ExitCode: -1}
}

// stopped is the result of a job core cancelled. Every other kill (lease, new instance, module off, shutdown) posts nothing.
func stopped() *sensorlink.JobResult {
	return &sensorlink.JobResult{Status: "stopped", Reason: "cancelled", ExitCode: -1}
}

func parseTargets(ss []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// post sends a result. 429, 503 and a transport error are tried again after Retry-After or the backoff, for as long as the
// lease: past that core has long given the job up. Any other refusal (400, 404, 413, 403, 409) is final: the job is over and
// the server never wants the result twice (spec section 7).
func (w *Worker) post(ctx context.Context, id string, res *sensorlink.JobResult) {
	start, bo := w.now(), sensorlink.NewBackoff(nil)
	for {
		err := w.link.PostResult(ctx, id, res)
		if err == nil || ctx.Err() != nil {
			return
		}
		wait := bo.Next()
		var e *sensorlink.Error
		if errors.As(err, &e) {
			if e.Status != http.StatusTooManyRequests && e.Status != http.StatusServiceUnavailable {
				w.log.WarnContext(ctx, "sensor_active_result_not_accepted", "id", id, "status", res.Status, "error", err)
				return
			}
			wait = max(wait, e.RetryAfter)
		}
		if w.now().Sub(start)+wait > Lease {
			w.log.WarnContext(ctx, "sensor_active_result_given_up", "id", id, "status", res.Status, "error", err)
			return
		}
		if w.sleep(ctx, wait) != nil {
			return
		}
	}
}

// argvOf is the job grammar of the table in sensor-protocol.md 6.4, checked here again and not trusted from core: a known
// shape, a rate of 1..1000 (a gentle job carries 1), 1..64 canonical unique private IPv4 targets (nmapargv.Build and
// Validate refuse a public address, 65 targets and anything else), a timeout of 1..7200 seconds. The argv is built here from
// those fields; no argv comes over the wire (D-111 (3)).
func argvOf(j sensorlink.Job) ([]string, error) {
	kind, ok := nmapargv.KindOf(j.Shape)
	if !ok {
		return nil, fmt.Errorf("unknown shape %q", j.Shape)
	}
	if j.TimeoutS < 1 || j.TimeoutS > MaxTimeout {
		return nil, fmt.Errorf("timeout %d s is outside 1..%d", j.TimeoutS, MaxTimeout)
	}
	if kind == nmapargv.Gentle && j.Rate != 1 {
		return nil, fmt.Errorf("a gentle job carries rate 1, got %d", j.Rate)
	}
	targets, err := parseTargets(j.Targets)
	if err != nil {
		return nil, err
	}
	argv, err := nmapargv.Build(kind, j.Rate, targets)
	if err != nil {
		return nil, err
	}
	if err := nmapargv.Validate(argv); err != nil {
		return nil, err
	}
	return argv, nil
}

// ---- heartbeat ----

func (w *Worker) heartbeats(ctx context.Context) {
	for {
		w.beat(ctx)
		if w.sleep(ctx, w.heartbeat) != nil {
			return
		}
	}
}

func (w *Worker) beat(ctx context.Context) {
	present, ver := w.nmapVersion(ctx)
	inst, err := w.link.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: w.version, Nmap: sensorlink.HeartbeatNmap{Present: present, Version: ver}})
	if err != nil {
		if ctx.Err() == nil {
			w.log.WarnContext(ctx, "sensor_active_heartbeat_failed", "error", err)
		}
		return
	}
	w.noteInstance(inst)
}

// nmapVersion runs `nmap --version` (a second allowlist entry that accepts exactly that argv) and reads the version from the
// first line, "Nmap version 7.94SVN ( https://nmap.org )". present is true when it ran; the version is "" when it cannot be read.
func (w *Worker) nmapVersion(ctx context.Context) (present bool, version string) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := w.runner.Run(rctx, versionBin, []string{"--version"}, nil)
	if err != nil {
		return false, ""
	}
	line, _, _ := strings.Cut(string(res.Stdout), "\n")
	if f := strings.Fields(line); len(f) >= 3 && f[0] == "Nmap" && f[1] == "version" && validVersion(f[2]) {
		return true, f[2]
	}
	return true, ""
}

func validVersion(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', strings.IndexByte("._+-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

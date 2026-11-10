package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// These tests drive the Dispatcher with a hand-written worker (the sensorlink client of the active role) over the real
// mutual-TLS link, so every answer of the protocol is checked in the form a worker sees it. The clock of the Dispatcher
// is a test clock: the 60, 90 and 30 second rules take no real time.

type fclock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fclock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fclock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type drig struct {
	d       *sa.Dispatcher
	clk     *fclock
	link    *linktest.Link
	worker  *sensorlink.Client
	passive *sensorlink.Client
}

func newDRig(t *testing.T, mut ...func(*sensorlink.Options)) *drig {
	t.Helper()
	clk := &fclock{t: time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)}
	d := sa.NewDispatcher(sa.DispatcherOptions{Now: clk.Now, Tick: 10 * time.Millisecond})
	link := linktest.New(t, activeBackend{d}, mut...)
	return &drig{d: d, clk: clk, link: link, worker: link.Client(t, sensorlink.Active), passive: link.Client(t, sensorlink.Passive)}
}

// beat is a heartbeat of a worker that has nmap (or not).
func (r *drig) beat(t *testing.T, present bool) string {
	t.Helper()
	inst, err := r.worker.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: present, Version: "7.94SVN"}})
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func argvOf(t *testing.T, kind nmapargv.Kind, rate int, ts ...string) []string {
	t.Helper()
	var addrs []netip.Addr
	for _, s := range ts {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	argv, err := nmapargv.Build(kind, rate, addrs)
	if err != nil {
		t.Fatal(err)
	}
	return argv
}

type probeResult struct {
	out sa.Output
	err error
}

// probe runs Probe in the background; ctx carries the deadline and cancel of the probe.
func probe(ctx context.Context, d *sa.Dispatcher, argv []string) <-chan probeResult {
	ch := make(chan probeResult, 1)
	go func() {
		out, err := d.Probe(ctx, argv)
		ch <- probeResult{out, err}
	}()
	return ch
}

func (r *drig) poll(t *testing.T, running string, wait time.Duration) sensorlink.JobsReply {
	t.Helper()
	rep, err := r.worker.Jobs(t.Context(), running, wait)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func await(t *testing.T, ch <-chan probeResult) probeResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("Probe did not return")
		return probeResult{}
	}
}

func notYet(t *testing.T, ch <-chan probeResult, d time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("Probe returned early: %+v", r)
	case <-time.After(d):
	}
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func okResult(xml string) *sensorlink.JobResult {
	r := &sensorlink.JobResult{Status: "done"}
	r.SetXML([]byte(xml))
	return r
}

func probeCtx(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(t.Context(), d)
}

// D-111 (3): the job on the wire is the shape, the rate, the targets and a timeout, and no argv; the result goes back to
// the probe as output.
func TestDispatchJobWireShapeAndResult(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := probeCtx(t, 90*time.Minute)
	defer cancel()
	ch := probe(ctx, r.d, argvOf(t, nmapargv.Normal, 100, "192.168.10.20", "10.0.0.7"))
	rep := r.poll(t, "", 5*time.Second)
	if !hex32.MatchString(rep.Instance) || len(rep.Jobs) != 1 || len(rep.Cancel) != 0 {
		t.Fatalf("reply = %+v", rep)
	}
	j := rep.Jobs[0]
	if !hex32.MatchString(j.ID) || j.Shape != "normal" || j.Rate != 100 || strings.Join(j.Targets, ",") != "192.168.10.20,10.0.0.7" || j.TimeoutS < 5390 || j.TimeoutS > 5400 {
		t.Fatalf("job = %+v", j)
	}
	notYet(t, ch, 50*time.Millisecond)
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	got := await(t, ch)
	if got.err != nil || string(got.out.XML) != "<nmaprun/>" || got.out.Truncated {
		t.Fatalf("probe = %+v", got)
	}
}

// The job id is 128 random bits: two jobs do not share a prefix, and an id nobody was given is not a job.
func TestJobIDsAreRandomAndUnguessable(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	seen := map[string]bool{}
	for range 3 {
		ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
		j := r.poll(t, "", 5*time.Second).Jobs[0]
		if seen[j.ID] {
			t.Fatalf("id %s repeated", j.ID)
		}
		seen[j.ID] = true
		if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
			t.Fatal(err)
		}
		await(t, ch)
	}
}

// D-113 (6): Health is unavailable without a heartbeat for 90 s, and when the heartbeat says nmap is missing; a probe then
// creates no job.
func TestHealthFollowsTheHeartbeat(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	if msg := r.d.NmapHealth(); !strings.Contains(msg, "has not reported") {
		t.Fatalf("before any heartbeat: %q", msg)
	}
	if _, err := r.d.Probe(t.Context(), argvOf(t, nmapargv.Sweep, 10, "10.0.0.1")); !errors.Is(err, sa.ErrWorkerUnavailable) || !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("Probe without a heartbeat: %v", err)
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 {
		t.Fatalf("a job was created without a worker: %+v", rep)
	}
	r.beat(t, true)
	if msg := r.d.NmapHealth(); msg != "" {
		t.Fatalf("with a heartbeat: %q", msg)
	}
	r.clk.Advance(90 * time.Second)
	if msg := r.d.NmapHealth(); msg != "" {
		t.Fatalf("90 s is still online: %q", msg)
	}
	r.clk.Advance(time.Second)
	if msg := r.d.NmapHealth(); !strings.Contains(msg, "has not reported") {
		t.Fatalf("91 s without a heartbeat: %q", msg)
	}
	r.beat(t, false)
	if msg := r.d.NmapHealth(); !strings.Contains(msg, "nmap is not installed") {
		t.Fatalf("nmap missing: %q", msg)
	}
	if _, err := r.d.Probe(t.Context(), argvOf(t, nmapargv.Sweep, 10, "10.0.0.1")); !errors.Is(err, sa.ErrNmapMissing) || !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("Probe with nmap missing: %v", err)
	}
}

// The service reports the same through Health, with the message of the worker (INV-6).
func TestServiceHealthFromTheWorker(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	e := newEnv(t, fakeOpts{})
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Events: e.ev, Prober: r.d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	if h := svc.Health(t.Context()); h.Status != "unavailable" || !strings.Contains(h.Message, "has not reported") {
		t.Fatalf("no heartbeat: %+v", h)
	}
	r.beat(t, true)
	if h := svc.Health(t.Context()); h.Status != "ok" {
		t.Fatalf("with heartbeat: %+v", h)
	}
	r.beat(t, false)
	if h := svc.Health(t.Context()); h.Status != "unavailable" || !strings.Contains(h.Message, "nmap is not installed") {
		t.Fatalf("nmap missing: %+v", h)
	}
}

// D-113 (4): a job the worker does not fetch in 60 s fails as worker_unavailable, and is not handed out afterwards.
func TestPickupTimeout(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	notYet(t, ch, 50*time.Millisecond)
	r.clk.Advance(59 * time.Second)
	r.beat(t, true) // the worker is alive, just not polling
	notYet(t, ch, 50*time.Millisecond)
	r.clk.Advance(2 * time.Second)
	if got := await(t, ch); !errors.Is(got.err, sa.ErrWorkerUnavailable) {
		t.Fatalf("err = %v", got.err)
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 {
		t.Fatalf("an expired job was handed out: %+v", rep)
	}
}

// D-113 (4): no heartbeat for 90 s while the job waits, or while it runs, fails it (worker_unavailable, worker_lost).
func TestNoHeartbeatFailsTheJob(t *testing.T) {
	t.Parallel()
	t.Run("before pickup", func(t *testing.T) {
		t.Parallel()
		r := newDRig(t)
		r.beat(t, true)
		ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
		notYet(t, ch, 50*time.Millisecond)
		r.clk.Advance(91 * time.Second)
		if got := await(t, ch); !errors.Is(got.err, sa.ErrWorkerUnavailable) {
			t.Fatalf("err = %v", got.err)
		}
	})
	t.Run("while running", func(t *testing.T) {
		t.Parallel()
		r := newDRig(t)
		r.beat(t, true)
		ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
		j := r.poll(t, "", 5*time.Second).Jobs[0]
		r.clk.Advance(91 * time.Second) // no poll names the job for 91 s
		if got := await(t, ch); !errors.Is(got.err, sa.ErrWorkerLost) {
			t.Fatalf("err = %v", got.err)
		}
		// M1: the lost job is not left to run for two hours: the first poll that still names it is told to stop it, at once
		start := time.Now()
		rep := r.poll(t, j.ID, 20*time.Second)
		if len(rep.Cancel) != 1 || rep.Cancel[0] != j.ID || len(rep.Jobs) != 0 || time.Since(start) > 5*time.Second {
			t.Fatalf("a lost job was not cancelled at once: %+v after %v", rep, time.Since(start))
		}
	})
}

// M1: a worker that reports a job this core does not know (core restarted while nmap ran) is told to stop it at once, and a
// new job is not handed to it meanwhile.
func TestRestartedCoreCancelsTheUnknownRunningJob(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	unknown := strings.Repeat("e", 32)
	start := time.Now()
	rep := r.poll(t, unknown, 20*time.Second)
	if len(rep.Cancel) != 1 || rep.Cancel[0] != unknown || len(rep.Jobs) != 0 || time.Since(start) > 5*time.Second {
		t.Fatalf("reply = %+v after %v", rep, time.Since(start))
	}
	// once it says it is free, the waiting job goes out
	if rep := r.poll(t, "", 5*time.Second); len(rep.Jobs) != 1 {
		t.Fatalf("reply = %+v", rep)
	}
	_ = ch
}

// L3: a running job is lost when its timeout plus 30 s has passed, however alive the worker looks; the poll that still names
// it is told to stop it, and Health says why active discovery waits. A probe with no deadline carries the 2 hour cap.
func TestRunningJobPastItsLimitIsLostAndCancelled(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := probeCtx(t, 20*time.Second)
	defer cancel()
	ch := probe(ctx, r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	if j.TimeoutS < 18 || j.TimeoutS > 20 {
		t.Fatalf("timeout_s = %d", j.TimeoutS)
	}
	r.clk.Advance(time.Duration(j.TimeoutS)*time.Second + 29*time.Second)
	r.beat(t, true)
	r.poll(t, j.ID, 0) // alive: it polls
	notYet(t, ch, 50*time.Millisecond)
	r.clk.Advance(2 * time.Second)
	r.beat(t, true)
	if got := await(t, ch); !errors.Is(got.err, sa.ErrWorkerLost) {
		t.Fatalf("err = %v", got.err)
	}
	if msg := r.d.NmapHealth(); !strings.Contains(msg, "past its time limit") {
		t.Fatalf("health = %q", msg)
	}
	if rep := r.poll(t, j.ID, 0); len(rep.Cancel) != 1 || rep.Cancel[0] != j.ID {
		t.Fatalf("reply = %+v", rep)
	}
	r.poll(t, "", 0) // free again
	if msg := r.d.NmapHealth(); msg != "" {
		t.Fatalf("health after the worker is free = %q", msg)
	}
	// no deadline on the probe: the job carries the 2 hour cap
	ch2 := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.2"))
	if got := r.poll(t, "", 5*time.Second).Jobs; len(got) != 1 || got[0].TimeoutS != 7200 {
		t.Fatalf("job = %+v", got)
	}
	_ = ch2
}

// D-113 (4): a poll that says the worker runs nothing (or something else) after the job was handed out and before a result:
// worker_lost; the reply that carried the job was lost, or the sensor restarted. The next job is then handed out.
func TestWorkerLostWhenAPollSaysItRunsNothing(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	r.poll(t, j.ID, 0) // running as it should: nothing happens
	notYet(t, ch, 50*time.Millisecond)
	r.poll(t, "", 0) // restarted
	if got := await(t, ch); !errors.Is(got.err, sa.ErrWorkerLost) {
		t.Fatalf("err = %v", got.err)
	}
	// its late result is refused: the job is over
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); !isCode(err, sensorlink.CodeUnknownJob) {
		t.Fatalf("late result: %v", err)
	}
	ch2 := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.2"))
	if rep := r.poll(t, "", 5*time.Second); len(rep.Jobs) != 1 {
		t.Fatalf("the next job was not handed out: %+v", rep)
	}
	_ = ch2
}

func isCode(err error, code string) bool {
	var e *sensorlink.Error
	return errors.As(err, &e) && e.Code == code
}

// A result for an id nobody was given, for a job that has finished, or sent twice, is 404 unknown_job (D-113: job-id
// guessing and replay).
func TestResultsForUnknownFinishedOrReplayedJobsAreRefused(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	if err := r.worker.PostResult(t.Context(), strings.Repeat("0", 32), okResult("<nmaprun/>")); !isCode(err, sensorlink.CodeUnknownJob) {
		t.Fatalf("no job at all: %v", err)
	}
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	if err := r.worker.PostResult(t.Context(), strings.Repeat("a", 32), okResult("<nmaprun/>")); !isCode(err, sensorlink.CodeUnknownJob) {
		t.Fatalf("a guessed id while a job runs: %v", err)
	}
	notYet(t, ch, 50*time.Millisecond) // the guess did not end the job
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	if got := await(t, ch); got.err != nil {
		t.Fatalf("probe: %v", got.err)
	}
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<evil/>")); !isCode(err, sensorlink.CodeUnknownJob) {
		t.Fatalf("a replay: %v", err)
	}
	// a job that was never handed out (it is still pending) is not running either
	ch2 := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.2"))
	notYet(t, ch2, 50*time.Millisecond)
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); !isCode(err, sensorlink.CodeUnknownJob) {
		t.Fatalf("a replay while the next job waits: %v", err)
	}
}

// The passive role can neither fetch jobs nor answer them: 403 forbidden_route, before any body is read.
func TestPassiveRoleCannotFetchOrAnswerJobs(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	if _, err := r.passive.Jobs(t.Context(), "", 0); !isCode(err, sensorlink.CodeForbiddenRoute) {
		t.Fatalf("passive Jobs: %v", err)
	}
	if err := r.passive.PostResult(t.Context(), j.ID, okResult("<evil/>")); !isCode(err, sensorlink.CodeForbiddenRoute) {
		t.Fatalf("passive PostResult for the running job: %v", err)
	}
	notYet(t, ch, 100*time.Millisecond)
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch)
}

// The module switch of the active role: off answers 409 module_off on the job routes (D-111 (4)).
func TestModuleOffAnswersTheWorker(t *testing.T) {
	t.Parallel()
	r := newDRig(t, func(o *sensorlink.Options) {
		o.ModuleOn = func(role sensorlink.Role) bool { return role != sensorlink.Active }
	})
	if _, err := r.worker.Jobs(t.Context(), "", 0); !isCode(err, sensorlink.CodeModuleOff) {
		t.Fatalf("Jobs: %v", err)
	}
}

// D-113 (5): core does not trust the worker's status. The exit code, the truncation and the XML decide.
func TestResultStatusIsNotTrusted(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		res  sensorlink.JobResult
		want func(sa.Output, error) bool
	}{
		"done exit 0 passes the xml on": {sensorlink.JobResult{Status: "done"}, func(o sa.Output, err error) bool { return err == nil && string(o.XML) == "<x/>" }},
		"done but exit 3 fails with the code": {sensorlink.JobResult{Status: "done", ExitCode: 3}, func(_ sa.Output, err error) bool {
			var ee *exec.ExitError
			return errors.As(err, &ee) && ee.ExitCode == 3
		}},
		"done but truncated is flagged":   {sensorlink.JobResult{Status: "done", Truncated: true}, func(o sa.Output, err error) bool { return err == nil && o.Truncated }},
		"failed with exit 0 is a failure": {sensorlink.JobResult{Status: "failed"}, func(_ sa.Output, err error) bool { return err != nil }},
		"stopped is a failure":            {sensorlink.JobResult{Status: "stopped", Reason: "cancelled", ExitCode: -1}, func(_ sa.Output, err error) bool { return err != nil }},
		"done with exit -1 is a failure":  {sensorlink.JobResult{Status: "done", ExitCode: -1}, func(_ sa.Output, err error) bool { return err != nil }},
		"refused": {sensorlink.JobResult{Status: "refused", Reason: "invalid_job", ExitCode: -1}, func(_ sa.Output, err error) bool {
			return errors.Is(err, sa.ErrWorkerRefused)
		}},
		"nmap_missing": {sensorlink.JobResult{Status: "failed", Reason: "nmap_missing", ExitCode: -1}, func(_ sa.Output, err error) bool {
			return errors.Is(err, sa.ErrNmapMissing)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newDRig(t)
			r.beat(t, true)
			ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
			j := r.poll(t, "", 5*time.Second).Jobs[0]
			res := c.res
			if res.Status == "done" {
				res.SetXML([]byte("<x/>"))
			}
			if err := r.worker.PostResult(t.Context(), j.ID, &res); err != nil {
				t.Fatal(err)
			}
			got := await(t, ch)
			if !c.want(got.out, got.err) {
				t.Fatalf("probe = %+v", got)
			}
			if name == "nmap_missing" {
				if msg := r.d.NmapHealth(); !strings.Contains(msg, "nmap is not installed") {
					t.Fatalf("health after nmap_missing: %q", msg)
				}
			}
		})
	}
}

// D-113 (5): XML of 8 MiB + 1 is 413 payload_too_large, and the probe ends failed at once (it does not wait for a lease).
func TestOversizedResultIs413AndFailsTheProbe(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	res := &sensorlink.JobResult{Status: "done"}
	res.SetXML([]byte(strings.Repeat("a", sensorlink.MaxResultXML+1)))
	if err := r.worker.PostResult(t.Context(), j.ID, res); !isCode(err, sensorlink.CodePayloadTooLarge) {
		t.Fatalf("PostResult: %v", err)
	}
	got := await(t, ch)
	if got.err == nil || strings.Contains(got.err.Error(), "context") {
		t.Fatalf("probe = %+v", got)
	}
	if err := r.worker.PostResult(t.Context(), j.ID, okResult("<nmaprun/>")); !isCode(err, sensorlink.CodeUnknownJob) {
		t.Fatalf("a second result after the 413: %v", err)
	}
}

// The same through the service: the probe row ends failed with the size-limit text, and nothing is recorded (INV-7, INV-9).
func TestOversizedResultEndsTheProbeRowFailed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	r := newDRig(t)
	r.beat(t, true)
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Events: e.ev, Prober: r.d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- svc.ScanDevice(e.ctx(), "a-web", "test") }()
	j := r.poll(t, "", 10*time.Second).Jobs[0]
	res := &sensorlink.JobResult{Status: "done"}
	res.SetXML([]byte(strings.Repeat("a", sensorlink.MaxResultXML+1)))
	if err := r.worker.PostResult(t.Context(), j.ID, res); !isCode(err, sensorlink.CodePayloadTooLarge) {
		t.Fatalf("PostResult: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("ScanDevice succeeded on a result that was too large")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ScanDevice did not return")
	}
	if got := e.str(`SELECT result FROM sa_probe ORDER BY id DESC LIMIT 1`); got != "failed: output over the size limit, discarded" {
		t.Fatalf("probe row result = %q", got)
	}
	if n := len(e.sink.observations()); n != 0 {
		t.Fatalf("%d observations from a discarded run", n)
	}
}

// D-113 (4): when the probe's context ends before the job is fetched, it is dropped; the worker never sees it.
func TestCancelBeforePickupDropsTheJob(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	ch := probe(ctx, r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	notYet(t, ch, 50*time.Millisecond)
	cancel()
	if got := await(t, ch); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v", got.err)
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 || len(rep.Cancel) != 0 {
		t.Fatalf("the worker was told of a job that was dropped: %+v", rep)
	}
}

// D-113 (4): after the worker has the job, the end of the probe's context sends cancel:[id] on the open long poll (which is
// woken); the probe returns when the worker confirms with its result.
func TestCancelAfterPickupGoesOutOnTheLongPoll(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	ch := probe(ctx, r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	polled := make(chan sensorlink.JobsReply, 1)
	go func() { polled <- r.poll(t, j.ID, 20*time.Second) }() // the worker's next long poll, held open
	<-time.After(100 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case rep := <-polled:
		if len(rep.Cancel) != 1 || rep.Cancel[0] != j.ID || len(rep.Jobs) != 0 {
			t.Fatalf("reply = %+v", rep)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("the long poll was not woken by the cancel")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the long poll was not woken by the cancel")
	}
	notYet(t, ch, 50*time.Millisecond) // still waiting for the worker to confirm
	stopped := &sensorlink.JobResult{Status: "stopped", Reason: "cancelled", ExitCode: -1}
	if err := r.worker.PostResult(t.Context(), j.ID, stopped); err != nil {
		t.Fatal(err)
	}
	if got := await(t, ch); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v", got.err)
	}
}

// D-113 (4): without a confirmation the probe counts as stopped 30 s after its context ended; the next job still waits until
// a poll says the worker runs nothing.
func TestUnconfirmedCancelIsStoppedAfter30sAndTheNextJobWaits(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	ch := probe(ctx, r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j := r.poll(t, "", 5*time.Second).Jobs[0]
	cancel()
	<-time.After(100 * time.Millisecond)
	r.clk.Advance(29 * time.Second)
	r.beat(t, true)
	notYet(t, ch, 100*time.Millisecond)
	r.clk.Advance(2 * time.Second)
	if got := await(t, ch); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v", got.err)
	}
	// the worker still runs j: a new job is not handed out while polls say so
	ch2 := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.2"))
	rep := r.poll(t, j.ID, 0)
	if len(rep.Jobs) != 0 || len(rep.Cancel) != 1 {
		t.Fatalf("a job was handed out to a busy worker: %+v", rep)
	}
	notYet(t, ch2, 50*time.Millisecond)
	// the worker is free (killed, result not delivered): the new job goes out
	rep = r.poll(t, "", 5*time.Second)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Targets[0] != "10.0.0.2" {
		t.Fatalf("reply = %+v", rep)
	}
	if err := r.worker.PostResult(t.Context(), rep.Jobs[0].ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch2)
}

// The instance nonce is the same on every reply of one core process and differs between processes (D-113 (4): the worker's
// lease and instance check).
func TestInstanceNonce(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	inst := r.beat(t, true)
	if !hex32.MatchString(inst) || r.poll(t, "", 0).Instance != inst {
		t.Fatalf("instance %q on the heartbeat, %q on the poll", inst, r.poll(t, "", 0).Instance)
	}
	if other := newDRig(t).beat(t, true); other == inst {
		t.Fatal("two dispatchers share an instance")
	}
}

// A new job waits while a poll still says the worker runs the previous one, and is handed out once it is free.
func TestOneJobInFlight(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	ch1 := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))
	j1 := r.poll(t, "", 5*time.Second).Jobs[0]
	ch2 := probe(t.Context(), r.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.2"))
	if rep := r.poll(t, j1.ID, 0); len(rep.Jobs) != 0 {
		t.Fatalf("a second job went out while the first runs: %+v", rep)
	}
	if err := r.worker.PostResult(t.Context(), j1.ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch1)
	j2 := r.poll(t, "", 5*time.Second).Jobs
	if len(j2) != 1 || j2[0].Targets[0] != "10.0.0.2" {
		t.Fatalf("second job = %+v", j2)
	}
	if err := r.worker.PostResult(t.Context(), j2[0].ID, okResult("<nmaprun/>")); err != nil {
		t.Fatal(err)
	}
	await(t, ch2)
}

// An argv that is not one of the three shapes never becomes a job.
func TestProbeRefusesAnArgvOutsideTheGrammar(t *testing.T) {
	t.Parallel()
	r := newDRig(t)
	r.beat(t, true)
	if _, err := r.d.Probe(t.Context(), []string{"-A", "-oX", "-", "10.0.0.1"}); err == nil {
		t.Fatal("accepted")
	}
	if rep := r.poll(t, "", 0); len(rep.Jobs) != 0 {
		t.Fatalf("job: %+v", rep)
	}
}

// serve is a hand-written worker that answers every job it fetches with xml until stop is closed; it returns what it saw.
func serve(t *testing.T, r *drig, xml []byte) (stop func() [][]string) {
	t.Helper()
	quit := make(chan struct{})
	done := make(chan [][]string, 1)
	go func() {
		var seen [][]string
		for {
			select {
			case <-quit:
				done <- seen
				return
			default:
			}
			rep, err := r.worker.Jobs(context.Background(), "", time.Second)
			if err != nil || len(rep.Jobs) == 0 {
				continue
			}
			j := rep.Jobs[0]
			seen = append(seen, j.Targets)
			res := &sensorlink.JobResult{Status: "done"}
			res.SetXML(xml)
			_ = r.worker.PostResult(context.Background(), j.ID, res)
		}
	}()
	return func() [][]string {
		close(quit)
		return <-done
	}
}

// M3: a sweep whose worker becomes unavailable mid-way stops after the batch that found out: it does not probe, and fail, the
// batches that are left. The cursor stays after the last finished batch, the job is stopped, and a later Tick runs the sweep
// again from the cursor.
func TestSweepStopsWhenTheWorkerIsUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) { e.inv.st.LANRanges = []string{"192.168.10.0/24"} })
	r := newDRig(t)
	r.beat(t, true)
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Events: e.ev, Prober: r.d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	xml, err := os.ReadFile("testdata/sweep.xml")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { _, err := svc.DiscoverRanges(e.ctx()); errc <- err }()
	j1 := r.poll(t, "", 10*time.Second).Jobs[0]
	res := &sensorlink.JobResult{Status: "done"}
	res.SetXML(xml)
	if err := r.worker.PostResult(t.Context(), j1.ID, res); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second batch to be waiting for the worker", func() bool { return e.count(`SELECT count(*) FROM sa_probe`) == 2 })
	r.clk.Advance(61 * time.Second) // nobody fetches it
	select {
	case err := <-errc:
		if !errors.Is(err, sa.ErrStopped) {
			t.Fatalf("DiscoverRanges err = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("DiscoverRanges did not return")
	}
	if n := e.count(`SELECT count(*) FROM sa_probe`); n != 2 {
		t.Fatalf("%d probe rows: the batches that were left were probed", n)
	}
	if got := e.str(`SELECT result FROM sa_probe ORDER BY id DESC LIMIT 1`); got != "failed: worker_unavailable" {
		t.Fatalf("last probe row = %q", got)
	}
	if got := e.str(`SELECT status FROM sa_job WHERE kind = 'sweep'`); got != sa.StatusStopped {
		t.Fatalf("sweep job status = %q", got)
	}
	last := j1.Targets[len(j1.Targets)-1]
	if got := e.str(`SELECT cursor FROM sa_sweep WHERE id = 1`); got != last {
		t.Fatalf("cursor = %q, want %q", got, last)
	}
	// the worker is back: the next Tick runs the sweep again, from the cursor
	r.beat(t, true)
	stop := serve(t, r, xml)
	if err := svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	seen := stop()
	if len(seen) == 0 || seen[0][0] != netip.MustParseAddr(last).Next().String() {
		t.Fatalf("the retry did not continue from the cursor: first targets %v, cursor was %s", seen, last)
	}
}

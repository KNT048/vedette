package worker_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// No test here runs a real nmap or sends a packet: the nmap is a shell script in t.TempDir(), run by the real worker
// through the real core/exec, over the real mutual-TLS link to a scripted core.

const xmlOK = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.10.20" addrtype="ipv4"/></host></nmaprun>`

// fakeCore is the core end of the link for the active role: it hands out the jobs a test pushes, carries its cancels and
// instance, and keeps what the worker sends.
type fakeCore struct {
	mu       sync.Mutex
	instance string
	queue    []sensorlink.Job
	cancel   []string
	handed   string // the job handed out and not yet answered
	running  string // what the latest poll said the worker runs
	polls    int
	failPoll error // when set, Jobs fails with it
	results  chan result
	beats    chan sensorlink.ActiveHeartbeat
}

type result struct {
	id  string
	res sensorlink.JobResult
	xml []byte
}

func newCore() *fakeCore {
	return &fakeCore{instance: strings.Repeat("a", 32), results: make(chan result, 16), beats: make(chan sensorlink.ActiveHeartbeat, 64)}
}

func (c *fakeCore) push(j sensorlink.Job) {
	c.mu.Lock()
	c.queue = append(c.queue, j)
	c.mu.Unlock()
}
func (c *fakeCore) cancelJob(id string) {
	c.mu.Lock()
	c.cancel = append(c.cancel, id)
	c.mu.Unlock()
}
func (c *fakeCore) setInstance(s string) {
	c.mu.Lock()
	c.instance = s
	c.mu.Unlock()
}
func (c *fakeCore) fail(err error) {
	c.mu.Lock()
	c.failPoll = err
	c.mu.Unlock()
}
func (c *fakeCore) runningNow() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *fakeCore) Jobs(ctx context.Context, wait time.Duration, running string) (sensorlink.JobsReply, error) {
	deadline := time.Now().Add(wait)
	for {
		c.mu.Lock()
		c.running = running
		c.polls++
		rep := sensorlink.JobsReply{Instance: c.instance, Jobs: []sensorlink.Job{}, Cancel: append([]string{}, c.cancel...)}
		if c.failPoll != nil {
			err := c.failPoll
			c.mu.Unlock()
			return rep, err
		}
		if len(c.queue) > 0 {
			rep.Jobs = append(rep.Jobs, c.queue[0])
			c.handed = c.queue[0].ID
			c.queue = c.queue[1:]
		}
		ready := len(rep.Jobs) > 0 || len(rep.Cancel) > 0
		c.cancel = nil // a cancel goes out once, as the dispatcher's does
		c.mu.Unlock()
		if ready || time.Now().After(deadline) || ctx.Err() != nil {
			return rep, nil
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
		}
	}
}

func (c *fakeCore) JobRunning(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handed == id
}

func (c *fakeCore) JobResult(_ context.Context, id string, r *sensorlink.JobResult) error {
	c.mu.Lock()
	if c.handed != id {
		c.mu.Unlock()
		return sensorlink.NewError(sensorlink.CodeUnknownJob)
	}
	c.handed = ""
	c.mu.Unlock()
	c.results <- result{id: id, res: *r, xml: r.XML()}
	return nil
}

func (c *fakeCore) ActiveHeartbeat(_ context.Context, hb *sensorlink.ActiveHeartbeat) (string, error) {
	select {
	case c.beats <- *hb:
	default:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instance, nil
}

var errNotMine = sensorlink.NewError(sensorlink.CodeForbiddenRoute)

func (c *fakeCore) Config(context.Context, time.Duration, string) (sensorlink.ConfigReply, error) {
	return sensorlink.ConfigReply{}, errNotMine
}
func (c *fakeCore) Observations(context.Context, *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	return sensorlink.ObservationsReply{}, errNotMine
}
func (c *fakeCore) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	return "", errNotMine
}

func (c *fakeCore) next(t *testing.T) result {
	t.Helper()
	select {
	case r := <-c.results:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("no result from the worker")
		return result{}
	}
}

// noResult asserts that nothing is posted for a while.
func (c *fakeCore) noResult(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case r := <-c.results:
		t.Fatalf("a result was posted: %+v", r.res)
	case <-time.After(d):
	}
}

// fakeNmap is a script that answers --version, records its argv and pids, and then behaves as mode says.
type fakeNmap struct {
	path string
	dir  string
}

func (f *fakeNmap) argvLog() string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "argv.log"))
	return string(b)
}

func (f *fakeNmap) pid(t *testing.T, name string) int {
	t.Helper()
	var n int
	waitFor(t, name+" pid", func() bool {
		b, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // a file of the test's own temp directory
		if err != nil {
			return false
		}
		n, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	})
	return n
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// writeNmap makes the script. body runs for a scan (not for --version); it may use $DIR.
func writeNmap(t *testing.T, body string) *fakeNmap {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
DIR=%q
if [ "$1" = "--version" ]; then echo "Nmap version 7.94SVN ( https://nmap.org )"; exit 0; fi
printf '%%s\n' "$@" >> "$DIR/argv.log"
echo $$ > "$DIR/nmap.pid"
%s
`, dir, body)
	path := filepath.Join(dir, "nmap")
	exectest.WriteScript(t, path, script)
	f := &fakeNmap{path: path, dir: dir}
	// No orphan processes after any test: whatever the script left alive is killed and fails the test.
	t.Cleanup(func() {
		for _, name := range []string{"nmap.pid", "child.pid"} {
			b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // a file of the test's own temp directory
			if err != nil {
				continue
			}
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 && alive(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Errorf("orphan process %d (%s) outlived the test", pid, name)
			}
		}
	})
	return f
}

const printXML = `cat <<'EOF'
` + xmlOK + `
EOF
`

// sleeper starts a grandchild, ignores SIGTERM and never finishes.
const sleeper = `trap '' TERM
sleep 300 &
echo $! > "$DIR/child.pid"
wait
`

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !cond(); <-time.After(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// fakeClock is the clock of the worker's lease.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	core  *fakeCore
	nmap  *fakeNmap
	clock *fakeClock
	stop  func() // stops the worker and waits for it
	done  chan error
}

// start runs a worker against a fresh link with the nmap script.
func start(t *testing.T, nm *fakeNmap) *rig {
	t.Helper()
	c := newCore()
	link := linktest.New(t, c)
	clk := &fakeClock{t: time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)}
	cfg := worker.Config{
		Link: link.Client(t, sensorlink.Active), NmapPath: nm.path, Version: "1.0.0",
		Now: clk.Now, Wait: time.Second, Heartbeat: 300 * time.Millisecond, Tick: 10 * time.Millisecond, // the wire carries whole seconds of wait
		Sleep: func(ctx context.Context, d time.Duration) error { // backoffs and heartbeat gaps are short in a test
			select {
			case <-time.After(min(d, 300*time.Millisecond)): // under the 10 requests a second of the role
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	w, err := worker.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r := &rig{core: c, nmap: nm, clock: clk, done: make(chan error, 1)}
	go func() { r.done <- w.Run(ctx) }()
	var once sync.Once
	r.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-r.done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("Run returned %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("the worker did not stop")
			}
		})
	}
	t.Cleanup(r.stop)
	return r
}

func job(id string, targets ...string) sensorlink.Job {
	if len(targets) == 0 {
		targets = []string{"192.168.10.20"}
	}
	return sensorlink.Job{ID: id, Shape: "normal", Rate: 100, Targets: targets, TimeoutS: 60}
}

const (
	id1 = "00000000000000000000000000000001"
	id2 = "00000000000000000000000000000002"
)

// A job runs with the argv the worker built, and its result carries the XML and the exit code (D-113 (3), (5)).
func TestRunsAJobWithTheFixedGrammar(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, printXML)
	r := start(t, nm)
	r.core.push(job(id1, "192.168.10.20", "10.0.0.7"))
	got := r.core.next(t)
	if got.id != id1 || got.res.Status != "done" || got.res.ExitCode != 0 || got.res.Truncated || !strings.Contains(string(got.xml), "192.168.10.20") {
		t.Fatalf("result = %+v xml %q", got.res, got.xml)
	}
	want := "--privileged\n-sS\n-sV\n-O\n-n\n--max-rate\n100\n--top-ports\n1000\n--host-timeout\n30m\n-oX\n-\n192.168.10.20\n10.0.0.7\n"
	if nm.argvLog() != want {
		t.Fatalf("argv:\n%s\nwant:\n%s", nm.argvLog(), want)
	}
	waitFor(t, "running to clear", func() bool { return r.core.runningNow() == "" })
}

// The worker holds no scope, but it refuses what the grammar forbids, and nmap never starts (D-113 (3)).
func TestRefusesWhatTheGrammarForbids(t *testing.T) {
	t.Parallel()
	many := make([]string, 65)
	for i := range many {
		many[i] = fmt.Sprintf("10.0.%d.%d", i/200, i%200+1)
	}
	for name, j := range map[string]sensorlink.Job{
		"public ip":        job(id1, "8.8.8.8"),
		"one public of 2":  job(id1, "192.168.10.1", "1.1.1.1"),
		"loopback":         job(id1, "127.0.0.1"),
		"65 targets":       {ID: id1, Shape: "normal", Rate: 100, Targets: many, TimeoutS: 60},
		"no target":        {ID: id1, Shape: "normal", Rate: 100, Targets: []string{}, TimeoutS: 60},
		"rate 0":           {ID: id1, Shape: "sweep", Rate: 0, Targets: []string{"10.0.0.1"}, TimeoutS: 60},
		"rate 1001":        {ID: id1, Shape: "sweep", Rate: 1001, Targets: []string{"10.0.0.1"}, TimeoutS: 60},
		"unknown shape":    {ID: id1, Shape: "aggressive", Rate: 10, Targets: []string{"10.0.0.1"}, TimeoutS: 60},
		"empty shape":      {ID: id1, Shape: "", Rate: 10, Targets: []string{"10.0.0.1"}, TimeoutS: 60},
		"timeout 7201":     {ID: id1, Shape: "normal", Rate: 10, Targets: []string{"10.0.0.1"}, TimeoutS: 7201},
		"timeout 0":        {ID: id1, Shape: "normal", Rate: 10, Targets: []string{"10.0.0.1"}, TimeoutS: 0},
		"gentle rate 5":    {ID: id1, Shape: "gentle", Rate: 5, Targets: []string{"10.0.0.1"}, TimeoutS: 60},
		"duplicate target": job(id1, "10.0.0.1", "10.0.0.1"),
		"not canonical":    job(id1, "010.0.0.1"),
		"ipv6":             job(id1, "fd00::1"),
		"a flag":           job(id1, "-sC"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmap(t, printXML)
			r := start(t, nm)
			r.core.push(j)
			got := r.core.next(t)
			if got.res.Status != "refused" || got.res.Reason != "invalid_job" || got.res.ExitCode != -1 || got.res.XMLB64 != "" {
				t.Fatalf("result = %+v", got.res)
			}
			if nm.argvLog() != "" {
				t.Fatalf("nmap ran: %s", nm.argvLog())
			}
		})
	}
}

// A job that arrives while another runs is refused as busy, and the first one is not disturbed.
func TestBusyRefusesTheSecondJob(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.push(job(id1))
	waitFor(t, "nmap to start", func() bool { return nm.argvLog() != "" })
	waitFor(t, "poll to carry running", func() bool { return r.core.runningNow() == id1 })
	r.core.push(job(id2)) // pushed while the first still runs; core's JobRunning follows the latest job handed out
	got := r.core.next(t)
	if got.id != id2 || got.res.Status != "refused" || got.res.Reason != "busy" {
		t.Fatalf("result = %+v", got)
	}
	if n := strings.Count(nm.argvLog(), "-oX"); n != 1 {
		t.Fatalf("nmap ran %d times", n)
	}
}

// D-113 (4): a cancel in the poll reply kills the whole process group, the SIGTERM-ignoring script and its child, and the
// result is stopped/cancelled.
func TestCancelKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.push(job(id1))
	pid, child := nm.pid(t, "nmap.pid"), nm.pid(t, "child.pid")
	r.core.cancelJob(id1)
	got := r.core.next(t)
	if got.res.Status != "stopped" || got.res.Reason != "cancelled" || got.res.XMLB64 != "" {
		t.Fatalf("result = %+v", got.res)
	}
	waitFor(t, "the process group to die", func() bool { return !alive(pid) && !alive(child) })
}

// Cancel racing start: the cancel arrives in the reply that carries the job, so nmap never starts, and the result still
// answers core's job.
func TestCancelRacingStart(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.cancelJob(id1)
	r.core.push(job(id1))
	got := r.core.next(t)
	if got.id != id1 || got.res.Status != "stopped" || got.res.Reason != "cancelled" {
		t.Fatalf("result = %+v", got)
	}
	if nm.argvLog() != "" {
		t.Fatalf("nmap ran: %s", nm.argvLog())
	}
}

// D-113 (4): no successful poll for the lease kills nmap and drops the result; nothing is posted.
func TestLeaseLossKillsNmap(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.push(job(id1))
	pid, child := nm.pid(t, "nmap.pid"), nm.pid(t, "child.pid")
	r.core.fail(sensorlink.NewError(sensorlink.CodeInternal)) // every poll fails from now on
	r.clock.Advance(worker.Lease - time.Second)
	<-time.After(100 * time.Millisecond)
	if !alive(pid) {
		t.Fatal("nmap was killed before the lease ran out")
	}
	r.clock.Advance(2 * time.Second)
	waitFor(t, "the process group to die", func() bool { return !alive(pid) && !alive(child) })
	r.core.noResult(t, 300*time.Millisecond)
}

// D-113 (4): a new instance nonce of core (it restarted) kills nmap and drops the result, in a poll reply and in a heartbeat.
func TestInstanceChangeKillsNmap(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.push(job(id1))
	pid, child := nm.pid(t, "nmap.pid"), nm.pid(t, "child.pid")
	r.core.setInstance(strings.Repeat("b", 32))
	waitFor(t, "the process group to die", func() bool { return !alive(pid) && !alive(child) })
	r.core.noResult(t, 300*time.Millisecond)
	waitFor(t, "the worker to be idle", func() bool { return r.core.runningNow() == "" })
}

// The job's own deadline stops nmap and says so.
func TestDeadlineStopsNmap(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	j := job(id1)
	j.TimeoutS = 1
	r.core.push(j)
	pid, child := nm.pid(t, "nmap.pid"), nm.pid(t, "child.pid")
	got := r.core.next(t)
	if got.res.Status != "stopped" || got.res.Reason != "deadline" {
		t.Fatalf("result = %+v", got.res)
	}
	waitFor(t, "the process group to die", func() bool { return !alive(pid) && !alive(child) })
}

// Output over 8 MiB is cut at 8 MiB and flagged; a non-zero exit is failed with its code and no XML.
func TestTruncatedAndFailedResults(t *testing.T) {
	t.Parallel()
	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		nm := writeNmap(t, `head -c 9000000 /dev/zero | tr '\0' 'a'`)
		r := start(t, nm)
		r.core.push(job(id1))
		got := r.core.next(t)
		if got.res.Status != "done" || !got.res.Truncated || len(got.xml) != 8<<20 {
			t.Fatalf("status %s truncated %v xml %d", got.res.Status, got.res.Truncated, len(got.xml))
		}
	})
	t.Run("exit 3", func(t *testing.T) {
		t.Parallel()
		nm := writeNmap(t, "echo partial; exit 3")
		r := start(t, nm)
		r.core.push(job(id1))
		got := r.core.next(t)
		if got.res.Status != "failed" || got.res.ExitCode != 3 || got.res.XMLB64 != "" {
			t.Fatalf("result = %+v", got.res)
		}
	})
}

// Heartbeats carry the version of nmap and whether it is there.
func TestHeartbeatReportsNmap(t *testing.T) {
	t.Parallel()
	r := start(t, writeNmap(t, printXML))
	select {
	case hb := <-r.core.beats:
		if hb.Version != "1.0.0" || !hb.Nmap.Present || hb.Nmap.Version != "7.94SVN" {
			t.Fatalf("heartbeat = %+v", hb)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no heartbeat")
	}
	// and again, on its period
	select {
	case <-r.core.beats:
	case <-time.After(10 * time.Second):
		t.Fatal("no second heartbeat")
	}
}

func TestHeartbeatSaysNmapIsMissing(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, printXML)
	nm.path = filepath.Join(t.TempDir(), "no-nmap-here")
	r := start(t, nm)
	select {
	case hb := <-r.core.beats:
		if hb.Nmap.Present || hb.Nmap.Version != "" {
			t.Fatalf("heartbeat = %+v", hb)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no heartbeat")
	}
	// a job still gets an answer: nmap_missing
	r.core.push(job(id1))
	got := r.core.next(t)
	if got.res.Status != "failed" || got.res.Reason != "nmap_missing" {
		t.Fatalf("result = %+v", got.res)
	}
}

// Stopping the worker kills a running nmap and returns only once it is gone.
func TestShutdownKillsNmap(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.push(job(id1))
	pid, child := nm.pid(t, "nmap.pid"), nm.pid(t, "child.pid")
	r.stop()
	if alive(pid) || alive(child) {
		t.Fatal("nmap outlived Run")
	}
	r.core.noResult(t, 100*time.Millisecond)
}

// The module being off (409 module_off) kills nmap and drops the result.
func TestModuleOffKillsNmap(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, sleeper)
	r := start(t, nm)
	r.core.push(job(id1))
	pid, child := nm.pid(t, "nmap.pid"), nm.pid(t, "child.pid")
	r.core.fail(sensorlink.NewError(sensorlink.CodeModuleOff))
	waitFor(t, "the process group to die", func() bool { return !alive(pid) && !alive(child) })
	r.core.noResult(t, 300*time.Millisecond)
}

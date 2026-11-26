package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

const rid2 = "22222222-2222-4222-8222-222222222222"

// fakeSleep records the waits the client asks for and, when clock is set, moves the host's clock by them instead of
// sleeping: the host's limiter then frees its slots exactly as it would after a real wait.
type fakeSleep struct {
	mu    sync.Mutex
	clock *servertest.Clock
	waits []time.Duration
}

func (f *fakeSleep) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.waits = append(f.waits, d)
	f.mu.Unlock()
	if f.clock != nil {
		f.clock.Advance(d)
	}
	return nil
}

func (f *fakeSleep) got() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.waits...)
}

func limitedHost(t *testing.T, reads, writes int, cmds ...server.Command) (*client.Client, *fakeSleep) {
	t.Helper()
	h := servertest.Start(t, cmds, func(o *server.Options) {
		o.RequestsPerMinute, o.WritesPerMinute = reads, writes
		o.Readers.Net = func(context.Context) (any, error) { return api.NetState{Decoys: []api.NetDecoy{}}, nil }
	})
	fs := &fakeSleep{clock: h.Clock}
	c := client.NewWithOptions(h.Socket, client.Options{MaxRateWait: 2 * time.Minute, RateBudget: 5 * time.Minute, Sleep: fs.Sleep})
	t.Cleanup(c.Close)
	return c, fs
}

// A read the host's request limiter refuses is sent again after the host's Retry-After (plus at most a quarter), and
// its answer is returned: the caller never sees the refusal.
func TestRateLimitedReadWaitsRetryAfter(t *testing.T) {
	t.Parallel()
	c, fs := limitedHost(t, 2, 0)
	ctx := context.Background()
	for range 2 {
		if _, err := c.StateNet(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.StateNet(ctx); err != nil {
		t.Fatalf("third read in the minute: %v, want it answered after a wait", err)
	}
	w := fs.got()
	if len(w) != 1 || w[0] < time.Minute || w[0] > time.Minute+15*time.Second {
		t.Fatalf("waits = %v, want one wait of the host's 60 s Retry-After plus at most 15 s", w)
	}
}

// Each wait is capped (MaxRateWait, plus its jitter): a long Retry-After becomes several shorter waits, within the budget.
func TestRateLimitWaitIsCapped(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil, func(o *server.Options) { o.RequestsPerMinute = 1 })
	fs := &fakeSleep{clock: h.Clock}
	c := client.NewWithOptions(h.Socket, client.Options{MaxRateWait: 20 * time.Second, RateBudget: 5 * time.Minute, Sleep: fs.Sleep})
	defer c.Close()
	ctx := context.Background()
	if _, err := c.Info(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Info(ctx); err != nil {
		t.Fatalf("second read: %v", err)
	}
	w := fs.got()
	if len(w) != 3 {
		t.Fatalf("waits = %v, want three waits of at most 20 s and its jitter", w)
	}
	for _, d := range w {
		if d > 25*time.Second {
			t.Fatalf("waits = %v, one is over the 20 s cap plus a quarter", w)
		}
	}
}

// A wait that would end after the caller's deadline is not started: the refusal is returned at once, so a short read
// (a page's 2 s budget) still answers in time and the caller decides.
func TestRateLimitStopsAtContextDeadline(t *testing.T) {
	t.Parallel()
	c, fs := limitedHost(t, 1, 0)
	if _, err := c.StateNet(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.StateNet(ctx)
	var he *client.Error
	if !errors.As(err, &he) || he.Code != api.CodeRateLimited || he.RetryAfterS < 1 {
		t.Fatalf("err = %v, want the host's rate_limited", err)
	}
	if w := fs.got(); len(w) != 0 {
		t.Fatalf("waits = %v, want none: the Retry-After is past the deadline", w)
	}
}

// Without a deadline the waits of one request stop after RateBudget.
func TestRateLimitBudgetWithoutDeadline(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil, func(o *server.Options) { o.RequestsPerMinute = 1 })
	fs := &fakeSleep{} // the host's clock does not move: it refuses every time
	c := client.NewWithOptions(h.Socket, client.Options{MaxRateWait: 10 * time.Second, RateBudget: 25 * time.Second, Sleep: fs.Sleep})
	defer c.Close()
	ctx := context.Background()
	if _, err := c.Info(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Info(ctx); !client.IsCode(err, api.CodeRateLimited) {
		t.Fatalf("err = %v, want rate_limited once the budget is spent", err)
	}
	var sum time.Duration
	for _, d := range fs.got() {
		sum += d
	}
	if n := len(fs.got()); n != 2 || sum > 25*time.Second {
		t.Fatalf("waits = %v, want two waits of 10 s (and jitter) within the 25 s budget", fs.got())
	}
}

// Core's page handlers call the host with the request's context, which has no deadline, and neither core's HTTP server
// nor the web app cut a slow answer off. With the default budget a refusal whose slot frees soon is still waited out,
// but one whose slot frees only late in the host's minute is returned within seconds, not after a minute of a spinner.
func TestRateLimitDefaultBudgetWithoutDeadline(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil, func(o *server.Options) { o.RequestsPerMinute = 1 })
	fs := &fakeSleep{clock: h.Clock}
	c := client.NewWithOptions(h.Socket, client.Options{Sleep: fs.Sleep})
	defer c.Close()
	ctx := context.Background()
	if _, err := c.Info(ctx); err != nil {
		t.Fatal(err)
	}
	h.Clock.Advance(55 * time.Second) // the slot frees in 5 s
	if _, err := c.Info(ctx); err != nil {
		t.Fatalf("a refusal whose slot frees in 5 s: %v, want it waited out", err)
	}
	fs.mu.Lock()
	fs.waits, fs.clock = nil, nil // from here the host's clock stands still: its next slot is a minute away
	fs.mu.Unlock()
	if _, err := c.Info(ctx); !client.IsCode(err, api.CodeRateLimited) {
		t.Fatalf("err = %v, want rate_limited", err)
	}
	var sum time.Duration
	for _, d := range fs.got() {
		sum += d
	}
	if sum > 20*time.Second {
		t.Fatalf("waits = %v (%v), want at most 20 s before the refusal is returned to a caller without a deadline", fs.got(), sum)
	}
}

// A refusal that is not the rate limiter's is the caller's to handle: never retried here, even with a retry hint.
func TestNoRetryForOtherCodes(t *testing.T) {
	t.Parallel()
	var checks atomic.Int64
	busy := server.Define(server.Spec[struct{}]{
		Name: "test.busy", Timeout: time.Minute,
		Check: func(context.Context, struct{}) error {
			checks.Add(1)
			return server.RefuseRetry(http.StatusConflict, api.CodeDpkgLocked, "dpkg is locked", 30)
		},
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return struct{}{}, nil },
	})
	c, fs := limitedHost(t, 0, 0, busy)
	ctx := context.Background()
	_, err := c.Run(ctx, "test.busy", nil, rid, "admin")
	var he *client.Error
	if !errors.As(err, &he) || he.Code != api.CodeDpkgLocked || he.RetryAfterS != 30 {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Run(ctx, "no.such", nil, rid2, "admin"); !client.IsCode(err, api.CodeUnknownCommand) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.GetRun(ctx, "rn_0000000000000000"); !client.IsCode(err, api.CodeRunNotFound) {
		t.Fatalf("err = %v", err)
	}
	if n := checks.Load(); n != 1 {
		t.Fatalf("the command was checked %d times, want 1", n)
	}
	if w := fs.got(); len(w) != 0 {
		t.Fatalf("waits = %v, want none", w)
	}
}

// One-shot start: a command the request limiter refuses was never seen by its handler, so it is sent again with the
// same request id and runs exactly once.
func TestRateLimitedStartIsSentAgain(t *testing.T) {
	t.Parallel()
	var runs atomic.Int64
	start := server.Define(server.Spec[struct{}]{
		Name: "test.start", Timeout: time.Minute,
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) { runs.Add(1); return struct{}{}, nil },
	})
	c, fs := limitedHost(t, 1, 0, start)
	ctx := context.Background()
	if _, err := c.Info(ctx); err != nil { // the minute's only request
		t.Fatal(err)
	}
	run, err := c.Run(ctx, "test.start", nil, rid, "admin")
	if err != nil || run.RunID == "" || run.RequestID != rid {
		t.Fatalf("run %+v err %v, want the command accepted after the wait", run, err)
	}
	if len(fs.got()) != 1 {
		t.Fatalf("waits = %v", fs.got())
	}
	waitTerminal(t, c, run.RunID)
	if n := runs.Load(); n != 1 {
		t.Fatalf("the command ran %d times, want 1", n)
	}
}

// Write command: the write limiter refuses before the body is read and before the request id is bound, so the command
// is sent again with the same id; it runs once, and the host knows that id for it.
func TestRateLimitedWriteCommandIsSentAgain(t *testing.T) {
	t.Parallel()
	var runs atomic.Int64
	write := server.Define(server.Spec[struct{}]{
		Name: "test.write", Write: true, Timeout: time.Minute,
		Run: func(context.Context, *server.RunContext, struct{}) (any, error) { runs.Add(1); return struct{}{}, nil },
	})
	c, fs := limitedHost(t, 0, 1, write)
	ctx := context.Background()
	first, err := c.Run(ctx, "test.write", nil, rid, "admin")
	if err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, c, first.RunID)
	second, err := c.Run(ctx, "test.write", nil, rid2, "admin")
	if err != nil || second.RequestID != rid2 || second.RunID == first.RunID {
		t.Fatalf("second write: run %+v err %v, want it accepted after the wait", second, err)
	}
	waitTerminal(t, c, second.RunID)
	if n := runs.Load(); n != 2 {
		t.Fatalf("ran %d times, want 2 (one per request id)", n)
	}
	if w := fs.got(); len(w) != 1 || w[0] < time.Minute {
		t.Fatalf("waits = %v, want one wait of the write limiter's minute", w)
	}
}

func waitTerminal(t *testing.T, c *client.Client, runID string) {
	t.Helper()
	s := c.Events(context.Background(), runID, 0) // no deadline: a connect the limiter refuses waits on the fake clock
	defer s.Close()
	for {
		_, err := s.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// zapHost is a fake host for the ZAP calls: each route answers 429 rate_limited the first refuse[route] times, then
// normally (the run is running for the first runningReads reads, then succeeded with a report).
type zapHost struct {
	mu           sync.Mutex
	refuse       map[string]int
	runningReads int
	hits         map[string]int
}

const zapReport = `{"site":[]}`

func (z *zapHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := "other"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/commands/"+api.CmdZapBaseline:
		route = "start"
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/runs/"):
		route = "poll"
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/zap/"):
		route = "report"
	}
	z.mu.Lock()
	z.hits[route]++
	hit := z.hits[route]
	refused := hit <= z.refuse[route]
	reads := hit - z.refuse[route]
	z.mu.Unlock()
	if refused {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(api.ErrorBody{Error: api.ErrorInfo{Code: api.CodeRateLimited, Message: "Too many requests; slow down.", RetryAfterS: 1}})
		return
	}
	run := api.Run{RunID: "rn_0000000000000001", Command: api.CmdZapBaseline, Status: api.StatusRunning, RequestID: rid}
	switch route {
	case "start":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(run)
	case "poll":
		if reads > z.runningReads {
			run.Status = api.StatusSucceeded
			run.Result, _ = json.Marshal(api.ZapBaselineResult{ReportID: "zr_1", Size: int64(len(zapReport))})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(run)
	case "report":
		_, _ = io.WriteString(w, zapReport)
	default:
		http.NotFound(w, r)
	}
}

func startZapHost(t *testing.T, z *zapHost) string {
	t.Helper()
	z.hits = map[string]int{}
	sock := filepath.Join(shortDir(t), "z.sock")
	ln := listenUnix(t, sock)
	srv := &http.Server{Handler: z, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// The ZAP passive scan end to end through the client: the start, a status read and the report download each refused
// once by the rate limiter still give the finished run and its report.
func TestZapBaselineThroughRateLimits(t *testing.T) {
	t.Parallel()
	z := &zapHost{refuse: map[string]int{"start": 1, "poll": 1, "report": 1}, runningReads: 1}
	sock := startZapHost(t, z)
	fs := &fakeSleep{}
	c := client.NewWithOptions(sock, client.Options{Sleep: fs.Sleep})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run, err := c.ZapBaseline(ctx, api.ZapBaselineArgs{}, rid, "exposure")
	if err != nil || run.Status != api.StatusSucceeded {
		t.Fatalf("run %+v err %v, want the run followed to success", run, err)
	}
	res, err := client.ResultOf[api.ZapBaselineResult](run)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := c.DownloadZapReport(ctx, res.ReportID)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	defer func() { _ = body.Close() }()
	if b, _ := io.ReadAll(body); string(b) != zapReport {
		t.Fatalf("report = %q", b)
	}
}

// Status poll: a read of a running run the limiter keeps refusing until the caller's time ends is "not known yet": the
// follow ends with the caller's context error, never with rate_limited as if the run had failed.
func TestFollowPollRefusedIsNotKnownYet(t *testing.T) {
	t.Parallel()
	z := &zapHost{refuse: map[string]int{"poll": 1 << 20}}
	sock := startZapHost(t, z)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sleeps atomic.Int64
	c := client.NewWithOptions(sock, client.Options{RateBudget: time.Second, MaxRateWait: time.Second, Sleep: func(ctx context.Context, _ time.Duration) error {
		if sleeps.Add(1) == 12 { // the caller gives up after a while
			cancel()
		}
		return ctx.Err()
	}})
	defer c.Close()
	run, err := c.ZapBaseline(ctx, api.ZapBaselineArgs{}, rid, "exposure")
	if !errors.Is(err, context.Canceled) || client.IsCode(err, api.CodeRateLimited) {
		t.Fatalf("err = %v, want the caller's cancellation", err)
	}
	if run.RunID == "" || run.Status != api.StatusRunning {
		t.Fatalf("run = %+v, want the run as last known (running)", run)
	}
}

// A long run is read less and less often: 2 s, then doubling, at most every 10 s (about six reads a minute, where a read
// every 2 s took half of the host's 60-a-minute budget by itself).
func TestFollowPacesLongRuns(t *testing.T) {
	t.Parallel()
	z := &zapHost{refuse: map[string]int{}, runningReads: 6}
	sock := startZapHost(t, z)
	fs := &fakeSleep{}
	c := client.NewWithOptions(sock, client.Options{Sleep: fs.Sleep})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if run, err := c.ZapBaseline(ctx, api.ZapBaselineArgs{}, rid, "exposure"); err != nil || run.Status != api.StatusSucceeded {
		t.Fatalf("run %+v err %v", run, err)
	}
	if got, want := fmt.Sprint(fs.got()), "[2s 4s 8s 10s 10s 10s 10s]"; got != want {
		t.Fatalf("waits between reads = %s, want %s", got, want)
	}
}

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
)

// limitedZapHost is a vedette-host whose request limiter refuses the first call of each ZAP route (the start, the first read of
// the run, the report) with 429 rate_limited, as a host whose one-minute budget core's other callers had just spent.
type limitedZapHost struct {
	mu   sync.Mutex
	hits map[string]int
}

func (z *limitedZapHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := r.Method + " " + r.URL.Path
	if strings.HasPrefix(r.URL.Path, "/v1/runs/") {
		route = "poll"
	}
	z.mu.Lock()
	z.hits[route]++
	hit := z.hits[route]
	z.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if hit == 1 {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(api.ErrorBody{Error: api.ErrorInfo{Code: api.CodeRateLimited, Message: "Too many requests; slow down.", RetryAfterS: 1}})
		return
	}
	run := api.Run{RunID: "rn_0123456789abcdef", Command: api.CmdZapBaseline, Status: api.StatusRunning}
	switch {
	case route == http.MethodPost+" /v1/commands/"+api.CmdZapBaseline:
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(run)
	case route == "poll":
		run.Status = api.StatusSucceeded
		run.Result, _ = json.Marshal(api.ZapBaselineResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11})
		_ = json.NewEncoder(w).Encode(run)
	case strings.HasPrefix(r.URL.Path, "/v1/zap/"):
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, `{"site":[]}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(api.ErrorBody{Error: api.ErrorInfo{Code: api.CodeUnknownCommand, Message: "no"}})
	}
}

// The passive ZAP step of a deep scan: ZAP ran, and the host's limiter refusing the start, the read of the run and the report
// download once each must not lose that page's report (the step was failed for every page before).
func TestExposureWeb_RateLimitedHostCallsKeepTheReport(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(shortTemp(t), "z.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	z := &limitedZapHost{hits: map[string]int{}}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: z}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	var waits int
	c := hostclient.NewWithOptions(sock, hostclient.Options{Sleep: func(ctx context.Context, _ time.Duration) error { waits++; return ctx.Err() }})
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	got, err := exposureWebScan{host: c}.Baseline(ctx, webIPTarget, webIPPage)
	if err != nil || string(got.Report) != `{"site":[]}` {
		t.Fatalf("report %q err %v, want the page's report", got.Report, err)
	}
	if waits != 4 {
		t.Errorf("%d waits, want one per refusal and the one before the first read of the run", waits)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	for route, n := range z.hits {
		if n != 2 {
			t.Errorf("%s: %d calls, want the refused one and one more", route, n)
		}
	}
}

// The exposure pages read the gateway at every refresh while a scan runs (every 5 s per open page): the host's state/net is
// asked once per exposureNetTTL, not at every refresh, so the pages do not spend the host's request budget the scan needs.
func TestExposureGateway_ReadsTheHostOncePerTTL(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	f := &fakeNet{st: api.NetState{DefaultRoute: &api.NetRoute{Gateway: "192.0.2.1"}}}
	g := &cachedNetState{r: f, ttl: exposureNetTTL, now: func() time.Time { return now }}
	for range 6 { // half a minute of one page's refreshes
		if got, err := g.StateNet(t.Context()); err != nil || got.DefaultRoute == nil || got.DefaultRoute.Gateway != "192.0.2.1" {
			t.Fatalf("%+v %v", got, err)
		}
		now = now.Add(4 * time.Second)
	}
	if f.calls != 1 {
		t.Fatalf("state/net was read %d times, want 1", f.calls)
	}
	now = now.Add(exposureNetTTL)
	if _, err := g.StateNet(t.Context()); err != nil || f.calls != 2 {
		t.Fatalf("after the TTL: %d reads, err %v", f.calls, err)
	}
	// A failed read is not kept: the next refresh asks again.
	f.err = context.DeadlineExceeded
	now = now.Add(exposureNetTTL)
	if _, err := g.StateNet(t.Context()); err == nil {
		t.Fatal("a failed read must be returned, not hidden behind an old answer")
	}
	f.err = nil
	if _, err := g.StateNet(t.Context()); err != nil || f.calls != 4 {
		t.Fatalf("after a failure: %d reads, err %v", f.calls, err)
	}
}

package sensoractive_test

import (
	"context"
	"os"
	"os/exec" //nolint:depguard // the test starts its own binary again with an env var; no external program (SYS-1 is about the product)
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// The contract tests of INV-1..INV-9 run twice: with the local Prober (nmap through core/exec in this process), and with
// the remote one (SP-3): a Dispatcher, the real mutual-TLS link, the real worker and the same fake nmap script. The second
// run is this binary started again with remoteEnvVar set, so the whole suite is reused with no change to its tests.
const remoteEnvVar = "VEDETTE_SA_PROBER"

func remoteMode() bool { return os.Getenv(remoteEnvVar) == "remote" }

// activeBackend is the Backend core serves to the active role: the Dispatcher for jobs and heartbeat. The server never
// routes the passive calls to it (the role decides the route before the Backend is asked).
type activeBackend struct{ *sa.Dispatcher }

func (activeBackend) Config(context.Context, time.Duration, string) (sensorlink.ConfigReply, error) {
	return sensorlink.ConfigReply{}, sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (activeBackend) Observations(context.Context, *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (activeBackend) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	return "", sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

// remote is the far end of a Dispatcher for an env: the link and a worker running the env's fake nmap.
type remote struct {
	d    *sa.Dispatcher
	link *linktest.Link
	path string // the nmap the worker runs
	stop func() // stops the worker and waits for it; safe to call twice
}

// startRemote wires a Dispatcher, a link and a worker for e, and waits until the worker's first heartbeat has arrived
// (or has failed to find nmap): Health then says what is true.
func startRemote(e *env) *remote {
	e.t.Helper()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(e.t, activeBackend{d})
	w, err := worker.New(worker.Config{Link: link.Client(e.t, sensorlink.Active), NmapPath: e.nm.path, Version: "1.0.0", Wait: time.Second})
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(e.t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				e.t.Error("the worker did not stop")
			}
		})
	}
	e.t.Cleanup(stop)
	waitFor(e.t, "the first heartbeat of the worker", func() bool {
		return !strings.Contains(d.NmapHealth(), "has not reported")
	})
	return &remote{d: d, link: link, path: e.nm.path, stop: stop}
}

// TestSuiteThroughTheDispatcher runs the whole package twice more, as this test binary started again: once with the local Prober
// and once with the remote one. The two runs must pass the same tests, and the stop paths (the window closing, a settings change,
// a lowered rate, a shortened window, the deadline, the sweep resuming, the probe row while the run is in progress) must be among
// them. What reruns remotely is every test that builds its Service through newEnv, e.build or buildWith/e.prober; the tests that
// hand sa.New a Prober of their own (a fake one) are the same in both runs.
func TestSuiteThroughTheDispatcher(t *testing.T) {
	if remoteMode() || os.Getenv(remoteEnvVar) != "" {
		t.Skip("this is a child run")
	}
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) (string, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.skip", "^TestSuiteThroughTheDispatcher$", "-test.count=1", "-test.timeout=4m", "-test.v")
		cmd.Env = append(os.Environ(), remoteEnvVar+"="+mode)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	type result struct {
		out string
		err error
	}
	res := map[string]chan result{"local": make(chan result, 1), "remote": make(chan result, 1)}
	for mode, ch := range res {
		go func() { o, err := run(mode); ch <- result{o, err} }()
	}
	local, remote := <-res["local"], <-res["remote"]
	if local.err != nil {
		t.Fatalf("the suite fails with the local Prober: %v\n%s", local.err, tail([]byte(local.out), 4000))
	}
	if remote.err != nil {
		t.Fatalf("the suite fails with the remote Prober: %v\n%s", remote.err, tail([]byte(remote.out), 6000))
	}
	pass := func(out string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(out, "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "--- PASS: "); ok {
				m[strings.Fields(rest)[0]] = true
			}
		}
		return m
	}
	lp, rp := pass(local.out), pass(remote.out)
	if len(lp) < 100 || len(lp) != len(rp) {
		t.Errorf("the local run passed %d tests, the remote run %d", len(lp), len(rp))
	}
	for name := range lp {
		if !rp[name] {
			t.Errorf("%s passed locally and did not in the remote run", name)
		}
	}
	for _, name := range []string{
		"TestContract_INV1_NeverOutsideScope", "TestContract_INV3_StopsWhenTheWindowCloses", "TestContract_INV3_SettingsChangeStopsTheRunningScan",
		"TestContract_INV4_LoweringTheRateStopsTheRunningJob", "TestContract_INV9_ProbeLog", "TestProbeRowExistsWhileTheRunIsInProgress",
		"TestWindowShortenedMidRunStopsAtTheNewEnd", "TestQueueDeviceCutByTheDeadlineGoesToTheBack", "TestQueueDeviceStoppedBySettingsKeepsItsAttempts",
		"TestSweepCutByTheWindowResumesWhereItStopped", "TestSettingsStopDuringPreChecksIsNotAnAttempt", "TestContract_INV6_MissingNmapIsUnavailable",
	} {
		if !rp[name] {
			t.Errorf("%s did not run in the remote suite", name)
		}
	}
}

// tail is what a failed child run says worth reading: its failing lines first, then the end of its output.
func tail(b []byte, n int) string {
	var fails []string
	for _, l := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "--- FAIL") || strings.Contains(t, "_test.go:") || strings.HasPrefix(t, "panic") {
			fails = append(fails, t)
		}
	}
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.Join(fails, "\n") + "\n----\n" + string(b)
}

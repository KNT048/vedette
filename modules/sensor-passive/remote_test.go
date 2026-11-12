package sensorpassive_test

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
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// The contract tests run twice: with the capture job inside the test process, linked to the Service in memory (what production does
// until SP-5), and with the capture on the far end of the real mutual-TLS link (SP-4): a sensorlink.Client, the real server, the
// Service as the passive Backend. The second run is this test binary started again with remoteEnvVar set, so the whole suite is
// reused with no change to its tests (the pattern of sensor-active's SP-3).
const remoteEnvVar = "VEDETTE_SP_CAPTURE"

func remoteMode() bool { return os.Getenv(remoteEnvVar) == "remote" }

// remote is the far end of a Service for an env: the link and a capture Runner that talks to it.
type remote struct {
	link   *linktest.Link
	client *sensorlink.Client
	runner *capture.Runner
}

// backendOnly marks a test that never starts the capture job: it calls the Service as the backend of the link (Observations,
// the heartbeats, Config) or reads it, so its run in the remote child would repeat the parent's in-process run step for step. The
// child skips it (TestSuiteThroughTheLink accepts that skip and no other); in the parent, a marked test that starts the capture job
// fails in env.job, so no test can lose its remote run by mistake.
func backendOnly(t *testing.T) {
	t.Helper()
	if remoteMode() {
		t.Skip(backendOnlySkip)
	}
	backendOnlyTests.Store(t.Name(), true)
}

const backendOnlySkip = "backend only: the in-process run of the parent is the same run"

var backendOnlyTests sync.Map // top-level test name -> true, in the parent

// job is what the env runs as "the capture job": Service.Run inside the process, or the Runner at the end of the link.
func (e *env) job() func(context.Context) error {
	if _, marked := backendOnlyTests.Load(strings.SplitN(e.t.Name(), "/", 2)[0]); marked {
		e.t.Fatal("this test is marked backendOnly but starts the capture job: drop the mark, so the remote run covers it")
	}
	if !remoteMode() && !e.forceRemote {
		return e.svc.Run
	}
	if e.rem == nil {
		e.rem = startRemote(e)
	}
	return e.rem.runner.Run
}

func startRemote(e *env) *remote {
	e.t.Helper()
	cards := e.host.Interfaces
	if e.sensorCards != nil {
		cards = e.sensorCards
	}
	flush := 40 * time.Millisecond
	if e.cfg.FlushEvery >= time.Second {
		flush = e.cfg.FlushEvery // a test that wants nothing flushed
	}
	link := linktest.New(e.t, linktest.Passive(e.svc), func(o *sensorlink.Options) { o.ModuleOn = func(sensorlink.Role) bool { return !e.off.Load() } })
	client := link.Client(e.t, sensorlink.Passive)
	r, err := capture.New(capture.Config{
		Link: client, Interfaces: cards, Open: e.src.open, Meta: e.meta,
		Clock: e.cfg.Clock, Log: e.cfg.Log, Version: "1.0.0",
		// 10 ms beats and flushes would be 100 requests a second: the link allows 10. The pace is the one thing that differs.
		FlushEvery: flush, HeartbeatEvery: 150 * time.Millisecond, RetryEvery: e.cfg.RetryEvery, SummaryEvery: e.cfg.SummaryEvery,
		ConfigWait: 2 * time.Second, ModuleOffEvery: 100 * time.Millisecond, RetryAfterCap: 50 * time.Millisecond,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return &remote{link: link, client: client, runner: r}
}

// TestSuiteThroughTheLink runs the whole package once more, as this test binary started again with the remote capture. The run with
// the in-process capture is this one: remoteMode is off here, every other test of the package runs in process, and the package fails if
// one of them does. The remote run must pass every one of them (the binary lists them with -test.list), and the contract tests (INV-1 to
// INV-9, POST-1 to POST-4, the module switch, the refused item, the long name) must be among them. A second child in process, which
// this test also started until now, only repeated this run: a third of the package's time under -race.
func TestSuiteThroughTheLink(t *testing.T) {
	if os.Getenv(remoteEnvVar) != "" {
		t.Skip("this is a child run")
	}
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	list, err := exec.CommandContext(ctx, exe, "-test.list", ".").Output() //nolint:gosec // exe is this test binary (os.Executable), with fixed arguments
	if err != nil {
		t.Fatalf("list the tests: %v", err)
	}
	var want []string
	for _, name := range strings.Fields(string(list)) {
		if !strings.HasPrefix(name, "Benchmark") && name != "TestSuiteThroughTheLink" {
			want = append(want, name)
		}
	}
	cmd := exec.CommandContext(ctx, exe, "-test.skip", "^TestSuiteThroughTheLink$", "-test.count=1", "-test.timeout=5m", "-test.v") //nolint:gosec // exe is this test binary, with fixed arguments
	cmd.Env = append(os.Environ(), remoteEnvVar+"=remote")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the suite fails with the remote capture: %v\n%s", err, tail(b, 6000))
	}
	// A test passes, or skips with the reason of backendOnly; nothing else counts. -test.v names the test before its output (=== RUN,
	// === CONT, === NAME), so a reason line belongs to the test named last.
	rp, said, skipped := map[string]bool{}, map[string]bool{}, map[string]bool{}
	current := ""
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		for _, p := range []string{"=== RUN ", "=== CONT ", "=== NAME ", "=== PAUSE "} {
			if rest, ok := strings.CutPrefix(l, p); ok {
				current = strings.TrimSpace(rest)
			}
		}
		if strings.Contains(l, backendOnlySkip) {
			said[current] = true
		}
		if rest, ok := strings.CutPrefix(l, "--- PASS: "); ok {
			rp[strings.Fields(rest)[0]] = true
		}
		if rest, ok := strings.CutPrefix(l, "--- SKIP: "); ok {
			skipped[strings.Fields(rest)[0]] = true
		}
	}
	backend := func(name string) bool { return skipped[name] && said[name] }
	if len(want) < 25 || len(rp) < 15 {
		t.Errorf("the package lists %d tests, the remote run passed %d", len(want), len(rp))
	}
	for _, name := range want {
		if !rp[name] && !backend(name) {
			t.Errorf("%s runs in process and did not pass in the remote run", name)
		}
	}
	for _, name := range []string{
		"TestContract_INV3_NoPayloadStored", "TestContract_INV5_ObservationsArePassiveThroughTheSink", "TestContract_INV6_NewMACUnapprovedBoxIsNotADevice",
		"TestContract_INV7_ExclusionBeforeExtraction", "TestContract_INV9_InterfaceRulesAndOwnOnlyWarning", "TestContract_POST1_OnlineWhileCapturing",
		"TestContract_POST2_CaptureMovesToTheNewCard", "TestContract_POST4_SpanStatsAreMeasured", "TestContract_CaptureFollowsTheModuleSwitch",
		"TestContract_OneRefusedItemDoesNotBlindTheBatch", "TestContract_LongHostnameDoesNotPoisonTheBatch",
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

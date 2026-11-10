package sensorpassive_test

import (
	"context"
	"os"
	"os/exec" //nolint:depguard // the test starts its own binary again with an env var; no external program (SYS-1 is about the product)
	"strings"
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

// job is what the env runs as "the capture job": Service.Run inside the process, or the Runner at the end of the link.
func (e *env) job() func(context.Context) error {
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

// TestSuiteThroughTheLink runs the whole package twice more, as this test binary started again: once with the in-process capture
// and once with the remote one. The two runs must pass the same tests, and the contract tests (INV-1 to INV-9, POST-1 to POST-4, the
// module switch, the refused item, the long name) must be among them.
func TestSuiteThroughTheLink(t *testing.T) {
	if os.Getenv(remoteEnvVar) != "" {
		t.Skip("this is a child run")
	}
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) (string, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.skip", "^TestSuiteThroughTheLink$", "-test.count=1", "-test.timeout=5m", "-test.v")
		cmd.Env = append(os.Environ(), remoteEnvVar+"="+mode)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	type result struct {
		out string
		err error
	}
	// One after the other: each child already runs its tests in parallel on every core, so two at once only doubled the load
	// (about 35 s of CPU each under -race) and starved the waits of both.
	var local, rem result
	local.out, local.err = run("local")
	rem.out, rem.err = run("remote")
	if local.err != nil {
		t.Fatalf("the suite fails with the in-process capture: %v\n%s", local.err, tail([]byte(local.out), 4000))
	}
	if rem.err != nil {
		t.Fatalf("the suite fails with the remote capture: %v\n%s", rem.err, tail([]byte(rem.out), 6000))
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
	lp, rp := pass(local.out), pass(rem.out)
	if len(lp) < 25 || len(lp) != len(rp) {
		t.Errorf("the in-process run passed %d tests, the remote run %d", len(lp), len(rp))
	}
	for name := range lp {
		if !rp[name] {
			t.Errorf("%s passed in process and did not in the remote run", name)
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

package sensoractive_test

import (
	"context"
	"os"
	"os/exec" //nolint:depguard // the test starts its own binary again with an env var; no external program (SYS-1 is about the product)
	"strings"
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
	e.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			e.t.Error("the worker did not stop")
		}
	})
	waitFor(e.t, "the first heartbeat of the worker", func() bool {
		return !strings.Contains(d.NmapHealth(), "has not reported")
	})
	return &remote{d: d, link: link}
}

// TestContractsThroughTheDispatcher runs INV-1..INV-9 again with the remote Prober.
func TestContractsThroughTheDispatcher(t *testing.T) {
	if remoteMode() {
		t.Skip("this is the child run")
	}
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run", "^TestContract_INV", "-test.count=1", "-test.timeout=3m", "-test.v") //nolint:gosec // exe is os.Executable: this test binary
	cmd.Env = append(os.Environ(), remoteEnvVar+"=remote")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the contract suite fails with the remote Prober: %v\n%s", err, tail(out, 6000))
	}
	for _, name := range []string{"TestContract_INV1_NeverOutsideScope", "TestContract_INV3_StopsWhenTheWindowCloses", "TestContract_INV9_ProbeLog"} {
		if !strings.Contains(string(out), "--- PASS: "+name) {
			t.Errorf("%s did not run in the child suite", name)
		}
	}
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

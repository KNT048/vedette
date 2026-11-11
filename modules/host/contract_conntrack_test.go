package host_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// Stale UDP syslog flows after core restarts (D-268, review M1 of D-167): when the host sees core run again it deletes the
// conntrack entries of the published syslog port, once, with one fixed argv. Nothing runs when core did not run again.

var wantConntrack = []string{"-D", "-f", "ipv4", "-p", "udp", "--orig-port-dst", "514"}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func startConntrack(t *testing.T) (*ctrEnv, *lockedBuf) {
	t.Helper()
	logs := &lockedBuf{}
	e := startCtr(t, func(c *ops.Config, _ *ops.Deps) { c.Logger = slog.New(slog.NewTextHandler(logs, nil)) })
	e.m.InstallUnit(api.ServiceCore, digA, true)
	return e, logs
}

func conntrackCalls(e *ctrEnv) [][]string { return e.m.Calls(ops.BinConntrack) }

func TestContract_Conntrack_AStartOfCoreByTheHostClearsTheFlowsOnce(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	e.start(t, api.ServiceCore, false)
	got := conntrackCalls(e)
	if len(got) != 1 || !slices.Equal(got[0], wantConntrack) {
		t.Fatalf("conntrack calls %v, want exactly one with %v", got, wantConntrack)
	}
	if n := strings.Count(logs.String(), "deleted="); n != 1 {
		t.Errorf("%d log lines about the delete, want 1:\n%s", n, logs.String())
	}
	// The poll sees the same run: nothing more.
	e.o.ObserveCore(context.Background())
	e.o.ObserveCore(context.Background())
	if got := conntrackCalls(e); len(got) != 1 {
		t.Fatalf("a look at the same run ran conntrack again: %v", got)
	}
	// Another restart by the host: one more.
	e.start(t, api.ServiceCore, true)
	if got := conntrackCalls(e); len(got) != 2 || !slices.Equal(got[1], wantConntrack) {
		t.Fatalf("conntrack calls after a second restart: %v", got)
	}
	// A start of another service never touches it.
	e.m.InstallUnit(api.ServiceHoneypot, digA, false)
	e.start(t, api.ServiceHoneypot, false)
	if got := conntrackCalls(e); len(got) != 2 {
		t.Fatalf("a restart of the honeypot ran conntrack: %v", got)
	}
}

func TestContract_Conntrack_ARestartTheHostDidNotMakeIsSeenByTheLook(t *testing.T) {
	t.Parallel()
	e, _ := startConntrack(t)
	e.m.SetRunning(api.ServiceCore, true)
	ctx := context.Background()
	e.o.ObserveCore(ctx) // the first look only remembers the run
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 0 {
		t.Fatalf("a first look ran conntrack: %v", got)
	}
	e.m.ContainerRestarted(api.ServiceCore) // systemd restarted core after a crash
	e.o.ObserveCore(ctx)
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 1 || !slices.Equal(got[0], wantConntrack) {
		t.Fatalf("conntrack calls after a crash restart: %v", got)
	}
}

func TestContract_Conntrack_NoContainerNoCall(t *testing.T) {
	t.Parallel()
	e, _ := startConntrack(t)
	ctx := context.Background()
	e.o.ObserveCore(ctx) // core was never started: podman says there is no such container
	e.m.SetRunning(api.ServiceCore, true)
	e.o.ObserveCore(ctx)
	e.m.SetRunning(api.ServiceCore, false) // stopped: nothing to compare
	e.m.ContainerRestarted(api.ServiceCore)
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 0 {
		t.Fatalf("conntrack ran without a core that runs again: %v", got)
	}
	e.m.InspectRaw(api.ServiceCore, "not json") // hostile output
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 0 {
		t.Fatalf("conntrack ran on unreadable podman output: %v", got)
	}
}

func TestContract_Conntrack_ExitOneMeansNothingToDeleteAndIsNotAFailure(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	e.m.Rule(ops.BinConntrack, "", "", 1, "", "")
	r := e.start(t, api.ServiceCore, false)
	if r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	if len(conntrackCalls(e)) != 1 || !strings.Contains(logs.String(), "deleted=0") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("exit 1 was handled as a failure or not logged as 0 entries:\n%s", logs.String())
	}
}

func TestContract_Conntrack_AnotherExitCodeIsLoggedAndTheStartStillSucceeds(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	e.m.Rule(ops.BinConntrack, "", "", 2, "", "")
	if r := e.start(t, api.ServiceCore, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "exit_code=2") {
		t.Fatalf("the failure was not logged:\n%s", logs.String())
	}
}

func TestContract_Conntrack_AMissingBinaryIsLoggedOnceAndNothingRuns(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	if err := os.Remove(filepath.Join(e.m.Bin, ops.BinConntrack)); err != nil {
		t.Fatal(err)
	}
	e.start(t, api.ServiceCore, false)
	e.start(t, api.ServiceCore, true)
	e.m.ContainerRestarted(api.ServiceCore)
	e.o.ObserveCore(context.Background())
	if got := conntrackCalls(e); len(got) != 0 {
		t.Fatalf("a program ran although the binary is missing: %v", got)
	}
	if n := strings.Count(logs.String(), "conntrack is not installed"); n != 1 {
		t.Fatalf("%d lines about the missing binary, want 1:\n%s", n, logs.String())
	}
}

func TestContract_Conntrack_TheValidatorAcceptsOnlyTheOneArgv(t *testing.T) {
	t.Parallel()
	if err := ops.ValidateConntrack(wantConntrack); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ops.ConntrackArgs(), wantConntrack) {
		t.Fatalf("%v", ops.ConntrackArgs())
	}
	for _, a := range [][]string{
		nil, {"-D"}, {"-F"}, {"-L"}, {"-D", "-p", "udp", "--orig-port-dst", "514"},
		{"-D", "-f", "ipv6", "-p", "udp", "--orig-port-dst", "514"},
		{"-D", "-f", "ipv4", "-p", "tcp", "--orig-port-dst", "514"},
		{"-D", "-f", "ipv4", "-p", "udp", "--orig-port-dst", "8443"},
		{"-D", "-f", "ipv4", "-p", "udp", "--orig-port-dst", "514", "-s", "10.0.0.1"},
		{"-D", "-f", "ipv4", "-p", "udp", "--orig-port-dst", "514", "-F"},
		{"-D", "-f", "ipv4", "-p", "udp", "--orig-port-dst", "514 "},
		{"--version"},
	} {
		if err := ops.ValidateConntrack(a); err == nil {
			t.Errorf("%v was accepted", a)
		}
	}
}

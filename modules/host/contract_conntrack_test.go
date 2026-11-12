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
	"time"

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
	// The first look after the host starts always clears once (a boot: core started after the host; or core ran again
	// while the host was down), and the same run is never cleared twice.
	e.o.ObserveCore(ctx)
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 1 || !slices.Equal(got[0], wantConntrack) {
		t.Fatalf("conntrack calls after the first looks: %v", got)
	}
	e.m.ContainerRestarted(api.ServiceCore) // systemd restarted core after a crash
	e.o.ObserveCore(ctx)
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 2 || !slices.Equal(got[1], wantConntrack) {
		t.Fatalf("conntrack calls after a crash restart: %v", got)
	}
}

func TestContract_Conntrack_NoContainerNoCall(t *testing.T) {
	t.Parallel()
	e, _ := startConntrack(t)
	ctx := context.Background()
	e.o.ObserveCore(ctx) // core was never started: podman says there is no such container
	if got := conntrackCalls(e); len(got) != 0 {
		t.Fatalf("conntrack ran with no container: %v", got)
	}
	e.m.SetRunning(api.ServiceCore, true)
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 1 {
		t.Fatalf("the first look at a running core: %v", got)
	}
	e.m.SetRunning(api.ServiceCore, false) // stopped: nothing to compare
	e.m.ContainerRestarted(api.ServiceCore)
	e.o.ObserveCore(ctx)
	e.m.InspectRaw(api.ServiceCore, "not json") // hostile output
	e.o.ObserveCore(ctx)
	if got := conntrackCalls(e); len(got) != 1 {
		t.Fatalf("conntrack ran without a core that runs again, or on unreadable podman output: %v", got)
	}
}

func TestContract_Conntrack_ExitOneWithTheZeroLineIsNotAFailureButWithoutItIs(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	e.m.ConntrackSays(1, "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.")
	r := e.start(t, api.ServiceCore, false)
	if r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	if len(conntrackCalls(e)) != 1 || !strings.Contains(logs.String(), "deleted=0") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("exit 1 was handled as a failure or not logged as 0 entries:\n%s", logs.String())
	}
	// Exit 1 is also what conntrack returns for a real error: that one is logged as an error.
	e2, logs2 := startConntrack(t)
	e2.m.ConntrackSays(1, "conntrack v1.4.8 (conntrack-tools): Operation failed: Operation not permitted")
	if r := e2.start(t, api.ServiceCore, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(logs2.String(), "level=ERROR") || strings.Contains(logs2.String(), "deleted=") {
		t.Fatalf("exit 1 without the zero line was taken for success:\n%s", logs2.String())
	}
}

func TestContract_Conntrack_AnotherExitCodeIsLoggedAndTheStartStillSucceeds(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	e.m.ConntrackSays(2, "boom")
	if r := e.start(t, api.ServiceCore, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "exit_code=2") {
		t.Fatalf("the failure was not logged:\n%s", logs.String())
	}
}

// A conntrack killed by a signal reports exit -1 (core/exec): not "deleted=0", a failure.
func TestContract_Conntrack_AKilledConntrackIsAFailureNotZeroDeleted(t *testing.T) {
	t.Parallel()
	e, logs := startConntrack(t)
	fake := filepath.Join(e.m.Bin, ops.BinConntrack)
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nkill -9 $$\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := e.start(t, api.ServiceCore, false); r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || strings.Contains(logs.String(), "deleted=") {
		t.Fatalf("a killed conntrack was logged as a success:\n%s", logs.String())
	}
}

// The watch loop itself: Start arms it, a restart of core makes one conntrack call, Close ends it.
func TestContract_Conntrack_TheWatchLoopClearsOnceAfterARestartAndStopsOnClose(t *testing.T) {
	t.Parallel()
	logs := &lockedBuf{}
	e := startCtr(t, func(c *ops.Config, d *ops.Deps) {
		c.Logger = slog.New(slog.NewTextHandler(logs, nil))
		d.CoreWatch = time.Millisecond
	})
	e.m.InstallUnit(api.ServiceCore, digA, true)
	e.m.SetRunning(api.ServiceCore, true)
	e.o.Start(context.Background(), e.h.Server)
	waitCalls := func(n int) {
		t.Helper()
		for i := 0; len(conntrackCalls(e)) < n; i++ {
			if i > 30000 {
				t.Fatalf("no conntrack call number %d from the watch loop", n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitCalls(1) // the first look after the host starts
	e.m.ContainerRestarted(api.ServiceCore)
	waitCalls(2)
	e.o.Close()
	n := len(conntrackCalls(e))
	e.m.ContainerRestarted(api.ServiceCore)
	time.Sleep(50 * time.Millisecond) // a negative check: it can only miss a late call, never fail without one
	if got := len(conntrackCalls(e)); got != n {
		t.Fatalf("the watch loop kept running after Close: %d calls, %d at Close", got, n)
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

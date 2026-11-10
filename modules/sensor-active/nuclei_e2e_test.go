package sensoractive_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
	"github.com/knt048/vedette/modules/sensor-active/worker/workertest"
)

// The whole path: a Dispatcher, the real mutual-TLS link, the real worker, and a fake nuclei (and a fake nmap) run through the
// real core/exec. Nothing reaches a network.

const fakeNmapScript = `#!/bin/sh
if [ "$1" = "--version" ]; then echo "Nmap version 7.94SVN ( https://nmap.org )"; exit 0; fi
sleep 300 &
wait
`

type e2e struct {
	d    *sa.Dispatcher
	nu   *workertest.Nuclei
	pack *workertest.Pack
	stop func()
}

func startE2E(t *testing.T, nucleiBody string) *e2e {
	t.Helper()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(t, activeBackend{d})
	nu := workertest.NewNuclei(t, nucleiBody)
	pk := workertest.NewPack(t, "CVE-2024-1", "CVE-2024-2")
	nmapPath := filepath.Join(t.TempDir(), "nmap")
	exectest.WriteScript(t, nmapPath, fakeNmapScript)
	w, err := worker.New(worker.Config{
		Link: link.Client(t, sensorlink.Active), NmapPath: nmapPath, Version: "1.0.0", Wait: time.Second, Heartbeat: 500 * time.Millisecond,
		NucleiPath: nu.Path, NucleiIndex: pk.Index, NucleiHome: filepath.Join(t.TempDir(), "home"), TemplatesDir: pk.Dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Error("the worker did not stop")
			}
		})
	}
	t.Cleanup(stop)
	waitFor(t, "the worker to be ready", func() bool { return d.Ready(t.Context()) == nil && d.NmapHealth() == "" })
	return &e2e{d: d, nu: nu, pack: pk, stop: stop}
}

func (e *e2e) req() sa.NucleiRequest {
	q := nreq()
	q.PackVersion, q.PackSHA256 = e.pack.Version, e.pack.SHA256
	return q
}

// A run goes out, nuclei prints a line for each template and target, core parses it.
func TestEndToEndNucleiRun(t *testing.T) {
	t.Parallel()
	e := startE2E(t, "cat <<'EOF'\n"+string(fixture(t, "nuclei_host_port.jsonl"))+"EOF\n")
	res, err := e.d.RunNuclei(t.Context(), e.req())
	if err != nil || len(res) != 3 || !res[0].Matched || res[0].Target != "192.168.10.20:8080" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	args := strings.Split(strings.TrimSpace(e.nu.Argv()), "\n")
	if err := nucleiargv.Validate(args); err != nil {
		t.Fatalf("what ran is not what nucleiargv allows: %v", err)
	}
}

// D-125 (3): an nmap sweep and a nuclei run are on the box at once, and a Stop of the nuclei run lands within 5 s: the long poll
// is woken, the worker kills nuclei's whole process group (its SIGTERM-ignoring child too), and the sweep is not touched.
func TestEndToEndStopLandsWithinFiveSecondsAndLeavesNoOrphan(t *testing.T) {
	t.Parallel()
	e := startE2E(t, workertest.Sleeper)
	nmapCtx, nmapCancel := context.WithCancel(t.Context())
	defer nmapCancel()
	nm := probe(nmapCtx, e.d, argvOf(t, nmapargv.Sweep, 10, "10.0.0.1"))

	ctx, stop := context.WithCancel(t.Context())
	ch := runNuclei(ctx, e.d, e.req())
	pid, child := e.nu.PID(t, "nuclei.pid"), e.nu.PID(t, "child.pid") // both slots are busy now
	notYet(t, nm, 100*time.Millisecond)

	start := time.Now()
	stop()
	got := awaitN(t, ch)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Stop took %v", d)
	}
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v", got.err)
	}
	waitFor(t, "the process group of nuclei to die", func() bool { return !e.nu.Alive(pid) && !e.nu.Alive(child) })
	notYet(t, nm, 100*time.Millisecond) // the sweep still runs
	nmapCancel()
	if got := await(t, nm); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("nmap: %v", got.err)
	}
}

// The worker's refusal of a pack it does not hold comes back as
// "scanner unavailable" with nothing run.
func TestEndToEndAnotherPackIsRefusedAndNothingRuns(t *testing.T) {
	t.Parallel()
	e := startE2E(t, "echo should-not-run")
	q := e.req()
	q.PackSHA256 = strings.Repeat("0", 64)
	_, err := e.d.RunNuclei(t.Context(), q)
	if !errors.Is(err, sa.ErrPackMismatch) || errors.Is(err, sa.ErrScannerUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if e.nu.Argv() != "" {
		t.Fatal("nuclei ran")
	}
}

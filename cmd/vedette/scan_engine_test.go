package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/worker"
	"github.com/knt048/vedette/modules/sensor-active/worker/workertest"
)

// S5: scan's Engine is the Dispatcher of sensor-active (scanEngine), over the real mutual-TLS link, to the real worker
// running a fake nuclei. Nothing reaches a network.

// s5Backend is the active half of the sensor link (sensorBackend without sensor-passive): the passive routes are refused.
type s5Backend struct{ *sensoractive.Dispatcher }

func (s5Backend) Config(context.Context, time.Duration, string) (sensorlink.ConfigReply, error) {
	return sensorlink.ConfigReply{}, sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (s5Backend) Observations(context.Context, *sensorlink.ObservationsRequest) (sensorlink.ObservationsReply, error) {
	return sensorlink.ObservationsReply{}, sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

func (s5Backend) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	return "", sensorlink.NewError(sensorlink.CodeForbiddenRoute)
}

// s5Inventory is one approved device in a confirmed scope; it records each consent asked.
type s5Inventory struct {
	mu    sync.Mutex
	asked int
}

var s5Device = scan.Device{ID: "a-1", Label: "NAS-1", IP: "192.168.10.20", Kind: "nas", Approved: true, Services: []scan.OpenPort{{Port: 8080, Name: "http"}}}

func (*s5Inventory) Scope(context.Context) (scan.Scope, error) {
	return scan.Scope{Networks: []string{"192.168.10.0/24"}, ConfirmedAt: "2026-11-01T00:00:00.000Z", ConfirmedBy: "it@acme.example"}, nil
}

func (*s5Inventory) Devices(context.Context) ([]scan.Device, error) {
	return []scan.Device{s5Device}, nil
}

func (i *s5Inventory) VulnScanPolicy(context.Context, string, bool) (scan.Decision, error) {
	i.mu.Lock()
	i.asked++
	i.mu.Unlock()
	return scan.Decision{Allowed: true, Reason: "ok", IP: s5Device.IP}, nil
}

// s5Findings holds one suspected finding of the device; it records each confirmation.
type s5Findings struct {
	mu        sync.Mutex
	confirmed []string
}

func (*s5Findings) List(_ context.Context, assetID string) ([]scan.FindingRef, error) {
	if assetID != "" && assetID != s5Device.ID {
		return nil, nil
	}
	return []scan.FindingRef{{ID: "f-1", AssetID: s5Device.ID, CVE: "CVE-2024-0001", Status: "suspected"}}, nil
}

func (f *s5Findings) ConfirmFromScan(_ context.Context, assetID, cve string, _ scan.Evidence) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirmed = append(f.confirmed, assetID+"|"+cve)
	return "f-1", nil
}

// orderEngine checks that a job reaches the scanner only after the device's consent was asked and its probe rows were
// written (INV-1, INV-7).
type orderEngine struct {
	scan.Engine
	t   *testing.T
	db  *store.DB
	inv *s5Inventory
}

func (o orderEngine) Run(ctx context.Context, j scan.Job) (nucleiout.Outcome, error) {
	var open int
	if err := o.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM scan_probe WHERE result IS NULL`).Scan(&open); err != nil {
		o.t.Error(err)
	}
	o.inv.mu.Lock()
	asked := o.inv.asked
	o.inv.mu.Unlock()
	if asked == 0 || open == 0 {
		o.t.Errorf("a job reached the scanner before its consent (%d asked) and its probe rows (%d open)", asked, open)
	}
	return o.Engine.Run(ctx, j)
}

type s5Env struct {
	svc *scan.Service
	fs  *s5Findings
}

// startS5 runs the worker with a fake nuclei that runs body, and a scan service whose engine is scanEngine over the
// Dispatcher. corePack, when set, changes the index core plans with (the worker keeps its own).
func startS5(t *testing.T, body string, corePack func([]byte) []byte) *s5Env {
	t.Helper()
	ctx := t.Context()
	d := sensoractive.NewDispatcher(sensoractive.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(t, s5Backend{d})
	nu := workertest.NewNuclei(t, body)
	pk := workertest.NewPack(t, "CVE-2024-1")
	nmapPath := filepath.Join(t.TempDir(), "nmap")
	exectest.WriteScript(t, nmapPath, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"Nmap version 7.94SVN ( https://nmap.org )\"; exit 0; fi\nexit 0\n")
	w, err := worker.New(worker.Config{
		Link: link.Client(t, sensorlink.Active), NmapPath: nmapPath, Version: "1.0.0", Wait: time.Second, Heartbeat: 500 * time.Millisecond,
		NucleiPath: nu.Path, NucleiIndex: pk.Index, NucleiHome: filepath.Join(t.TempDir(), "home"), TemplatesDir: pk.Dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(wctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the worker did not stop")
		}
	})
	raw, err := os.ReadFile(pk.Index)
	if err != nil {
		t.Fatal(err)
	}
	if corePack != nil {
		raw = corePack(raw)
	}
	ix, err := pack.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	inv, fs := &s5Inventory{}, &s5Findings{}
	svc, err := scan.NewService(scan.Config{DB: db, Audit: audit.New(nil), Inventory: inv, Findings: fs, Log: log, Pack: ix,
		Engine: orderEngine{Engine: scanEngine{d}, t: t, db: db, inv: inv}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for d.Ready(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatalf("the worker is not ready: %v", d.Ready(ctx))
		}
		waitTick(t)
	}
	return &s5Env{svc: svc, fs: fs}
}

// waitTick waits a little without time.Sleep (forbidigo).
func waitTick(t *testing.T) {
	t.Helper()
	tm := time.NewTimer(20 * time.Millisecond)
	defer tm.Stop()
	select {
	case <-tm.C:
	case <-t.Context().Done():
	}
}

// scanToEnd starts a scan of the device a person picked and returns the run once it has ended.
func (e *s5Env) scanToEnd(t *testing.T) scan.RunView {
	t.Helper()
	v, err := e.svc.StartRun(t.Context(), "it@acme.example", []string{s5Device.ID})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		got, err := e.svc.Run(t.Context(), v.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "running" && got.Status != "stopping" {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the run did not end: %+v", got)
		}
		waitTick(t)
	}
}

// A line nuclei prints for the device's template is a match, and only a match confirms the finding (INV-8).
func TestScanEngineAMatchConfirmsTheFinding(t *testing.T) {
	t.Parallel()
	e := startS5(t, `echo '{"template-id":"CVE-2024-1","host":"http://192.168.10.20:8080","matcher-status":true}'`, nil)
	got := e.scanToEnd(t)
	if got.Status != "done" || len(got.Results) != 1 || got.Results[0].Result != "matched" {
		t.Fatalf("run: %+v", got)
	}
	if e.fs.confirmed == nil || e.fs.confirmed[0] != "a-1|CVE-2024-0001" {
		t.Fatalf("confirmed: %v", e.fs.confirmed)
	}
}

// D-133 (5): nuclei prints matches only, so a run that prints nothing is "no match reported", never "not vulnerable",
// and it never touches the finding.
func TestScanEngineEmptyOutputIsOnlyNoMatchReported(t *testing.T) {
	t.Parallel()
	e := startS5(t, "true", nil)
	got := e.scanToEnd(t)
	if got.Status != "done" || len(got.Results) != 1 || got.Results[0].Result != "not_matched" || !strings.Contains(got.Results[0].Note, "no match reported") {
		t.Fatalf("run: %+v", got)
	}
	if len(e.fs.confirmed) != 0 {
		t.Fatalf("an empty output touched the finding: %v", e.fs.confirmed)
	}
}

// D-133 (4): core planned against another template pack than the image holds (the embedded index drifted): the
// Dispatcher refuses before anything is sent, and the run stops saying so instead of failing device by device.
func TestScanEngineAnotherPackStopsTheRun(t *testing.T) {
	t.Parallel()
	e := startS5(t, "echo should-not-run", func(raw []byte) []byte {
		return []byte(strings.Replace(string(raw), `"version":"2026.11.10"`, `"version":"2026.11.11"`, 1))
	})
	got := e.scanToEnd(t)
	if got.Status != "auto_stopped" || got.StopReason == nil || !strings.Contains(*got.StopReason, "template pack") {
		t.Fatalf("run: status %s, reason %v", got.Status, got.StopReason)
	}
	if len(e.fs.confirmed) != 0 {
		t.Fatalf("confirmed: %v", e.fs.confirmed)
	}
}

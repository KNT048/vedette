package core_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

type runsComposite struct {
	server.Fallback
	*core.RunHandlers
}

// newRunsStack serves the runs routes over a real run manager that is not started, so the runs it holds stay queued.
func newRunsStack(t *testing.T) (*stack, *run.Manager) {
	t.Helper()
	db := migrated(t)
	log := slog.New(slog.DiscardHandler)
	reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: "test", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	m, err := run.New(run.Config{DB: db, Audit: audit.New(nil), Gate: reg, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	noop := func(context.Context, *run.Exec) (run.Result, error) { return run.Result{}, nil }
	for _, k := range []run.Kind{
		{Module: "sensor-active", Name: "lan_sweep", Lane: "nmap", Resumable: true, AdminResume: true, Run: noop},
		{Module: "sensor-active", Name: "device_check", Lane: "checks", Run: noop},
	} {
		if err := m.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	s := &stack{t: t, db: db, reg: reg}
	s.h, err = server.New(server.Config{API: runsComposite{Fallback: server.Fallback{Log: log}, RunHandlers: core.NewRunHandlers(m)}, Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: reg, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

// The Runs tab and the run page answer with every engine's module off (core serves them); Stop and Resume are an operator's (Resume
// an administrator's for a kind whose start is),
// audited, and answer the run page; an ended run cannot be stopped and a run with no work left cannot be resumed.
func TestRuns_ListPageStopAndResume(t *testing.T) {
	t.Parallel()
	s, m := newRunsStack(t)
	turnOff(t, s, "sensor-passive", "sensor-active", "agent-intake", "scan", "exposure", "honeypot")
	sweep, err := m.Create(t.Context(), run.Spec{Module: "sensor-active", Kind: "lan_sweep", Title: "LAN sweep of 192.0.2.0/24", Trigger: run.Schedule, RequestedBy: run.System,
		Steps: []run.StepPlan{{Name: "192.0.2.0/24", Total: 256}}})
	if err != nil {
		t.Fatal(err)
	}
	check, err := m.Create(t.Context(), run.Spec{Module: "sensor-active", Kind: "device_check", Title: "Check 192.0.2.20", Trigger: run.Manual, RequestedBy: "admin@acme.example",
		Subject: &run.Subject{Kind: "device", ID: "a-printer", Label: "Office printer"}})
	if err != nil {
		t.Fatal(err)
	}

	code, list := s.call("GET", "/runs?limit=1", "viewer", "")
	if code != http.StatusOK || list["total"] != 2.0 || len(list["items"].([]any)) != 1 {
		t.Fatalf("GET /runs?limit=1 = %d %v", code, list)
	}
	if code, list = s.call("GET", "/runs?subject_kind=device&subject_id=a-printer", "viewer", ""); code != http.StatusOK || list["total"] != 1.0 {
		t.Fatalf("a device's runs = %d %v", code, list)
	}
	if code, list = s.call("GET", "/runs?status=queued&q=sweep", "viewer", ""); code != http.StatusOK || list["total"] != 1.0 {
		t.Fatalf("queued sweeps = %d %v", code, list)
	}
	code, page := s.call("GET", "/runs/"+sweep, "viewer", "")
	if code != http.StatusOK || page["status"] != "queued" || page["can_stop"] != false || page["total"] != 256.0 || len(page["steps"].([]any)) != 1 || page["summary"] == "" {
		t.Fatalf("run page for a viewer = %d %v (a viewer may not stop it)", code, page)
	}
	if code, page = s.call("GET", "/runs/"+sweep, "operator", ""); code != http.StatusOK || page["can_stop"] != true || page["can_resume"] != false {
		t.Fatalf("run page for an operator = %d %v", code, page)
	}
	if code, _ := s.call("GET", "/runs/run-unknown", "viewer", ""); code != http.StatusNotFound {
		t.Fatalf("unknown run = %d", code)
	}

	if code, _ := s.call("POST", "/runs/"+sweep+"/stop", "viewer", ""); code != http.StatusForbidden {
		t.Fatalf("a viewer's stop = %d, want 403", code)
	}
	code, page = s.call("POST", "/runs/"+sweep+"/stop", "operator", "")
	// the operator may not resume a sweep (an administrator's to start): the answer says so for the person asking
	if code != http.StatusOK || page["status"] != "stopped" || page["stop_reason"] != "Stopped by it@acme.example" || page["can_resume"] != false ||
		page["summary"] != "Stopped by it@acme.example; 0 of 256 done" {
		t.Fatalf("stop = %d %v", code, page)
	}
	if code, page = s.call("GET", "/runs/"+sweep, "admin", ""); code != http.StatusOK || page["can_resume"] != true {
		t.Fatalf("the stopped sweep for an administrator = %d %v", code, page)
	}
	if code, body := s.call("POST", "/runs/"+sweep+"/stop", "operator", ""); code != http.StatusConflict || body["error"].(map[string]any)["code"] != "not_running" {
		t.Fatalf("second stop = %d %v", code, body)
	}
	if code, _ := s.call("POST", "/runs/"+sweep+"/resume", "operator", ""); code != http.StatusForbidden {
		t.Fatalf("an operator's resume of a sweep only an admin starts = %d, want 403", code)
	}
	if code, page = s.call("POST", "/runs/"+sweep+"/resume", "admin", ""); code != http.StatusOK || page["status"] != "queued" {
		t.Fatalf("resume = %d %v", code, page)
	}
	// A device check cannot go on from where it stopped.
	if code, _ = s.call("POST", "/runs/"+check+"/stop", "admin", ""); code != http.StatusOK {
		t.Fatalf("stop of the check = %d", code)
	}
	if code, body := s.call("POST", "/runs/"+check+"/resume", "admin", ""); code != http.StatusConflict || body["error"].(map[string]any)["code"] != "not_resumable" {
		t.Fatalf("resume of a check = %d %v", code, body)
	}
	if n := count(t, s.db, `SELECT count(*) FROM core_audit WHERE action IN ('scanning.run_stop', 'scanning.run_resume')`); n != 3 {
		t.Errorf("audit rows of stop and resume = %d, want 3", n)
	}
}

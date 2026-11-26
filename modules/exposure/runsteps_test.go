package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/progress"
	corerun "github.com/knt048/vedette/core/run"
)

// runDetail reads run id as the run page does.
func (e *env) runDetail(ctx context.Context, id string) corerun.Detail {
	e.t.Helper()
	d, err := e.svc.cfg.Runs.Get(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

// newestScanRun is the newest scan's run.
func (e *env) newestScanRun() corerun.Detail {
	e.t.Helper()
	var id string
	if err := e.svc.cfg.DB.Reader().QueryRowContext(e.ctx(), `SELECT r.id FROM exp_scan x JOIN core_run r ON r.id = x.run_id ORDER BY r.queued_at DESC, r.rowid DESC LIMIT 1`).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return e.runDetail(e.ctx(), id)
}

type wantStep struct {
	name string
	st   corerun.Status
	note string // a part of the note; "" checks nothing
}

func checkSteps(t *testing.T, d corerun.Detail, want []wantStep) {
	t.Helper()
	if len(d.Steps) != len(want) {
		var got []string
		for _, s := range d.Steps {
			got = append(got, s.Name+" "+string(s.Status))
		}
		t.Fatalf("steps %q, want %d", got, len(want))
	}
	for i, w := range want {
		s := d.Steps[i]
		note := ""
		if s.Note != nil {
			note = *s.Note
		}
		if s.Name != w.name || s.Status != w.st || !strings.Contains(note, w.note) || s.EndedAt == nil {
			t.Errorf("step %d = %q %s %q (ended %v), want %q %s with %q", i+1, s.Name, s.Status, note, s.EndedAt, w.name, w.st, w.note)
		}
	}
}

func logOf(d corerun.Detail) string {
	var lines []string
	for _, l := range d.Log {
		lines = append(lines, l.Text)
	}
	return strings.Join(lines, "\n")
}

// The run page lists every step of a deep scan of an IP in the order it runs, each with how it ended and what it found; the run
// counts its steps, and its log has a line for each start and end.
func TestRunSteps_ADeepIPScanListsEveryStepInOrder(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	s := e.scanIP(gbOpen())
	d := e.runDetail(e.ctx(), s.RunID)
	checkSteps(t, d, []wantStep{
		{stepNameCheck, corerun.Done, "Deep scan"},
		{stepNameSurfaceIP, corerun.Done, "open of the commonly exposed ones"},
		{stepNamePortsDeep, corerun.Done, "1 open TCP port found"},
		{stepNameServiceDeep, corerun.Done, "Service identification (nmap -sV) on 98 TCP ports"},
		{stepNameNuclei, corerun.Done, "deep templates ran, 1 matched"},
		{stepNameZAP, corerun.Done, "ZAP scanned 1 page, 1 alert"},
		{stepNameZAPAct, corerun.Skipped, notActiveNoScanner},
		{stepNameSave, corerun.Done, "open service"},
		{stepNameOpenVAS, corerun.Done, "OpenVAS found 4 results"},
		{stepNameDisruptive, corerun.Skipped, notDisruptiveOff},
	})
	if d.Done != 10 || d.Total != 10 || d.Summary != "Done: 10 of 10 steps" {
		t.Errorf("run = %d of %d, %q", d.Done, d.Total, d.Summary)
	}
	log := logOf(d)
	for _, line := range []string{"Started: " + stepNameCheck, "Done: " + stepNamePortsDeep, "Started: " + stepNameOpenVAS, "Done: " + stepNameOpenVAS + " (", "OpenVAS found 4 results"} {
		if !strings.Contains(log, line) {
			t.Errorf("the log has no %q:\n%s", line, log)
		}
	}
}

// A step that does not run says why (skipped), and still counts: OpenVAS turned off, and service identification the scan container
// cannot run, which leaves the templates and ZAP nothing to check.
func TestRunSteps_ASkippedStepSaysWhy(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	if _, err := e.svc.SetGreenbone(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	e.svc.cfg.Services = &fakeServices{err: &Unavailable{Reason: "the Active discovery module is off."}}
	s := e.scanIP(gbOpen())
	d := e.runDetail(e.ctx(), s.RunID)
	off := "Service identification (nmap -sV) did not run: the Active discovery module is off."
	checkSteps(t, d, []wantStep{
		{stepNameCheck, corerun.Done, ""},
		{stepNameSurfaceIP, corerun.Done, ""},
		{stepNamePortsDeep, corerun.Skipped, off},
		{stepNameServiceDeep, corerun.Skipped, off},
		{stepNameNuclei, corerun.Skipped, "service identification"},
		{stepNameZAP, corerun.Skipped, "the web ports are not known"},
		{stepNameZAPAct, corerun.Skipped, "nothing to attack"},
		{stepNameSave, corerun.Done, ""},
		{stepNameOpenVAS, corerun.Skipped, notGBOff},
		{stepNameDisruptive, corerun.Skipped, notDisruptiveOff},
	})
	if d.Done != 10 {
		t.Errorf("a step skipped for a reason counts as done: %d of %d", d.Done, d.Total)
	}
	if !strings.Contains(logOf(d), "Skipped: "+stepNameOpenVAS+". "+notGBOff) {
		t.Errorf("log:\n%s", logOf(d))
	}
	if r, ok := e.engineRuns()[StepOpenVAS]; ok {
		t.Errorf("a skipped OpenVAS step is not a run of it: %+v", r)
	}
}

// A step that fails says why, and the steps after it are listed as not reached (not counted done).
func TestRunSteps_AFailedStepAndTheStepsNotReached(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	e.scanIP(gbOpen())
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{err: errors.New("the probe socket closed")})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", e.detectedID(ipA)); err == nil {
		t.Fatal("the scan did not fail")
	}
	d := e.newestScanRun()
	checkSteps(t, d, []wantStep{
		{stepNameCheck, corerun.Done, ""},
		{stepNameSurfaceIP, corerun.Failed, "error on the box"},
		{stepNamePortsDeep, corerun.Skipped, notReachedFailed},
		{stepNameServiceDeep, corerun.Skipped, notReachedFailed},
		{stepNameNuclei, corerun.Skipped, notReachedFailed},
		{stepNameZAP, corerun.Skipped, notReachedFailed},
		{stepNameZAPAct, corerun.Skipped, notReachedFailed},
		{stepNameSave, corerun.Skipped, notReachedFailed},
		{stepNameOpenVAS, corerun.Skipped, notReachedFailed},
		{stepNameDisruptive, corerun.Skipped, notReachedFailed},
	})
	if d.Done != 2 || d.Total != 10 || d.Status != corerun.Failed {
		t.Errorf("run = %s, %d of %d", d.Status, d.Done, d.Total)
	}
	if strings.Contains(*d.Steps[1].Note, "probe socket") {
		t.Errorf("the box's own error text reached the page: %q", *d.Steps[1].Note)
	}
	if !strings.Contains(logOf(d), "Failed: "+stepNameSurfaceIP) {
		t.Errorf("log:\n%s", logOf(d))
	}
}

// reportingServices reports nmap's phases while it runs, then lets the test look at the run before it answers.
type reportingServices struct {
	ServiceScanner
	during func(ctx context.Context)
}

func (r reportingServices) ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error) {
	r.during(ctx)
	return r.ServiceScanner.ScanServices(ctx, t, ip)
}

// Where a running step is, from the engines' progress reports, is its note; nmap's service phase ends the port discovery.
func TestRunSteps_ProgressIsTheNoteOfTheRunningStep(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	var mid corerun.Detail
	var midRun string
	e.svc.cfg.Services = reportingServices{ServiceScanner: e.svc.cfg.Services, during: func(ctx context.Context) {
		rs := runStepsOf(ctx)
		progress.Report(ctx, progress.Update{Phase: progress.PhasePorts, Percent: 41, Remaining: 9 * time.Minute})
		rs.flush(ctx)
		midRun = rs.x.ID()
		if RunIDOf(ctx) != midRun { // the probe log names the run
			t.Errorf("RunIDOf = %q, want %q", RunIDOf(ctx), midRun)
		}
		ports := e.runDetail(ctx, midRun)
		if st := ports.Steps[2]; st.Status != corerun.Running || st.Note == nil || *st.Note != "41%, about 9 minutes left" {
			t.Errorf("port discovery while it runs = %s %v", st.Status, st.Note)
		}
		progress.Report(ctx, progress.Update{Phase: progress.PhaseServices, Percent: 50})
		rs.flush(ctx)
		mid = e.runDetail(ctx, midRun)
	}}
	e.scanIP(gbOpen())
	if mid.Steps[2].Status != corerun.Done || mid.Steps[3].Status != corerun.Running || mid.Steps[3].Note == nil || *mid.Steps[3].Note != "reading service versions: 50%" {
		t.Errorf("after the service phase: ports %s, services %s %v", mid.Steps[2].Status, mid.Steps[3].Status, mid.Steps[3].Note)
	}
	if mid.Summary != "3 of 10 steps" {
		t.Errorf("summary while it runs = %q", mid.Summary)
	}
	if d := e.runDetail(e.ctx(), midRun); d.Steps[3].Note == nil || !strings.HasPrefix(*d.Steps[3].Note, "Service identification") {
		t.Errorf("the end replaces the live note: %v", d.Steps[3].Note)
	}
}

func TestLiveNote(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		u     progress.Update
		named bool
		want  string
	}{
		{progress.Update{Phase: progress.PhaseVulns, Percent: -1, Done: 1240, Total: 3600, Unit: progress.UnitChecks}, false, "1,240 of 3,600 template checks"},
		{progress.Update{Phase: progress.PhaseVulns, Percent: -1, Done: 1240, Total: 3600, Unit: progress.UnitChecks}, true, "1,240 of 3,600 template checks"},
		{progress.Update{Phase: progress.PhaseOpenVAS, Percent: 41}, false, "41%"},
		{progress.Update{Phase: progress.PhaseScripts, Percent: -1}, true, "running nmap's scripts"},
		{progress.Update{Phase: progress.PhasePorts, Percent: 140, Remaining: 90 * time.Hour}, true, "finding open ports"}, // out of range: left out
		{progress.Update{Phase: progress.PhasePorts, Percent: -1, Done: 9, Total: 3}, false, ""},
	} {
		if got := liveNote(tc.u, tc.named); got != tc.want {
			t.Errorf("liveNote(%+v, %v) = %q, want %q", tc.u, tc.named, got, tc.want)
		}
	}
}

// A domain's deep scan lists its name discovery, a step per address it scans (in the order it scans them), one step for the addresses
// its cap leaves for the next scans, then the rest of the plan.
func TestRunSteps_ADomainDeepScanListsItsAddresses(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	ips := []string{"9.9.9.1", "9.9.9.2", "9.9.9.3", "9.9.9.4", "9.9.9.5"}
	var hosts []HostRow
	for i, ip := range ips {
		name := fmt.Sprintf("h%d.acme.example", i+1)
		hosts = append(hosts, HostRow{Name: name, IP: ip, Source: "ct", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}})
		d.dns.point(name, ip)
	}
	d.run.content = Content{Hosts: hosts, Ports: []PortRow{}}
	s := d.scan()
	run := d.runDetail(d.ctx(), s.RunID)
	want := []wantStep{
		{stepNameCheck, corerun.Done, "Deep scan"},
		{stepNameSurfaceDom, corerun.Done, "5 names found, on 5 addresses."},
	}
	for i, ip := range ips[:3] {
		want = append(want, wantStep{fmt.Sprintf("Deep scan of %s (h%d.acme.example)", ip, i+1), corerun.Done, "Service identification"})
	}
	want = append(want, wantStep{stepNameWaiting, corerun.Skipped, "2 addresses wait for the next scans"},
		wantStep{stepNameNuclei, corerun.Done, ""}, wantStep{stepNameZAP, "", ""}, wantStep{stepNameZAPAct, corerun.Skipped, ""}, wantStep{stepNameSave, corerun.Done, ""},
		wantStep{stepNameOpenVAS, corerun.Skipped, ""}, wantStep{stepNameDisruptive, corerun.Skipped, ""})
	if len(run.Steps) == len(want) {
		want[len(want)-5].st = run.Steps[len(want)-5].Status // ZAP: whatever the pages gave, it ended
	}
	checkSteps(t, run, want)
	if run.Done != run.Total {
		t.Errorf("run = %d of %d steps", run.Done, run.Total)
	}
}

// In nmap's real phase order (the port scan, then the service scan, then its scripts) the port discovery ends when the service scan
// starts, before the count of open ports is known; it still ends with that count once nmap answers, its status and end time unchanged.
func TestRunSteps_PortDiscoveryEndsWithItsCountInNmapsPhaseOrder(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	var mid corerun.Detail
	var midRun string
	e.svc.cfg.Services = reportingServices{ServiceScanner: e.svc.cfg.Services, during: func(ctx context.Context) {
		rs := runStepsOf(ctx)
		midRun = rs.x.ID()
		for _, u := range []progress.Update{
			{Phase: progress.PhasePorts, Percent: 12, Remaining: 20 * time.Minute},
			{Phase: progress.PhasePorts, Percent: 99},
			{Phase: progress.PhaseServices, Percent: 10},
			{Phase: progress.PhaseServices, Percent: 80},
			{Phase: progress.PhaseScripts, Percent: 30},
		} {
			progress.Report(ctx, u)
			rs.flush(ctx)
		}
		mid = e.runDetail(ctx, midRun)
	}}
	e.scanIP(gbOpen())
	if p := mid.Steps[2]; p.Status != corerun.Done || p.EndedAt == nil {
		t.Fatalf("port discovery during the service scan = %s ended %v, want done", p.Status, p.EndedAt)
	}
	d := e.runDetail(e.ctx(), midRun)
	p := d.Steps[2]
	if p.Status != corerun.Done || p.Note == nil || !strings.Contains(*p.Note, "open TCP port") {
		t.Errorf("port discovery at the end = %s %v, want done with the count of open ports", p.Status, p.Note)
	}
	if p.EndedAt == nil || *p.EndedAt != *mid.Steps[2].EndedAt {
		t.Errorf("port discovery ended at %v, then %v: the count must not move its end", mid.Steps[2].EndedAt, p.EndedAt)
	}
	if s := d.Steps[3]; s.Status != corerun.Done || s.Note == nil || !strings.HasPrefix(*s.Note, "Service identification") {
		t.Errorf("service step at the end = %s %v", s.Status, s.Note)
	}
}

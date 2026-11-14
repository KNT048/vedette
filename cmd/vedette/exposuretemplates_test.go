package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The template scanner of exposure (INV-23, D-561, D-520) over fakes of the gate, the probe log and the Dispatcher: no process runs
// and no packet leaves. The pack is the committed index core plans with: CVE-2018-13379 and CVE-2019-19781 are read-only GETs it marks
// own_ip; CVE-2001-0537 (Cisco IOS exec/show/config through the URL) and CVE-2010-0738 (a HEAD with an action parameter) are in it
// but not marked (D-520).

type templatesFake struct {
	events  []string // in order: gate, log <ids>, run <ids>, done <id=result...>
	gateOK  bool
	logErr  error
	runErr  error
	runErrs map[int]error // by call number, after runErr
	block   int           // this call (1-based) waits for its context to end
	answer  func(r sensoractive.NucleiRequest) nucleiout.Outcome
	reqs    []sensoractive.NucleiRequest
	actor   string
	done    []scan.ExternalProbe // the rows of the last completing write
}

func (f *templatesFake) scanner() exposureTemplateScan {
	return exposureTemplateScan{
		pack: nucleipack.Index,
		gate: func(_ context.Context, actor string, _ netip.Addr) (bool, error) {
			f.events, f.actor = append(f.events, "gate"), actor
			return f.gateOK, nil
		},
		probes: func(_ context.Context, ps []scan.ExternalProbe) error {
			if f.logErr != nil {
				return f.logErr
			}
			var b strings.Builder
			for _, p := range ps {
				if p.Result == "" && !strings.HasPrefix(f.last(), "run") {
					fmt.Fprintf(&b, " %s", p.Template)
					if p.IP != ownPublicIP.String() || !strings.HasPrefix(p.Request, "nuclei "+p.Template+" to http://8.8.8.8:18443 ") {
						f.events = append(f.events, "bad row "+p.Request)
					}
				} else {
					fmt.Fprintf(&b, " %s=%s", p.Template, p.Result)
				}
			}
			kind := "log"
			if strings.HasPrefix(f.last(), "run") {
				kind, f.done = "done", ps
			}
			f.events = append(f.events, kind+b.String())
			return nil
		},
		run: func(ctx context.Context, r sensoractive.NucleiRequest) (nucleiout.Outcome, error) {
			f.reqs = append(f.reqs, r)
			f.events = append(f.events, "run "+strings.Join(r.Templates, " "))
			if len(f.reqs) == f.block {
				<-ctx.Done()
				return nucleiout.Outcome{}, ctx.Err()
			}
			if err := f.runErrs[len(f.reqs)]; err != nil {
				return nucleiout.Outcome{}, err
			}
			if f.runErr != nil {
				return nucleiout.Outcome{}, f.runErr
			}
			return f.answer(r), nil
		},
		log: slog.New(slog.DiscardHandler),
	}
}

func (f *templatesFake) last() string {
	if len(f.events) == 0 {
		return ""
	}
	return f.events[len(f.events)-1]
}

func ownJob(cves ...string) exposure.TemplateJob {
	return exposure.TemplateJob{Port: 18443, Scheme: "http", Host: ownPublicIP.String(), CVEs: cves, Scope: exposure.ScopeOwnIP, RPS: exposure.TemplateRPS}
}

// Obligations (1) to (3): the gate with the actor, then the probe rows with the real template ids, then the job (scope own_ip, one
// public target, 5 a second, the pack's templates of the CVEs only), then the results with their CVE and the rows completed.
func TestExposureTemplatesLogBeforeSendingAndMapResults(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome {
		return nucleiout.Outcome{Results: []nucleiout.Result{
			{Template: "CVE-2018-13379", Target: "8.8.8.8:18443", Matched: true},
			{Template: "CVE-2019-19781", Target: "8.8.8.8:18443"},
		}}
	}}
	got, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{User: "u-admin"}, ownPublicIP,
		[]exposure.TemplateJob{ownJob("CVE-2018-13379", "CVE-2019-19781", "CVE-2001-0537", "CVE-2010-0738", "CVE-2099-0001")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gate", "log CVE-2018-13379 CVE-2019-19781", "run CVE-2018-13379 CVE-2019-19781", "done CVE-2018-13379=matched CVE-2019-19781=not_matched"}
	if !slices.Equal(f.events, want) || f.actor != "u-admin" {
		t.Fatalf("events %q actor %q", f.events, f.actor)
	}
	r := f.reqs[0]
	if r.Scope != nucleiargv.ScopeOwnIP || r.Rate != nucleiargv.OwnIPRate || len(r.Targets) != 1 || r.Targets[0] != (nucleiargv.Target{Host: "8.8.8.8", Port: 18443, Scheme: "http"}) || r.PackSHA256 == "" {
		t.Fatalf("request %+v", r)
	}
	wantRes := []exposure.TemplateResult{
		{Port: 18443, Template: "CVE-2018-13379", CVE: "CVE-2018-13379", Outcome: exposure.OutcomeMatched},
		{Port: 18443, Template: "CVE-2019-19781", CVE: "CVE-2019-19781", Outcome: exposure.OutcomeNoMatch},
	}
	notes := []string{"Safe templates for exploited vulnerabilities: CVE-2001-0537, CVE-2010-0738 on port 18443: not run on a public IP: this check is not a read-only request."}
	if !slices.Equal(got.Results, wantRes) || !slices.Equal(got.Sent, []string{"CVE-2018-13379", "CVE-2019-19781"}) || !slices.Equal(got.NotChecked, notes) {
		t.Fatalf("scan %+v", got)
	}
}

// N44-4, review r1 M1: with -ms nuclei prints a line for every template it runs, so a template a finished run printed nothing for was
// not run: its probe row says "Not run" (and is not "No match reported") and a "Not checked" line counts it. A
// template that failed because the address stopped answering is an error, not "not run".
func TestExposureTemplatesSilentTemplateIsNotRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		hostErrors []nucleiout.HostError
		notRun     bool
	}{
		{nil, true},
		{[]nucleiout.HostError{{Target: "8.8.8.8:18443", Errors: 3, Unreachable: true}}, false},
	} {
		f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome {
			return nucleiout.Outcome{Results: []nucleiout.Result{{Template: "CVE-2018-13379", Target: "8.8.8.8:18443", Matched: true}}, HostErrors: tc.hostErrors}
		}}
		got, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{User: "u-admin"}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379", "CVE-2019-19781")})
		if err != nil {
			t.Fatal(err)
		}
		if f.last() != "done CVE-2018-13379=matched CVE-2019-19781=" || len(f.done) != 2 { // "" is written as no_response
			t.Fatalf("host errors %v: events %q", tc.hostErrors, f.events)
		}
		line := "Safe templates for exploited vulnerabilities on port 18443: nuclei printed no result for 1 of 2, so they did not run (CVE-2019-19781)."
		if tc.notRun != strings.HasPrefix(f.done[1].Request, notRunRequest) || tc.notRun != slices.Contains(got.NotChecked, line) ||
			len(got.Sent) != 2 || strings.HasPrefix(f.done[0].Request, notRunRequest) {
			t.Fatalf("host errors %v: rows %+v, scan %+v", tc.hostErrors, f.done, got)
		}
	}
}

// The gate says no right before the run: nothing is logged or sent, and the page says why.
func TestExposureTemplatesGateRefusesBeforeAnything(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: false}
	_, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{User: "u"}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")})
	var un *exposure.Unavailable
	if !errors.As(err, &un) || !strings.Contains(un.Reason, "no longer reaches the Internet through 8.8.8.8") || !slices.Equal(f.events, []string{"gate"}) {
		t.Fatalf("%v %q", err, f.events)
	}
}

// What the Dispatcher says becomes a sentence of the page; the worker's own-IP fence is told apart from an older worker.
func TestExposureTemplatesUnavailableReasons(t *testing.T) {
	t.Parallel()
	for in, want := range map[error]string{
		fmt.Errorf("%w (not_own_ip): %w", sensoractive.ErrWorkerRefused, sensoractive.ErrNotOwnIP):                "no longer reaches the Internet through 8.8.8.8",
		fmt.Errorf("%w (egress_unverified): %w", sensoractive.ErrWorkerRefused, sensoractive.ErrEgressUnverified): "could not reach the public IP services",
		sensoractive.ErrOwnIPUnsupported:      "older than the rest of Vedette and cannot run them",
		sensoractive.ErrNucleiBusy:            "busy",
		sensoractive.ErrScanWorkerUnavailable: "not available",
		sensoractive.ErrPackMismatch:          "another template pack",
	} {
		f := &templatesFake{gateOK: true, runErr: in}
		_, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")})
		var un *exposure.Unavailable
		if !errors.As(err, &un) || !strings.Contains(un.Reason, want) {
			t.Errorf("%v: %v", in, err)
		}
	}
}

// A template without a line on an address that stopped answering is an error, never a "no match"; a CVE whose template the pack
// does not mark own_ip, or that has none, is not sent at all, and the first gets its "not a read-only request" line.
func TestExposureTemplatesOutcomes(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome {
		return nucleiout.Outcome{HostErrors: []nucleiout.HostError{{Target: "8.8.8.8:18443", Errors: 3, Unreachable: true}}}
	}}
	got, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")})
	if err != nil || len(got.Results) != 1 || got.Results[0].Outcome != exposure.OutcomeError {
		t.Fatalf("%+v %v", got, err)
	}
	f = &templatesFake{gateOK: true}
	got, err = f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2010-0738", "CVE-2001-0537", "CVE-2099-0001")})
	if err != nil || len(got.Results)+len(got.Sent) != 0 || len(f.events) != 0 || len(got.NotChecked) != 1 || !strings.Contains(got.NotChecked[0], "CVE-2010-0738, CVE-2001-0537 on port") {
		t.Fatalf("%+v %v %q", got, err, f.events)
	}
}

// D-520 end to end through the production builder (exposureTemplatesFor: the module switch, the pack index, the Dispatcher, the scan
// module's probe log) with a fake worker that says own_ip over the real mutual-TLS link: the job is scope own_ip on the one address
// and port, the probe log holds a row per template id with its outcome, and CVE-2018-13379 comes back matched.
func TestExposureTemplatesEndToEndWithAFakeWorker(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	c := linktest.New(t, sensorBackend{s.d.SensorPassive, s.d.SensorDispatcher}).Client(t, sensorlink.Active)
	ctx, cancel := context.WithCancel(t.Context())
	jobs := make(chan sensorlink.Job, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.94"},
				Nuclei: sensorlink.HeartbeatNuclei{Present: true, Version: "v3.11.1", Pack: sensorlink.HeartbeatPack{Version: ix.Version, SHA256: ix.SHA256}, OwnIP: true}}
			if _, err := c.ActiveHeartbeat(ctx, hb); err != nil {
				return
			}
			rep, err := c.Jobs(ctx, nil, time.Second)
			if err != nil {
				return
			}
			for _, j := range rep.Jobs {
				jobs <- j
				res := &sensorlink.JobResult{Status: "done"}
				res.SetJSONL([]byte(`{"template-id":"CVE-2018-13379","host":"8.8.8.8","port":"18443","matcher-status":true}` + "\n" +
					`{"template-id":"CVE-2019-19781","host":"8.8.8.8","port":"18443","matcher-status":false}` + "\n"))
				_ = c.PostResult(ctx, j.ID, res)
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(20 * time.Second); s.d.SensorDispatcher.NucleiHealth() != ""; waitTick(t) {
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat from the fake worker")
		}
	}
	g := &gateFor{ok: true}
	got, err := exposureTemplatesFor(*s.d, g.gate, nil).ScanTemplates(t.Context(), exposure.ScanTarget{User: "ops@acme.example"}, ownPublicIP,
		[]exposure.TemplateJob{ownJob("CVE-2018-13379", "CVE-2019-19781")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 || got.Results[0].Outcome != exposure.OutcomeMatched || got.Results[0].CVE != "CVE-2018-13379" || len(got.Sent) != 2 {
		t.Fatalf("scan %+v", got)
	}
	j := <-jobs
	if n := j.Nuclei; n == nil || n.Scope != "own_ip" || n.Rate != 5 || len(n.Targets) != 1 || n.Targets[0] != (sensorlink.NucleiTarget{Host: "8.8.8.8", Port: 18443, Scheme: "http"}) {
		t.Fatalf("job %+v", j)
	}
	rows, err := scanService(*s.d).Probes(t.Context())
	results := map[string]string{}
	for _, r := range rows {
		results[r.Template] = r.Result
	}
	if err != nil || results["CVE-2018-13379"] != "matched" || results["CVE-2019-19781"] != "not_matched" || len(g.actors) != 1 || g.actors[0] != "ops@acme.example" {
		t.Fatalf("probe log %v %v, gate asked as %v", results, err, g.actors)
	}
}

// Review M2 and L2: when exposure's 5 minutes run out in a later run, or a later run fails, the results of the earlier runs are kept
// (the probe log holds them as matched) and the page says why the rest has none; a stop of the scan still drops the step.
func TestExposureTemplatesLaterRunsDoNotLoseEarlierResults(t *testing.T) {
	t.Parallel()
	answer := func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		return nucleiout.Outcome{Results: []nucleiout.Result{{Template: r.Templates[0], Target: fmt.Sprintf("8.8.8.8:%d", r.Targets[0].Port), Matched: true}}}
	}
	jobs := []exposure.TemplateJob{ownJob("CVE-2018-13379"), ownJob("CVE-2019-19781")}
	jobs[1].Port = 18444
	synctest.Test(t, func(t *testing.T) {
		f := &templatesFake{gateOK: true, answer: answer, block: 2}
		ctx, cancel := context.WithTimeout(t.Context(), exposure.TemplatesTimeout)
		defer cancel()
		got, err := f.scanner().ScanTemplates(ctx, exposure.ScanTarget{}, ownPublicIP, jobs)
		if err != nil || len(got.Results) != 1 || got.Results[0].Outcome != exposure.OutcomeMatched || len(got.NotChecked) != 1 ||
			!strings.Contains(got.NotChecked[0], "did not finish within 5 minutes") || !strings.Contains(got.NotChecked[0], "CVE-2019-19781") {
			t.Fatalf("timeout: %+v %v", got, err)
		}
	})
	f := &templatesFake{gateOK: true, answer: answer, runErrs: map[int]error{2: sensoractive.ErrNucleiBusy}}
	got, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{}, ownPublicIP, jobs)
	if err != nil || len(got.Results) != 1 || len(got.NotChecked) != 1 || !strings.Contains(got.NotChecked[0], "on port 18444 did not run: the scan container's nuclei was busy") {
		t.Fatalf("failure: %+v %v", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	f = &templatesFake{gateOK: true, answer: answer, block: 2}
	go cancel()
	if _, err := f.scanner().ScanTemplates(ctx, exposure.ScanTarget{}, ownPublicIP, jobs); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: %v", err)
	}
}

// Review L5: the probe log cannot be written, so nothing is sent and the page says why.
func TestExposureTemplatesNothingSentWithoutTheProbeLog(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, logErr: errors.New("disk full")}
	_, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")})
	var un *exposure.Unavailable
	if !errors.As(err, &un) || un.Reason != templatesNoLog || len(f.reqs) != 0 {
		t.Fatalf("%v, %d runs", err, len(f.reqs))
	}
}

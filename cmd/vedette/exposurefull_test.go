package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// FULL-4 (D-527): the deep scan of a target whose testing terms are accepted, over the fakes of exposuretemplates_test.go and the
// committed pack. No process runs and no packet leaves.

func fullTarget(disruptive bool) exposure.ScanTarget {
	return exposure.ScanTarget{ID: "t-1", User: "u-admin", Mode: exposure.ScanMode{Full: true, Disruptive: disruptive}}
}

func fullJobOf(cves ...string) exposure.TemplateJob {
	return exposure.TemplateJob{Port: 18443, Scheme: "http", Host: ownPublicIP.String(), CVEs: cves, Scope: exposure.ScopeOwnIP, RPS: exposure.FullTemplateRPS,
		Depth: exposure.DepthFull, Service: "http", Product: "Apache httpd", CPE: "cpe:/a:apache:http_server:2.4.49"}
}

// modes answers ModeNow from a list, one per call (the last repeats), and counts the calls.
type modes struct {
	list  []exposure.ScanMode
	calls int
}

func (m *modes) now(context.Context, string, string) (exposure.ScanMode, error) {
	m.calls++
	return m.list[min(m.calls, len(m.list))-1], nil
}

// Tech first, then what it found: the first runs hold only technologies templates; a match of nginx-version (and the -sV product
// apache) bring in the nginx and apache templates, the generic ones (git-config) and the KEV template of the port's CVE; every run
// is full at 20 a second, at most 200 templates, logged before it is sent, and no technologies template runs twice.
func TestExposureFullTechTagsChooseTheTemplates(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		var o nucleiout.Outcome
		for _, id := range r.Templates {
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443", Matched: id == "nginx-version" || id == "git-config", MatcherName: "nginx"})
		}
		return o
	}}
	m := &modes{list: []exposure.ScanMode{{Full: true}}}
	a := f.scanner()
	a.mode = m.now
	got, err := a.ScanTemplates(t.Context(), fullTarget(false), ownPublicIP, []exposure.TemplateJob{fullJobOf("CVE-2021-41773")})
	if err != nil {
		t.Fatal(err)
	}
	techDone, sawTech := false, map[string]bool{}
	var later []string
	for _, r := range f.reqs {
		if r.Depth != nucleiargv.DepthFull || r.Rate != nucleiargv.FullRate || r.Disruptive || len(r.Templates) > nucleiargv.MaxFullTemplates || r.Scope != nucleiargv.ScopeOwnIP {
			t.Fatalf("request %+v", r)
		}
		for _, id := range r.Templates {
			tp, _ := ix.Get(id)
			switch {
			case tp.Tech() && techDone:
				t.Fatalf("technologies template %s after the selection started", id)
			case tp.Tech():
				if sawTech[id] {
					t.Fatalf("%s ran twice", id)
				}
				sawTech[id] = true
			default:
				techDone = true
				later = append(later, id)
			}
			if !tp.RunsAt(true, false) {
				t.Fatalf("%s is not in a set a full job without the tick may run", id)
			}
		}
	}
	for _, want := range []string{"git-config", "CVE-2021-41773"} {
		if !slices.Contains(later, want) {
			t.Errorf("%s not chosen", want)
		}
	}
	nginx, apache := 0, 0
	for _, id := range later {
		tp, _ := ix.Get(id)
		nginx += boolInt(slices.Contains(tp.Tags, "nginx"))
		apache += boolInt(slices.Contains(tp.Tags, "apache"))
	}
	if nginx == 0 || apache == 0 || len(sawTech) < 800 {
		t.Errorf("nginx %d, apache %d templates chosen after %d technologies templates", nginx, apache, len(sawTech))
	}
	// each run: ModeNow, then the gate, then its probe rows, then the job
	for i, e := range f.events {
		if strings.HasPrefix(e, "run ") && (i < 2 || f.events[i-1] != "log"+strings.TrimPrefix(e, "run") || f.events[i-2] != "gate") {
			t.Fatalf("event %d %.60q is not after its gate and its probe rows", i, e)
		}
	}
	if m.calls != len(f.reqs)+1 {
		t.Errorf("ModeNow read %d times for %d runs", m.calls, len(f.reqs))
	}
	var deep exposure.TemplateResult
	for _, r := range got.Results {
		if r.Template == "git-config" {
			deep = r
		}
	}
	if deep.Outcome != exposure.OutcomeMatched || deep.CVE != "" || deep.Name == "" || deep.Severity == "" {
		t.Errorf("the deep result of git-config: %+v", deep)
	}
}

// exposure sizes its bound with the full rate of nucleiargv (it may not import it).
func TestExposureFullRateIsTheGrammarsRate(t *testing.T) {
	t.Parallel()
	if exposure.FullTemplateRPS != nucleiargv.FullRate || exposure.DepthFull != nucleiargv.DepthFull {
		t.Fatalf("exposure %d %q, nucleiargv %d %q", exposure.FullTemplateRPS, exposure.DepthFull, nucleiargv.FullRate, nucleiargv.DepthFull)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// The terms withdrawn before the first run: nothing is logged or sent, and exposure gets the reason. Withdrawn between two runs: the
// runs before are kept and the page says why the rest was not sent.
func TestExposureFullModeNowNotFullSendsNothing(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	a := f.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{{}}}).now
	_, err := a.ScanTemplates(t.Context(), fullTarget(false), ownPublicIP, []exposure.TemplateJob{fullJobOf()})
	var un *exposure.Unavailable
	if !errors.As(err, &un) || un.Reason != templatesNotFull || len(f.events) != 0 {
		t.Fatalf("err %v, events %q", err, f.events)
	}
	f2 := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	a = f2.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{{Full: true}, {Full: true}, {}}}).now
	got, err := a.ScanTemplates(t.Context(), fullTarget(false), ownPublicIP, []exposure.TemplateJob{fullJobOf()})
	if err != nil || len(f2.reqs) != 1 || len(got.Sent) != len(f2.reqs[0].Templates) || len(got.NotChecked) != 1 || !strings.Contains(got.NotChecked[0], templatesNotFull) {
		t.Fatalf("got %+v, %d runs, %v", got.NotChecked, len(f2.reqs), err)
	}
}

// The tick taken back during the scan: no disruptive template and no disruptive job from then on; with the tick, they run.
func TestExposureFullDisruptiveOnlyWhileTicked(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	disruptive := func(reqs []sensoractive.NucleiRequest) (jobs, tmpls int) {
		for _, r := range reqs {
			jobs += boolInt(r.Disruptive)
			for _, id := range r.Templates {
				tp, _ := ix.Get(id)
				tmpls += boolInt(tp.FullSet() == pack.SetDisruptive)
			}
		}
		return jobs, tmpls
	}
	answer := func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		var o nucleiout.Outcome
		for _, id := range r.Templates {
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443", Matched: id == "wordpress-detect"})
		}
		return o
	}
	ticked := &templatesFake{gateOK: true, answer: answer}
	a := ticked.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{{Full: true, Disruptive: true}}}).now
	if _, err := a.ScanTemplates(t.Context(), fullTarget(true), ownPublicIP, []exposure.TemplateJob{fullJobOf()}); err != nil {
		t.Fatal(err)
	}
	if j, n := disruptive(ticked.reqs); j == 0 || n == 0 {
		t.Fatalf("with the tick: %d disruptive jobs, %d disruptive templates (wordpress-detect and the -sV product apache bring in their default logins)", j, n)
	}
	dropped := &templatesFake{gateOK: true, answer: answer}
	a = dropped.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{{Full: true, Disruptive: true}, {Full: true}}}).now
	if _, err := a.ScanTemplates(t.Context(), fullTarget(true), ownPublicIP, []exposure.TemplateJob{fullJobOf()}); err != nil {
		t.Fatal(err)
	}
	if j, n := disruptive(dropped.reqs); j != 0 || n != 0 {
		t.Fatalf("tick taken back: %d disruptive jobs, %d disruptive templates", j, n)
	}
}

// A port that is not web runs the network templates of its service, never an http one.
func TestExposureFullOtherPortRunsItsNetworkTemplates(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	a := f.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{{Full: true}}}).now
	j := fullJobOf()
	j.Scheme, j.Service, j.Product, j.CPE = "", "ssh", "OpenSSH", ""
	if _, err := a.ScanTemplates(t.Context(), fullTarget(false), ownPublicIP, []exposure.TemplateJob{j}); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) == 0 {
		t.Fatal("no network template ran on an ssh port")
	}
	for _, r := range f.reqs {
		for _, id := range r.Templates {
			if tp, _ := ix.Get(id); !strings.HasPrefix(tp.Path, "network/") {
				t.Errorf("%s (%s) on an ssh port", id, tp.Path)
			}
		}
	}
}

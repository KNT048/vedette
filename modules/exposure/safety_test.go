package exposure

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fakeSafety is the ScanSafety seam: the shared safety block of Settings › Scanning as cmd/vedette hands it over (#850).
type fakeSafety struct {
	s   Safety
	err error
}

func (f *fakeSafety) ScanSafety(context.Context) (Safety, error) { return f.s, f.err }

func prefixes(t *testing.T, v ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, x := range v {
		if !strings.Contains(x, "/") {
			x += "/32"
		}
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

// INV-31: the shared speed only lowers the rate of the template jobs (and the probe log says the rate that was asked), never raises it.
func TestContract_INV30_SharedSpeedLowersTheTemplateRate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ ceiling, want int }{{2, 2}, {20, TemplateRPS}, {0, TemplateRPS}} {
		e, f := tplEnv(t)
		e.svc.cfg.Safety = &fakeSafety{s: Safety{RPS: tc.ceiling}}
		e.scanIP(Content{})
		if len(f.jobs) != 1 || f.jobs[0][0].RPS != tc.want {
			t.Fatalf("ceiling %d: jobs = %+v, want rate %d", tc.ceiling, f.jobs, tc.want)
		}
		if !strings.Contains(f.log.rows[0].Request, "at most "+strconv.Itoa(tc.want)+" requests a second") {
			t.Fatalf("ceiling %d: probe row = %q", tc.ceiling, f.log.rows[0].Request)
		}
	}
}

// INV-31: an IP target on the shared exclusion list is refused before anything is sent (400 out_of_scope, as the LAN's Scan now),
// the refusal is audited; a list that cannot be read refuses every scan (503), nothing is sent either.
func TestContract_INV30_ExcludedIPIsNotScanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	run := &fakeRunner{}
	e.svc.SetRunner(run)
	e.svc.cfg.Safety = &fakeSafety{s: Safety{Exclusions: prefixes(t, "198.51.100.0/24", ipA)}}
	_, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	wantAPI(t, err, 400, "out_of_scope")
	if !strings.Contains(err.Error(), "exclusion list under Settings, Scanning, Safety") || run.calls != 0 {
		t.Fatalf("err = %v, runner calls = %d", err, run.calls)
	}
	if !slices.ContainsFunc(e.audits(), func(a auditRow) bool {
		return a.Action == "exposure.scan" && strings.Contains(a.Detail, "out_of_scope")
	}) {
		t.Fatalf("audits = %+v", e.audits())
	}
	e.svc.cfg.Safety = &fakeSafety{err: errors.New("scan config unreadable")}
	_, err = e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	wantAPI(t, err, 503, "scanner_unavailable")
	if run.calls != 0 {
		t.Fatalf("runner calls = %d", run.calls)
	}
	e.svc.cfg.Safety = &fakeSafety{s: Safety{Exclusions: prefixes(t, "198.51.100.7")}} // another address: scanned as before
	if _, err = e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err != nil || run.calls != 1 {
		t.Fatalf("err = %v, runner calls = %d", err, run.calls)
	}
}

// INV-31: a domain's address on the exclusion list gets nothing in its deep scan and says why; the others go on.
func TestContract_INV30_DeepScanSkipsExcludedAddresses(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.svc.cfg.Safety = &fakeSafety{s: Safety{Exclusions: prefixes(t, ipB)}}
	d.acceptTerms(d.dom.ID, false)
	s := d.scan()
	if slices.Contains(d.seams.serviceIPs(), ipB) || len(d.seams.serviceIPs()) == 0 {
		t.Fatalf("services asked for %v", d.seams.serviceIPs())
	}
	if deepOf(s, ipB).Deep != DeepRefused || !hasLine(s, "is on the exclusion list under Settings, Scanning, Safety, so nothing was sent to it.") {
		t.Fatalf("ipB = %+v, lines = %+v", deepOf(s, ipB), s.NotChecked)
	}
}

// INV-31: a domain target without terms, the box's own IP and another address excluded: nothing goes to either (no ZAP page,
// no service identification), each excluded address is said once; ScannableIP answers false for an excluded address.
func TestContract_INV30_DomainSkipsExcludedAddresses(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.Safety = &fakeSafety{s: Safety{Exclusions: prefixes(t, ipA, ipB)}}
	s := d.scan()
	d.seams.mu.Lock()
	for _, p := range d.seams.pages {
		if p.IP.String() == ipA || p.IP.String() == ipB {
			t.Errorf("ZAP baseline sent to excluded %s (%s)", p.IP, p.URL)
		}
	}
	for _, c := range d.seams.services {
		if c.ip == ipA || c.ip == ipB {
			t.Errorf("nmap -sV sent to excluded %s", c.ip)
		}
	}
	d.seams.mu.Unlock()
	if !hasLine(s, ipB+" is on the exclusion list under Settings, Scanning, Safety, so nothing was sent to it.") {
		t.Fatalf("lines = %+v", s.NotChecked)
	}
	ok, err := d.svc.ScannableIP(d.ctx(), "admin@acme.example", netip.MustParseAddr(ipA))
	if err != nil || ok {
		t.Fatalf("ScannableIP(excluded box IP) = %v, %v", ok, err)
	}
	d.svc.cfg.Safety = &fakeSafety{}
	if ok, err = d.svc.ScannableIP(d.ctx(), "admin@acme.example", netip.MustParseAddr(ipA)); err != nil || !ok {
		t.Fatalf("ScannableIP(box IP, no exclusion) = %v, %v", ok, err)
	}
}

// INV-31: while the shared block cannot be read, a domain's scan is refused before anything is sent (503).
func TestContract_INV30_DomainUnreadableBlockSendsNothing(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.Safety = &fakeSafety{err: errors.New("down")}
	_, err := d.svc.Scan(d.ctx(), "admin@acme.example", d.dom.ID)
	wantAPI(t, err, 503, "scanner_unavailable")
	d.seams.mu.Lock()
	defer d.seams.mu.Unlock()
	if d.run.calls > 0 || len(d.seams.pages) > 0 || len(d.seams.services) > 0 {
		t.Errorf("block unreadable but sent: runner=%d services=%d pages=%d", d.run.calls, len(d.seams.services), len(d.seams.pages))
	}
	if ok, _ := d.svc.ScannableIP(d.ctx(), "admin@acme.example", netip.MustParseAddr(ipA)); ok {
		t.Fatal("ScannableIP true while the block cannot be read")
	}
}

// INV-31: a Full-depth job is lowered too; an address excluded after the scan started gets no templates.
func TestContract_INV30_FullJobsLoweredAndLateExclusion(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	on := true
	e.terms = &on
	e.svc.cfg.Safety = &fakeSafety{s: Safety{RPS: 3}}
	e.scanIP(Content{})
	if len(f.jobs) != 1 || len(f.jobs[0]) == 0 {
		t.Fatalf("jobs = %+v", f.jobs)
	}
	for _, j := range f.jobs[0] {
		if j.Depth != DepthFull || j.RPS != 3 {
			t.Fatalf("full job = %+v", j)
		}
	}
	e2, f2 := tplEnv(t)
	late := &lateSafety{}
	e2.svc.cfg.Safety = late
	s := e2.scanIP(Content{})
	if len(f2.jobs) != 0 || !hasLine(s, ipA+" is on the exclusion list") {
		t.Fatalf("jobs = %+v, lines = %+v", f2.jobs, s.NotChecked)
	}
}

// lateSafety excludes ipA from its second read on: the start of the scan passes, the template step sees the exclusion.
type lateSafety struct{ reads int }

func (l *lateSafety) ScanSafety(context.Context) (Safety, error) {
	l.reads++
	if l.reads <= 2 { // the checks when the scan is asked and right before it starts
		return Safety{}, nil
	}
	return Safety{Exclusions: []netip.Prefix{netip.MustParsePrefix(ipA + "/32")}}, nil
}

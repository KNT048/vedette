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

// INV-30: the shared speed only lowers the rate of the template jobs (and the probe log says the rate that was asked), never raises it.
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

// INV-30: an IP target on the shared exclusion list is refused before anything is sent (400 out_of_scope, as the LAN's Scan now),
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

// INV-30, D-571: a domain's address on the exclusion list gets nothing in its deep scan and says why; the others go on.
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

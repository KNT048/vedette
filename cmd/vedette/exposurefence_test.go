package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A deep step of exposure that carries ScanTarget.Domain goes out as a domain_ip job (nmap, nuclei) with the
// scope's fields and the CNAME chain in the probe log, never through the box's own-IP gate; the worker's refusals become lines.

var testScope = &exposure.DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: strings.Repeat("ab", 8), Chain: "www.acme.example -> acme.edge.example.net"}

func domainTarget(full bool) exposure.ScanTarget {
	return exposure.ScanTarget{ID: "t-1", Kind: exposure.KindDomain, Value: "acme.example", User: "u-admin", Mode: exposure.ScanMode{Full: full}, Domain: testScope}
}

func TestDomainServicesGoOutAsADomainIPJob(t *testing.T) {
	t.Parallel()
	var got sensoractive.DomainIP
	var kind nmapargv.Kind
	a := exposureServiceScan{
		scan: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.DeepSettings, sensoractive.OwnEgress) (sensoractive.External, error) {
			t.Fatal("a domain step went through the box's own-IP scan")
			return sensoractive.External{}, nil
		},
		scanDomain: func(_ context.Context, _ netip.Addr, k nmapargv.Kind, _ sensoractive.DeepSettings, d sensoractive.DomainIP, gate sensoractive.DeepGate) (sensoractive.External, error) {
			got, kind = d, k
			if gate == nil {
				t.Error("no DeepGate: the terms would not be read right before the job")
			}
			return sensoractive.External{}, nil
		},
	}
	if _, err := a.ScanServices(t.Context(), domainTarget(true), ownPublicIP); err != nil {
		t.Fatal(err)
	}
	want := sensorlink.DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: testScope.Token}
	if got.Scope != want || got.Chain != testScope.Chain || kind != nmapargv.ExternalFull {
		t.Fatalf("job %+v kind %v", got, kind)
	}
	// Without accepted terms nothing goes to an address that is not the box's.
	_, err := a.ScanServices(t.Context(), domainTarget(false), ownPublicIP)
	var un *exposure.Unavailable
	if !errors.As(err, &un) {
		t.Fatalf("a domain step without the terms: %v", err)
	}
}

func TestDomainRefusalsBecomeLines(t *testing.T) {
	t.Parallel()
	for reason, want := range map[string]string{
		domainfence.TokenForeign: "did not recognise this box's token",
		domainfence.NotOwned:     "vedette-verify=" + testScope.Token,
		domainfence.NameMoved:    "no longer points at 8.8.8.8",
		domainfence.Unchecked:    "DNS did not answer",
		domainfence.CNAMEOutside: "points (CNAME) outside the domain",
	} {
		a := exposureServiceScan{scanDomain: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.DeepSettings, sensoractive.DomainIP, sensoractive.DeepGate) (sensoractive.External, error) {
			return sensoractive.External{}, &sensoractive.DomainRefusedError{Reason: reason}
		}}
		_, err := a.ScanServices(t.Context(), domainTarget(true), ownPublicIP)
		var un *exposure.Unavailable
		if !errors.As(err, &un) || !strings.Contains(un.Reason, want) {
			t.Errorf("%s: %v", reason, err)
		}
	}
	a := exposureServiceScan{scanDomain: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.DeepSettings, sensoractive.DomainIP, sensoractive.DeepGate) (sensoractive.External, error) {
		return sensoractive.External{}, sensoractive.ErrDomainUnsupported
	}}
	_, err := a.ScanServices(t.Context(), domainTarget(true), ownPublicIP)
	var un *exposure.Unavailable
	if !errors.As(err, &un) || !strings.Contains(un.Reason, "no domain fence key") {
		t.Errorf("no key: %v", err)
	}
}

func TestDomainTemplatesGoOutAsADomainIPJob(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: false, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	m := &modes{list: []exposure.ScanMode{{Full: true}}}
	a := f.scanner()
	a.mode = m.now
	var rows []string
	inner := a.probes
	a.probes = func(ctx context.Context, ps []scan.ExternalProbe) error {
		for _, p := range ps {
			rows = append(rows, p.Request)
		}
		return inner(ctx, ps)
	}
	if _, err := a.ScanTemplates(t.Context(), domainTarget(true), ownPublicIP, []exposure.TemplateJob{fullJobOf("CVE-2018-13379")}); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) == 0 {
		t.Fatal("nothing was sent")
	}
	for _, r := range f.reqs {
		if r.Scope != sensorlink.ScopeDomainIP || r.Domain == nil || r.Domain.Name != "www.acme.example" || r.Domain.Token != testScope.Token {
			t.Fatalf("request %+v", r)
		}
	}
	for _, e := range f.events {
		if e == "gate" {
			t.Fatal("a domain_ip run asked the box's own-IP gate")
		}
	}
	if len(rows) == 0 || !strings.Contains(rows[0], "domain_ip acme.example via acme.edge.example.net, deep scan") {
		t.Fatalf("probe rows %q", rows)
	}
	// Without accepted terms: no template at all.
	f2 := &templatesFake{gateOK: true}
	if _, err := f2.scanner().ScanTemplates(t.Context(), domainTarget(false), ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")}); err == nil || len(f2.reqs) != 0 {
		t.Fatalf("a domain step without the terms: %v, %d requests", err, len(f2.reqs))
	}
}

// zap.baseline of a domain's page carries the domain's stored token, as in older releases (the host accepts a domain verified
// before the fence for the passive scan); core asks the host for no token per page.
func TestDomainWebSendsTheStoredToken(t *testing.T) {
	t.Parallel()
	h := &fakeZapHost{run: zapRun(t, api.StatusRefused, api.CodeTargetNotOwned, nil)}
	w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
	_, err := w.Baseline(t.Context(), webDomTarget, webDomPage)
	var un *exposure.Unavailable
	if h.got.TXTToken != "0123456789abcdef" || !errors.As(err, &un) || !strings.Contains(un.Reason, "no longer has its vedette-verify TXT record") {
		t.Fatalf("token %q, %v", h.got.TXTToken, err)
	}
}

type fakeFenceHost struct{ got api.ExposureFenceCheckArgs }

func (f *fakeFenceHost) ExposureFenceCheck(_ context.Context, a api.ExposureFenceCheckArgs, _, _ string) (string, error) {
	f.got = a
	return "", errors.New("host: name_moved")
}

func TestOpenVASAsksTheHostsFence(t *testing.T) {
	t.Parallel()
	h := &fakeFenceHost{}
	err := exposureGreenbone{fence: h}.CheckDomainIP(t.Context(), *testScope, ownPublicIP, exposure.FenceCheck{Disruptive: true, Recheck: true})
	if err == nil || h.got != (api.ExposureFenceCheckArgs{Domain: "acme.example", Name: "www.acme.example", IP: "8.8.8.8", Token: testScope.Token, Disruptive: true, Recheck: true}) {
		t.Fatalf("%+v %v", h.got, err)
	}
	if (exposureGreenbone{}).CheckDomainIP(t.Context(), *testScope, ownPublicIP, exposure.FenceCheck{}) == nil {
		t.Fatal("no host, and the fence said yes")
	}
}

// Review r2 L-5: with a long domain and a long CDN final name, a nuclei probe row keeps the template's own request whole and fits
// scan_probe.request with room for the "Not run" prefix; only the domain part is shortened.
func TestDomainTemplateRowKeepsTheRequest(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	long := &exposure.DomainScope{Domain: strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example", Name: "www.x.example",
		Token: testScope.Token, Chain: "www.x.example -> " + strings.Repeat("e", 60) + "." + strings.Repeat("d", 60) + ".edgekey.example.net"}
	f := &templatesFake{answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	a := f.scanner()
	var rows []scan.ExternalProbe
	inner := a.probes
	a.probes = func(ctx context.Context, ps []scan.ExternalProbe) error {
		rows = append(rows, ps...)
		return inner(ctx, ps)
	}
	tp, ok := ix.Get("CVE-2018-13379")
	if !ok {
		t.Fatal("no template")
	}
	r := templateRun{port: 18443, target: nucleiargv.Target{Host: ownPublicIP.String(), Port: 18443, Scheme: "http"}, tmpls: []pack.Template{tp}, full: true, disruptive: true, domain: long}
	if _, _, _, err := a.send(t.Context(), "u-admin", ownPublicIP, ix, r); err != nil {
		t.Fatal(err)
	}
	req := rows[0].Request
	if !strings.HasSuffix(req, "): "+tp.Request) || utf8.RuneCountInString(req) > probeRequestMax || !strings.Contains(req, "b.example via …") || !strings.Contains(req, "example.net, deep scan") {
		t.Fatalf("row (%d) %q", utf8.RuneCountInString(req), req)
	}
}

// nmap's closed replies reach exposure: the address answered the service step even with no open port.
func TestServiceScanSaysTheAddressRefused(t *testing.T) {
	t.Parallel()
	a := exposureServiceScan{
		scan: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.DeepSettings, sensoractive.OwnEgress) (sensoractive.External, error) {
			return sensoractive.External{Ports: 65535, Refused: true}, nil
		},
	}
	got, err := a.ScanServices(t.Context(), exposure.ScanTarget{ID: "t-2", Kind: exposure.KindIP, Value: ownPublicIP.String(), User: "u-admin", Mode: exposure.ScanMode{Full: true}}, ownPublicIP)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Refused {
		t.Fatalf("got %+v", got)
	}
}

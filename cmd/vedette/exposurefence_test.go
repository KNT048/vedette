package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// D-591 (FULL-5 slice 2): a deep step of exposure that carries ScanTarget.Domain goes out as a domain_ip job (nmap, nuclei) with the
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
		scan: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.OwnEgress) (sensoractive.External, error) {
			t.Fatal("a domain step went through the box's own-IP scan")
			return sensoractive.External{}, nil
		},
		scanDomain: func(_ context.Context, _ netip.Addr, k nmapargv.Kind, d sensoractive.DomainIP, gate sensoractive.DeepGate) (sensoractive.External, error) {
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
		a := exposureServiceScan{scanDomain: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.DomainIP, sensoractive.DeepGate) (sensoractive.External, error) {
			return sensoractive.External{}, &sensoractive.DomainRefusedError{Reason: reason}
		}}
		_, err := a.ScanServices(t.Context(), domainTarget(true), ownPublicIP)
		var un *exposure.Unavailable
		if !errors.As(err, &un) || !strings.Contains(un.Reason, want) {
			t.Errorf("%s: %v", reason, err)
		}
	}
	a := exposureServiceScan{scanDomain: func(context.Context, netip.Addr, nmapargv.Kind, sensoractive.DomainIP, sensoractive.DeepGate) (sensoractive.External, error) {
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
	if len(rows) == 0 || !strings.Contains(rows[0], "domain_ip acme.example, name www.acme.example (CNAME chain www.acme.example -> acme.edge.example.net)") {
		t.Fatalf("probe rows %q", rows)
	}
	// Without accepted terms: no template at all.
	f2 := &templatesFake{gateOK: true}
	if _, err := f2.scanner().ScanTemplates(t.Context(), domainTarget(false), ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")}); err == nil || len(f2.reqs) != 0 {
		t.Fatalf("a domain step without the terms: %v, %d requests", err, len(f2.reqs))
	}
}

// zap.baseline of a domain's page carries the box-bound token from the host; a domain verified before the fence, whose TXT record
// lacks it, gets a line that names the TXT value to add.
func TestDomainWebUsesTheBoxBoundToken(t *testing.T) {
	t.Parallel()
	box := strings.Repeat("cd", 8)
	h := &fakeZapHost{run: zapRun(t, api.StatusRefused, api.CodeTargetNotOwned, nil)}
	w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil },
		fence: func(context.Context, string) (string, error) { return box, nil }}
	_, err := w.Baseline(t.Context(), webDomTarget, webDomPage)
	var un *exposure.Unavailable
	if h.got.TXTToken != box || !errors.As(err, &un) || !strings.Contains(un.Reason, "vedette-verify="+box) {
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
	err := exposureGreenbone{fence: h}.CheckDomainIP(t.Context(), *testScope, ownPublicIP)
	if err == nil || h.got != (api.ExposureFenceCheckArgs{Domain: "acme.example", Name: "www.acme.example", IP: "8.8.8.8", Token: testScope.Token}) {
		t.Fatalf("%+v %v", h.got, err)
	}
	if (exposureGreenbone{}).CheckDomainIP(t.Context(), *testScope, ownPublicIP) == nil {
		t.Fatal("no host, and the fence said yes")
	}
}

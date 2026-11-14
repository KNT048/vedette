package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// D-591 (FULL-5 slice 2): a deep nmap of an address a verified domain's name resolves to goes out as a domain_ip job, only to a worker
// that holds the fence key, and the worker's own fence decides; the probe row says which domain and name chose the address, with the
// CNAME chain. The fake nmap prints testdata/external_full.xml (address 8.8.8.8); the DNS is a fake.

var testFenceKey = []byte(strings.Repeat("k", domainfence.KeySize))

// zoneDNS: acme.example carries this box's token, www.acme.example points at 8.8.8.8 through a CNAME inside the domain.
type zoneDNS struct{ txt string }

func (z zoneDNS) LookupTXT(context.Context, string) ([]string, error) { return []string{z.txt}, nil }
func (zoneDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{boxIP}, nil
}
func (zoneDNS) LookupCNAME(context.Context, string) (string, error) { return "web.acme.example.", nil }

func domainEnv(t *testing.T, txt string) *env {
	t.Helper()
	fx, err := filepath.Abs(filepath.Join("testdata", "external_full.xml"))
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, fakeOpts{always: fx})
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(t, activeBackend{d})
	fence, err := domainfence.New(testFenceKey, zoneDNS{txt: txt}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w, err := worker.New(worker.Config{Link: link.Client(t, sensorlink.Active), NmapPath: e.nm.path, Version: "1.0.0", Wait: time.Second,
		Egress: workerEgress{netip.MustParseAddr("1.1.1.1")}, Fence: fence})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the first heartbeat of the worker", func() bool { return !strings.Contains(d.NmapHealth(), "has not reported") })
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, Prober: d, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func domainRun(key []byte) sa.DomainIP {
	return sa.DomainIP{Scope: sensorlink.DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: domainfence.Token(key, "acme.example")},
		Chain: "www.acme.example -> web.acme.example"}
}

func TestScanDomainIPThroughTheWorkersFence(t *testing.T) {
	t.Parallel()
	e := domainEnv(t, "vedette-verify="+domainfence.Token(testFenceKey, "acme.example"))
	gate := &deepFence{now: nmapargv.ExternalFull}
	got, err := e.svc.ScanDomainIP(e.ctx(), boxIP, nmapargv.ExternalFull, domainRun(testFenceKey), gate)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 3 || len(gate.asked) != 1 || gate.ownFence.asked != 0 {
		t.Fatalf("got %d services, terms asked %v, own egress asked %d times", len(got.Services), gate.asked, gate.ownFence.asked)
	}
	if s := e.str(`SELECT result FROM sa_probe`); s != "domain_ip acme.example, name www.acme.example (CNAME chain: www.acme.example -> web.acme.example): ok: 3 open ports, 5 script results" {
		t.Fatalf("probe row = %s", s)
	}
}

func TestScanDomainIPRefusedByTheWorkersFence(t *testing.T) {
	t.Parallel()
	other := []byte(strings.Repeat("o", domainfence.KeySize))
	// another box's token, which the domain really carries: the worker's key does not give it
	e := domainEnv(t, "vedette-verify="+domainfence.Token(other, "acme.example"))
	_, err := e.svc.ScanDomainIP(e.ctx(), boxIP, nmapargv.ExternalFull, domainRun(other), &deepFence{now: nmapargv.ExternalFull})
	var refused *sa.DomainRefusedError
	if !errors.As(err, &refused) || refused.Reason != domainfence.TokenForeign || refused.MidRun {
		t.Fatalf("err = %v", err)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Fatalf("nmap ran %d times", n)
	}
	if s := e.str(`SELECT result FROM sa_probe`); !strings.HasSuffix(s, "refused by the scan container's domain fence (token_foreign), nothing sent") || !strings.HasPrefix(s, "domain_ip acme.example") {
		t.Fatalf("probe row = %s", s)
	}
}

func TestScanDomainIPIsDeepOnly(t *testing.T) {
	t.Parallel()
	e := domainEnv(t, "")
	if _, err := e.svc.ScanDomainIP(e.ctx(), boxIP, nmapargv.External, domainRun(testFenceKey), &deepFence{now: nmapargv.ExternalFull}); err == nil {
		t.Fatal("a domain_ip run of the External shape was accepted")
	}
	if _, err := e.svc.ScanDomainIP(e.ctx(), boxIP, nmapargv.ExternalFull, domainRun(testFenceKey), &deepFence{now: nmapargv.External}); !errors.Is(err, sa.ErrNotDeep) {
		t.Fatalf("terms withdrawn: %v", err)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Fatalf("nmap ran %d times", n)
	}
}

// A worker whose heartbeat does not say domain_ip (no fence key) never gets a domain_ip job, nmap or nuclei.
func TestDomainJobsNeedAWorkerWithTheKey(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
	hb := &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.95", Full: true},
		Nuclei: sensorlink.HeartbeatNuclei{Present: true, Version: "v3.11.1", Pack: sensorlink.HeartbeatPack{Version: "2026.11.10", SHA256: packSHA}, OwnIP: true, Full: true}}
	if _, err := d.ActiveHeartbeat(t.Context(), hb); err != nil {
		t.Fatal(err)
	}
	argv, _ := nmapargv.Build(nmapargv.ExternalFull, nmapargv.FullRate, []netip.Addr{boxIP})
	if _, err := d.ProbeDomain(t.Context(), argv, domainRun(testFenceKey).Scope); !errors.Is(err, sa.ErrDomainUnsupported) {
		t.Fatalf("nmap: %v", err)
	}
	req := ownIPReq()
	req.Rate, req.Depth, req.Scope = nucleiargv.FullRate, nucleiargv.DepthFull, sensorlink.ScopeDomainIP
	scope := domainRun(testFenceKey).Scope
	req.Domain = &scope
	if _, err := d.RunNuclei(t.Context(), req); !errors.Is(err, sa.ErrDomainUnsupported) {
		t.Fatalf("nuclei: %v", err)
	}
	if rep, _ := d.Jobs(t.Context(), 10*time.Millisecond, nil); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out: %+v", rep.Jobs)
	}
}

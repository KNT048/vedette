package worker_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// A domain_ip job runs only after the worker's own domain fence said yes (its key, the domain's TXT record,
// the name's address now); every refusal is posted before the tool starts, and a deep nmap stops when a re-check fails. No test asks
// real DNS: the resolver is a fake.

var (
	fenceKey   = []byte(strings.Repeat("f", domainfence.KeySize))
	otherKey   = []byte(strings.Repeat("x", domainfence.KeySize))
	domainAddr = "8.8.4.4"
)

// fakeZone is the DNS of acme.example: its TXT records (on acme.example itself), www's addresses and CNAME (acme.example itself is no
// CNAME: the ownership rule reads a record only at a name that is not one); failing makes every lookup a server failure.
type fakeZone struct {
	mu      sync.Mutex
	txt     []string
	a       []netip.Addr
	cname   string
	failing bool
}

func newZone() *fakeZone {
	return &fakeZone{txt: []string{"vedette-verify=" + domainfence.Token(fenceKey, "acme.example")}, a: []netip.Addr{netip.MustParseAddr(domainAddr)}, cname: "www.acme.example"}
}

func (z *fakeZone) err(name string) error {
	if z.failing {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return nil
}

func (z *fakeZone) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".") // the ownership rule asks rooted names
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.err(name); err != nil {
		return nil, err
	}
	if name != "acme.example" { // the record is the domain's own; no other name of the zone has one (no wildcard)
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return z.txt, nil
}

func (z *fakeZone) LookupNetIP(_ context.Context, _, name string) ([]netip.Addr, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.a, z.err(name)
}

func (z *fakeZone) LookupCNAME(_ context.Context, name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	z.mu.Lock()
	defer z.mu.Unlock()
	if name == "acme.example" { // the domain is not a CNAME; www is
		return name + ".", z.err(name)
	}
	return z.cname + ".", z.err(name)
}

func (z *fakeZone) set(f func(*fakeZone)) { z.mu.Lock(); f(z); z.mu.Unlock() }

func withFence(t *testing.T, z *fakeZone) func(*worker.Config) {
	t.Helper()
	f, err := domainfence.New(fenceKey, z, func(d string) bool { return d == "acme.example" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return func(c *worker.Config) { c.Fence = f }
}

func domainScope(key []byte) *sensorlink.DomainScope {
	return &sensorlink.DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: domainfence.Token(key, "acme.example")}
}

func domainNmapJob(kind nmapargv.Kind, key []byte) sensorlink.Job {
	return sensorlink.Job{ID: id1, Kind: sensorlink.KindNmap, Shape: kind.Name(), Rate: nmapargv.FullRate, Targets: []string{domainAddr}, TimeoutS: 60,
		Scope: sensorlink.ScopeDomainIP, Domain: domainScope(key)}
}

func TestDomainNmapJobRunsBehindTheDomainFence(t *testing.T) {
	t.Parallel()
	nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
	eg := &fakeEgress{answers: []string{"1.1.1.1"}} // the box's own egress is another address: the own-IP fence is not the one asked
	r := start(t, nm, func(c *worker.Config) { c.Egress = eg }, withFence(t, newZone()))
	r.core.push(domainNmapJob(nmapargv.ExternalFull, fenceKey))
	if got := r.core.next(t); got.res.Status != "done" || eg.count() != 0 {
		t.Fatalf("result = %+v after %d egress rounds", got.res, eg.count())
	}
	if !strings.Contains(nm.argvLog(), domainAddr) {
		t.Fatalf("argv %q", nm.argvLog())
	}
}

func TestDomainNmapJobRefusals(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		job  sensorlink.Job
		zone func(*fakeZone)
		want string
	}{
		"another box's token": {domainNmapJob(nmapargv.ExternalFull, otherKey), func(z *fakeZone) { z.txt = []string{"vedette-verify=" + domainfence.Token(otherKey, "acme.example")} }, domainfence.TokenForeign},
		"TXT record gone":     {domainNmapJob(nmapargv.ExternalFull, fenceKey), func(z *fakeZone) { z.txt = nil }, domainfence.NotOwned},
		"name moved":          {domainNmapJob(nmapargv.ExternalFull, fenceKey), func(z *fakeZone) { z.a = []netip.Addr{netip.MustParseAddr("1.1.1.1")} }, domainfence.NameMoved},
		"DNS fails":           {domainNmapJob(nmapargv.ExternalFull, fenceKey), func(z *fakeZone) { z.failing = true }, domainfence.Unchecked},
		"disruptive, CNAME outside": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalDisruptive, fenceKey)
			j.Ports = []int{22, 443}
			return j
		}(), func(z *fakeZone) { z.cname = "acme.cdn.example.net" }, domainfence.CNAMEOutside},
		"a domain scope on External": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalFull, fenceKey)
			j.Shape, j.Rate = "external", nmapargv.ExternalRate
			return j
		}(), func(*fakeZone) {}, "invalid_job"},
		"domain_ip without fields": {func() sensorlink.Job { j := domainNmapJob(nmapargv.ExternalFull, fenceKey); j.Domain = nil; return j }(), func(*fakeZone) {}, "invalid_job"},
		// The record's parent name stays between the domain and its registered domain
		"proof_at on a public suffix": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalFull, fenceKey)
			j.Domain.Domain, j.Domain.Name, j.Domain.ProofAt = "victim.github.io", "victim.github.io", "github.io"
			return j
		}(), func(*fakeZone) {}, "invalid_job"},
		"proof_at above a private suffix": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalFull, fenceKey)
			j.Domain.Domain, j.Domain.Name, j.Domain.ProofAt = "bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com", "amazonaws.com"
			return j
		}(), func(*fakeZone) {}, "invalid_job"},
		"a name outside the proof name": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalFull, fenceKey)
			j.Domain.Domain, j.Domain.Name, j.Domain.ProofAt = "git.acme.example", "www.evil.example", "acme.example"
			return j
		}(), func(*fakeZone) {}, "invalid_job"},
		"a name above the proof name": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalFull, fenceKey)
			j.Domain.Domain, j.Domain.Name, j.Domain.ProofAt = "a.b.acme.example", "acme.example", "b.acme.example"
			return j
		}(), func(*fakeZone) {}, "invalid_job"},
		"a name outside the domain": {func() sensorlink.Job {
			j := domainNmapJob(nmapargv.ExternalFull, fenceKey)
			j.Domain.Name = "www.evil.example"
			return j
		}(), func(*fakeZone) {}, "invalid_job"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
			z := newZone()
			z.set(c.zone)
			r := start(t, nm, withFence(t, z))
			r.core.push(c.job)
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != c.want || nm.argvLog() != "" {
				t.Fatalf("result = %+v, argv %q", got.res, nm.argvLog())
			}
		})
	}
}

// A worker without the fence key never says domain_ip and refuses such a job (core should not have sent it).
func TestDomainJobWithoutAFenceKey(t *testing.T) {
	t.Parallel()
	nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
	r := start(t, nm)
	r.core.push(domainNmapJob(nmapargv.ExternalFull, fenceKey))
	if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || nm.argvLog() != "" {
		t.Fatalf("result = %+v", got.res)
	}
	select {
	case hb := <-r.core.beats:
		if hb.DomainIP {
			t.Fatal("a worker without the key said domain_ip")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no heartbeat")
	}
}

// Review r1 L2: the TXT record removed while a deep nmap runs stops it at the next re-check, and its output is dropped.
func TestDomainNmapJobStopsWhenTheTXTGoesMidRun(t *testing.T) {
	t.Parallel()
	nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, sleeper)
	z := newZone()
	ticks := make(chan time.Time)
	r := start(t, nm, withFence(t, z), func(c *worker.Config) { c.EgressTicks = ticks })
	r.core.push(domainNmapJob(nmapargv.ExternalFull, fenceKey))
	waitFor(t, "nmap to start", func() bool { return nm.argvLog() != "" })
	z.set(func(z *fakeZone) { z.txt = nil })
	ticks <- time.Time{}
	if got := r.core.next(t); got.res.Status != "stopped" || got.res.Reason != domainfence.NotOwned || got.res.XMLB64 != "" {
		t.Fatalf("result = %+v", got.res)
	}
}

func TestDomainNucleiJobRunsBehindTheDomainFence(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		key  []byte
		want string
	}{
		"this box's token":    {fenceKey, "done"},
		"another box's token": {otherKey, "refused"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eg := &fakeEgress{answers: []string{"1.1.1.1"}}
			r := startNuclei(t, printJSONL, func(cfg *worker.Config) { cfg.Egress = eg }, withFence(t, newZone()))
			editIndex(t, r.pack.Index, func(m map[string]any) { m["sets"] = []string{"deep"}; delete(m, "own_ip"); delete(m, "cve") })
			j := r.fullJob(false)
			j.Nuclei.Targets[0].Host = domainAddr
			j.Nuclei.Scope, j.Nuclei.Domain = sensorlink.ScopeDomainIP, domainScope(c.key)
			r.core.push(j)
			got := r.core.next(t)
			if got.res.Status != c.want || eg.count() != 0 {
				t.Fatalf("result = %+v after %d egress rounds", got.res, eg.count())
			}
			if c.want == "refused" && (got.res.Reason != domainfence.TokenForeign || r.nu.Argv() != "") {
				t.Fatalf("result = %+v, argv %q", got.res, r.nu.Argv())
			}
		})
	}
}

// A domain_ip nuclei job is depth full only: the read-only KEV shape of own_ip with a domain scope is invalid_job.
func TestDomainNucleiJobIsFullOnly(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, printJSONL, withFence(t, newZone()))
	j := r.ownIPJob()
	j.Nuclei.Targets[0].Host = domainAddr
	j.Nuclei.Scope, j.Nuclei.Domain = sensorlink.ScopeDomainIP, domainScope(fenceKey)
	r.core.push(j)
	if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || r.nu.Argv() != "" {
		t.Fatalf("result = %+v", got.res)
	}
}

// Review r1 L6: a domain_ip nuclei job is re-checked while it runs like a deep nmap: the TXT record removed meanwhile stops it at the
// next re-check and its output is dropped.
func TestDomainNucleiJobStopsWhenTheTXTGoesMidRun(t *testing.T) {
	t.Parallel()
	z := newZone()
	ticks := make(chan time.Time)
	r := startNuclei(t, sleeper, withFence(t, z), func(c *worker.Config) { c.EgressTicks = ticks })
	editIndex(t, r.pack.Index, func(m map[string]any) { m["sets"] = []string{"deep"}; delete(m, "own_ip"); delete(m, "cve") })
	j := r.fullJob(false)
	j.Nuclei.Targets[0].Host = domainAddr
	j.Nuclei.Scope, j.Nuclei.Domain = sensorlink.ScopeDomainIP, domainScope(fenceKey)
	r.core.push(j)
	waitFor(t, "nuclei to start", func() bool { return r.nu.Argv() != "" })
	z.set(func(z *fakeZone) { z.txt = nil })
	ticks <- time.Time{}
	if got := r.core.next(t); got.res.Status != "stopped" || got.res.Reason != domainfence.NotOwned || got.res.JSONLB64 != "" {
		t.Fatalf("result = %+v", got.res)
	}
}

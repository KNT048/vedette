package exposure

// A deep scan in two nmap runs: the port scan of every TCP port, then -sV and the scripts only on the open ports it found.

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	corerun "github.com/knt048/vedette/core/run"
)

// splitServices is a scan container that runs the deep scan in two runs: open is what its port scan finds, then services is what
// -sV and the scripts read on the ports it is given. The one-run ScanServices (fakeServices) answers a scan that is not deep.
type splitServices struct {
	fakeServices
	open     OpenPorts
	openErr  error
	services ServiceScan
	mu       sync.Mutex
	sweeps   int
	listed   [][]int
}

func (f *splitServices) ScanOpenPorts(_ context.Context, t ScanTarget, ip netip.Addr) (OpenPorts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip.String() != t.Value || !t.Mode.Full {
		return OpenPorts{}, context.Canceled
	}
	f.sweeps++
	return f.open, f.openErr
}

func (f *splitServices) ScanOpenServices(_ context.Context, t ScanTarget, ip netip.Addr, ports []int) (ServiceScan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip.String() != t.Value || !t.Mode.Full {
		return ServiceScan{}, context.Canceled
	}
	f.listed = append(f.listed, slices.Clone(ports))
	return f.services, nil
}

// A deep scan whose port scan found no open port does not start the service run: the port step says so, the service step is skipped
// with why, and nothing else is sent.
func TestDeepScanWithNoOpenPortSkipsTheServiceStep(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	sv := &splitServices{open: OpenPorts{Ports: 65535, Refused: true}}
	e.svc.cfg.Services = sv
	s := e.scanIP(Content{})
	if sv.sweeps != 1 || len(sv.listed) != 0 || len(sv.calls) != 0 {
		t.Fatalf("port scans %d, service runs %v, one-run scans %d: want one port scan and no other job", sv.sweeps, sv.listed, len(sv.calls))
	}
	d := e.runDetail(e.ctx(), s.RunID)
	if p := d.Steps[2]; p.Name != stepNamePortsDeep || p.Status != corerun.Done || p.Note == nil || !strings.Contains(*p.Note, "0 open TCP ports found") {
		t.Fatalf("port step = %s %s %v", p.Name, p.Status, p.Note)
	}
	if v := d.Steps[3]; v.Name != stepNameServiceDeep || v.Status != corerun.Skipped || v.Note == nil || *v.Note != notServicesNoOpen {
		t.Fatalf("service step = %s %s %v", v.Name, v.Status, v.Note)
	}
	if len(s.Services) != 0 || len(s.Scripts) != 0 {
		t.Fatalf("services %+v scripts %+v", s.Services, s.Scripts)
	}
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool { return c.Kind == "services" && strings.Contains(c.Text, "every TCP port") }) {
		t.Fatalf("checks = %+v", s.Checks)
	}
}

// The service run reads exactly the open ports the port scan found, without a port the target's settings skip and without a port the
// box's own network answers (INV-44): from 22, 443, 5060 (a SIP helper of the network), 8443 and 25 (skipped) only 22, 443 and 8443
// are read, and the service step's note says so.
func TestDeepScanReadsOnlyTheTargetsOwnOpenPorts(t *testing.T) {
	t.Parallel()
	e, _, _ := deepScans(t)
	e.svc.cfg.Path = &fakePath{ports: []int{5060}}
	ids := e.detect(ipA)
	e.deepRow(ids[0].ID, false, true, true, true, true, SpeedNormal, "[25]", "[]")
	read := swept(22, 443, 8443)
	read.Ports = 3
	sv := &splitServices{open: OpenPorts{Open: []int{8443, 22, 25, 5060, 443}, Ports: 65534}, services: read}
	e.svc.cfg.Services = sv
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", Ident: IdentProbed}}}})
	r, err := e.svc.Scan(e.ctx(), "admin@acme.example", ids[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sv.listed) != 1 || !slices.Equal(sv.listed[0], []int{22, 443, 8443}) {
		t.Fatalf("the service run read %v, want [[22 443 8443]]", sv.listed)
	}
	if len(sv.calls) != 0 {
		t.Fatalf("the one run on every port ran too: %d", len(sv.calls))
	}
	d := e.runDetail(e.ctx(), r.RunID)
	if p := d.Steps[2]; p.Status != corerun.Done || p.Note == nil || !strings.Contains(*p.Note, "3 open TCP ports found") {
		t.Fatalf("port step = %s %v", p.Status, p.Note)
	}
	if v := d.Steps[3]; v.Status != corerun.Done || v.Note == nil || !strings.Contains(*v.Note, "of the 3 open ones") {
		t.Fatalf("service step = %s %v", v.Status, v.Note)
	}
	if n := e.count(`SELECT count(*) FROM exp_service WHERE ip = ? AND state = 'open'`, ipA); n != 3 {
		t.Fatalf("%d open services, want 3", n)
	}
}

// A scan container that does not run the two runs (an older worker) gets the one run on every port, as before.
func TestDeepScanFallsBackToOneRunOnAnOlderWorker(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	sv := &splitServices{fakeServices: fakeServices{scan: swept(22)}, openErr: ErrPortsFirstUnsupported}
	e.svc.cfg.Services = sv
	s := e.scanIP(Content{})
	if sv.sweeps != 1 || len(sv.listed) != 0 || len(sv.calls) != 1 {
		t.Fatalf("port scans %d, service runs %v, one-run scans %d", sv.sweeps, sv.listed, len(sv.calls))
	}
	if len(s.Services) != 1 || s.Services[0].Port != 22 {
		t.Fatalf("services = %+v", s.Services)
	}
}

// A port the port scan found open that the service run then did not see open (it stopped answering between the two runs, or nmap's
// second look lost it) was not missed by the sweep: the scan says nothing about it. It is never closed on that scan, and the service
// step says the scan is incomplete there.
func TestDeepScanNeverClosesAPortItsPortScanFoundOpen(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{80, 22}, swept(80, 22), nil)
	if state(22) != ServiceOpen {
		t.Fatalf("22 after the first scan: %s", state(22))
	}
	sv := &splitServices{open: OpenPorts{Open: []int{22, 80}, Ports: 65535}, services: swept(80)}
	e.svc.cfg.Services = sv
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}}}})
	r, err := e.svc.Scan(e.ctx(), "admin@acme.example", e.detectedID(ipA))
	if err != nil {
		t.Fatal(err)
	}
	if len(sv.listed) != 1 || !slices.Equal(sv.listed[0], []int{22, 80}) {
		t.Fatalf("the service run read %v", sv.listed)
	}
	if state(22) == ServiceClosed || closedByNewest(e) != 0 {
		t.Fatalf("22, which the port scan found open, was closed (%s; the scan says %d closed)", state(22), closedByNewest(e))
	}
	d := e.runDetail(e.ctx(), r.RunID)
	if v := d.Steps[3]; v.Status != corerun.Partial || v.Note == nil || !strings.Contains(*v.Note, "found 1 TCP port open that the service identification moments later did not") {
		t.Fatalf("service step = %s %v, want partly done", v.Status, v.Note)
	}
}

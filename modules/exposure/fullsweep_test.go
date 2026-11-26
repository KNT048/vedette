package exposure

import (
	"errors"
	"testing"
	"time"
)

// deepScans verifies ipA, records its commitment and accepts its testing terms (without the disruptive checks), so every scan is
// the deep scan: the runner's fixed list, then nmap on every TCP port. scan runs one with the runner reporting the open ports given
// and the service step answering services (or err), then moves the clock past ScanEvery; state is the state of a port of ipA.
func deepScans(t *testing.T) (e *env, scan func(runner []int, services ServiceScan, err error) ScanResult, state func(int) string) {
	t.Helper()
	e = newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(ips[0].ID, false)
	scan = func(runner []int, services ServiceScan, err error) ScanResult {
		t.Helper()
		ports := []PortRow{}
		for _, p := range runner {
			ports = append(ports, PortRow{IP: ipA, Port: p, Service: "http", Ident: IdentProbed})
		}
		e.svc.cfg.Services = &fakeServices{scan: services, err: err}
		e.svc.SetRunner(&fakeRunner{content: Content{Ports: ports}})
		r, scanErr := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		e.advance(ScanEvery + time.Minute)
		return r
	}
	state = func(port int) string {
		t.Helper()
		var st string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT state FROM exp_service WHERE ip = ? AND port = ?`, ipA, port).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	return e, scan, state
}

// closedByNewest is the number of services the newest scan says it closed (its summary's counts).
func closedByNewest(e *env) int {
	e.t.Helper()
	return e.count(`SELECT coalesce(json_extract(x.summary, '$.counts.closed_services'), -1) FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		ORDER BY r.queued_at DESC, r.rowid DESC LIMIT 1`)
}

func swept(ports ...int) ServiceScan {
	s := ServiceScan{Ports: 65535}
	for _, p := range ports {
		s.Services = append(s.Services, ServiceRow{IP: ipA, Port: p, Name: "http", Product: "nginx", Version: "1.27.0", Method: "probed"})
	}
	return s
}

// INV-22: a deep scan's nmap step probes every TCP port. When it finished and the address still answered it on the ports the
// runner found open this run, a port open before that it did not see is no longer seen after that one scan, and the run says it
// closed it; its history (first and last seen) stays.
func TestCoverage_AFullPortScanThatDidNotSeeAPortClosesIt(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{80}, swept(80, 22, 2000), nil)
	if state(2000) != ServiceOpen {
		t.Fatalf("2000 found open: %s", state(2000))
	}
	scan([]int{80}, swept(80, 22), nil)
	if state(2000) != ServiceClosed || closedByNewest(e) != 1 {
		t.Fatalf("after a full-port scan that did not see 2000: %s, the scan says %d closed", state(2000), closedByNewest(e))
	}
	if state(22) != ServiceOpen || state(80) != ServiceOpen {
		t.Fatalf("the ports it saw: 22 %s, 80 %s", state(22), state(80))
	}
}

// Fail safe: a deep scan that cannot be trusted to have seen every port says nothing about a port it did not see. Not one of these
// closes 2000, however many of them run in a row: an nmap step that failed, a target that answered nothing at all, a sweep that
// missed a port the runner found open moments before (the address stopped answering it, a firewall or IPS cutting in), and a
// sweep whose service batch for that port did not finish.
func TestCoverage_AnUntrustworthyFullPortScanNeverClosesAPort(t *testing.T) {
	t.Parallel()
	unfinished := swept(80, 22)
	unfinished.Unfinished = []int{2000}
	for name, tc := range map[string]struct {
		runner   []int
		services ServiceScan
		err      error
	}{
		"nmap failed":             {runner: []int{80}, err: errors.New("nmap failed")},
		"nothing answered":        {runner: nil, services: ServiceScan{Ports: 65535}},
		"stopped answering":       {runner: []int{80}, services: swept(22)},
		"the port's batch is cut": {runner: []int{80}, services: unfinished},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, scan, state := deepScans(t)
			scan([]int{80}, swept(80, 22, 2000), nil)
			for i := range 3 {
				scan(tc.runner, tc.services, tc.err)
				if state(2000) != ServiceOpen {
					t.Fatalf("scan %d closed 2000", i+1)
				}
			}
		})
	}
}

// A default scan to which the target answered nothing at all (while the box was online) is not a miss either: two of them in a
// row leave the ports of the fixed list that the scan before found open as they were.
func TestCoverage_AScanThatReachedNothingIsNotAMiss(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	scan := func(ports ...int) {
		t.Helper()
		rows := []PortRow{}
		for _, p := range ports {
			rows = append(rows, PortRow{IP: ipA, Port: p, Service: "https", Ident: IdentProbed})
		}
		e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 1000, Probed: topThousand()}}
		e.svc.SetRunner(&fakeRunner{content: Content{Ports: rows}})
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err != nil {
			t.Fatal(err)
		}
		e.advance(ScanEvery + time.Minute)
	}
	scan(443, 8443)
	scan()
	scan()
	if n := e.count(`SELECT count(*) FROM exp_service WHERE ip = ? AND state = 'open'`, ipA); n != 2 {
		t.Fatalf("after two scans that reached nothing, %d of the 2 services are open", n)
	}
}

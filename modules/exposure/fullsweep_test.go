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
// runner found open this run, a port of the runner's fixed list that both the runner and that sweep missed is no longer seen after
// that one scan (two probes of this run missed it). A port outside the fixed list only the sweep probed, so it needs the miss of
// the scan before too: it is closed by the second trusted sweep in a row. The history (first and last seen) stays.
func TestCoverage_AFullPortScanThatDidNotSeeAPortClosesIt(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{80, 22}, swept(80, 22, 32400), nil)
	if state(22) != ServiceOpen || state(32400) != ServiceOpen {
		t.Fatalf("found open: 22 %s, 32400 %s", state(22), state(32400))
	}
	scan([]int{80}, swept(80), nil)
	if state(22) != ServiceClosed || closedByNewest(e) != 1 {
		t.Fatalf("22, missed by the runner and by a trusted sweep: %s, the scan says %d closed", state(22), closedByNewest(e))
	}
	if state(32400) != ServiceOpen {
		t.Fatalf("32400, outside the fixed list, after one trusted sweep that missed it: %s", state(32400))
	}
	scan([]int{80}, swept(80), nil)
	if state(32400) != ServiceClosed || closedByNewest(e) != 1 {
		t.Fatalf("32400 after a second trusted sweep that missed it: %s, the scan says %d closed", state(32400), closedByNewest(e))
	}
	if state(80) != ServiceOpen {
		t.Fatalf("80, which every scan saw: %s", state(80))
	}
}

// A deep scan of an address that has no open port left: nmap's closed replies (TCP RST) show the address answered the sweep, so the
// sweep counts. The fixed list's port the runner missed too closes at once; the port outside it closes with the second such sweep.
func TestCoverage_AnEmptySweepWithClosedRepliesCounts(t *testing.T) {
	t.Parallel()
	_, scan, state := deepScans(t)
	scan([]int{80}, swept(80, 32400), nil)
	empty := ServiceScan{Ports: 65535, Refused: true}
	scan(nil, empty, nil)
	if state(80) != ServiceClosed || state(32400) != ServiceOpen {
		t.Fatalf("after one empty sweep with closed replies: 80 %s, 32400 %s", state(80), state(32400))
	}
	scan(nil, empty, nil)
	if state(32400) != ServiceClosed {
		t.Fatalf("32400 after two empty sweeps with closed replies: %s", state(32400))
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

// emptyScans is a verified IP target with 443 open, then scans in which nothing is open: answered says the address replied (the
// runner's connect or nmap got a TCP RST), so the scan is a miss; gap is the time between two scans.
func emptyScans(t *testing.T, answered func(c *Content, s *ServiceScan)) (scan func(gap time.Duration), open func() int) {
	t.Helper()
	e := newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	run := func(c Content, svc ServiceScan) {
		t.Helper()
		e.svc.cfg.Services = &fakeServices{scan: svc}
		e.svc.SetRunner(&fakeRunner{content: c})
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err != nil {
			t.Fatal(err)
		}
	}
	run(Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https", Ident: IdentProbed}}}, ServiceScan{Ports: 1000, Probed: topThousand()})
	scan = func(gap time.Duration) {
		t.Helper()
		e.advance(gap)
		c, svc := Content{Ports: []PortRow{}}, ServiceScan{Ports: 1000, Probed: topThousand()}
		if answered != nil {
			answered(&c, &svc)
		}
		run(c, svc)
	}
	open = func() int { return e.count(`SELECT count(*) FROM exp_service WHERE ip = ? AND state = 'open'`, ipA) }
	return scan, open
}

// INV-22, INV-41: "nothing open" is a result when the address showed it is reachable in that scan (a TCP RST to the runner's
// connect or to nmap): the owner closed the last open port, and the normal two-miss rule closes it.
func TestCoverage_AnEmptyScanOfAnAddressThatAnsweredIsAMiss(t *testing.T) {
	t.Parallel()
	for name, answered := range map[string]func(c *Content, s *ServiceScan){
		"the runner got a reset": func(c *Content, _ *ServiceScan) { c.Answered = map[string]bool{ipA: true} },
		"nmap got a reset":       func(_ *Content, s *ServiceScan) { s.Refused = true },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scan, open := emptyScans(t, answered)
			scan(ScanEvery + time.Minute)
			if n := open(); n != 1 {
				t.Fatalf("after one empty scan, %d open", n)
			}
			scan(ScanEvery + time.Minute)
			if n := open(); n != 0 {
				t.Fatalf("after two empty scans of an address that answered, %d still open", n)
			}
		})
	}
}

// Fail safe with a limit: scans to which the address replied nothing at all (no open port, no reset) are not misses while they are
// few or close together (a lost NAT loopback, a firewall dropping the box's probes); the third such scan in a row, at least 24 hours
// after the first, closes the ports they all missed.
func TestCoverage_EmptyScansWithNoReplyCloseOnlyAfterThreeOverADay(t *testing.T) {
	t.Parallel()
	scan, open := emptyScans(t, nil)
	scan(ScanEvery + time.Minute)
	scan(ScanEvery + time.Minute)
	scan(ScanEvery + time.Minute)
	if n := open(); n != 1 {
		t.Fatalf("after three empty scans within the hour, %d open", n)
	}
	scan(23 * time.Hour)
	if n := open(); n != 1 {
		t.Fatalf("after four empty scans within 24 hours, %d open", n)
	}
	scan(time.Hour)
	if n := open(); n != 0 {
		t.Fatalf("after empty scans spanning more than 24 hours, %d still open", n)
	}
}

// A domain's address that is not the box's own: the runner never port-scanned it (only the checks by name), so a port of the fixed
// list that a trusted sweep missed has one probe of this run against it and needs the scan before to have missed it too.
func TestCoverage_AListPortTheRunnerDidNotProbeNeedsTwoSweeps(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.seams.extra = []ServiceRow{{IP: ipB, Port: 2222, Name: "ssh", Product: "OpenSSH"}}
	d.scan()
	state := func() string {
		var st string
		_ = d.db.Reader().QueryRowContext(d.ctx(), `SELECT state FROM exp_service WHERE ip = ? AND port = 2222`, ipB).Scan(&st)
		return st
	}
	if state() != ServiceOpen {
		t.Fatalf("first scan: %q", state())
	}
	d.seams.mu.Lock()
	d.seams.extra = nil
	d.seams.mu.Unlock()
	d.advance(ScanEvery + time.Minute)
	d.scan()
	if state() != ServiceOpen {
		t.Fatalf("after one trusted sweep, the runner never having probed the address: %q", state())
	}
	d.advance(ScanEvery + time.Minute)
	d.scan()
	if state() != ServiceClosed {
		t.Fatalf("after two trusted sweeps in a row: %q", state())
	}
}

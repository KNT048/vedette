package exposure

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// topThousand is a stand-in for the ports the default scan's nmap says it probed (its own most common ports): 1 to 1000.
func topThousand(without ...int) []int {
	out := make([]int, 0, 1000)
	for p := 1; p <= 1000; p++ {
		if !slices.Contains(without, p) {
			out = append(out, p)
		}
	}
	return out
}

// INV-22: a port outside the fixed list counts as checked only by a scan whose service step probed it, in this scan and in the scan
// before alike. 666 is open from a deep scan; scan A is a default scan whose nmap step failed (it probed only the fixed list); scan B
// probed 666 and missed it. A did not probe 666, so it is not the first miss: after B the service is still open. Scan C probes and
// misses it too: two scans that probed it missed it, so C closes it.
func TestCoverage_TopPortNeedsTwoScansThatProbedIt(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := replayEnv(t, f)
	const ip = "198.51.100.2"
	port := func(p int) PortRow { return PortRow{IP: ip, Port: p, Service: "http", Ident: IdentProbed} }
	state := func(p int) string {
		var st string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT state FROM exp_service WHERE target_id = 'xt-ip' AND port = ?`, p).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	partial := []NotCheckedRow{{Kind: "ports", Text: notOtherPortsIP}}

	deep := e.replay("xt-ip", "2026-11-18T02:00:00.000Z", Content{Ports: []PortRow{port(80), port(666)}})
	if deep.checked[ip] != coverAll {
		t.Fatalf("the deep scan's coverage: %q", deep.checked[ip])
	}
	a := e.replay("xt-ip", "2026-11-19T02:00:00.000Z", Content{Ports: []PortRow{port(80)}, NotChecked: partial})
	if a.checked[ip] != coverList || len(a.topPorts) != 0 || state(666) != ServiceOpen {
		t.Fatalf("scan A (nmap failed): coverage %q, top ports %q, 666 %s", a.checked[ip], a.topPorts, state(666))
	}
	probed := map[string][]int{ip: topThousand()}
	b := e.replay("xt-ip", "2026-11-20T02:00:00.000Z", Content{Ports: []PortRow{port(80)}, NotChecked: partial, Probed: probed})
	if b.checked[ip] != coverTop || b.counts.ClosedServices != 0 || state(666) != ServiceOpen {
		t.Fatalf("scan B (first scan that probed 666): coverage %q, counts %+v, 666 %s", b.checked[ip], b.counts, state(666))
	}
	if !slices.Equal(b.topPorts, []string{portKey(ip, 666)}) {
		t.Fatalf("scan B's port items: %q", b.topPorts)
	}
	c := e.replay("xt-ip", "2026-11-21T02:00:00.000Z", Content{Ports: []PortRow{port(80)}, NotChecked: partial, Probed: probed})
	if c.counts.ClosedServices != 1 || state(666) != ServiceClosed {
		t.Fatalf("scan C (second scan that probed 666): counts %+v, 666 %s", c.counts, state(666))
	}
}

// A scan whose service step probed other ports than this one (its batch did not finish, or it is not among nmap's ports) never
// counts toward closing it, before or after a scan that probed it.
func TestCoverage_ScanThatDidNotProbeThePortIsNotAMiss(t *testing.T) {
	t.Parallel()
	f := loadReplay(t)
	e := replayEnv(t, f)
	const ip = "198.51.100.2"
	port := func(p int) PortRow { return PortRow{IP: ip, Port: p, Service: "http", Ident: IdentProbed} }
	partial := []NotCheckedRow{{Kind: "ports", Text: notOtherPortsIP}}
	e.replay("xt-ip", "2026-11-18T02:00:00.000Z", Content{Ports: []PortRow{port(80), port(18443)}}) // deep
	other := map[string][]int{ip: topThousand()}                                                    // 18443 is not among them
	for i, at := range []string{"2026-11-19T02:00:00.000Z", "2026-11-20T02:00:00.000Z", "2026-11-21T02:00:00.000Z"} {
		out := e.replay("xt-ip", at, Content{Ports: []PortRow{port(80)}, NotChecked: partial, Probed: other})
		if out.counts.ClosedServices != 0 || len(out.topPorts) != 0 {
			t.Fatalf("scan %d that did not probe 18443: counts %+v, top ports %q", i+1, out.counts, out.topPorts)
		}
	}
	probed := map[string][]int{ip: append(topThousand(), 18443)}
	if out := e.replay("xt-ip", "2026-11-22T02:00:00.000Z", Content{Ports: []PortRow{port(80)}, NotChecked: partial, Probed: probed}); out.counts.ClosedServices != 0 {
		t.Fatalf("the first scan that probed 18443 closed it: %+v", out.counts)
	}
	if out := e.replay("xt-ip", "2026-11-23T02:00:00.000Z", Content{Ports: []PortRow{port(80)}, NotChecked: partial, Probed: probed}); out.counts.ClosedServices != 1 {
		t.Fatalf("the second scan that probed 18443 did not close it: %+v", out.counts)
	}
}

// The whole default scan, through the service step and the run's items: a port whose -sV batch did not finish is said under Not
// checked and is not counted as probed, even when the scanner also lists it as probed; scans like that never close it. Once two
// scans probe it and miss it, it is closed. A scan whose service step failed probes only the fixed list.
func TestCoverage_UnfinishedBatchNeverClosesAService(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	scan := func(services ServiceScan, err error) ScanResult {
		t.Helper()
		e.svc.cfg.Services = &fakeServices{scan: services, err: err}
		e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 80, Service: "http", Ident: IdentProbed}}}})
		r, scanErr := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		e.advance(ScanEvery + time.Minute)
		return r
	}
	state := func() string {
		var st string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT state FROM exp_service WHERE ip = ? AND port = 666`, ipA).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	open := ServiceScan{Ports: 1000, Probed: topThousand(), Services: []ServiceRow{{IP: ipA, Port: 666, Name: "http", Product: "nginx", Version: "1.27.0"}}}
	scan(open, nil)
	if state() != ServiceOpen {
		t.Fatalf("666 found open: %s", state())
	}
	unfinished := ServiceScan{Ports: 1000, Probed: topThousand(), Unfinished: []int{666}} // the scanner lists 666 in both: unfinished wins
	for i := range 3 {
		r := scan(unfinished, nil)
		if !slices.Contains(notChecked(r), "Service identification of 1 port did not finish this time (nmap's time limit for each batch of ports, or too little time left); the next scan reads them first.") {
			t.Fatalf("scan %d: not checked = %q", i+1, notChecked(r))
		}
		if _, in := slices.BinarySearch(r.Probed[ipA], 666); in || state() != ServiceOpen {
			t.Fatalf("scan %d with 666 unfinished: probed has 666 %v, 666 %s", i+1, in, state())
		}
	}
	scan(ServiceScan{}, errors.New("nmap failed")) // probes only the fixed list
	if state() != ServiceOpen {
		t.Fatalf("a failed service step closed 666")
	}
	scan(ServiceScan{Ports: 1000, Probed: topThousand()}, nil)
	if state() != ServiceOpen {
		t.Fatalf("one scan that probed 666 closed it")
	}
	scan(ServiceScan{Ports: 1000, Probed: topThousand()}, nil)
	if state() != ServiceClosed {
		t.Fatalf("two scans that probed 666 and missed it left it %s", state())
	}
}

package exposure

import (
	"slices"
	"testing"
	"time"
)

// INV-22: a port the last observation had open and a scan that checked its address did not report is "missed once" and still
// counts as open; the second scan in a row that misses it closes it (scans counted, not days); a scan that sees it resets it.
type nsEnv struct {
	*env
	id  string
	run *fakeRunner
}

func newNS(t *testing.T) *nsEnv {
	t.Helper()
	e := newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	e.svc.SetRunner(r)
	return &nsEnv{env: e, id: ips[0].ID, run: r}
}

func ports(n ...int) Content {
	var c Content
	for _, p := range n {
		c.Ports = append(c.Ports, PortRow{IP: ipA, Port: p, Service: "tcp"})
	}
	return c
}

// scan advances the clock by d, scans with c and returns what the page reads.
func (n *nsEnv) scan(d time.Duration, c Content) Snapshot {
	n.t.Helper()
	n.advance(d)
	n.run.content = c
	s, err := n.svc.Scan(n.ctx(), "admin@acme.example", n.id)
	if err != nil {
		n.t.Fatal(err)
	}
	got, err := n.svc.SnapshotOf(n.ctx(), n.id, s.Date)
	if err != nil {
		n.t.Fatal(err)
	}
	return got
}

func misses25(s Snapshot) (int, bool) {
	for _, p := range s.Ports {
		if p.Port == 25 {
			return p.Misses, true
		}
	}
	return 0, false
}

func TestNotSeen_OneMissIsNotClosed_TwoMissesAre(t *testing.T) {
	t.Parallel()
	n := newNS(t)
	d1 := n.scan(day, ports(80, 25))
	d2 := n.scan(day, ports(80))
	if m, ok := misses25(d2); !ok || m != 1 || d2.Counts.Ports != 2 {
		t.Fatalf("after one miss: %+v counts %+v", d2.Ports, d2.Counts)
	}
	if d2.Ports[1].LastSeen != d1.Date {
		t.Fatalf("last seen %q, want %s", d2.Ports[1].LastSeen, d1.Date)
	}
	df, err := n.svc.Diff(n.ctx(), n.id, d1.Date, d2.Date)
	if err != nil || len(df.Removed) != 0 || len(df.Changed) != 1 || df.Changed[0].To != PortNotSeen {
		t.Fatalf("diff after one miss: %+v %v", df, err)
	}
	d3 := n.scan(day, ports(80))
	if _, ok := misses25(d3); ok || d3.Counts.Ports != 1 {
		t.Fatalf("after two misses: %+v", d3.Ports)
	}
	df, err = n.svc.Diff(n.ctx(), n.id, d2.Date, d3.Date)
	if err != nil || len(df.Removed) != 1 || df.Removed[0].Label != ipA+":25" || len(df.Added) != 0 {
		t.Fatalf("diff after two misses: %+v %v", df, err)
	}
}

// H1: the same day counts too. A customer who fixed a port and presses Scan now twice sees it closed; a scan earlier today that saw
// the port is not forgotten by one miss, and seeing it again resets the count.
func TestNotSeen_CountedPerScanNotPerDay(t *testing.T) {
	t.Parallel()
	n := newNS(t)
	n.scan(day, ports(80, 25))
	if s := n.scan(day, ports(80)); s.Counts.Ports != 2 { // D: miss 1
		t.Fatalf("first miss: %+v", s.Ports)
	}
	if m, ok := misses25(n.scan(ScanEvery, ports(80, 25))); !ok || m != 0 { // 09:00 seen again: normal
		t.Fatal("seen again is a normal row")
	}
	if m, ok := misses25(n.scan(ScanEvery, ports(80))); !ok || m != 1 { // 09:15 one miss: kept, not closed
		t.Fatalf("a miss after a sighting earlier the same day: kept=%v misses=%d", ok, m)
	}
	if _, ok := misses25(n.scan(ScanEvery, ports(80))); ok { // a second scan in a row: closed
		t.Fatal("two misses in a row on one day did not close it")
	}
	// back the next day, seen: a new row, not a carried one
	if m, ok := misses25(n.scan(day, ports(80, 25))); !ok || m != 0 {
		t.Fatal("seen after closing")
	}
}

// a runner cannot forge the mark (sanitize drops it), and the service read on a kept port and its CVE stay until the port closes
func TestNotSeen_ForgedMarkDroppedServiceKept(t *testing.T) {
	t.Parallel()
	n := newNS(t)
	c := ports(80)
	c.Ports[0].LastSeen, c.Ports[0].Misses = "2020-01-01", 1
	c.Services = []ServiceRow{{IP: ipA, Port: 80, Name: "http", Product: "Apache httpd", Version: "2.4.49"}}
	d1 := n.scan(day, c)
	if d1.Ports[0].LastSeen != "" || d1.Ports[0].Misses != 0 {
		t.Fatalf("forged mark kept: %+v", d1.Ports[0])
	}
	d2 := n.scan(day, Content{})
	if len(d2.Ports) != 1 || len(d2.Services) != 1 {
		t.Fatalf("after one miss: ports %+v services %+v", d2.Ports, d2.Services)
	}
	if d3 := n.scan(day, Content{}); len(d3.Ports) != 0 || len(d3.Services) != 0 {
		t.Fatalf("after two misses: ports %+v services %+v", d3.Ports, d3.Services)
	}
}

// M1: a domain scan that did not port-scan an address (it is not a scannable IP target now) says nothing about its ports.
func TestNotSeen_UncheckedAddressIsNotAMiss(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := scanReady(t, e)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	first, err := e.svc.Scan(e.ctx(), "admin@acme.example", v.ID)
	if err != nil {
		t.Fatal(err)
	}
	var last Snapshot
	for range 3 { // ipB (smtp 25) is no IP target: the scan never port-scanned it
		e.advance(day)
		run.content = sampleContent()
		run.content.Ports = run.content.Ports[:2]
		s, err := e.svc.Scan(e.ctx(), "admin@acme.example", v.ID)
		if err != nil {
			t.Fatal(err)
		}
		if last, err = e.svc.SnapshotOf(e.ctx(), v.ID, s.Date); err != nil {
			t.Fatal(err)
		}
	}
	if p := last.Ports[2]; p.Port != 25 || p.Misses != 0 || p.LastSeen != first.Date {
		t.Fatalf("the unchecked port = %+v, want kept as it was, last seen %s", p, first.Date)
	}
}

// N1: a name that did not resolve this time (a failed lookup) does not make its address "gone": its ports are kept, unchecked, and
// the next scan that sees them again adds no "new port"; a miss earlier is not erased either.
func TestNotSeen_FailedLookupKeepsThePorts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := scanReady(t, e)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	scan := func(c Content) Snapshot {
		t.Helper()
		e.advance(day)
		run.content = c
		s, err := e.svc.Scan(e.ctx(), "admin@acme.example", v.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.svc.SnapshotOf(e.ctx(), v.ID, s.Date)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	d1 := scan(sampleContent())
	flaky := sampleContent() // mail.acme.example (ipB) did not resolve: no host row, no port on ipB
	flaky.Hosts, flaky.Ports = flaky.Hosts[:2], flaky.Ports[:2]
	for range 2 {
		d := scan(flaky)
		p := d.Ports[len(d.Ports)-1]
		if len(d.Ports) != 3 || p.Port != 25 || !p.Unchecked || p.Misses != 0 || p.LastSeen != d1.Date {
			t.Fatalf("a failed lookup: %+v", d.Ports)
		}
	}
	back := scan(sampleContent())
	if p := back.Ports[2]; p.Port != 25 || p.LastSeen != "" || p.Unchecked {
		t.Fatalf("seen again: %+v", back.Ports)
	}
	// the name now points elsewhere: the address left the domain and its ports go with it
	moved := sampleContent()
	moved.Hosts[2].IP = ipA
	moved.Ports = moved.Ports[:2]
	if d := scan(moved); len(d.Ports) != 2 {
		t.Fatalf("a moved name: %+v", d.Ports)
	}
}

// INV-22 with the default scan's nmap ports: a port outside the runner's fixed list but among nmap's most common ports (666 here)
// is checked by every scan whose service step says it probed it (ServiceScan.Probed), so one miss marks it and the second scan in
// a row that misses it closes it. Without that list (no service step, or one that did not say) the same port is never called
// missed or closed: the scan did not probe it.
func TestNotSeen_TopPortClosedOnlyByScansThatProbedIt(t *testing.T) {
	t.Parallel()
	top := make([]int, 1000)
	for i := range top {
		top[i] = i + 1
	}
	misses666 := func(s Snapshot) (PortRow, bool) {
		for _, p := range s.Ports {
			if p.Port == 666 {
				return p, true
			}
		}
		return PortRow{}, false
	}
	n := newNS(t)
	n.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: len(top), Probed: top}}
	n.scan(day, ports(80, 666))
	d2 := n.scan(day, ports(80))
	if p, ok := misses666(d2); !ok || p.Misses != 1 || p.Unchecked {
		t.Fatalf("after one miss: %+v", d2.Ports)
	}
	if !slices.Contains(notChecked(d2), "TCP ports other than the 1000 ports this scan probed: nmap's 1000 most common ports and the fixed list of commonly exposed ports.") {
		t.Fatalf("not checked = %q", notChecked(d2))
	}
	if d3 := n.scan(day, ports(80)); func() bool { _, ok := misses666(d3); return ok }() {
		t.Fatalf("two scans that probed it missed it, still open: %+v", d3.Ports)
	}

	unprobed := newNS(t) // no service step: only the runner's fixed list was probed
	unprobed.scan(day, ports(80, 666))
	for range 2 {
		s := unprobed.scan(day, ports(80))
		if p, ok := misses666(s); !ok || p.Misses != 0 || !p.Unchecked {
			t.Fatalf("a scan that did not probe 666 marked it: %+v", s.Ports)
		}
	}
}

// A default scan some of whose -sV batches did not finish says how many ports were not identified and that the next scan reads
// them first; those ports are not in Probed, so outside the runner's fixed list they are never missed or closed by that scan.
func TestNotSeen_UnfinishedBatchPortsAreSaidAndNotCounted(t *testing.T) {
	t.Parallel()
	n := newNS(t)
	n.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 2, Probed: []int{22, 80}, Unfinished: []int{10022, 18443}}}
	n.scan(day, ports(80, 18443))
	s := n.scan(day, ports(80))
	if !slices.Contains(notChecked(s), "Service identification of 2 ports did not finish this time (nmap's time limit for each batch of ports, or too little time left); the next scan reads them first.") {
		t.Fatalf("not checked = %q", notChecked(s))
	}
	for range 2 {
		s = n.scan(day, ports(80))
	}
	for _, p := range s.Ports {
		if p.Port == 18443 && (p.Misses != 0 || !p.Unchecked) {
			t.Fatalf("an unfinished port was counted as checked: %+v", p)
		}
	}
	if !slices.ContainsFunc(s.Ports, func(p PortRow) bool { return p.Port == 18443 }) {
		t.Fatalf("an unfinished port was closed: %+v", s.Ports)
	}
}

// When the address answers on almost every port, the scanner drops each port where -sV named no service, though it stays in Probed:
// such a port is not counted as checked, so a real service nmap cannot name (8444, outside the fixed list) found by a normal scan is
// kept through any number of those scans. A port of the fixed list is still checked there (the runner TCP-connects it): 8443 is
// missed, then closed.
func TestNotSeen_AnswersEverywhereDoesNotCheckDroppedPorts(t *testing.T) {
	t.Parallel()
	find := func(s Snapshot, port int) (PortRow, bool) {
		for _, p := range s.Ports {
			if p.Port == port {
				return p, true
			}
		}
		return PortRow{}, false
	}
	probed := append(make([]int, 0, 1002), 8443, 8444)
	for p := 1; p <= 1000; p++ {
		probed = append(probed, p)
	}
	slices.Sort(probed)
	n := newNS(t)
	n.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: len(probed), Probed: probed}}
	n.scan(day, ports(80, 8443, 8444))
	n.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: len(probed), Probed: probed, AnswersEverywhere: true}}
	s := n.scan(day, ports(80))
	if !slices.Contains(notChecked(s), notAnswersEverywhereKept) {
		t.Fatalf("not checked = %q", notChecked(s))
	}
	if p, ok := find(s, 8443); !ok || p.Misses != 1 {
		t.Fatalf("8443 (fixed list) after one answers-everywhere scan: %+v", s.Ports)
	}
	for i := range 3 {
		s = n.scan(day, ports(80))
		if p, ok := find(s, 8444); !ok || p.Misses != 0 || !p.Unchecked {
			t.Fatalf("answers-everywhere scan %d counted 8444 as checked: %+v", i+2, s.Ports)
		}
	}
	if _, ok := find(s, 8443); ok {
		t.Fatalf("8443 (fixed list), missed by two scans, is still open: %+v", s.Ports)
	}
}

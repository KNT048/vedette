package exposure

import (
	"testing"
	"time"
)

// INV-22 (D-560): a port the last observation had open and a scan that checked its address did not report is "missed once" and still
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

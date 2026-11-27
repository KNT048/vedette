package exposure

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corerun "github.com/knt048/vedette/core/run"
)

// fakeProbe is a Liveness that also tells a closed port from a silent one (PortProber): answer is what each port gets (PortOpen by
// default); asked records the ports each Probe call was asked about.
type fakeProbe struct {
	mu     sync.Mutex
	answer map[int]string
	asked  [][]int
}

func (f *fakeProbe) Alive(_ context.Context, _ netip.Addr, ports []int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, p := range ports {
		out[p] = f.answer[p] == "" || f.answer[p] == PortOpen
	}
	return out, nil
}

func (f *fakeProbe) Probe(_ context.Context, ip netip.Addr, ports []int) (map[int]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip.String() != ipA {
		return nil, nil
	}
	f.asked = append(f.asked, slices.Clone(ports))
	out := map[int]string{}
	for _, p := range ports {
		out[p] = f.answer[p]
		if out[p] == "" {
			out[p] = PortOpen
		}
	}
	return out, nil
}

// A WAF that blocks the box's public IP drops its packets to 80 and 443 (no answer, no reset) while 22 still answers: the runner and
// a trusted sweep both miss 80 and 443. Ports open before that now give no answer at all are not a miss: they stay open, the target
// says why in one line, and they close only when the third scan in a row, at least a day after the first, finds them silent too.
func TestSilentPorts_AWAFThatBlocksTheBoxClosesNothing(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{22, 80, 443}, swept(22, 80, 443), nil)
	probe := &fakeProbe{answer: map[int]string{80: PortSilent, 443: PortSilent}}
	e.svc.cfg.Liveness = probe
	r := scan([]int{22}, swept(22), nil)
	if state(80) != ServiceOpen || state(443) != ServiceOpen || closedByNewest(e) != 0 {
		t.Fatalf("after a scan to which 80 and 443 gave no answer at all: 80 %s, 443 %s, %d closed", state(80), state(443), closedByNewest(e))
	}
	if len(probe.asked) != 1 || !slices.Equal(probe.asked[0], []int{80, 443}) {
		t.Fatalf("the re-check asked about %v, want the ports open before that this scan missed [80 443]", probe.asked)
	}
	i := slices.IndexFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "silent_ports" })
	if i < 0 || !strings.Contains(r.NotChecked[i].Text, "Ports 80 and 443 of "+ipA+" were open before and gave no answer at all") ||
		!strings.Contains(r.NotChecked[i].Text, "If you closed them yourself, they are marked closed after three scans over a day.") {
		t.Fatalf("the target's line: %+v", r.NotChecked)
	}
	if n := e.count(`SELECT count(*) FROM core_run_log WHERE run_id = ? AND text LIKE 'Ports 80 and 443 of %gave no answer at all%'`, r.RunID); n != 1 {
		t.Fatalf("%d run log lines about the silent ports", n)
	}
	e.advance(13 * time.Hour)
	scan([]int{22}, swept(22), nil)
	if state(80) != ServiceOpen {
		t.Fatalf("80 after the second silent scan: %s", state(80))
	}
	e.advance(13 * time.Hour)
	scan([]int{22}, swept(22), nil)
	if state(80) != ServiceClosed || state(443) != ServiceClosed || state(22) != ServiceOpen {
		t.Fatalf("after three silent scans over more than a day: 80 %s, 443 %s, 22 %s", state(80), state(443), state(22))
	}
}

// Three silent scans within a few hours are not enough: the block may last that long.
func TestSilentPorts_ThreeSilentScansWithinADayCloseNothing(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{22, 80}, swept(22, 80), nil)
	e.svc.cfg.Liveness = &fakeProbe{answer: map[int]string{80: PortSilent}}
	for i := range 4 {
		scan([]int{22}, swept(22), nil)
		if state(80) != ServiceOpen {
			t.Fatalf("80 after silent scan %d within an hour: %s", i+1, state(80))
		}
	}
}

// A port that answers the re-check with a reset is closed: the rules of INV-22 apply as before (the runner and a trusted sweep both
// missed a port of the fixed list: closed at once). A port that accepts the re-check is open: the scan missed it, it is not a miss.
func TestSilentPorts_AResetClosesAndAnAnswerKeeps(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{22, 80, 443}, swept(22, 80, 443), nil)
	e.svc.cfg.Liveness = &fakeProbe{answer: map[int]string{80: PortClosed, 443: PortOpen}}
	scan([]int{22}, swept(22), nil)
	if state(80) != ServiceClosed {
		t.Fatalf("80, which answered the re-check with a reset: %s", state(80))
	}
	if state(443) != ServiceOpen {
		t.Fatalf("443, which accepted the re-check: %s", state(443))
	}
}

// The hint that the box could not reach its own public address (NAT loopback) is said only of the box's own IP: a typed IP of the
// box's list that a domain's name points at is scannable too, but it is not the box's, and the router of the box has nothing to do
// with it.
func TestLiveness_TheNATLoopbackHintIsOnlyForTheBoxsOwnIP(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.svc.SetRunner(&fakeRunner{content: Content{}})
	v := w.addIP(ipC)
	w.files.serve(ipC, "https", v.Token+"\n")
	if r := w.verify(v.ID); !r.Verified {
		t.Fatalf("the typed IP is not proved: %+v", r)
	}
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	box := w.detect(ipA)
	if _, err := w.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	st := ScanTarget{Kind: KindDomain, Value: "acme.example", User: "admin@acme.example"}
	if text := w.svc.lostText(w.ctx(), st, map[string][]int{ipC: {443}}); strings.Contains(text, "NAT loopback") {
		t.Fatalf("the typed IP %s gets the NAT loopback hint: %q", ipC, text)
	}
	if text := w.svc.lostText(w.ctx(), st, map[string][]int{ipA: {443}}); !strings.Contains(text, "NAT loopback") {
		t.Fatalf("the box's own IP %s does not get the NAT loopback hint: %q", ipA, text)
	}
}

// domainDisruptive is the deep seams with nmap's disruptive scripts: it records the addresses they ran on.
type domainDisruptive struct {
	*deepSeams
	ran []string
}

func (f *domainDisruptive) ScanDisruptive(_ context.Context, _ ScanTarget, ip netip.Addr, _ []int) (ServiceScan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, ip.String())
	return ServiceScan{}, nil
}

// A domain's deep scan in which the box's own address stops answering while the domain's other addresses still answer: the last
// step, nmap's disruptive scripts, runs on nothing, and its note says why (the box's address stopped answering), never that no open
// port was found or that no address is the box's own.
func TestDisruptive_ADomainWhoseOwnAddressStoppedAnsweringSaysSo(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, true)
	d.allGroups(d.idOfIP(ipA)) // the box's IP target too: the address takes both targets' settings
	svc := &domainDisruptive{deepSeams: d.seams}
	d.svc.cfg.Services = svc
	d.svc.cfg.Liveness = &fakeAlive{up: func(_ int, ip netip.Addr, _ int) bool { return ip.String() != ipA }}
	s := d.scan()
	run := d.runDetail(d.ctx(), s.RunID)
	st := stepOf(t, run, stepNameDisruptive)
	note := noteOf(st)
	if len(svc.ran) != 0 {
		t.Fatalf("the disruptive scripts ran on %v", svc.ran)
	}
	if st.Status != corerun.Skipped || !strings.Contains(note, ipA+":443 stopped answering during the scan") ||
		strings.Contains(note, notDisruptiveNoPorts) || strings.Contains(note, notDisruptiveNoAddress) {
		t.Fatalf("disruptive step = %s %q", st.Status, note)
	}
}

// "Three silent scans in a row": a scan to which the port accepted the re-check in between starts the count again. Silent, open,
// silent, silent over more than a day is two silent scans in a row, not three, so the port stays open.
func TestSilentPorts_AnAnswerInBetweenStartsTheSilentCountAgain(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{22, 80}, swept(22, 80), nil)
	probe := &fakeProbe{answer: map[int]string{80: PortSilent}}
	e.svc.cfg.Liveness = probe
	scan([]int{22}, swept(22), nil) // silent
	probe.answer = map[int]string{80: PortOpen}
	scan([]int{22}, swept(22), nil) // the scan missed it, the re-check got an answer: open
	probe.answer = map[int]string{80: PortSilent}
	e.advance(13 * time.Hour)
	scan([]int{22}, swept(22), nil) // silent
	e.advance(13 * time.Hour)
	scan([]int{22}, swept(22), nil) // silent, more than a day after the first silent scan
	if state(80) != ServiceOpen {
		t.Fatalf("80 after silent, open, silent, silent: %s, want open (two silent scans in a row since it answered)", state(80))
	}
	e.advance(13 * time.Hour)
	scan([]int{22}, swept(22), nil) // the third silent scan in a row, more than a day after the first of them
	if state(80) != ServiceClosed {
		t.Fatalf("80 after three silent scans in a row over more than a day: %s", state(80))
	}
}

// A scan in which the port accepted the re-check, or gave no answer at all, is not a miss of it, so it is never "the scan before
// that missed it too" of the two-miss rule: a port outside the fixed list that one probe of each scan misses (the sweep; no re-check)
// needs two scans that really missed it to close.
func TestSilentPorts_AnAnsweredOrSilentScanIsNotTheMissBefore(t *testing.T) {
	t.Parallel()
	for _, before := range []string{PortOpen, PortSilent} {
		t.Run(before, func(t *testing.T) {
			t.Parallel()
			e, scan, state := deepScans(t)
			scan([]int{22}, swept(22, 32400), nil)
			e.svc.cfg.Liveness = &fakeProbe{answer: map[int]string{32400: before}}
			scan([]int{22}, swept(22), nil)
			e.svc.cfg.Liveness = nil
			scan([]int{22}, swept(22), nil) // the first scan that really missed it
			if state(32400) != ServiceOpen {
				t.Fatalf("32400 after a scan to which it was %s, then one miss: %s, want open (one miss)", before, state(32400))
			}
			scan([]int{22}, swept(22), nil) // the second
			if state(32400) != ServiceClosed {
				t.Fatalf("32400 after two scans that missed it: %s", state(32400))
			}
		})
	}
}

// Two probes of one run that agree close a port at once, outside the fixed list too: a trusted sweep missed it and the re-check got a
// reset from the target.
func TestSilentPorts_ASweepMissAndAResetOfTheRecheckCloseAtOnce(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{22}, swept(22, 32400), nil)
	e.svc.cfg.Liveness = &fakeProbe{answer: map[int]string{32400: PortClosed}}
	scan([]int{22}, swept(22), nil)
	if state(32400) != ServiceClosed || closedByNewest(e) != 1 {
		t.Fatalf("32400 after a sweep miss and a reset to the re-check: %s, %d closed", state(32400), closedByNewest(e))
	}
}

// The target's line about silent ports is kept when many ports are silent: a line longer than a "Not checked" line may be is dropped
// when the results are written, so the line names a few ports and counts the rest.
func TestSilentPorts_ManySilentPortsKeepTheirLine(t *testing.T) {
	t.Parallel()
	e, scan, _ := deepScans(t)
	ports := []int{22}
	answer := map[int]string{}
	for p := 10001; p <= 10030; p++ {
		ports = append(ports, p)
		answer[p] = PortSilent
	}
	scan([]int{22}, swept(ports...), nil)
	e.svc.cfg.Liveness = &fakeProbe{answer: answer}
	r := scan([]int{22}, swept(22), nil)
	i := slices.IndexFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "silent_ports" })
	if i < 0 || !strings.Contains(r.NotChecked[i].Text, "were open before and gave no answer at all") {
		t.Fatalf("the target's line about 30 silent ports: %+v", r.NotChecked)
	}
}

// A target that had open ports and of which no port answers the box at all (a WAF or firewall that blocks the box's public IP drops
// every packet) is not "done, 0 ports open": the run ends partly done with one plain line, the ports stay open (the silent rule may
// still close them after three scans over a day), and nothing is counted closed. The box's own IP gets the NAT-loopback hint instead.
func TestUnanswered_NoPortOfTheBoxsOwnIPAnsweredEndsPartlyDone(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{22, 80, 443}, swept(22, 80, 443), nil)
	e.svc.cfg.Liveness = &fakeProbe{answer: map[int]string{22: PortSilent, 80: PortSilent, 443: PortSilent}}
	r := scan(nil, ServiceScan{Ports: 65535}, nil)
	d := e.runDetail(e.ctx(), r.RunID)
	want := "No port of " + ipA + " answered this box."
	if d.Status != corerun.Partial || !strings.Contains(d.Summary, want) {
		t.Fatalf("run = %s %q, want partly done saying %q", d.Status, d.Summary, want)
	}
	i := slices.IndexFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "unanswered" })
	if i < 0 || !strings.HasPrefix(r.NotChecked[i].Text, want) || !strings.Contains(r.NotChecked[i].Text, "NAT loopback") {
		t.Fatalf("the target's line: %+v", r.NotChecked)
	}
	if state(22) != ServiceOpen || state(80) != ServiceOpen || state(443) != ServiceOpen || closedByNewest(e) != 0 {
		t.Fatalf("after a scan nothing answered: 22 %s, 80 %s, 443 %s, %d closed", state(22), state(80), state(443), closedByNewest(e))
	}
}

// The same on a domain whose addresses are not the box's: the line names the box's public IP to allow in the site's WAF or firewall.
func TestUnanswered_NoPortOfADomainAnsweredNamesTheBoxsIP(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.scan()
	if n := d.count(`SELECT count(*) FROM exp_service WHERE target_id = ? AND state = 'open'`, d.dom.ID); n == 0 {
		t.Fatal("the first scan found no open port")
	}
	d.advance(ScanEvery + time.Minute)
	d.seams.none = true
	d.run.content.Ports = nil
	s := d.scan()
	run := d.runDetail(d.ctx(), s.RunID)
	want := "No port of " + ipB + " (www.acme.example and api.acme.example) answered this box. If the site has a WAF or firewall, allow this box's public IP " + ipA + " during deep scans."
	if run.Status != corerun.Partial || !strings.Contains(run.Summary, "answered this box") {
		t.Fatalf("run = %s %q", run.Status, run.Summary)
	}
	if !hasLine(s, want) {
		t.Fatalf("not checked %q, want %q", notChecked(s), want)
	}
	if n := d.count(`SELECT count(*) FROM exp_service WHERE target_id = ? AND state = 'closed'`, d.dom.ID); n != 0 {
		t.Fatalf("%d services closed by a scan nothing answered", n)
	}
}

// A target that answers with resets (its owner closed every port) did answer: a plain result, no such line, the run is done.
func TestUnanswered_ResetsAreAnAnswer(t *testing.T) {
	t.Parallel()
	e, scan, _ := deepScans(t)
	scan([]int{80}, swept(80), nil)
	e.svc.cfg.Liveness = &fakeProbe{answer: map[int]string{80: PortClosed}}
	r := scan(nil, ServiceScan{Ports: 65535}, nil)
	d := e.runDetail(e.ctx(), r.RunID)
	if d.Status != corerun.Done || slices.ContainsFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "unanswered" }) {
		t.Fatalf("run = %s %q, lines %+v", d.Status, d.Summary, r.NotChecked)
	}
}

// A target whose only rows were ports the network answers (retired by this scan) had no open port of its own: no such line.
func TestUnanswered_OnlyRowsOfTheNetworkSayNothing(t *testing.T) {
	t.Parallel()
	e, scan, state := deepScans(t)
	scan([]int{5060}, swept(5060), nil) // no check: the network's 5060 stored as the target's
	e.svc.cfg.Path = &fakePath{ports: []int{5060}}
	r := scan([]int{5060}, swept(5060), nil)
	d := e.runDetail(e.ctx(), r.RunID)
	if state(5060) != ServiceClosed || d.Status != corerun.Done || slices.ContainsFunc(r.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "unanswered" }) {
		t.Fatalf("5060 %s, run = %s %q, lines %+v", state(5060), d.Status, d.Summary, r.NotChecked)
	}
}

// The line speaks of the addresses this scan asked only: the open port of a name whose address lookup got no answer this time
// (INV-27: its rows are kept as they were) was not asked, so a scan whose other names answered nothing ends done, with no such line.
func TestUnanswered_PortsOfANameNotLookedUpSayNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	dom := e.committedDomain()
	day1 := Content{
		Hosts: []HostRow{{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassPublic, Contacted: true}}},
			{Name: "vpn.acme.example", IP: ipB, Source: "wordlist", IPs: []HostIP{{IP: ipB, Family: "ipv4", Class: ClassPublic, Contacted: true}}}},
		Ports: []PortRow{{IP: ipB, Port: 443, Service: "https", HTTP: true}},
	}
	run := &fakeRunner{content: day1}
	e.svc.SetRunner(run)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_service WHERE target_id = ? AND state = 'open'`, dom.ID); n != 1 {
		t.Fatalf("%d open services after the first scan, want 1", n)
	}
	e.advance(24 * time.Hour)
	run.content = Content{Hosts: day1.Hosts[:1], Ports: []PortRow{}, Unresolved: []string{"vpn.acme.example"}}
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	d := e.runDetail(e.ctx(), s.RunID)
	if d.Status != corerun.Done || slices.ContainsFunc(s.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "unanswered" }) {
		t.Fatalf("run = %s %q, lines %q", d.Status, d.Summary, notChecked(s))
	}
}

// probeRecorder is a PortProber that records which ports of which address it was asked about; every port accepts the liveness
// check, and the re-check gets no answer at all.
type probeRecorder struct {
	mu    sync.Mutex
	asked map[string][]int
}

func (f *probeRecorder) Alive(_ context.Context, _ netip.Addr, ports []int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, p := range ports {
		out[p] = true
	}
	return out, nil
}

func (f *probeRecorder) Probe(_ context.Context, ip netip.Addr, ports []int) (map[int]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.asked == nil {
		f.asked = map[string][]int{}
	}
	f.asked[ip.String()] = append(f.asked[ip.String()], ports...)
	out := map[int]string{}
	for _, p := range ports {
		out[p] = PortSilent
	}
	return out, nil
}

// The re-check connects only to ports this scan may probe on the address (PRIVACY flow 9): after the domain's testing terms are
// withdrawn, a hosting address is checked by name on 80 and 443 only, so a port an earlier deep scan stored there (22) gets no
// connect, however it is stored.
func TestSilentPorts_TheRecheckStaysInTheScopeOfTheScan(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.seams.extra = []ServiceRow{{IP: ipB, Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6"}}
	d.scan()
	if n := d.count(`SELECT count(*) FROM exp_service WHERE ip = ? AND port = 22 AND state = 'open'`, ipB); n != 1 {
		t.Fatalf("the deep scan stored %d open rows of %s:22", n, ipB)
	}
	if _, err := d.svc.RevokeTerms(d.ctx(), "admin@acme.example", d.dom.ID); err != nil {
		t.Fatal(err)
	}
	d.advance(ScanEvery + time.Minute)
	d.seams.mu.Lock()
	d.seams.extra = nil
	d.seams.mu.Unlock()
	rec := &probeRecorder{}
	d.svc.cfg.Liveness = rec
	d.scan()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if slices.ContainsFunc(rec.asked[ipB], func(p int) bool { return p != 80 && p != 443 }) {
		t.Fatalf("the re-check of a scan without testing terms connected to %s on %v", ipB, rec.asked[ipB])
	}
}

// Each address that stopped answering gets the hint of its own vantage, in the same words as its line: the box's own IP the NAT
// loopback hint, any other address what to allow; never the NAT loopback hint for an address that is not the box's.
func TestLiveness_EachLostAddressGetsTheHintOfItsOwnVantage(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.svc.SetRunner(&fakeRunner{content: Content{}})
	v := w.addIP(ipC)
	w.files.serve(ipC, "https", v.Token+"\n")
	if r := w.verify(v.ID); !r.Verified {
		t.Fatalf("the typed IP is not proved: %+v", r)
	}
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	box := w.detect(ipA)
	if _, err := w.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	st := ScanTarget{Kind: KindDomain, Value: "acme.example", User: "admin@acme.example"}
	text := w.svc.lostText(w.ctx(), st, map[string][]int{ipA: {443}, ipC: {8443}})
	if strings.Count(text, "NAT loopback") != 1 {
		t.Fatalf("the NAT loopback hint is not said once, for the box's own IP only: %q", text)
	}
	own := ipA + ":443 stopped answering during the scan. " + natHint
	other := ipC + ":8443 stopped answering during the scan. If the site has a WAF or firewall, allow this box's public IP"
	if !strings.Contains(text, own) || !strings.Contains(text, other) {
		t.Fatalf("each address does not get the hint of its own vantage: %q", text)
	}
}

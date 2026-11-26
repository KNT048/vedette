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
	if i < 0 || !strings.Contains(r.NotChecked[i].Text, "Ports 80 and 443 of "+ipA+" were open before and gave no answer at all") {
		t.Fatalf("the target's line: %+v", r.NotChecked)
	}
	if n := e.count(`SELECT count(*) FROM core_run_log WHERE run_id = ? AND text LIKE '%gave no answer at all%'`, r.RunID); n != 1 {
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

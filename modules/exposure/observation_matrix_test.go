package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// The observation matrix of an external scan. Every probe the box sends is seen from the box's own network position (its vantage):
// the box's own public IP is reached from inside through the router's NAT loopback, a firewall or WAF may block the box's address
// only, a firewall helper may answer some ports for every destination, an IPS may start dropping the box mid-run. What the box
// observes is therefore a fact about the path as much as about the target. Each row below describes one vantage (what each probe
// gets, phase by phase), a history (the rows a clean earlier scan stored) and what the product should conclude: the stored port
// rows, the run's outcome, a step's outcome and the "Not checked" line the customer reads.
//
// The rows drive the real scan (runScan, coverage, the closing rules, liveness, the re-check, the network-path check) through fakes
// built from one description of the network (omNet), so a row says what the network does, not which function decides. Rows the
// current code gets wrong fail with what differs. Several observations cannot be passed through the current ports at all (a reset
// the network gives for a never-routed address, the vantage of a run); their rows fail until the scan takes them in.

// omAnswer is what one TCP connect from the box got.
type omAnswer string

const (
	omSynAck  omAnswer = "syn-ack" // the connection was accepted
	omReset   omAnswer = "reset"   // a TCP reset, or an ICMP refusal (connect reports both as refused)
	omSilence omAnswer = "silence" // no answer at all
)

// omPhase is when in a run a probe is sent, in the order a deep scan of an IP sends them.
type omPhase int

const (
	omRunner  omPhase = iota // the runner's connect to the fixed list of commonly exposed ports
	omSweep                  // nmap's sweep of every TCP port, with service identification
	omAlive                  // the liveness checks before each engine step and before the results are written
	omRecheck                // the re-check of the ports open before that this scan missed
)

// omTestNet is the never-routed address the network-path check connects to (RFC 5737).
const omTestNet = "192.0.2.1"

// omNet is the network as the box sees it in one run: what a probe of phase p to ip:port gets. Probes to omTestNet are the
// network-path check; their phase is omRunner.
type omNet func(p omPhase, ip string, port int) omAnswer

// omHost is a target seen over a clean path: a syn-ack on open, rest on every other port (omReset for a host that is up, omSilence
// for one whose firewall drops what is not open); a never-routed address answers nothing.
func omHost(rest omAnswer, open ...int) omNet {
	return func(_ omPhase, ip string, port int) omAnswer {
		switch {
		case ip == omTestNet:
			return omSilence
		case slices.Contains(open, port):
			return omSynAck
		}
		return rest
	}
}

// omEverything is a target every port of which answers a, from every phase (a router answering for its own address, a block of
// every packet); the path is clean.
func omEverything(a omAnswer) omNet {
	return func(_ omPhase, ip string, _ int) omAnswer {
		if ip == omTestNet {
			return omSilence
		}
		return a
	}
}

// omPath is n behind a network that answers a on ports for every destination, the never-routed address too (a firewall's SIP or
// SCCP helper with a syn-ack, an egress filter with a reset).
func omPath(n omNet, a omAnswer, ports ...int) omNet {
	return func(p omPhase, ip string, port int) omAnswer {
		if slices.Contains(ports, port) {
			return a
		}
		return n(p, ip, port)
	}
}

// omFrom is n until phase from, then then: the vantage changes during the run (a NAT loopback lost, an IPS that starts dropping).
func omFrom(n omNet, from omPhase, then omNet) omNet {
	return func(p omPhase, ip string, port int) omAnswer {
		if ip != omTestNet && p >= from {
			return then(p, ip, port)
		}
		return n(p, ip, port)
	}
}

// omOnly is n in phase only, then for every other phase.
func omOnly(n omNet, only omPhase, other omNet) omNet {
	return func(p omPhase, ip string, port int) omAnswer {
		if ip != omTestNet && p != only {
			return other(p, ip, port)
		}
		return n(p, ip, port)
	}
}

// omPorts is every port a run probes in this harness: the fixed list and a few outside it (2000 SCCP, 32400 a media server).
func omPorts() []int {
	return append(slices.Clone(commonports.Numbers()), 2000, 32400)
}

// omWire is the box's probes, all answered from one omNet: the runner, nmap's sweep, the network-path check, the liveness checks
// and the re-check. pathErr makes the network-path check fail.
type omWire struct {
	mu      sync.Mutex
	net     omNet
	ip      string
	pathErr bool
	nmapErr error
}

func (w *omWire) answer(p omPhase, ip string, port int) omAnswer {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.net(p, ip, port)
}

// Scan is the runner: a connect to the fixed list; a refused port marks the address as having answered (the real runner's Refused).
func (w *omWire) Scan(_ context.Context, st ScanTarget) (Content, error) {
	c := Content{}
	if st.Kind == KindDomain { // one name on a hosting address, checked by name on 80 and 443
		c.Hosts = []HostRow{{Name: "www." + st.Value, IP: w.ip, Source: "wordlist", IPs: []HostIP{{IP: w.ip, Family: "ipv4", Class: ClassPublic, Contacted: true}}}}
		for _, port := range []int{80, 443} {
			if w.answer(omRunner, w.ip, port) == omSynAck {
				c.Ports = append(c.Ports, PortRow{IP: w.ip, Port: port, Service: "http", Ident: IdentProbed})
			}
		}
		return c, nil
	}
	for _, port := range commonports.Numbers() {
		switch w.answer(omRunner, st.Value, port) {
		case omSynAck:
			c.Ports = append(c.Ports, PortRow{IP: st.Value, Port: port, Service: "http", Ident: IdentProbed})
		case omReset:
			c.Answered = map[string]bool{st.Value: true}
		}
	}
	return c, nil
}

// ScanServices is nmap's deep sweep of every TCP port, with service identification of the open ones.
func (w *omWire) ScanServices(_ context.Context, st ScanTarget, ip netip.Addr) (ServiceScan, error) {
	if ip.String() != st.Value {
		return ServiceScan{}, errors.New("asked for another address than the target")
	}
	if w.nmapErr != nil {
		return ServiceScan{}, w.nmapErr
	}
	s := ServiceScan{Ports: 65535}
	for _, port := range omPorts() {
		switch w.answer(omSweep, st.Value, port) {
		case omSynAck:
			s.Services = append(s.Services, ServiceRow{IP: st.Value, Port: port, Name: "http", Product: "nginx", Version: "1.27.0", Method: "probed"})
		case omReset:
			s.Refused = true
		}
	}
	return s, nil
}

// AnsweredByPath is the network-path check: a port that a never-routed address accepts is answered by the network. The current port
// can carry only accepted connects, so a reset the network gives for every destination is not passed on.
func (w *omWire) AnsweredByPath(_ context.Context, ports []int) ([]int, error) {
	if w.pathErr {
		return nil, errors.New("the check could not run")
	}
	var out []int
	for _, p := range ports {
		if w.answer(omRunner, omTestNet, p) == omSynAck {
			out = append(out, p)
		}
	}
	return out, nil
}

// Alive is the liveness check.
func (w *omWire) Alive(_ context.Context, ip netip.Addr, ports []int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, p := range ports {
		out[p] = w.answer(omAlive, ip.String(), p) == omSynAck
	}
	return out, nil
}

// Probe is the re-check before the results are written.
func (w *omWire) Probe(_ context.Context, ip netip.Addr, ports []int) (map[int]string, error) {
	out := map[int]string{}
	for _, p := range ports {
		out[p] = map[omAnswer]string{omSynAck: PortOpen, omReset: PortClosed, omSilence: PortSilent}[w.answer(omRecheck, ip.String(), p)]
	}
	return out, nil
}

// omKind is which target a row scans.
type omKind int

const (
	omOwnIP  omKind = iota // the box's own public IP, which the box reaches from inside the network (NAT loopback)
	omTyped                // a public IP the customer typed and proved (a VPS, a host elsewhere): reached over the Internet
	omDomain               // a proved domain whose name points at a hosting address, checked by name (no testing terms)
)

// omStep is the outcome a row wants of one step of the run.
type omStep struct {
	name   string
	status corerun.Status
}

// omWant is what the product should conclude after the row's last scan. A nil or empty field checks nothing.
type omWant struct {
	open    []int          // ports whose stored row is open
	closed  []int          // ports whose stored row is closed
	notOpen []int          // ports with no open row (closed, retired or never stored)
	absent  []int          // ports never stored
	run     corerun.Status // the run's outcome
	line    []string       // a "Not checked" line of the last scan contains each of these (case-insensitive)
	steps   []omStep
}

// omRow is one cell of the matrix that changes an outcome.
type omRow struct {
	name   string
	kind   omKind
	before []omNet // clean scans that store the history, in order
	// beforeNoPath: the history scans run without the network-path check (rows stored before the check existed).
	beforeNoPath bool
	now          omNet
	scans        int           // scans of now (default 1)
	gap          time.Duration // between the scans of now (default ScanEvery and a minute)
	pathErr      bool
	nmapErr      error
	want         omWant
	// decision names the product rule the row's expectation changes; "" when the expectation follows the rules as written.
	decision string
}

// omRows is the matrix. Names: vantage/history/observation.
var omRows = []omRow{
	// ---- a clean path: what the box sees is the target ----
	{
		name: "clean_path/open_before/ports_keep_answering", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omHost(omReset, 22, 80, 443),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Done},
	},
	{
		name: "clean_path/open_before/target_resets_a_fixed_list_port", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omHost(omReset, 22, 443),
		want: omWant{open: []int{22, 443}, closed: []int{80}, run: corerun.Done},
	},
	{
		name: "clean_path/open_before/full_sweep_and_runner_miss_port_53", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 53)}, now: omHost(omReset, 22),
		want: omWant{open: []int{22}, closed: []int{53}, run: corerun.Done},
	},
	{
		// Two probes of this run say 32400 is closed: the trusted sweep missed it and the re-check got a reset from the target. The
		// fixed-list rule closes on two probes of one run; the re-check is a second probe too, but the closing rules ignore it.
		name: "clean_path/open_before/sweep_miss_and_recheck_reset_outside_fixed_list", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 32400)}, now: omHost(omReset, 22),
		want: omWant{open: []int{22}, closed: []int{32400}, run: corerun.Done},
	},
	{
		// nmap's sweep failed: ports outside the fixed list were not checked. The ports step is Failed, the run says Done.
		name: "clean_path/open_before/sweep_failed", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 32400)}, now: omHost(omReset, 22, 80, 32400), nmapErr: errors.New("nmap exited 1"),
		want: omWant{open: []int{22, 80, 32400}, run: corerun.Partial},
	},

	// ---- the box's own IP through NAT loopback ----
	{
		// The router lost its NAT loopback before the run and answers its own address with resets: every port open before now
		// resets and nothing opens. From inside, that is the box losing its view, not the owner closing every port at once.
		name: "own_ip_loopback/open_before/lost_before_run_router_resets_every_port", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 443, 32400)}, now: omEverything(omReset),
		want: omWant{open: []int{22, 80, 443, 32400}, run: corerun.Partial, line: []string{ipA, "loopback"}},
	},
	{
		name: "own_ip_loopback/open_before/lost_before_run_no_answer_at_all", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omEverything(omSilence),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Partial, line: []string{ipA, "loopback"}},
	},
	{
		name: "own_ip_loopback/open_before/lost_before_run_no_answer_for_three_scans_over_a_day", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80)}, now: omEverything(omSilence), scans: 3, gap: 13 * time.Hour,
		want:     omWant{open: []int{22, 80}, run: corerun.Partial},
		decision: "INV-22 (2) closes every port of an address that answered nothing at all to three scans over a day; the model keeps them, marked as not reached, until the target itself answers",
	},
	{
		name: "own_ip_loopback/open_before/lost_mid_run", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omFrom(omHost(omReset, 22, 80, 443), omAlive, omEverything(omSilence)),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Partial, line: []string{ipA, "loopback"}},
	},

	// ---- an external host behind a firewall or WAF that blocks the box ----
	{
		// A VPS whose own firewall drops what is not open (no resets at all), behind a WAF that blocks the box on 80 and 443.
		name: "external_waf/open_before/blocks_web_ports_from_start", kind: omTyped,
		before: []omNet{omHost(omSilence, 22, 80, 443)}, now: omPath(omHost(omSilence, 22), omSilence, 80, 443),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Partial, line: []string{ipC, "80"}},
	},
	{
		name: "external_waf/open_before/blocks_every_port_from_start", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omEverything(omSilence),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Partial, line: []string{ipC}},
	},
	{
		name: "external_waf/open_before/blocks_mid_run", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omFrom(omHost(omReset, 22, 80, 443), omAlive, omEverything(omSilence)),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Partial, line: []string{ipC}},
	},
	{
		// The same observations as the lost NAT loopback with resets, over a clean path to a host elsewhere: the host is up and every
		// service stopped. Here the resets are the target's.
		name: "external_clean/open_before/host_up_every_port_resets", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omEverything(omReset),
		want: omWant{closed: []int{22, 80, 443}, run: corerun.Done},
	},

	{
		// A WAF or CDN in front of the domain's hosting address drops the box from the start: the check by name gets nothing on 80
		// and 443. The silent-port re-check never runs on a domain's address checked by name, so two scans close both.
		name: "hosting_waf/open_before/blocks_the_box_on_the_names_address", kind: omDomain,
		before: []omNet{omHost(omReset, 80, 443)}, now: omEverything(omSilence), scans: 2,
		want: omWant{open: []int{80, 443}, run: corerun.Partial, line: []string{ipB}},
	},

	// ---- rate limiting or an IPS that drops the box after some requests ----
	{
		// The runner saw 22, 80 and 443; nmap's sweep then got answers from 22 only (an IPS cut in), and the ban was lifted before the
		// liveness check. The sweep is not trusted (coverage), but its step says "1 open TCP port found." and the run says Done.
		name: "rate_limit/open_before/ips_cuts_the_sweep", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 80, 443)},
		now:    omOnly(omPath(omHost(omReset, 22), omSilence, 80, 443), omSweep, omHost(omReset, 22, 80, 443)),
		want: omWant{open: []int{22, 80, 443}, run: corerun.Partial,
			steps: []omStep{{stepNamePortsDeep, corerun.Partial}}},
	},

	// ---- a middlebox that answers some ports for every destination ----
	{
		name: "middlebox_synack/never_seen/sip_and_sccp_helpers", kind: omOwnIP,
		now:  omPath(omHost(omReset, 22), omSynAck, 2000, 5060),
		want: omWant{open: []int{22}, absent: []int{2000, 5060}, run: corerun.Done, line: []string{"5060", "your own network"}},
	},
	{
		name: "middlebox_synack/open_before/real_sip_service_neither_seen_nor_missed", kind: omOwnIP,
		before: []omNet{omHost(omReset, 22, 5060)}, now: omPath(omHost(omReset, 22, 5060), omSynAck, 5060),
		want: omWant{open: []int{22, 5060}, run: corerun.Done, line: []string{"5060"}},
	},
	{
		// Rows of 2000 and 5060 stored by scans before the network-path check existed: the network answers them, so they were never
		// the target's, yet nothing ever closes them.
		name: "middlebox_synack/phantom_rows_stored_before_the_check/check_now_wired", kind: omOwnIP,
		before: []omNet{omPath(omHost(omReset, 22), omSynAck, 2000, 5060)}, beforeNoPath: true,
		now:  omPath(omHost(omReset, 22), omSynAck, 2000, 5060),
		want: omWant{open: []int{22}, notOpen: []int{2000, 5060}, run: corerun.Done},
	},
	{
		// The network-path check failed: 5060 may be the firewall's helper. The run cannot tell and says nothing.
		name: "middlebox_synack/never_seen/path_check_fails", kind: omOwnIP,
		now: omPath(omHost(omReset, 22), omSynAck, 5060), pathErr: true,
		want: omWant{open: []int{22}, run: corerun.Partial, line: []string{"5060"}},
	},
	{
		// An egress filter on the box's network refuses port 25 to every address (an ISP or office rule): the box gets a reset from
		// 25 of a mail server that is open from the Internet. A reset that a never-routed address gets too is the network's.
		name: "middlebox_reset/open_before/egress_filter_refuses_a_port_everywhere", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 25)}, now: omPath(omHost(omReset, 22, 25), omReset, 25),
		want: omWant{open: []int{22, 25}, run: corerun.Done, line: []string{"25"}},
	},
}

// omFence is the Vedette host's fence for a typed IP: it gives the target's own token.
type omFence string

func (f omFence) Token(context.Context, string) (string, error) { return string(f), nil }
func (f omFence) Forget(context.Context, string) error          { return nil }

// omEnv is one row's box: a target ready for the deep scan (commitment and testing terms without the disruptive checks).
type omEnv struct {
	*env
	id   string
	ip   string
	wire *omWire
}

func newOMEnv(t *testing.T, kind omKind) *omEnv {
	t.Helper()
	e := newEnv(t)
	o := &omEnv{env: e, wire: &omWire{}}
	switch kind {
	case omOwnIP:
		ips := e.detect(ipA)
		o.id, o.ip = ips[0].ID, ipA
	case omTyped:
		files := &fileSite{files: map[string]string{}}
		e.svc.cfg.IPFetch = files
		v, err := e.svc.AddTarget(e.ctx(), "admin@acme.example", KindIP, ipC)
		if err != nil {
			t.Fatal(err)
		}
		files.serve(ipC, "http", v.Token)
		e.svc.cfg.DomainFence = omFence(v.Token) // the host's fence lists the typed IP with its own token: its deep steps run
		e.advance(DomainCheckEvery)
		if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", v.ID); err != nil || !r.Verified {
			t.Fatalf("verifying the typed IP: %+v %v", r, err)
		}
		o.id, o.ip = v.ID, ipC
	case omDomain:
		v := e.addVerifiedDomain()
		o.id, o.ip = v.ID, ipB
	}
	if _, err := e.commit(o.id); err != nil {
		t.Fatal(err)
	}
	if kind != omDomain {
		e.acceptTerms(o.id, false)
	}
	o.wire.ip = o.ip
	e.svc.SetRunner(o.wire)
	e.svc.cfg.Services = o.wire
	e.svc.cfg.Liveness = o.wire
	return o
}

// scan runs one deep scan of the target over n, with or without the network-path check.
func (o *omEnv) scan(n omNet, path bool, pathErr bool, nmapErr error) ScanResult {
	o.t.Helper()
	o.wire.mu.Lock()
	o.wire.net, o.wire.pathErr, o.wire.nmapErr = n, pathErr, nmapErr
	o.wire.mu.Unlock()
	o.svc.cfg.Path = nil
	if path {
		o.svc.cfg.Path = o.wire
	}
	r, err := o.svc.Scan(o.ctx(), "admin@acme.example", o.id)
	if err != nil {
		o.t.Fatalf("the scan: %v", err)
	}
	return r
}

// state is the stored state of a port of the target: open, closed, or "" when no row was ever stored.
func (o *omEnv) state(port int) string {
	o.t.Helper()
	var st string
	err := o.db.Reader().QueryRowContext(o.ctx(), `SELECT state FROM exp_service WHERE ip = ? AND port = ?`, o.ip, port).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	if err != nil {
		o.t.Fatal(err)
	}
	return st
}

// runRow runs a row and returns what differs from its expectation, and the run of its last scan.
func runRow(t *testing.T, row omRow) ([]string, corerun.Detail) {
	t.Helper()
	o := newOMEnv(t, row.kind)
	for _, b := range row.before {
		o.scan(b, !row.beforeNoPath, false, nil)
		o.advance(ScanEvery + time.Minute)
	}
	scans, gap := max(row.scans, 1), row.gap
	if gap == 0 {
		gap = ScanEvery + time.Minute
	}
	var r ScanResult
	for i := range scans {
		if i > 0 {
			o.advance(gap)
		}
		r = o.scan(row.now, true, row.pathErr, row.nmapErr)
	}
	d := o.runDetail(o.ctx(), r.RunID)
	var diff []string
	for _, p := range row.want.open {
		if st := o.state(p); st != ServiceOpen {
			diff = append(diff, fmt.Sprintf("port %d is %q, want open", p, st))
		}
	}
	for _, p := range row.want.closed {
		if st := o.state(p); st != ServiceClosed {
			diff = append(diff, fmt.Sprintf("port %d is %q, want closed", p, st))
		}
	}
	for _, p := range row.want.notOpen {
		if st := o.state(p); st == ServiceOpen {
			diff = append(diff, fmt.Sprintf("port %d is open, want it closed or retired", p))
		}
	}
	for _, p := range row.want.absent {
		if st := o.state(p); st != "" {
			diff = append(diff, fmt.Sprintf("port %d has a %q row, want none", p, st))
		}
	}
	if row.want.run != "" && d.Status != row.want.run {
		why := ""
		if d.Error != nil {
			why = " (" + *d.Error + ")"
		}
		diff = append(diff, fmt.Sprintf("the run is %s%s, want %s", d.Status, why, row.want.run))
	}
	if len(row.want.line) > 0 {
		var lines []string
		for _, n := range r.NotChecked {
			lines = append(lines, n.Text)
		}
		found := slices.ContainsFunc(r.NotChecked, func(n NotCheckedRow) bool {
			for _, part := range row.want.line {
				if !strings.Contains(strings.ToLower(n.Text), strings.ToLower(part)) {
					return false
				}
			}
			return true
		})
		if !found {
			diff = append(diff, fmt.Sprintf("no \"Not checked\" line contains %q; the lines: %q", row.want.line, lines))
		}
	}
	for _, w := range row.want.steps {
		st := stepOf(t, d, w.name)
		if st.Status != w.status {
			diff = append(diff, fmt.Sprintf("step %q is %s (%q), want %s", w.name, st.Status, noteOf(st), w.status))
		}
	}
	return diff, d
}

// TestObservationMatrix runs every row of the matrix. A failing row names what the product concludes that it should not.
func TestObservationMatrix(t *testing.T) {
	t.Parallel()
	for _, row := range omRows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			diff, _ := runRow(t, row)
			if len(diff) == 0 {
				return
			}
			msg := strings.Join(diff, "\n  ")
			if row.decision != "" {
				msg += "\n  (the expectation changes a rule: " + row.decision + ")"
			}
			t.Errorf("%s:\n  %s", row.name, msg)
		})
	}
}

// TestObservationMatrix_EveryDoneStepSaysWhatItDid: in every row, a step that ended done has a note. A step done with no note is a
// step that may never have run.
func TestObservationMatrix_EveryDoneStepSaysWhatItDid(t *testing.T) {
	t.Parallel()
	for _, row := range omRows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, d := runRow(t, row)
			for _, st := range d.Steps {
				if st.Status == corerun.Done && strings.TrimSpace(noteOf(st)) == "" {
					t.Errorf("step %q is done with no note", st.Name)
				}
			}
		})
	}
}

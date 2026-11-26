package exposure

import (
	"cmp"
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
	sameErr bool // the comparison of a target's answer with the network's fails
	nmapErr error
	// A domain's scan: class is the kind of the name's address (ClassPublic: hosting; ClassBox: the box's own IP); allPorts makes
	// the runner report every port of that address (it stands in for an earlier deep scan); dnsFails makes the name's lookup get no
	// answer this time (the row is carried forward, nothing is sent to the address).
	class    string
	allPorts bool
	dnsFails bool
	// carryFlags: the row carried forward for a failed lookup keeps the scan before's flags (Contacted) as they were.
	carryFlags bool
	// distinct are the ports on which the target's answer (certificate, banner, HTTP response) differs from what a never-routed
	// address gets through the same middlebox. The current ports cannot carry it: the network-path check sees only a connect.
	distinct []int
}

func (w *omWire) answer(p omPhase, ip string, port int) omAnswer {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.net(p, ip, port)
}

// Scan is the runner: a connect to the fixed list; a refused port marks the address as having answered (the real runner's Refused).
func (w *omWire) Scan(_ context.Context, st ScanTarget) (Content, error) {
	c := Content{}
	if st.Kind == KindDomain { // one name on one address: checked by name on 80 and 443, or port-scanned when it is the box's own IP
		class := cmp.Or(w.class, ClassPublic)
		name := "www." + st.Value
		if w.dnsFails { // the lookup got no answer: nothing is sent; the real runner lists the name as unresolved, with no row
			c.Unresolved = []string{name}
			if w.carryFlags { // a runner that hands the scan before's row back, flags and all
				c.Hosts = []HostRow{{Name: name, IP: w.ip, Source: "wordlist", LookupFailed: true, IPs: []HostIP{{IP: w.ip, Family: "ipv4", Class: class, Contacted: true}}}}
			}
			return c, nil
		}
		c.Hosts = []HostRow{{Name: name, IP: w.ip, Source: "wordlist", IPs: []HostIP{{IP: w.ip, Family: "ipv4", Class: class, Contacted: true}}}}
		ports := []int{80, 443}
		if class == ClassBox || w.allPorts {
			ports = omPorts()
		}
		for _, port := range ports {
			switch w.answer(omRunner, w.ip, port) {
			case omSynAck:
				c.Ports = append(c.Ports, PortRow{IP: w.ip, Port: port, Service: "http", Ident: IdentProbed})
			case omReset:
				if class == ClassBox {
					c.Answered = map[string]bool{w.ip: true}
				}
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
	omOwnIP       omKind = iota // the box's own public IP, which the box reaches from inside the network (NAT loopback)
	omTyped                     // a public IP the customer typed and proved (a VPS, a host elsewhere): reached over the Internet
	omDomain                    // a proved domain whose name points at a hosting address, checked by name (no testing terms)
	omDomainOnBox               // a proved domain whose name points at the box's own IP (port-scanned there; no testing terms)
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
	noLine  []string       // no "Not checked" line of the last scan contains this (case-insensitive)
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
	beforeAll    bool // the history scans report every port of a domain's address (an earlier deep scan stored them)
	dnsFails     bool // the now scans get no answer to the name's lookup
	carryFlags   bool // with dnsFails: the carried row keeps the scan before's flags
	distinct     []int
	sameErr      bool // the comparison of the target's answer with the network's fails (the connect check itself works)
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

	// ---- when "no port answered this box" may be said ----
	{
		// A light scan (no testing terms now, or an address left out by the deep scan's cap this run) checks the hosting address by
		// name on 80 and 443 only; the rows an earlier deep scan stored there are on 22 and 8443, which this scan never probed. Nothing
		// it probed was open before, so nothing "did not answer".
		name: "unanswered_line/hosting_open_before_on_other_ports/light_scan_probes_only_80_443", kind: omDomain,
		before: []omNet{omHost(omSilence, 22, 8443)}, beforeAll: true, now: omHost(omSilence, 22, 8443),
		want: omWant{open: []int{22, 8443}, run: corerun.Done, noLine: []string{"answered this box"}},
	},
	{
		// The domain's name, on the box's own IP, got no DNS answer this time (the runner lists it as unresolved): nothing was sent to
		// the address. That is a lookup failure, not a target that did not answer.
		name: "unanswered_line/domain_on_box_ip_open_before/dns_no_answer_this_time", kind: omDomainOnBox,
		before: []omNet{omHost(omReset, 22, 443)}, now: omHost(omReset, 22, 443), dnsFails: true,
		want: omWant{open: []int{22, 443}, noLine: []string{"answered this box"}, line: []string{"lookup"}},
	},
	{
		// The same on a hosting address, with the row handed back as the scan before stored it (contacted then): still no packet went
		// to the address this time. Whether the line is said must not hang on a flag of a carried row.
		name: "unanswered_line/hosting_open_before/dns_no_answer_row_carried_with_its_flags", kind: omDomain,
		before: []omNet{omHost(omReset, 80, 443)}, now: omHost(omReset, 80, 443), dnsFails: true, carryFlags: true,
		want: omWant{open: []int{80, 443}, noLine: []string{"answered this box"}, line: []string{"lookup"}},
	},
	{
		// The rule the line exists for: an external host whose every port the box probed, open before, gave no answer at all while
		// the box reached the Internet. The line is said and names what to do.
		name: "unanswered_line/external_open_before/every_probed_port_silent", kind: omTyped,
		before: []omNet{omHost(omSilence, 22, 443)}, now: omEverything(omSilence),
		want: omWant{open: []int{22, 443}, run: corerun.Partial, line: []string{ipC}},
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
		// A transparent or SYN proxy on the path for 80 and 443 (a corporate web proxy, a firewall's web filter) accepts those ports
		// for every destination, the never-routed address too. The target's real web services, stored over a clean path, go through
		// the proxy all the same: the proxy is no evidence that they are gone, so their rows (and issues) must stay.
		name: "middlebox_proxy/open_before/transparent_proxy_on_80_443_keeps_real_web_rows", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 80, 443)}, now: omPath(omHost(omReset, 22, 80, 443), omSynAck, 80, 443),
		want: omWant{open: []int{22, 80, 443}},
	},
	{
		// Through the same proxy, the target's real web service answers with its own certificate and pages; the never-routed address
		// gets the proxy's own answer (an error page, a closed connection). Comparing the two tells the target's service from the
		// proxy's, so a real web service is still found.
		name: "middlebox_proxy/never_seen/real_web_service_told_apart_from_the_proxy", kind: omTyped,
		now: omPath(omHost(omReset, 22, 443), omSynAck, 80, 443), distinct: []int{443},
		want: omWant{open: []int{22, 443}, notOpen: []int{80}},
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
	{
		// The same egress filter in front of a mail server whose row was stored by scans that could not tell a clean path (stored
		// before the vantage was checked, or with the check not wired). A network that refuses 25 for every address cannot have made
		// that row: it says nothing about the target, so the row and its issues stay.
		name: "middlebox_reset/stored_before_the_check/egress_filter_refuses_a_real_mail_port", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 25)}, beforeNoPath: true, now: omPath(omHost(omReset, 22, 25), omReset, 25),
		want: omWant{open: []int{22, 25}, run: corerun.Done, line: []string{"25"}},
	},
	{
		// Real web rows stored before the vantage was checked, now behind a transparent proxy on 80 and 443: the target's own
		// certificate and pages differ from what the never-routed address gets, so the rows stay without a clean history.
		name: "middlebox_proxy/stored_before_the_check/real_web_rows_told_apart_from_the_proxy", kind: omTyped,
		before: []omNet{omHost(omReset, 22, 80, 443)}, beforeNoPath: true, now: omPath(omHost(omReset, 22, 80, 443), omSynAck, 80, 443),
		distinct: []int{80, 443},
		want:     omWant{open: []int{22, 80, 443}},
	},
	{
		// Rows stored before the vantage was checked: a real SSH server on 22, and 5060 that a SIP helper answered then. Now the
		// network accepts 22 and 5060 for every address. The SSH server sends its own banner, which the never-routed address does
		// not get, so 22 is the target's and stays; 5060 answers nothing of its own, so it was the network's and is retired.
		name: "middlebox_proxy/stored_before_the_check/real_ssh_kept_and_phantom_sip_retired", kind: omTyped,
		before: []omNet{omPath(omHost(omReset, 22), omSynAck, 5060)}, beforeNoPath: true,
		now: omPath(omHost(omReset, 22), omSynAck, 22, 5060), distinct: []int{22},
		want: omWant{open: []int{22}, notOpen: []int{5060}, run: corerun.Done},
	},
	{
		// A light scan checks the hosting address by name on 80 and 443 only. The rows an earlier deep scan stored there on 22 and
		// 8443 are outside what this scan may probe (no testing terms now, or the address waits for its turn at depth), so the
		// re-check does not connect to them either, and nothing is said about them: they stay as they were.
		name: "scope/hosting_open_before_on_other_ports/light_scan_rechecks_only_the_web_ports", kind: omDomain,
		before: []omNet{omHost(omSilence, 22, 8443)}, beforeAll: true, now: omHost(omSilence, 80, 443),
		want: omWant{open: []int{22, 8443}, run: corerun.Done, noLine: []string{"no answer at all"}},
	},
	{
		// A row an earlier deep scan stored on 22 of the hosting address, before the vantage was checked. Now the box sits behind a
		// network that accepts 22 for every address, and the light scan checks the address by name on 80 and 443 only: nothing of
		// this scan reached 22 there, and its answer was never compared with the network's, so the network's syn-ack says nothing
		// about the row. It stays.
		name: "middlebox_proxy/stored_before_the_check/row_on_a_port_this_scan_did_not_probe_is_kept", kind: omDomain,
		before: []omNet{omHost(omSilence, 22, 80, 443)}, beforeAll: true, beforeNoPath: true,
		now: omPath(omHost(omSilence, 22, 80, 443), omSynAck, 22), distinct: []int{22},
		want: omWant{open: []int{22, 80, 443}, run: corerun.Done},
	},
	{
		// A real SSH row stored before the vantage was checked; now the network accepts 22 for every address and the comparison of
		// the target's banner with the network's fails. A comparison that did not run says nothing about the target: the row stays.
		name: "middlebox_proxy/stored_before_the_check/row_kept_when_the_comparison_fails", kind: omTyped,
		before: []omNet{omHost(omReset, 22)}, beforeNoPath: true, now: omPath(omHost(omReset, 22), omSynAck, 22), distinct: []int{22},
		sameErr: true,
		want:    omWant{open: []int{22}},
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
	case omDomainOnBox:
		ips := e.detect(ipA)
		if _, err := e.commit(ips[0].ID); err != nil {
			t.Fatal(err)
		}
		v := e.addVerifiedDomain()
		o.id, o.ip = v.ID, ipA
		o.wire.class = ClassBox
	}
	if _, err := e.commit(o.id); err != nil {
		t.Fatal(err)
	}
	if kind != omDomain && kind != omDomainOnBox {
		e.acceptTerms(o.id, false)
	}
	o.wire.ip = o.ip
	e.svc.SetRunner(o.wire)
	e.svc.cfg.Services = o.wire
	e.svc.cfg.Liveness = o.wire
	return o
}

// omScan is how one scan of a row runs.
type omScan struct {
	path, pathErr, sameErr, allPorts, dnsFails, carryFlags bool
	nmapErr                                                error
	distinct                                               []int
}

// scan runs one scan of the target over n (the deep scan for an IP target).
func (o *omEnv) scan(n omNet, how omScan) ScanResult {
	o.t.Helper()
	o.wire.mu.Lock()
	o.wire.net, o.wire.pathErr, o.wire.sameErr, o.wire.nmapErr = n, how.pathErr, how.sameErr, how.nmapErr
	o.wire.allPorts, o.wire.dnsFails, o.wire.carryFlags, o.wire.distinct = how.allPorts, how.dnsFails, how.carryFlags, how.distinct
	o.wire.mu.Unlock()
	o.svc.cfg.Path = nil
	if how.path {
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
		o.scan(b, omScan{path: !row.beforeNoPath, allPorts: row.beforeAll})
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
		r = o.scan(row.now, omScan{path: true, pathErr: row.pathErr, sameErr: row.sameErr, nmapErr: row.nmapErr, dnsFails: row.dnsFails, carryFlags: row.carryFlags, distinct: row.distinct})
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
	for _, part := range row.want.noLine {
		if i := slices.IndexFunc(r.NotChecked, func(n NotCheckedRow) bool { return strings.Contains(strings.ToLower(n.Text), strings.ToLower(part)) }); i >= 0 {
			diff = append(diff, fmt.Sprintf("a \"Not checked\" line contains %q: %q", part, r.NotChecked[i].Text))
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

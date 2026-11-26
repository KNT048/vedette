package exposure

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// The observation model of an external scan (INV-22, INV-42, INV-44, INV-45). Every probe the box sends is seen from the box's own
// network position, its vantage: the box's own public IP is reached from inside through the router's NAT loopback, a firewall or WAF
// may block the box only, a firewall helper or a proxy may answer some ports for every destination, an egress filter may refuse some
// ports for every destination, an IPS may start dropping the box in the middle of a run. What the box observes is therefore a fact
// about the path as much as about the target.
//
// So the probes of a run (the runner, nmap's sweep, the liveness checks, the re-check of the ports open before that the scan missed,
// the calibration of the vantage against never-routed addresses) only record what each got, in the run's observer. One pure
// function, verdicts, turns that log into one verdict for each address and port of the run, and every consumer reads the verdict
// only: the stored rows (open, kept, closed, retired), the engines (open ports only), the run's outcome, and the customer's lines,
// which one function (vantageLines) writes from the verdict's reason. The verdicts are kept as run items of kind itemVerdict; the
// streaks and the scan before come from them.
//
//	| verdict    | what the run observed                                                                     | the stored row                         |
//	|------------|-------------------------------------------------------------------------------------------|----------------------------------------|
//	| open       | a syn-ack from the target (or, through a network that answers the port, a different answer) | opened or kept                         |
//	| closed     | missed while the address answered, no sign of the network                                  | closed at once when two probes agree, else when the scan before missed it too |
//	| filtered   | no answer at all (no reset) to the re-check while the address answered elsewhere            | closed by the third such scan over a day |
//	| unreached  | nothing of the address answered, or every port flipped to resets through NAT loopback      | kept ("not reached since"); 30 days: no longer listed |
//	| lost       | answered earlier in the run, then stopped                                                  | kept, as unreached                     |
//	| network    | the network answers the port for every address (syn-ack or reset), same answer as there     | kept; a syn-ack one retired when this run read its answer as the network's and no run saw it over a clean path |
//	| unknown    | the calibration failed, or a probe step failed or was cut                                  | kept, as unreached                     |

// The verdicts.
const (
	verdictOpen      = "open"
	verdictClosed    = "closed"
	verdictFiltered  = "filtered"
	verdictUnreached = "unreached"
	verdictLost      = "lost"
	verdictNetwork   = "network"
	verdictUnknown   = "unknown"
)

// The reasons of a verdict: whose answer it is, and so which words the customer reads.
const (
	reasonLoopback = "loopback" // the box's own public IP, reached from inside its network (NAT loopback)
	reasonBlocked  = "blocked"  // any other address: a firewall, a WAF or a ban list in front of the target
	reasonSynAck   = "synack"   // network: it accepts the port for every address
	reasonReset    = "reset"    // network: it refuses the port for every address
	reasonPath     = "path"     // unknown: the check of the network failed
	reasonStep     = "step"     // unknown: a probe step meant for the port failed or was cut
)

// The rollup of an address.
const (
	addrReachable = "reachable"
	addrUnreached = "unreached"
	addrLost      = "lost"
)

// itemVerdict is the kind of the run item of one verdict: its subject is portKey, its outcome the verdict (an open port seen over a
// path the run did not check is itemOpenUnchecked), its note the reason in words.
const (
	itemVerdict       = "verdict"
	itemOpenUnchecked = "open_unchecked"
)

// notReachedFor is how long a port that the scans keep not reaching (unreached, lost, unknown) stays listed after it was last seen.
const notReachedFor = 30 * 24 * time.Hour

// The filtered streak that closes a port: the filteredScans-th such scan in a row, at least filteredSpan after the first.
const (
	filteredScans = 3
	filteredSpan  = 24 * time.Hour
)

// calibFailed is the calibration's answer of a port the check failed on.
const calibFailed = "failed"

// ---- the probe log of a run ----

// sweepFacts is what a deep scan's nmap sweep of every TCP port of one address did.
type sweepFacts struct {
	ran     bool   // it ran to its end (every port was probed)
	trusted bool   // sweepTrusted: it saw every port the runner saw there, and at least one port or a reset
	cut     string // why its results are incomplete ("" when they are not): it failed, did not finish, or missed what answered
	unfin   []int  // the ports whose service batch did not finish
}

// observer is the probe log of one run: what each probe source got, per address and port, and the vantage's calibration. A step
// called outside a run gets an empty one.
type observer struct {
	check PathChecker
	x     *corerun.Exec // nil outside a run
	log   *slog.Logger

	mu       sync.Mutex
	calib    map[int]string          // port: what the never-routed addresses got (PortOpen, PortClosed, PortSilent, calibFailed)
	distinct map[string]bool         // portKey: the target's own answer differs from the network's
	same     map[string]bool         // portKey: the target's own answer was read this run and is the network's (compared, not failed)
	said     map[int]bool            // the network's ports said in the run's log
	resets   map[string]bool         // address: the runner or the sweep got a reset on some port
	sweeps   map[string]sweepFacts   // address: its deep sweep
	alive    map[string]map[int]bool // address, port: the newest liveness answer (true: accepted)
	lost     map[string][]int        // address: the ports that answered earlier in the run and stopped
	recheck  map[string]map[int]string
	cuts     map[string]string // address: why a probe step meant for it failed (service identification of a default scan)
	leftOut  map[string][]int  // address: the ports found open there that the network answers (left out of the results)
}

type observerKey struct{}

func (s *Service) newObserver(x *corerun.Exec) *observer {
	return &observer{check: s.cfg.Path, x: x, log: s.cfg.Log, calib: map[int]string{}, distinct: map[string]bool{}, same: map[string]bool{}, said: map[int]bool{},
		resets: map[string]bool{}, sweeps: map[string]sweepFacts{}, alive: map[string]map[int]bool{}, lost: map[string][]int{},
		recheck: map[string]map[int]string{}, cuts: map[string]string{}, leftOut: map[string][]int{}}
}

// withObserver is ctx for the work of one run, with its own probe log.
func (s *Service) withObserver(ctx context.Context, x *corerun.Exec) context.Context {
	return context.WithValue(ctx, observerKey{}, s.newObserver(x))
}

// observerOf is ctx's probe log; a new, empty one when ctx carries none (a step called outside a run).
func (s *Service) observerOf(ctx context.Context) *observer {
	if o, ok := ctx.Value(observerKey{}).(*observer); ok {
		return o
	}
	return s.newObserver(nil)
}

// noteResets records that the runner or the sweep got a reset somewhere on each of addrs.
func (o *observer) noteResets(addrs ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, a := range addrs {
		o.resets[ipKey(a)] = true
	}
}

// noteSweep records a deep sweep of ip.
func (o *observer) noteSweep(ip string, f sweepFacts) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweeps[ipKey(ip)] = f
}

// noteCut records that a probe step meant for ip failed or was cut, and why.
func (o *observer) noteCut(ip, why string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cuts[ipKey(ip)] = why
}

// sweepCut is why the deep sweep of ip is incomplete ("" when it is not, or did not run).
func (o *observer) sweepCut(ip string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sweeps[ipKey(ip)].cut
}

// swept says a deep sweep of every port of ip ran this run.
func (o *observer) swept(ip string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.sweeps[ipKey(ip)]
	return ok
}

// noteAlive records a liveness check of ip: a port that answered earlier in the run and does not accept a connection now is lost.
func (o *observer) noteAlive(ip string, up map[int]bool) (newly []int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	k := ipKey(ip)
	if o.alive[k] == nil {
		o.alive[k] = map[int]bool{}
	}
	for p, ok := range up {
		o.alive[k][p] = ok
		if !ok && !slices.Contains(o.lost[k], p) {
			o.lost[k] = append(o.lost[k], p)
			newly = append(newly, p)
		}
	}
	slices.Sort(o.lost[k])
	slices.Sort(newly)
	return newly
}

// noteRecheck records what the re-check of ip got.
func (o *observer) noteRecheck(ip string, got map[int]string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	k := ipKey(ip)
	if o.recheck[k] == nil {
		o.recheck[k] = map[int]string{}
	}
	maps.Copy(o.recheck[k], got)
}

// lostPort says port of ip stopped answering this run.
func (o *observer) lostPort(ip string, port int) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Contains(o.lost[ipKey(ip)], port)
}

// lostOf is the ports of each address that stopped answering this run (a copy).
func (o *observer) lostOf() map[string][]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string][]int{}
	for k, ps := range o.lost {
		if len(ps) > 0 {
			out[k] = slices.Clone(ps)
		}
	}
	return out
}

// gone says none of the ports open on ip this run (open) answers any more, and at least one was lost.
func (o *observer) gone(ip string, open map[string][]int) bool {
	k := ipKey(ip)
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.lost[k]) == 0 {
		return false
	}
	for _, p := range open[k] {
		if !slices.Contains(o.lost[k], p) {
			return false
		}
	}
	return true
}

// allGone says every address with a port open this run stopped answering.
func (o *observer) allGone(open map[string][]int) bool {
	if len(open) == 0 {
		return false
	}
	for ip := range open {
		if !o.gone(ip, open) {
			return false
		}
	}
	return true
}

// ---- the inputs of verdicts ----

// addrObs is what the probes of one run observed on one address.
type addrObs struct {
	class      string         // the ports the runner and the sweep covered there for closing (coverage: coverAll, coverList, coverTop, coverWeb)
	probed     []int          // the ports the default scan's service step probed (coverTop), ascending
	listed     bool           // the runner TCP-connected the whole fixed list there
	sweep      *sweepFacts    // a deep sweep of every port; nil when none ran
	stepCut    string         // a probe step meant for the address failed or was cut ("" when none)
	open       map[int]bool   // the ports that accepted a connection this run
	resets     bool           // the runner or the sweep got a reset on some port
	alive      map[int]bool   // the newest liveness answer of each port asked
	lost       []int          // the ports that answered earlier in the run and stopped
	recheck    map[int]string // the re-check of the ports open before that the scan missed
	loopback   bool           // the box's own public IP, reached from inside the network
	storedOpen []int          // the ports with an open row before this scan
	leftOut    []int          // the ports found open that the network answers, left out of the results
}

// observation is everything verdicts reads.
type observation struct {
	addrs    map[string]*addrObs
	checked  bool                // a network-path check was wired
	calib    map[int]string      // its answers
	distinct map[string]bool     // portKey: the target's own answer differs from the network's
	same     map[string]bool     // portKey: the target's own answer was read this run and is the network's
	deep     bool                // the run is a deep scan (the words of the lines)
	names    map[string][]string // the names of each address (a domain's), for the lines
}

// portVerdict is the verdict of one port of one address.
type portVerdict struct {
	ip     string
	port   int
	v      string
	reason string
	probes int  // closed: the probes of this run that missed it (two agree: closed at once)
	seen   bool // it accepted a connection this run: it is in the results
	same   bool // network (synack): this run read the target's own answer on the port and it was the network's
	clean  bool // open: the network-path check ran for the port and the network does not answer it
	stored bool // it had an open row before this scan
}

// addrRollup is the verdict of one address.
type addrRollup struct {
	state  string
	reason string
}

// verdictSet is the verdicts of one run.
type verdictSet struct {
	ports map[string]portVerdict // portKey
	addrs map[string]addrRollup
}

func (v verdictSet) of(ip string, port int) (portVerdict, bool) {
	pv, ok := v.ports[portKey(ip, port)]
	return pv, ok
}

// sorted is the verdicts by address and port.
func (v verdictSet) sorted() []portVerdict {
	out := slices.Collect(maps.Values(v.ports))
	slices.SortFunc(out, func(a, b portVerdict) int {
		return cmp.Or(cmpAddr(a.ip, b.ip), cmp.Compare(a.port, b.port))
	})
	return out
}

func cmpAddr(a, b string) int {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return strings.Compare(a, b)
	}
	return x.Compare(y)
}

// ---- verdicts ----

// verdicts is the one decision of a run: for each address the run probed, a verdict for each port that had an open row before the
// scan or accepted a connection in it, and the address's rollup. Pure: everything it reads is in o.
func verdicts(o observation) verdictSet {
	out := verdictSet{ports: map[string]portVerdict{}, addrs: map[string]addrRollup{}}
	network := func(p int) bool { a := o.calib[p]; return a == PortOpen || a == PortClosed }
	failed := func(p int) bool { return o.checked && o.calib[p] == calibFailed }
	netReset := slices.ContainsFunc(slices.Collect(maps.Values(o.calib)), func(a string) bool { return a == PortClosed })
	for _, ip := range slices.SortedFunc(maps.Keys(o.addrs), cmpAddr) {
		a := o.addrs[ip]
		reason := reasonBlocked
		if a.loopback {
			reason = reasonLoopback
		}
		// What of the address answered this run, the ports the network answers left out. A reset the runner or the sweep got
		// somewhere is the address's only when the network refuses no port for every address (an egress filter's resets look the same).
		synack := slices.ContainsFunc(slices.Collect(maps.Keys(a.open)), func(p int) bool { return !network(p) }) ||
			slices.ContainsFunc(slices.Collect(maps.Keys(a.alive)), func(p int) bool { return a.alive[p] && !network(p) })
		resets := a.resets && !netReset
		answered := synack || resets
		for p, r := range a.recheck {
			if !network(p) && (r == PortOpen || r == PortClosed) {
				answered = true
				synack = synack || r == PortOpen
			}
		}
		// The box's own address, reached through NAT loopback, flipped to resets on every port with nothing open: the router answers
		// for its own address (it lost its loopback), so the resets are not the target's.
		flip := a.loopback && !synack && resets
		lostAddr := len(a.lost) > 0
		ports := map[int]bool{}
		for _, p := range a.storedOpen {
			ports[p] = true
		}
		for p := range a.open {
			ports[p] = true
		}
		for _, p := range a.leftOut {
			ports[p] = true
		}
		for _, p := range slices.Sorted(maps.Keys(ports)) {
			v := portVerdict{ip: ip, port: p, seen: a.open[p], stored: slices.Contains(a.storedOpen, p)}
			legacy := covers(a.class, a.probed, p)
			touched := legacy || (a.sweep != nil && a.sweep.ran) || a.recheck[p] != ""
			switch {
			case network(p) && a.open[p] && (o.calib[p] == PortClosed || o.distinct[portKey(ip, p)]):
				v.v, v.clean = verdictOpen, true // through the network's answer, the target's own service answered
			case network(p):
				v.v, v.reason = verdictNetwork, reasonSynAck
				if o.calib[p] == PortClosed {
					v.reason = reasonReset
				}
				v.same = v.reason == reasonSynAck && o.same[portKey(ip, p)]
			case slices.Contains(a.lost, p):
				v.v, v.reason = verdictLost, reason
			case a.open[p] && failed(p):
				v.v, v.reason = verdictUnknown, reasonPath
			case a.open[p]:
				v.v, v.clean = verdictOpen, o.checked
			case lostAddr:
				v.v, v.reason = verdictLost, reason
			case a.sweep != nil && slices.Contains(a.sweep.unfin, p):
				v.v, v.reason = verdictUnknown, reasonStep
			case a.recheck[p] == PortOpen:
				v.v, v.clean = verdictOpen, o.checked && !failed(p)
			case touched && (!answered || flip):
				v.v, v.reason = verdictUnreached, reason
			case touched && failed(p):
				v.v, v.reason = verdictUnknown, reasonPath
			case a.recheck[p] == PortSilent:
				v.v, v.reason = verdictFiltered, reason
			case legacy:
				v.v, v.probes = verdictClosed, 1
				if a.sweep != nil && a.sweep.trusted && a.class == coverAll && a.listed && slices.Contains(commonports.Numbers(), p) {
					v.probes = 2 // the runner's connect and a trusted sweep of every port both missed it
				}
				if a.recheck[p] == PortClosed {
					v.probes++ // and the re-check got a reset
				}
			case a.stepCut != "" && v.stored:
				v.v, v.reason = verdictUnknown, reasonStep
			default: // this run did not probe it: no verdict
				continue
			}
			out.ports[portKey(ip, p)] = v
		}
		roll := addrRollup{state: addrReachable, reason: reason}
		for _, v := range out.ports {
			if ipKey(v.ip) != ip {
				continue
			}
			switch {
			case v.v == verdictLost:
				roll.state = addrLost
			case v.v == verdictUnreached && roll.state != addrLost:
				roll.state = addrUnreached
			}
		}
		out.addrs[ip] = roll
	}
	return out
}

// ---- what the customer reads ----

// vantageLine is one "Not checked" line of the verdicts, and whether it makes the run partly done.
type vantageLine struct {
	row     NotCheckedRow
	problem bool
}

// vantageLines are the lines the verdicts say, one for each address and fact: the one place their words are made (the run's log, its
// reason and the steps use the same). boxIP is this box's public IP ("" when not known).
func vantageLines(o observation, vs verdictSet, boxIP string) []vantageLine {
	var out []vantageLine
	by := map[string]map[string][]int{} // address, verdict(+reason): ports
	for _, v := range vs.sorted() {
		k := v.v
		switch {
		case v.v == verdictNetwork || v.v == verdictUnknown:
			k += "/" + v.reason
		case v.v == verdictLost && !v.seen: // kept because its address stopped answering: the line names the ports that did
			continue
		}
		if by[v.ip] == nil {
			by[v.ip] = map[string][]int{}
		}
		by[v.ip][k] = append(by[v.ip][k], v.port)
	}
	for _, ip := range slices.SortedFunc(maps.Keys(by), cmpAddr) {
		roll, ports := vs.addrs[ip], by[ip]
		hint := blockedHint(boxIP, o.deep)
		if roll.reason == reasonLoopback {
			hint = natHint
		}
		switch roll.state {
		case addrLost:
			out = append(out, vantageLine{NotCheckedRow{Kind: "lost", Text: clipText(lostLine(ip, ports[verdictLost], roll.reason == reasonLoopback, boxIP, o.deep), maxLineText)}, true})
		case addrUnreached:
			who := ip
			if n := o.names[ip]; len(n) > 0 {
				who += " (" + joinAnd(n, 2) + ")"
			}
			out = append(out, vantageLine{NotCheckedRow{Kind: "unanswered", Text: clipText("No port of "+who+" answered this box. "+hint, maxLineText)}, true})
		}
		if f := ports[verdictFiltered]; len(f) > 0 && roll.state == addrReachable {
			n := len(f)
			why := "a firewall or WAF may be blocking this box"
			if roll.reason == reasonLoopback {
				why = "the router may not pass them to the box's own public address from inside (NAT loopback)"
			}
			out = append(out, vantageLine{NotCheckedRow{Kind: "silent_ports", Text: clipText(fmt.Sprintf(
				"%s of %s %s open before and gave no answer at all in this scan (no reset): %s, so %s kept as %s. If you closed %s yourself, %s marked closed after three scans over a day.",
				upperFirst(portsOnly(f)), ip, itThem(n, "was", "were"), why, itThey(n)+" "+isAre(n), itThem(n, "it was", "they were"),
				itThem(n, "it", "them"), itThey(n)+" "+isAre(n)), maxLineText)}, true})
		}
		if p := ports[verdictNetwork+"/"+reasonSynAck]; len(p) > 0 {
			out = append(out, vantageLine{NotCheckedRow{Kind: "network_path", Text: clipText(upperFirst(fmt.Sprintf(
				"%s answered by your own network (a firewall helper or a proxy), not by %s (the same answer comes for an address that is never routed), so %s left out of the results.",
				portsWords(p), ip, itWas(len(p)))), maxLineText)}, false})
		}
		if p := ports[verdictNetwork+"/"+reasonReset]; len(p) > 0 {
			out = append(out, vantageLine{NotCheckedRow{Kind: "network_path", Text: clipText(upperFirst(fmt.Sprintf(
				"%s refused by your own network for every address (an egress filter: an address that is never routed gets the same reset), so this box cannot check %s on %s; an earlier result is kept.",
				portsWords(p), itThem(len(p), "it", "them"), ip)), maxLineText)}, false})
		}
		if p := ports[verdictUnknown+"/"+reasonPath]; len(p) > 0 {
			out = append(out, vantageLine{NotCheckedRow{Kind: "network_path", Text: clipText(fmt.Sprintf(
				"This box could not tell whether %s of %s %s answered by your own network (the check with an address that is never routed failed), so %s kept as found and this scan is incomplete.",
				portsOnly(p), ip, isAre(len(p)), itThey(len(p))+" "+isAre(len(p))), maxLineText)}, true})
		}
	}
	return out
}

// natHint is said of the box's own public IP reached from inside: the likely cause, without claiming a firewall or an IPS.
const natHint = "The box could not reach its own public address from inside your network: the router may not support NAT loopback (hairpin NAT), or something blocked it. The ports may still be open from the Internet."

// blockedHint is said of any other address that does not answer the box: what to allow, and where.
func blockedHint(boxIP string, deep bool) string {
	when := "during scans"
	if deep {
		when = "during deep scans"
	}
	if boxIP != "" {
		return "If the site has a WAF or firewall, allow this box's public IP " + boxIP + " " + when + "."
	}
	return "If the site has a WAF or firewall, allow this box's public IP " + when + "."
}

// lostSentence is "Results incomplete: 203.0.113.5:9443 and 203.0.113.5:10443 stopped answering during the scan." ("" when none).
func lostSentence(lost map[string][]int) string {
	var where []string
	for _, ip := range slices.SortedFunc(maps.Keys(lost), cmpAddr) {
		for _, p := range lost[ip] {
			where = append(where, ip+":"+strconv.Itoa(p))
		}
	}
	if len(where) == 0 {
		return ""
	}
	return "Results incomplete: " + joinAnd(where, 6) + " stopped answering during the scan."
}

// lostLine is the sentence of one address whose ports stopped answering, with the hint of its own vantage: the NAT-loopback hint for
// the box's own IP reached from inside (loopback), what to allow for any other address. The address's line (vantageLines) and the
// notes of the steps that skip or lose a port (lostText) are made here, in the same words.
func lostLine(ip string, ports []int, loopback bool, boxIP string, deep bool) string {
	hint := blockedHint(boxIP, deep)
	if loopback {
		hint = natHint
	}
	return lostSentence(map[string][]int{ip: ports}) + " " + hint
}

// lostText is the sentences of the ports of the target that stopped answering ("" when none), one for each address with the hint of
// its own vantage (lostLine).
func (s *Service) lostText(ctx context.Context, st ScanTarget, lost map[string][]int) string {
	var parts []string
	boxIP, known := "", false
	for _, ip := range slices.SortedFunc(maps.Keys(lost), cmpAddr) {
		if len(lost[ip]) == 0 {
			continue
		}
		loop := s.loopback(ctx, st, ip)
		if !loop && !known {
			boxIP, known = s.boxPublicIP(ctx), true
		}
		parts = append(parts, lostLine(ip, lost[ip], loop, boxIP, st.Mode.Full))
	}
	return strings.Join(parts, " ")
}

// loopback says ip is the box's own public IP, reached from inside the network: an IP target the box found as its own address, or an
// address of a domain's names that is such a target (not one typed in), while it is the box's current egress address when that is known.
func (s *Service) loopback(ctx context.Context, st ScanTarget, ip string) bool {
	if !s.ownAddress(ctx, st, ip) {
		return false
	}
	now := s.boxPublicIP(ctx)
	return now == "" || ipKey(now) == ipKey(ip)
}

// ownAddress says ip is the box's own public IP: an IP target that is not typed in (the box saw it as its own address), or an
// address of a domain's names that is a scannable IP target the box found as its own (not one typed in).
func (s *Service) ownAddress(ctx context.Context, st ScanTarget, ip string) bool {
	if st.Kind == KindIP {
		return !st.Typed && ipKey(st.Value) == ipKey(ip)
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if ok, err := s.ScannableIP(ctx, st.User, a); err != nil || !ok {
		return false
	}
	_, typed := s.typedAddr(ctx, a) // a typed IP of the box's list is scannable, but not the box's own
	return !typed
}

// boxPublicIP is the box's current public IP as its records say ("" when not known).
func (s *Service) boxPublicIP(ctx context.Context) string {
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the box's addresses failed", "error", err)
		return ""
	}
	return egressNowOf(all, s.clock()).by
}

// ---- building the observation of a run ----

// observation builds what verdicts reads from the run's probe log, the content as it will be written and its coverage (cov), and the
// open rows before the scan (prev).
func (s *Service) observation(ctx context.Context, st ScanTarget, c Content, cov coverResult, prev []PortRow) observation {
	ob := s.observerOf(ctx)
	o := observation{addrs: map[string]*addrObs{}, deep: st.Mode.Full, names: map[string][]string{}}
	at := func(ip string) *addrObs {
		k := ipKey(ip)
		if o.addrs[k] == nil {
			o.addrs[k] = &addrObs{open: map[int]bool{}}
		}
		return o.addrs[k]
	}
	for ip, class := range cov.checked {
		a := at(ip)
		a.class, a.listed, a.probed = class, cov.listed[ip], c.Probed[ip]
	}
	for _, p := range c.Ports {
		at(p.IP).open[p.Port] = true
	}
	for _, r := range c.Services {
		at(r.IP).open[r.Port] = true
	}
	for ip, ok := range c.Answered { // the runner's own report: a reset on some port
		if ok {
			ob.noteResets(ip)
		}
	}
	ob.mu.Lock()
	for ip := range ob.resets {
		at(ip).resets = true
	}
	for ip, f := range ob.sweeps {
		a := at(ip)
		f := f
		a.sweep, a.stepCut = &f, f.cut
	}
	for ip, up := range ob.alive {
		at(ip).alive = maps.Clone(up)
	}
	for ip, ps := range ob.lost {
		if len(ps) > 0 {
			at(ip).lost = slices.Clone(ps)
		}
	}
	for ip, got := range ob.recheck {
		at(ip).recheck = maps.Clone(got)
	}
	for ip, ps := range ob.leftOut {
		at(ip).leftOut = slices.Clone(ps)
	}
	for ip, why := range ob.cuts {
		if a := o.addrs[ipKey(ip)]; a != nil && a.stepCut == "" {
			a.stepCut = why
		}
	}
	ob.mu.Unlock()
	for _, p := range prev {
		if a := o.addrs[ipKey(p.IP)]; a != nil && !slices.Contains(a.storedOpen, p.Port) {
			a.storedOpen = append(a.storedOpen, p.Port)
		}
	}
	for _, h := range c.Hosts {
		for _, x := range h.IPs {
			if k := ipKey(x.IP); o.addrs[k] != nil && h.Name != "" && !slices.Contains(o.names[k], h.Name) && st.Kind == KindDomain {
				o.names[k] = append(o.names[k], h.Name)
			}
		}
	}
	var scoped []int
	for ip, a := range o.addrs {
		a.loopback = s.loopback(ctx, st, ip)
		scoped = append(scoped, a.storedOpen...)
		for p := range a.open {
			scoped = append(scoped, p)
		}
	}
	if ob.check != nil {
		o.checked = true
		ob.calibrate(ctx, scoped) // every port a verdict is given for is checked (most were at the start of the run)
	}
	ob.mu.Lock()
	o.calib, o.distinct, o.same = maps.Clone(ob.calib), maps.Clone(ob.distinct), maps.Clone(ob.same)
	ob.mu.Unlock()
	return o
}

// ---- the verdict items: the memory of the scans before ----

// verdictItems are the run items of vs.
func verdictItems(vs verdictSet) []corerun.Item {
	var out []corerun.Item
	for _, v := range vs.sorted() {
		k := portKey(v.ip, v.port)
		outcome := v.v
		if v.v == verdictOpen && !v.clean {
			outcome = itemOpenUnchecked
		}
		out = append(out, corerun.Item{SubjectKind: itemVerdict, SubjectID: k, Label: k, Outcome: outcome, Note: reasonWords(v)})
	}
	return out
}

// reasonWords is the reason of a verdict in words, for the run page ("" when it needs none).
func reasonWords(v portVerdict) string {
	switch {
	case v.v == verdictOpen && !v.clean:
		return "open; the network-path check did not run for this port"
	case v.v == verdictClosed && v.probes >= 2:
		return "missed by two probes of this scan"
	case v.v == verdictNetwork && v.reason == reasonReset:
		return "your own network refuses this port for every address"
	case v.v == verdictNetwork:
		return "your own network answers this port for every address"
	case v.v == verdictUnknown && v.reason == reasonPath:
		return "the network-path check failed"
	case v.v == verdictUnknown:
		return "the probe step did not finish"
	case v.reason == reasonLoopback:
		return "seen from inside the box's own network (NAT loopback)"
	}
	return ""
}

// recordVerdicts writes the verdicts of the run as its items.
func (s *Service) recordVerdicts(ctx context.Context, x *corerun.Exec, vs verdictSet) {
	items := verdictItems(vs)
	if len(items) == 0 {
		return
	}
	if err := x.AddItems(ctx, items...); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: recording the verdicts of a scan", "run", x.ID(), "error", err)
	}
}

// priorVerdict is the verdict an earlier run of the target gave a port.
type priorVerdict struct {
	at      string
	outcome string
}

// priorVerdictsMax bounds how many verdicts of the runs before are read for one port: far more than the rules need (the scan
// before, a filtered streak of filteredScans over filteredSpan), so the cost of a scan does not grow with the target's history.
const priorVerdictsMax = 100

// priorVerdicts are the verdicts the runs of target before run gave port (portKey), newest first: at most priorVerdictsMax, and
// then the newest clean sighting (verdictOpen) when it is older than those (seenClean must know of one however old it is).
func priorVerdicts(ctx context.Context, q querier, target, run, port string) ([]priorVerdict, error) {
	const from = ` FROM core_run_item i JOIN core_run r ON r.id = i.run_id
		WHERE r.module = ? AND r.kind = ? AND r.subject_kind = 'target' AND r.subject_id = ? AND r.id <> ? AND r.started_at IS NOT NULL
			AND r.started_at < (SELECT started_at FROM core_run WHERE id = ?) AND i.subject_kind = ? AND i.subject_id = ?`
	args := []any{ModuleID, RunKind, target, run, run, itemVerdict, port}
	read := func(query string, args ...any) ([]priorVerdict, error) {
		rows, err := q.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("the verdicts before of %s: %w", port, err)
		}
		defer func() { _ = rows.Close() }()
		var out []priorVerdict
		for rows.Next() {
			var p priorVerdict
			if err := rows.Scan(&p.at, &p.outcome); err != nil {
				return nil, fmt.Errorf("the verdicts before of %s: %w", port, err)
			}
			out = append(out, p)
		}
		return out, rows.Err()
	}
	out, err := read(`SELECT r.started_at, i.outcome`+from+` ORDER BY r.started_at DESC, i.seq DESC LIMIT ?`, append(args, priorVerdictsMax)...)
	if err != nil || len(out) < priorVerdictsMax || seenClean(out) {
		return out, err
	}
	clean, err := read(`SELECT r.started_at, i.outcome`+from+` AND i.outcome = ? ORDER BY r.started_at DESC LIMIT 1`, append(args, verdictOpen)...)
	return append(out, clean...), err
}

// runStart is when run started ("" when not known).
func runStart(ctx context.Context, q querier, run string) string {
	var at sql.NullString
	_ = q.QueryRowContext(ctx, `SELECT started_at FROM core_run WHERE id = ?`, run).Scan(&at)
	return at.String
}

// filteredStreak says this scan, which found port filtered, is the filteredScans-th or later in a row to find it filtered since it was
// last seen open (lastSeen), at least filteredSpan after the first of them.
func filteredStreak(prior []priorVerdict, lastSeen, now string) bool {
	n, first := 1, now
	for _, p := range prior {
		if p.outcome != verdictFiltered || p.at <= lastSeen {
			break
		}
		n, first = n+1, p.at
	}
	if n < filteredScans {
		return false
	}
	a, err1 := parseTS(first)
	b, err2 := parseTS(now)
	return err1 == nil && err2 == nil && b.Sub(a) >= filteredSpan
}

// seenClean says a run saw the port open over a path the network-path check found clean.
func seenClean(prior []priorVerdict) bool {
	return slices.ContainsFunc(prior, func(p priorVerdict) bool { return p.outcome == verdictOpen })
}

// ---- a box that reached nothing ----

// reachTimeout bounds the one round of the public IP services that tells a box that could not reach anything from a target that
// answered nothing.
const reachTimeout = 30 * time.Second

// answered says something of the target answered this scan: an open port, a page, a certificate, an admin page, a service that
// identification named, a page ZAP read, a finding or finished check of an engine, or a reset the runner or the sweep got.
func (o *observer) answered(c Content) bool {
	o.mu.Lock()
	resets := len(o.resets) > 0
	o.mu.Unlock()
	return resets || len(c.Ports) > 0 || len(c.Answered) > 0 || len(c.Certs) > 0 || len(c.AdminPanels) > 0 || len(c.Services) > 0 ||
		len(c.WebPages) > 0 || len(c.WebFindings) > 0 || len(c.Greenbone) > 0 || len(c.TemplatesRan) > 0 || len(c.ScriptsRan) > 0
}

// reached is the address rollup's "offline" reason (INV-41): a scan to which nothing answered is a result only when the box itself
// could reach the Internet, so one round of the three public IP services (INV-2) runs then. When none of them answers either, the
// box had no network and the scan is incomplete: it ends with an error that says so and nothing is written. nil when something
// answered, or when the services answered (a target that answers nothing is a result: its addresses are unreached).
func (s *Service) reached(ctx context.Context, t Target, c Content) error {
	if s.observerOf(ctx).answered(c) || ctx.Err() != nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	_, err := s.cfg.Prober.Round(rctx)
	if err == nil || errors.Is(err, ErrNoAgreement) || ctx.Err() != nil {
		return nil
	}
	s.cfg.Log.WarnContext(ctx, "exposure: a scan got no answer and the box could not reach the public IP services either", "target", t.Value, "error", err)
	return errUnreachable(t.Value)
}

// errUnreachable is the end of a scan that reached nothing while the box was offline.
func errUnreachable(target string) *APIError {
	return apiErr(502, "unreachable", "The box could not reach %s, nor the public services it uses to check its own Internet connection, so this scan is "+
		"incomplete: nothing was saved and the results of the last complete scan stay. Check the box's network (cable, address, DNS), then scan again.", target)
}

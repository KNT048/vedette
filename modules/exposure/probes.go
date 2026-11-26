package exposure

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// The probe sources of a run besides the runner and nmap's sweep (observe.go): each one only records what it got in the run's
// observer. The verdicts and the words about them are observe.go's.
//
//   - The calibration of the vantage (INV-44, PathChecker): once at the start of the run for the fixed list and the ports open before,
//     then for each port found open, a TCP connect to never-routed addresses (syn-ack, reset or nothing). For a port the network
//     answers with a syn-ack that the target answered too, the target's answer is compared with the never-routed address's (its TLS
//     certificate, else its HTTP answer; on another port the banner it sends first): a different answer is the target's own service.
//   - The liveness checks (INV-42, Liveness): before each engine step and before the results are written, a TCP connect to the ports
//     seen open earlier in the run.
//   - The re-check (INV-22, PortProber): right before the results are written, a TCP connect to the ports open before that the scan
//     did not see.

// Liveness says which of ports still accept a TCP connection on ip: a plain connect from the box, closed at once, no data sent.
// cmd/vedette implements it; nil: no check (every port is taken as answering).
type Liveness interface {
	Alive(ctx context.Context, ip netip.Addr, ports []int) (map[int]bool, error)
}

// What one TCP connect to a port got (PortProber, PathChecker).
const (
	PortOpen   = "open"   // the connection was accepted
	PortClosed = "closed" // a reset: nothing listens there
	PortSilent = "silent" // no answer at all
)

// PortProber is a Liveness that also tells a closed port (a reset) from a silent one (no answer): a plain connect from the box to
// each port, closed at once, no data sent. cmd/vedette's liveness check implements it.
type PortProber interface {
	Probe(ctx context.Context, ip netip.Addr, ports []int) (map[int]string, error)
}

// Bounds of the probes: the addresses and ports a liveness check and the re-check ask about, and the time each may take.
const (
	maxAliveAddrs   = 4
	maxAlivePorts   = 16
	aliveCheckLimit = 30 * time.Second
	maxRecheckAddrs = 8
	maxRecheckPorts = 32
	recheckLimit    = time.Minute
)

// ---- the calibration of the vantage ----

// calibrate asks the PathChecker about the ports of ports this run has not asked about yet. A check that fails records the ports
// as failed (their verdict is unknown); no checker records nothing.
func (o *observer) calibrate(ctx context.Context, ports []int) {
	if o.check == nil || len(ports) == 0 {
		return
	}
	o.mu.Lock()
	var ask []int
	for _, p := range ports {
		if _, done := o.calib[p]; !done && p >= 1 && p <= 65535 && !slices.Contains(ask, p) {
			ask = append(ask, p)
		}
	}
	o.mu.Unlock()
	if len(ask) == 0 {
		return
	}
	slices.Sort(ask)
	got, err := o.check.PathAnswers(ctx, ask)
	if err != nil && ctx.Err() == nil {
		o.log.WarnContext(ctx, "exposure: checking which ports the box's own network answers failed", "ports", ask, "error", err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, p := range ask {
		switch a := got[p]; {
		case err != nil:
			o.calib[p] = calibFailed
		case a == PortOpen || a == PortClosed:
			o.calib[p] = a
		default:
			o.calib[p] = PortSilent
		}
	}
}

// calibrateStart is the calibration at the start of a run: the fixed list and the ports open before on the target.
func (s *Service) calibrateStart(ctx context.Context, t Target) {
	o := s.observerOf(ctx)
	if o.check == nil {
		return
	}
	ports := slices.Clone(commonports.Numbers())
	if prev, err := servicesOf(ctx, s.cfg.DB.Reader(), t.ID, true); err == nil {
		for _, x := range prev {
			ports = append(ports, x.Port)
		}
	}
	o.calibrate(ctx, ports)
}

// networkPorts is, of the ports open on ip, those the network answers with a syn-ack for every address and on which ip's own answer
// is the network's too (asked once per address and port): they are not the target's. Ports the check failed on stay (unknown).
func (s *Service) networkPorts(ctx context.Context, ip string, open []int) map[int]bool {
	o := s.observerOf(ctx)
	o.calibrate(ctx, open)
	out := map[int]bool{}
	for _, p := range open {
		o.mu.Lock()
		a := o.calib[p]
		d, asked := o.distinct[portKey(ip, p)]
		o.mu.Unlock()
		if a != PortOpen {
			continue
		}
		if !asked {
			d = s.distinctAnswer(ctx, ip, p)
			o.mu.Lock()
			o.distinct[portKey(ip, p)] = d
			o.mu.Unlock()
		}
		if !d {
			out[p] = true
		}
	}
	return out
}

// distinctAnswer says ip's answer on port differs from what a never-routed address gets through the same network. A comparison that
// fails says no: the port stays the network's.
func (s *Service) distinctAnswer(ctx context.Context, ip string, port int) bool {
	o := s.observerOf(ctx)
	a, err := netip.ParseAddr(ip)
	if err != nil || o.check == nil {
		return false
	}
	same, err := o.check.SameAsPath(ctx, a, port)
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.Log.WarnContext(ctx, "exposure: comparing a target's answer with the network's failed", "ip", ip, "port", port, "error", err)
		}
		return false
	}
	return !same
}

// leftOut says in the run's log, once for each port, that the results of ip lost ports to the network.
func (s *Service) leftOut(ctx context.Context, ip string, ports map[int]bool) {
	if len(ports) == 0 {
		return
	}
	o := s.observerOf(ctx)
	o.mu.Lock()
	var news []int
	k := ipKey(ip)
	for port := range ports {
		if !slices.Contains(o.leftOut[k], port) {
			o.leftOut[k] = append(o.leftOut[k], port)
		}
		if !o.said[port] {
			o.said[port] = true
			news = append(news, port)
		}
	}
	x := o.x
	o.mu.Unlock()
	if len(news) == 0 || x == nil {
		return
	}
	slices.Sort(news)
	line := upperFirst(fmt.Sprintf("%s answered by your own network, not by %s: a TCP connect to an address that is never routed (192.0.2.0/24, "+
		"198.51.100.0/24, 203.0.113.0/24) got the same answer there, so %s left out of the results.", portsWords(news), ip, itWas(len(news))))
	wc, cancel := wctx(ctx)
	defer cancel()
	if err := x.Log(wc, corerun.Warn, line); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: writing a line of the scan's run failed", "run", x.ID(), "error", err)
	}
}

// dropPathPorts is c without what the runner found on the ports the network answers (INV-44): the open ports, the admin pages and
// the certificates read on them.
func (s *Service) dropPathPorts(ctx context.Context, c Content) Content {
	byIP := map[string][]int{}
	for _, p := range c.Ports {
		k := ipKey(p.IP)
		byIP[k] = append(byIP[k], p.Port)
	}
	path := map[string]map[int]bool{}
	for _, ip := range slices.Sorted(maps.Keys(byIP)) {
		if n := s.networkPorts(ctx, ip, byIP[ip]); len(n) > 0 {
			path[ip] = n
		}
	}
	if len(path) == 0 {
		return c
	}
	c.Ports = slices.DeleteFunc(slices.Clone(c.Ports), func(p PortRow) bool { return path[ipKey(p.IP)][p.Port] })
	c.AdminPanels = slices.DeleteFunc(slices.Clone(c.AdminPanels), func(a AdminRow) bool { return path[ipKey(a.IP)][a.Port] })
	all := map[int]bool{}
	for _, ports := range path {
		maps.Copy(all, ports)
	}
	c.Certs = slices.DeleteFunc(slices.Clone(c.Certs), func(x CertRow) bool { return all[certPort(x.Host)] })
	for _, ip := range slices.Sorted(maps.Keys(path)) {
		s.leftOut(ctx, ip, path[ip])
	}
	return c
}

// certPort is the port of a certificate row's host ("name" is 443, "name:8443" is 8443).
func certPort(host string) int {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i+1:], "]") {
		if n, err := strconv.Atoi(host[i+1:]); err == nil {
			return n
		}
	}
	return 443
}

// dropPathServices is what service identification of ip read without the ports the network answers (INV-44): their services, the
// scripts that ran on them, and the ports it probed or did not finish.
func (s *Service) dropPathServices(ctx context.Context, ip string, res ServiceScan, got []ServiceRow) (ServiceScan, []ServiceRow) {
	open := make([]int, 0, len(got))
	for _, r := range got {
		open = append(open, r.Port)
	}
	path := s.networkPorts(ctx, ip, open)
	if len(path) == 0 {
		return res, got
	}
	got = slices.DeleteFunc(slices.Clone(got), func(r ServiceRow) bool { return path[r.Port] })
	res.Scripts = slices.DeleteFunc(slices.Clone(res.Scripts), func(r ScriptRow) bool { return r.Port != 0 && path[r.Port] })
	res.Probed = slices.DeleteFunc(slices.Clone(res.Probed), func(p int) bool { return path[p] })
	res.Unfinished = slices.DeleteFunc(slices.Clone(res.Unfinished), func(p int) bool { return path[p] })
	s.leftOut(ctx, ip, path)
	return res, got
}

// ---- the liveness checks ----

// checkAlive asks Liveness about the ports seen open this run that have not stopped answering yet, at most maxAliveAddrs addresses
// and maxAlivePorts ports each, and records the answers. It writes one line of the run's log. Without a Liveness, outside a scan's
// run (the step of one of a domain's addresses) or once the run is stopped it does nothing.
func (s *Service) checkAlive(ctx context.Context, st ScanTarget, c *Content, before string) {
	rs := runStepsOf(ctx)
	if s.cfg.Liveness == nil || rs == nil || ctx.Err() != nil {
		return
	}
	o := s.observerOf(ctx)
	open := openPorts(*c)
	ips := slices.Sorted(maps.Keys(open))
	if st.Kind == KindIP { // the target's own address first
		ips = slices.DeleteFunc(ips, func(ip string) bool { return ip != ipKey(st.Value) })
	}
	var newly, asked []string
	for _, ip := range ips[:min(len(ips), maxAliveAddrs)] {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		ask := slices.DeleteFunc(slices.Clone(open[ip]), func(p int) bool { return o.lostPort(ip, p) })
		if len(ask) == 0 {
			continue
		}
		ask = ask[:min(len(ask), maxAlivePorts)]
		actx, cancel := context.WithTimeout(ctx, aliveCheckLimit)
		up, err := s.cfg.Liveness.Alive(actx, a, ask)
		cancel()
		if err != nil || ctx.Err() != nil { // the check itself failed: nothing is said about the ports
			if err != nil && ctx.Err() == nil {
				s.cfg.Log.WarnContext(ctx, "exposure: the liveness check failed", "target", st.Value, "ip", ip, "error", err)
			}
			continue
		}
		got := map[int]bool{}
		for _, p := range ask {
			asked = append(asked, ip+":"+strconv.Itoa(p))
			got[p] = up[p]
		}
		for _, p := range o.noteAlive(ip, got) {
			newly = append(newly, ip+":"+strconv.Itoa(p))
		}
	}
	switch { // every check is a line of the run's log: what was connected to, and what no longer answered
	case len(newly) > 0:
		rs.logLine(ctx, corerun.Warn, fmt.Sprintf("Before %s: checked that the target still answers (a TCP connect to %s): %s no longer accepted a connection; it answered earlier in this scan.",
			before, joinAnd(asked, 6), joinAnd(newly, 6)))
	case len(asked) > 0:
		rs.logLine(ctx, corerun.Info, fmt.Sprintf("Before %s: checked that the target still answers (a TCP connect to %s): it does.", before, joinAnd(asked, 6)))
	}
}

// beforeEngine is the liveness check before the engine step key (kind: its "Not checked" lines): false when every address of the
// target stopped answering, and the step is then skipped with why. Otherwise the step runs on the ports that still answer, and when
// some stopped answering its results are incomplete and the step says so. The run's outcome comes from the verdicts.
func (s *Service) beforeEngine(ctx context.Context, st ScanTarget, c *Content, key, name, kind string) bool {
	rs := runStepsOf(ctx)
	if rs == nil {
		return true
	}
	o := s.observerOf(ctx)
	if !o.allGone(openPorts(*c)) {
		s.checkAlive(ctx, st, c, name)
	}
	text := s.lostText(ctx, st, o.lostOf())
	if text == "" {
		return true
	}
	if o.allGone(openPorts(*c)) {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: kind, Text: clipText(name+" did not run. "+text, maxLineText)})
		rs.skip(ctx, key, "Not run. "+text)
		return false
	}
	rs.incompleteOn(key, text)
	return true
}

// skipIfGone skips step key with why when every address of the target stopped answering earlier in the run (no new check): true when
// it did.
func (s *Service) skipIfGone(ctx context.Context, st ScanTarget, c Content, key string) bool {
	rs := runStepsOf(ctx)
	o := s.observerOf(ctx)
	if rs == nil || !o.allGone(openPorts(c)) {
		return false
	}
	rs.skip(ctx, key, "Not run. "+s.lostText(ctx, st, o.lostOf()))
	return true
}

// lostPort says port of ip stopped answering this run.
func (s *Service) lostPort(ctx context.Context, ip string, port int) bool {
	return s.observerOf(ctx).lostPort(ip, port)
}

// unanswered is nuclei's own sign that a port stopped answering: of the templates that ran on it, at least unansweredMin and at least
// half got no answer. A template whose requests got only connection errors, or that nuclei skipped after giving the address up as
// unresponsive, comes back as OutcomeError (cmd/vedette's outcomes); one whose lines all named another address or could not be read is
// Elsewhere. It names the ports with how many.
func unanswered(ip string, res []TemplateResult) string {
	type tally struct{ all, none int }
	by := map[int]*tally{}
	for _, r := range res {
		t := by[r.Port]
		if t == nil {
			t = &tally{}
			by[r.Port] = t
		}
		t.all++
		if r.Elsewhere || r.Outcome == OutcomeError {
			t.none++
		}
	}
	ports := make([]int, 0, len(by))
	for p, t := range by {
		if t.all >= unansweredMin && 2*t.none >= t.all {
			ports = append(ports, p)
		}
	}
	slices.Sort(ports)
	var parts []string
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%s:%d for %d of %d templates", ip, p, by[p].none, by[p].all))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Results incomplete: nuclei got no answer from " + joinAnd(parts, 4) + " (the port may have stopped answering)."
}

// unansweredMin is the fewest templates on a port for unanswered to judge it.
const unansweredMin = 20

// ---- the re-check of the ports open before ----

// recheckMissed connects once more to the ports open before that this scan did not see, on the addresses it probed (asked), and
// records what each got. It writes one line of the run's log with what it saw; what that means is the verdicts'.
func (s *Service) recheckMissed(ctx context.Context, t Target, c Content, asked map[string]bool) {
	pp, ok := s.cfg.Liveness.(PortProber)
	if !ok || ctx.Err() != nil {
		return
	}
	o := s.observerOf(ctx)
	prev, err := servicesOf(ctx, s.cfg.DB.Reader(), t.ID, true)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the open services before the re-check failed", "target", t.Value, "error", err)
		return
	}
	seen, lost := openPorts(c), o.lostOf()
	missed := map[string][]int{}
	for _, x := range prev {
		k := ipKey(x.IP)
		if !asked[k] || len(lost[k]) > 0 || slices.Contains(seen[k], x.Port) || slices.Contains(missed[k], x.Port) {
			continue
		}
		missed[k] = append(missed[k], x.Port)
	}
	ips := slices.Sorted(maps.Keys(missed))
	var said []string
	for _, ip := range ips[:min(len(ips), maxRecheckAddrs)] {
		a, err := netip.ParseAddr(ip)
		if err != nil || !IsPublicIPv4(a) {
			continue
		}
		ports := missed[ip]
		slices.Sort(ports)
		ports = ports[:min(len(ports), maxRecheckPorts)]
		pctx, cancel := context.WithTimeout(ctx, recheckLimit)
		got, err := pp.Probe(pctx, a, ports)
		cancel()
		if err != nil || ctx.Err() != nil { // the check itself failed: nothing is said about the ports
			if err != nil && ctx.Err() == nil {
				s.cfg.Log.WarnContext(ctx, "exposure: the re-check of the ports the scan missed failed", "target", t.Value, "ip", ip, "error", err)
			}
			continue
		}
		kept := map[int]string{}
		for _, p := range ports {
			switch got[p] {
			case PortOpen:
				said = append(said, ip+":"+strconv.Itoa(p)+" accepted the connection")
			case PortClosed:
				said = append(said, ip+":"+strconv.Itoa(p)+" answered with a reset")
			case PortSilent:
				said = append(said, ip+":"+strconv.Itoa(p)+" gave no answer")
			default:
				continue
			}
			kept[p] = got[p]
		}
		o.noteRecheck(ip, kept)
	}
	if len(said) > 0 {
		runStepsOf(ctx).logLine(ctx, corerun.Info, "Before writing the results: the ports open before that this scan did not see were connected to again (a TCP connect, nothing sent): "+
			joinAnd(said, 6)+".")
	}
}

// askedAddrs are the addresses (canonical spelling) this scan sent packets to: an IP target's own, a domain's addresses its deep
// scan swept, the box's own addresses among a domain's (the runner connects to its fixed list there), and those checked by name. The
// address of a name whose lookup got no answer this time was not asked, whatever its carried row says.
func (s *Service) askedAddrs(ctx context.Context, st ScanTarget, c Content) map[string]bool {
	out := map[string]bool{}
	if st.Kind == KindIP {
		out[ipKey(st.Value)] = true
		return out
	}
	o := s.observerOf(ctx)
	for _, h := range c.Hosts {
		if h.LookupFailed || slices.Contains(c.Unresolved, h.Name) {
			continue
		}
		for _, a := range h.IPs {
			if a.Class == ClassBox || a.Contacted || o.swept(a.IP) {
				out[ipKey(a.IP)] = true
			}
		}
	}
	return out
}

// ---- words ----

// openPorts is the ports seen open on each address of c this run, by its canonical spelling, ascending.
func openPorts(c Content) map[string][]int {
	out := map[string][]int{}
	add := func(ip string, port int) {
		if port < 1 || port > 65535 {
			return
		}
		k := ipKey(ip)
		if !slices.Contains(out[k], port) {
			out[k] = append(out[k], port)
		}
	}
	for _, p := range c.Ports {
		add(p.IP, p.Port)
	}
	for _, r := range c.Services {
		add(r.IP, r.Port)
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

// joinAnd is "a", "a and b", "a, b and c", at most most items then "and 3 more".
func joinAnd(items []string, most int) string {
	if len(items) > most {
		return strings.Join(items[:most], ", ") + " and " + strconv.Itoa(len(items)-most) + " more"
	}
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// retiredText is the sentence of the save step about the rows this scan no longer lists without the target having closed them, with
// a space in front ("" when none): the network's ports, and the ports not reached for 30 days.
func retiredText(network, unreached map[string][]int) string {
	var parts []string
	for _, ip := range slices.SortedFunc(maps.Keys(network), cmpAddr) {
		ports := slices.Sorted(slices.Values(network[ip]))
		parts = append(parts, fmt.Sprintf("%s of %s %s no longer listed: %s answered by your own network, not by %s.",
			upperFirst(portsOnly(ports)), ip, isAre(len(ports)), itThey(len(ports))+" "+isAre(len(ports)), ip))
	}
	for _, ip := range slices.SortedFunc(maps.Keys(unreached), cmpAddr) {
		ports := slices.Sorted(slices.Values(unreached[ip]))
		parts = append(parts, fmt.Sprintf("%s of %s %s no longer listed: not reached for 30 days.", upperFirst(portsOnly(ports)), ip, isAre(len(ports))))
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

// How many ports and addresses a line names before it counts the rest ("and 3 more"): "Not checked" lines hold maxLineText.
const maxLinePorts = 6

// portsWords is "port 5060 is", "ports 2000 and 5060 are", or past maxLinePorts "ports 2000, …, 5060 and 3 more are".
func portsWords(ports []int) string {
	if len(ports) == 1 {
		return "port " + strconv.Itoa(ports[0]) + " is"
	}
	return portsOnly(ports) + " are"
}

// portsOnly is "port 80", "ports 80 and 443", or past maxLinePorts "ports 80, …, 8443 and 3 more".
func portsOnly(ports []int) string {
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = strconv.Itoa(p)
	}
	if len(list) == 1 {
		return "port " + list[0]
	}
	return "ports " + joinAnd(list, maxLinePorts)
}

// itWas is "it was" or "they were".
func itWas(n int) string { return itThem(n, "it was", "they were") }

func itThey(n int) string { return itThem(n, "it", "they") }
func isAre(n int) string  { return itThem(n, "is", "are") }

// itThem is one when n is 1, else many.
func itThem(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

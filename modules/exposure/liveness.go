package exposure

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	corerun "github.com/knt048/vedette/core/run"
)

// A target can stop answering in the middle of a scan: the router in front of the box's own public IP loses its NAT loopback (the
// box then cannot reach its own address from inside the network, while the ports stay open from outside), a firewall or a ban list
// starts dropping the box's packets, a link goes down. The engines then send their checks into the void and report "nothing found".
// So before each engine step (templates, ZAP's passive and active scans, OpenVAS, nmap's disruptive scripts) and before the results
// are written, the scan checks that the ports seen open earlier in this run still accept a TCP connection (Liveness: a connect, no
// data). A port that no longer answers is lost for the rest of the run: the next engines skip it, the step that lost it ends partly
// done with why, and an address none of whose ports answer any more is not scanned further (its later steps are skipped with why).
// The run then ends partly done, never done. A scan in which an address stopped answering never counts as a miss of its ports
// (coverage: the address gets the run item coverLost, "stopped_answering", which checks no port).

// Liveness says which of ports still accept a TCP connection on ip: a plain connect from the box, closed at once, no data sent.
// cmd/vedette implements it; nil: no check (every port is taken as answering).
type Liveness interface {
	Alive(ctx context.Context, ip netip.Addr, ports []int) (map[int]bool, error)
}

// Bounds of one liveness check: the addresses and ports a check asks about (the ports seen open on an IP target are at most
// commonports.MaxBelievableOpen anyway), and the time it may take.
const (
	maxAliveAddrs   = 4
	maxAlivePorts   = 16
	aliveCheckLimit = 30 * time.Second
)

// coverLost is the run item of an address that stopped answering during the scan: it checks no port, so the scan is not a miss of any.
const coverLost = "stopped_answering"

// natHint is said of the box's own public IP when it stops answering: the likely cause, without claiming a firewall or an IPS.
const natHint = "The box could not reach its own public address from inside your network: the router may not support NAT loopback (hairpin NAT), or something blocked it. The ports may still be open from the Internet."

// lostText is the sentence of the ports of the target that stopped answering ("" when none): "Results incomplete: 203.0.113.5:9443 and
// 203.0.113.5:10443 stopped answering during the scan." and, for the box's own public IP, natHint.
func (s *Service) lostText(ctx context.Context, st ScanTarget, lost map[string][]int) string {
	if len(lost) == 0 {
		return ""
	}
	ips := make([]string, 0, len(lost))
	for ip := range lost {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	var where []string
	own := false
	for _, ip := range ips {
		for _, p := range lost[ip] {
			where = append(where, ip+":"+strconv.Itoa(p))
		}
		if s.ownAddress(ctx, st, ip) {
			own = true
		}
	}
	text := "Results incomplete: " + joinAnd(where, 6) + " stopped answering during the scan."
	if own {
		text += " " + natHint
	}
	return text
}

// ownAddress says ip is the box's own public IP: an IP target that is not typed in (the box saw it as its own address), or an
// address of a domain's names that is a scannable IP target (the box's own).
func (s *Service) ownAddress(ctx context.Context, st ScanTarget, ip string) bool {
	if st.Kind == KindIP {
		return !st.Typed && ipKey(st.Value) == ip
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	ok, err := s.ScannableIP(ctx, st.User, a)
	return err == nil && ok
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

// lostPort says port of ip stopped answering this run.
func (c Content) lostPort(ip string, port int) bool { return slices.Contains(c.Lost[ipKey(ip)], port) }

// gone says none of the ports seen open on ip this run answers any more (and at least one was lost).
func (c Content) gone(ip string) bool {
	k := ipKey(ip)
	if len(c.Lost[k]) == 0 {
		return false
	}
	for _, p := range openPorts(c)[k] {
		if !slices.Contains(c.Lost[k], p) {
			return false
		}
	}
	return true
}

// allGone says every address of c with a port seen open this run stopped answering.
func (c Content) allGone() bool {
	open := openPorts(c)
	if len(open) == 0 || len(c.Lost) == 0 {
		return false
	}
	for ip := range open {
		if !c.gone(ip) {
			return false
		}
	}
	return true
}

// checkAlive asks Liveness about the ports seen open this run that have not stopped answering yet, at most maxAliveAddrs addresses
// and maxAlivePorts ports each, and adds those that do not answer to c.Lost. It writes one line of the run's log when a port stopped
// answering. Without a Liveness, outside a scan's run (the step of one of a domain's addresses) or once the run is stopped it does
// nothing.
func (s *Service) checkAlive(ctx context.Context, st ScanTarget, c *Content, before string) {
	rs := runStepsOf(ctx)
	if s.cfg.Liveness == nil || rs == nil || ctx.Err() != nil {
		return
	}
	open := openPorts(*c)
	ips := make([]string, 0, len(open))
	for ip := range open {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	if st.Kind == KindIP { // the target's own address first
		ips = slices.DeleteFunc(ips, func(ip string) bool { return ip != ipKey(st.Value) })
	}
	var newly, asked []string
	for _, ip := range ips[:min(len(ips), maxAliveAddrs)] {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		ask := slices.DeleteFunc(slices.Clone(open[ip]), func(p int) bool { return c.lostPort(ip, p) })
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
		for _, p := range ask {
			asked = append(asked, ip+":"+strconv.Itoa(p))
			if up[p] {
				continue
			}
			if c.Lost == nil {
				c.Lost = map[string][]int{}
			}
			c.Lost[ip] = append(c.Lost[ip], p)
			newly = append(newly, ip+":"+strconv.Itoa(p))
		}
		slices.Sort(c.Lost[ip])
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
// target stopped answering, and the step is then skipped with why (the run ends partly done). Otherwise the step runs on the ports
// that still answer, and when some stopped answering its results are incomplete and the step says so.
func (s *Service) beforeEngine(ctx context.Context, st ScanTarget, c *Content, key, name, kind string) bool {
	rs := runStepsOf(ctx)
	if rs == nil {
		return true
	}
	if !c.allGone() {
		s.checkAlive(ctx, st, c, name)
	}
	text := s.lostText(ctx, st, c.Lost)
	if text == "" {
		return true
	}
	rs.problem(text)
	if c.allGone() {
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
	if rs == nil || !c.allGone() {
		return false
	}
	text := s.lostText(ctx, st, c.Lost)
	rs.problem(text)
	rs.skip(ctx, key, "Not run. "+text)
	return true
}

// unanswered is nuclei's own sign that a port stopped answering: of the templates that ran on it, at least unansweredMin and at least
// half got no answer. A template whose requests got only connection errors, or that nuclei skipped after giving the address up as
// unresponsive, comes back as OutcomeError (cmd/vedette's outcomes); one whose lines all named another address or could not be read is
// Elsewhere (nucleiout keeps at most 20 such templates a run, so Elsewhere alone would rarely reach half). It names the ports with how
// many.
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

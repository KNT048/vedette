package exposure

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	corerun "github.com/knt048/vedette/core/run"
)

// INV-44: some networks answer a TCP connect on a few ports for any destination (an office firewall's SIP or SCCP helper answers the
// SYN on 5060 or 2000 itself, a transparent proxy or a SYN proxy does the same). From such a network every target shows those ports
// open. Before a port found open counts as the target's, the run asks the PathChecker once whether the port also answers for an
// address that is never routed; a port that does is the network's: it is left out of the results (no service, no issue, no engine
// step), and it is neither seen nor missed for closing (INV-22). The run's log and the target's "Not checked" lines say so.

// itemPathPort is the kind of a run item that says the network answered port (its subject) for any destination in this run, so the
// run did not check that port anywhere (previousCheck skips it).
const itemPathPort = "path_port"

// outcomePathPort is the outcome of an itemPathPort item.
const outcomePathPort = "answered_by_network"

// notPathPorts is the "Not checked" line of the ports the network answered: the ports ("Ports 2000 and 5060 are"), the addresses
// whose results lost them, and "it was" or "they were".
const notPathPorts = "%s answered by your own network (a firewall helper or a proxy), not by %s (the same answer comes for an address that is never routed), so %s left out of the results."

// pathRun is one run's answers of the PathChecker: each port is checked at most once a run, the first time a scan step finds it open.
type pathRun struct {
	check PathChecker
	x     *corerun.Exec // nil outside a run (a test of one step)

	mu    sync.Mutex
	known map[int]bool    // a port checked this run: true when the network answered it
	addrs map[string]bool // the addresses whose results lost a port to it
	order []string        // those addresses in the order they lost one (the line names them in that order)
	ports map[int]bool    // the ports left out
	said  map[int]bool    // the ports already said in the run's log
}

type pathRunKey struct{}

// withPathRun is ctx for the work of one run, with its own record of the network's answers.
func (s *Service) withPathRun(ctx context.Context, x *corerun.Exec) context.Context {
	return context.WithValue(ctx, pathRunKey{}, s.newPathRun(x))
}

func (s *Service) newPathRun(x *corerun.Exec) *pathRun {
	return &pathRun{check: s.cfg.Path, x: x, known: map[int]bool{}, addrs: map[string]bool{}, ports: map[int]bool{}, said: map[int]bool{}}
}

// pathRunOf is ctx's record of the network's answers; a new one when ctx carries none (a step called outside a run).
func (s *Service) pathRunOf(ctx context.Context) *pathRun {
	if p, ok := ctx.Value(pathRunKey{}).(*pathRun); ok {
		return p
	}
	return s.newPathRun(nil)
}

// answeredByPath says which of ports the network answers for any destination, asking the checker only about the ports this run has not
// asked about yet. A checker that is missing or fails knows of none: the results stay as they were before the check existed.
func (s *Service) answeredByPath(ctx context.Context, ports []int) map[int]bool {
	p := s.pathRunOf(ctx)
	if p.check == nil || len(ports) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var ask []int
	for _, port := range ports {
		if _, done := p.known[port]; !done && port >= 1 && port <= 65535 && !slices.Contains(ask, port) {
			ask = append(ask, port)
		}
	}
	if len(ask) > 0 {
		slices.Sort(ask)
		got, err := p.check.AnsweredByPath(ctx, ask)
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "exposure: checking which ports the box's own network answers failed; the open ports are kept", "ports", ask, "error", err)
			return p.knownLocked(ports)
		}
		for _, port := range ask {
			p.known[port] = slices.Contains(got, port)
		}
	}
	return p.knownLocked(ports)
}

// knownLocked is the ports of ports the network answers, as far as this run knows. The caller holds mu.
func (p *pathRun) knownLocked(ports []int) map[int]bool {
	out := map[int]bool{}
	for _, port := range ports {
		if p.known[port] {
			out[port] = true
		}
	}
	return out
}

// leftOut records that the results of ip lost ports to the network, and says it in the run's log once for each port.
func (s *Service) leftOut(ctx context.Context, ip string, ports map[int]bool) {
	if len(ports) == 0 {
		return
	}
	p := s.pathRunOf(ctx)
	p.mu.Lock()
	var news []int
	if !p.addrs[ip] {
		p.addrs[ip] = true
		p.order = append(p.order, ip)
	}
	for port := range ports {
		p.ports[port] = true
		if !p.said[port] {
			p.said[port] = true
			news = append(news, port)
		}
	}
	x := p.x
	p.mu.Unlock()
	if len(news) == 0 || x == nil {
		return
	}
	slices.Sort(news)
	line := upperFirst(fmt.Sprintf("%s answered by your own network, not by %s: a TCP connect to an address that is never routed (192.0.2.0/24, "+
		"198.51.100.0/24, 203.0.113.0/24) got an answer there too, so %s left out of the results.", portsWords(news), ip, itWas(len(news))))
	wc, cancel := wctx(ctx)
	defer cancel()
	if err := x.Log(wc, corerun.Warn, line); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: writing a line of the scan's run failed", "run", x.ID(), "error", err)
	}
}

// pathPortsOf is what the run left out: the ports, ascending, and the "Not checked" line that says so ("" when none).
func (s *Service) pathPortsOf(ctx context.Context) ([]int, string) {
	p := s.pathRunOf(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ports) == 0 {
		return nil, ""
	}
	ports := slices.Sorted(maps.Keys(p.ports))
	addrs := slices.Clone(p.order)
	who := strings.Join(addrs, ", ")
	switch {
	case len(addrs) > maxLineAddrs:
		who = strings.Join(addrs[:maxLineAddrs], ", ") + " or " + strconv.Itoa(len(addrs)-maxLineAddrs) + " more"
	case len(addrs) > 1:
		who = strings.Join(addrs[:len(addrs)-1], ", ") + " or " + addrs[len(addrs)-1]
	}
	// a "Not checked" line longer than maxLineText is dropped when the results are written: a few ports and addresses, then counts
	return ports, clipText(upperFirst(fmt.Sprintf(notPathPorts, portsWords(ports), who, itWas(len(ports)))), maxLineText)
}

// How many ports and addresses a line names before it counts the rest ("and 3 more"): "Not checked" lines hold maxLineText.
const (
	maxLinePorts = 6
	maxLineAddrs = 3
)

// portsWords is "port 5060 is", "ports 2000 and 5060 are", or past maxLinePorts "ports 2000, …, 5060 and 3 more are".
func portsWords(ports []int) string {
	if len(ports) == 1 {
		return "port " + strconv.Itoa(ports[0]) + " is"
	}
	return portsOnly(ports) + " are"
}

// itWas is "it was" or "they were".
func itWas(n int) string {
	if n == 1 {
		return "it was"
	}
	return "they were"
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// dropPathPorts is c without what the runner found on the ports the network answers (INV-44): the open ports, the admin pages and
// the certificates read on them. It says so for each address that lost one.
func (s *Service) dropPathPorts(ctx context.Context, c Content) Content {
	open := make([]int, 0, len(c.Ports))
	for _, p := range c.Ports {
		open = append(open, p.Port)
	}
	path := s.answeredByPath(ctx, open)
	if len(path) == 0 {
		return c
	}
	lost := map[string]map[int]bool{}
	c.Ports = slices.DeleteFunc(slices.Clone(c.Ports), func(p PortRow) bool {
		if !path[p.Port] {
			return false
		}
		k := ipKey(p.IP)
		if lost[k] == nil {
			lost[k] = map[int]bool{}
		}
		lost[k][p.Port] = true
		return true
	})
	c.AdminPanels = slices.DeleteFunc(slices.Clone(c.AdminPanels), func(a AdminRow) bool { return path[a.Port] })
	c.Certs = slices.DeleteFunc(slices.Clone(c.Certs), func(x CertRow) bool { return path[certPort(x.Host)] })
	for _, ip := range slices.Sorted(maps.Keys(lost)) {
		s.leftOut(ctx, ip, lost[ip])
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
// scripts that ran on them, and the ports it probed or did not finish (neither seen nor missed: the run did not check them).
func (s *Service) dropPathServices(ctx context.Context, ip string, res ServiceScan, got []ServiceRow) (ServiceScan, []ServiceRow) {
	open := make([]int, 0, len(got))
	for _, r := range got {
		open = append(open, r.Port)
	}
	path := s.answeredByPath(ctx, open)
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

// recordPathPorts writes, as items of the run, the ports the network answered this run: a later scan's closing does not take this
// run as one that checked them (previousCheck).
func (s *Service) recordPathPorts(ctx context.Context, x *corerun.Exec, ports []int) {
	if len(ports) == 0 {
		return
	}
	items := make([]corerun.Item, 0, len(ports))
	for _, p := range ports {
		n := strconv.Itoa(p)
		items = append(items, corerun.Item{SubjectKind: itemPathPort, SubjectID: n, Label: "port " + n, Outcome: outcomePathPort})
	}
	if err := x.AddItems(ctx, items...); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: recording the ports the box's own network answered", "run", x.ID(), "error", err)
	}
}

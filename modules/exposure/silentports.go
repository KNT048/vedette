package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"time"

	corerun "github.com/knt048/vedette/core/run"
)

// INV-22: a firewall or WAF that starts dropping the box's packets to some ports of a target (it blocked the box's public IP) while
// other ports still answer looks, to the runner's connect and to nmap's sweep, exactly like those ports being closed: both miss them,
// and the sweep is still trusted because the other ports answered. So right before the results are written, the ports that were open
// before and that this scan did not see are connected to once more (PortProber), and what they answer decides:
//
//	| the re-check of a port open before that this scan missed | the port                                                            |
//	|-----------------------------------------------------------|---------------------------------------------------------------------|
//	| it accepts the connection                                 | open: the scan missed it, not a miss                                |
//	| a reset (TCP RST: closed)                                 | the rules of INV-22 as before (a trusted sweep and the runner: at once) |
//	| no answer at all (timeout, no reset)                      | not a miss; closed by the third such scan in a row, a day after the first |
//	| not asked (no prober, the check failed, past the bounds) | the rules of INV-22 as before                                        |
//
// An address that stopped answering during the scan (liveness.go, coverLost) is not re-checked: the scan is no miss there anyway.

// What one TCP connect to a port got (PortProber).
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

// Bounds of the re-check: the addresses and ports a scan asks about, and the time it may take.
const (
	maxRecheckAddrs = 8
	maxRecheckPorts = 32
	recheckLimit    = time.Minute
)

// itemSilentPort is the kind of a run item that says a port open before gave no answer at all to this scan (its subject is portKey):
// silentStreak counts them.
const itemSilentPort = "silent_port"

// itemAnsweredPort is the kind of a run item that says a port open before, that this scan did not see, accepted the re-check's
// connection (its subject is portKey, its outcome outcomeStillOpen): the port answered in that run, so silentStreak counts the
// silent scans after it only, and neither it nor a silent run is a scan that missed the port for previousCheck.
const (
	itemAnsweredPort = "answered_port"
	outcomeStillOpen = "still_open"
)

// The silent streak that closes a port: the silentStreakScans-th silent scan in a row, at least silentStreakSpan after the first.
const (
	silentStreakScans = 3
	silentStreakSpan  = 24 * time.Hour
)

// recheckMissed re-checks the ports open before on the addresses this scan port-scanned that it did not see (see above) and fills
// c.Silent and c.Answering. It writes one line of the run's log and, for the silent ones, one "Not checked" line of the target.
func (s *Service) recheckMissed(ctx context.Context, t Target, c *Content) {
	pp, ok := s.cfg.Liveness.(PortProber)
	if !ok || ctx.Err() != nil {
		return
	}
	prev, err := servicesOf(ctx, s.cfg.DB.Reader(), t.ID, true)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the open services before the re-check failed", "target", t.Value, "error", err)
		return
	}
	seen := openPorts(*c)
	path, _ := s.pathPortsOf(ctx)
	scanned := portScanned(t, *c)
	missed := map[string][]int{}
	for _, x := range prev {
		k := ipKey(x.IP)
		if !scanned[k] || len(c.Lost[k]) > 0 || slices.Contains(seen[k], x.Port) || slices.Contains(path, x.Port) || slices.Contains(missed[k], x.Port) {
			continue
		}
		missed[k] = append(missed[k], x.Port)
	}
	ips := slices.Sorted(maps.Keys(missed))
	var silent, answering, closed []string
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
		for _, p := range ports {
			where := ip + ":" + strconv.Itoa(p)
			switch got[p] {
			case PortSilent:
				if c.Silent == nil {
					c.Silent = map[string][]int{}
				}
				c.Silent[ip] = append(c.Silent[ip], p)
				silent = append(silent, where)
			case PortOpen:
				if c.Answering == nil {
					c.Answering = map[string][]int{}
				}
				c.Answering[ip] = append(c.Answering[ip], p)
				answering = append(answering, where)
			case PortClosed:
				closed = append(closed, where)
			}
		}
	}
	if len(silent)+len(answering)+len(closed) == 0 {
		return
	}
	line := "Before writing the results: the ports open before that this scan did not see were connected to again (a TCP connect, nothing sent)."
	if len(closed) > 0 {
		line += " " + joinAnd(closed, 6) + " answered with a reset: closed."
	}
	if len(answering) > 0 {
		line += " " + joinAnd(answering, 6) + " accepted the connection: still open, the scan missed it."
	}
	if len(silent) > 0 {
		line += " " + joinAnd(silent, 6) + " gave no answer at all (no reset): a firewall or WAF that blocks this box looks like this, so they are kept open until three scans in a row over at least a day find them silent."
		for _, ip := range slices.Sorted(maps.Keys(c.Silent)) {
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "silent_ports", Text: fmt.Sprintf(
				"%s of %s were open before and gave no answer at all in this scan (no reset): a firewall or WAF may be blocking this box. %s kept as %s until three scans in a row over at least a day find %s silent.",
				upperFirst(portsOnly(c.Silent[ip])), ip, upperFirst(itThey(len(c.Silent[ip]))+" "+isAre(len(c.Silent[ip]))), itThem(len(c.Silent[ip]), "it was", "they were"), itThem(len(c.Silent[ip]), "it", "them"))})
		}
	}
	runStepsOf(ctx).logLine(ctx, corerun.Info, line)
}

// portsOnly is "port 80" or "ports 80 and 443".
func portsOnly(ports []int) string {
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = strconv.Itoa(p)
	}
	if len(list) == 1 {
		return "port " + list[0]
	}
	return "ports " + joinAnd(list, len(list))
}

func itThey(n int) string { return itThem(n, "it", "they") }
func isAre(n int) string  { return itThem(n, "is", "are") }

// itThem is one when n is 1, else many.
func itThem(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// portScanned is the addresses this scan port-scanned (by their canonical spelling): an IP target's own address, a domain's addresses
// its deep scan swept, and the box's own addresses among a domain's (the runner connects to its fixed list there). Only these are
// re-checked: the scan already reached them.
func portScanned(t Target, c Content) map[string]bool {
	out := map[string]bool{}
	if t.Kind == KindIP {
		out[ipKey(t.Value)] = true
		return out
	}
	for ip := range c.Swept {
		out[ipKey(ip)] = true
	}
	for _, h := range c.Hosts {
		for _, a := range h.IPs {
			if a.Class == ClassBox {
				out[ipKey(a.IP)] = true
			}
		}
	}
	return out
}

// silentStreak says this scan (run runID) of target is the silentStreakScans-th or later scan in a row to which port (portKey) gave no
// answer at all since it last answered (it was last seen open, lastSeen, or it accepted a later re-check: itemAnsweredPort), at least
// silentStreakSpan after the first of them.
func silentStreak(ctx context.Context, q querier, target, runID, port, lastSeen string) (bool, error) {
	var answered sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT max(r.started_at) FROM core_run_item i JOIN core_run r ON r.id = i.run_id
		WHERE r.module = ? AND r.kind = ? AND r.subject_kind = 'target' AND r.subject_id = ? AND r.id <> ?
			AND r.started_at < (SELECT started_at FROM core_run WHERE id = ?) AND i.subject_kind = ? AND i.subject_id = ?`,
		ModuleID, RunKind, target, runID, runID, itemAnsweredPort, port).Scan(&answered); err != nil {
		return false, fmt.Errorf("the last answer of %s: %w", port, err)
	}
	since := lastSeen
	if answered.Valid && answered.String > since {
		since = answered.String
	}
	var n int
	var first, now sql.NullString
	err := q.QueryRowContext(ctx, `SELECT count(*), min(r.started_at), (SELECT started_at FROM core_run WHERE id = ?) FROM core_run_item i JOIN core_run r ON r.id = i.run_id
		WHERE r.module = ? AND r.kind = ? AND r.subject_kind = 'target' AND r.subject_id = ? AND r.id <> ? AND r.started_at IS NOT NULL
			AND r.started_at > ? AND r.started_at < (SELECT started_at FROM core_run WHERE id = ?) AND i.subject_kind = ? AND i.subject_id = ?`,
		runID, ModuleID, RunKind, target, runID, since, runID, itemSilentPort, port).Scan(&n, &first, &now)
	if err != nil {
		return false, fmt.Errorf("the silent scans of %s: %w", port, err)
	}
	if n+1 < silentStreakScans || !first.Valid || !now.Valid {
		return false, nil
	}
	a, err1 := parseTS(first.String)
	b, err2 := parseTS(now.String)
	return err1 == nil && err2 == nil && b.Sub(a) >= silentStreakSpan, nil
}

// recordSilent writes, as items of the run, the ports that gave no answer at all to this scan and the ones that accepted the re-check
// (silentStreak and previousCheck read them).
func (s *Service) recordSilent(ctx context.Context, x *corerun.Exec, silent, answering map[string][]int) {
	var items []corerun.Item
	for _, ip := range slices.Sorted(maps.Keys(silent)) {
		for _, p := range silent[ip] {
			k := portKey(ip, p)
			items = append(items, corerun.Item{SubjectKind: itemSilentPort, SubjectID: k, Label: k, Outcome: PortSilent})
		}
	}
	for _, ip := range slices.Sorted(maps.Keys(answering)) {
		for _, p := range answering[ip] {
			k := portKey(ip, p)
			items = append(items, corerun.Item{SubjectKind: itemAnsweredPort, SubjectID: k, Label: k, Outcome: outcomeStillOpen})
		}
	}
	if len(items) == 0 {
		return
	}
	if err := x.AddItems(ctx, items...); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: recording the ports that gave no answer", "run", x.ID(), "error", err)
	}
}

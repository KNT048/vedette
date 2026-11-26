package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The scan writer: the one writer of exp_host, exp_address, exp_service and exp_issue. A scan's content is merged into the rows of its
// target: what it saw gets last_seen (and first_seen when new), a service it no longer finds on an address it checked is closed, an
// issue an engine that ran no longer reports is gone. What a scan did not check is left as it was, so one scan that could not reach
// an address never reads as a fix.

// engineSet is the engines whose issues one write replaces: an issue of an engine in it that the write does not report is gone (when
// its service was seen by this scan, or it is about the target as a whole); the issues of the other engines are left as they were.
type engineSet map[IssueEngine]bool

// scanWrite is what one scan hands the writer.
type scanWrite struct {
	target Target
	runID  string
	user   string
	at     time.Time
	c      Content // sanitized
	// verdicts are this run's verdicts of each address and port (observe.go): the only thing the closing of a service reads; gone is
	// the addresses of the services open before that no name of the domain points at any more.
	verdicts verdictSet
	gone     map[string]bool
	ran      engineSet // the engines that ran in this scan, besides the surface (the surface always ran when there is a write)
	vulns    []VulnRow // the exploited CVEs matched on its services (withVulns)
	first    bool      // the target had no rows before this scan
}

// written is what a write changed.
type written struct {
	closed []string // the services this scan closed
	// retired are the ports, by address, whose rows earlier scans stored open and that this scan no longer lists without the target
	// having closed them: the box's own network answers them (INV-44), or they were not reached for 30 days. Their issues are gone;
	// they are not counted as closed by the target.
	retired, unreached map[string][]int
	verdicts           verdictSet    // the run's verdicts: its run items
	lines              []vantageLine // what they say: the target's lines, the run's log and its reason
	final              vulnSet       // the content as written, with the exploited CVEs matched on it
	counts             ScanCounts
	opened             []PortRow
	newIssues          []string
	// openedAt and newAt are opened and newIssues with the target that holds each row once the tree settled: the target the alert and
	// the event name.
	openedAt []OpenedService
	newAt    []NewIssue
	first    bool              // the target's first scan: the baseline
	again    map[string]string // the new issues a scan opened again after a person marked them patched or mitigated: how
	probed   map[string]string // the names the scan probed (its hosts), with the ids of their rows: items of its run
}

// issueIn is one issue a scan reported, before it is a row.
type issueIn struct {
	engine   IssueEngine
	key      string
	ip       string // with port: the service it is about; empty: about the target, or a name in host
	host     string // a name under the domain whose address carries the service (resolved through the scan's own hosts)
	port     int
	title    string
	severity string
	cves     []string
	detail   IssueDetail
}

// writeScan writes the rows of one scan in tx, with its exposure.scan audit row, and returns what changed.
func (s *Service) writeScan(ctx context.Context, tx *sql.Tx, w scanWrite) (written, error) {
	if _, err := loadTarget(ctx, tx, w.target.ID); err != nil { // deleted while the scan ran
		return written{}, err
	}
	at := store.FormatTS(w.at)
	hostIDs, err := writeHosts(ctx, tx, w.target.ID, at, w.c.Hosts)
	if err != nil {
		return written{}, err
	}
	out := written{probed: hostIDs}
	if _, err := writeHosts(ctx, tx, w.target.ID, at, w.c.Listed); err != nil { // found, not probed: rows without addresses
		return written{}, err
	}
	if err := writeAddresses(ctx, tx, w.target, at, w.c.Hosts, hostIDs); err != nil {
		return written{}, err
	}
	var retiredIDs []string
	if out.opened, out.closed, retiredIDs, out.retired, out.unreached, err = s.writeServices(ctx, tx, w, at); err != nil {
		return written{}, err
	}
	out.counts.ClosedServices = len(out.closed)
	issues := surfaceIssues(w.c, w.at)
	ran := engineSet{EngineSurface: true}
	for e, ok := range w.ran {
		ran[e] = ok
	}
	if ran[EngineNuclei] {
		issues = append(issues, nucleiIssues(w.c.Templates)...)
	}
	if ran[EngineZAP] {
		issues = append(issues, zapIssues(w.c.WebFindings)...)
	}
	if ran[EngineMatch] {
		issues = append(issues, matchIssues(w.vulns)...)
	}
	hosts := hostAddrs(w.target, w.c.Hosts)
	var again []reopenedIssue
	if out.newIssues, again, err = writeIssues(ctx, tx, w.target.ID, w.runID, at, hosts, issues, ran, scanCoverage(w)); err != nil {
		return written{}, err
	}
	if out.again, err = s.auditAgain(ctx, tx, again); err != nil {
		return written{}, err
	}
	if err := goneWithService(ctx, tx, append(slices.Clone(out.closed), retiredIDs...)); err != nil {
		return written{}, err
	}
	// The tree as it is now decides which of these names the target scans: the rows of a name another target took over while the scan ran
	// (or one a runner probed against the plan) go to that target, and what went with them is not new here.
	openedIDs, err := serviceIDs(ctx, tx, w.target.ID, out.opened)
	if err != nil {
		return written{}, err
	}
	hl, err := settleTree(ctx, tx, "")
	if err != nil {
		return written{}, err
	}
	var keptIDs []string
	out.opened, keptIDs, out.newIssues = stillNew(hl, out.opened, openedIDs, out.newIssues)
	out.counts.NewServices, out.counts.NewIssues = len(out.opened), len(out.newIssues)
	if out.openedAt, err = holders(ctx, tx, w.target.ID, out.opened, keptIDs); err != nil {
		return written{}, err
	}
	if out.newAt, err = issueHolders(ctx, tx, out.newIssues, out.again); err != nil {
		return written{}, err
	}
	if err := rowCounts(ctx, tx, w.target.ID, &out.counts); err != nil {
		return written{}, err
	}
	found := countsOf(w.c, ipOf(w.target), w.at)
	if err := updateSummary(ctx, tx, w.runID, func(sum *scanSummary) {
		sum.Counts, sum.Found = &out.counts, &found
		sum.Checks, sum.NotChecked = append(sum.Checks, w.c.Checks...), append(sum.NotChecked, w.c.NotChecked...)
	}); err != nil {
		return written{}, err
	}
	detail := fmt.Sprintf("%d names, %d open services (%d new, %d closed), %d open issues (%d new)", out.counts.Hosts, out.counts.Services,
		out.counts.NewServices, out.counts.ClosedServices, out.counts.Issues, out.counts.NewIssues)
	return out, s.audit(ctx, tx, w.user, "exposure.scan", w.target.Value, detail)
}

// serviceIDs is the id of target's row of each port.
func serviceIDs(ctx context.Context, tx *sql.Tx, target string, ports []PortRow) ([]string, error) {
	ids := make([]string, len(ports))
	for i, p := range ports {
		err := tx.QueryRowContext(ctx, `SELECT id FROM exp_service WHERE target_id = ? AND ip = ? AND port = ? AND proto = 'tcp'`, target, ipKey(p.IP), p.Port).Scan(&ids[i])
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("the services opened: %w", err)
		}
	}
	return ids, nil
}

// stillNew keeps, of the services opened (ids: their rows) and the issues new in a write, those the settle did not fold into a row another
// target held before: a port or an issue new here stays new (once) when it moves with its name to the target that scans it now.
func stillNew(hl *handLog, opened []PortRow, ids []string, fresh []string) ([]PortRow, []string, []string) {
	var ports []PortRow
	var kept []string
	for i, p := range opened {
		if !hl.merged[ids[i]] {
			ports, kept = append(ports, p), append(kept, ids[i])
		}
	}
	var out []string
	for _, id := range fresh {
		if !hl.merged[id] {
			out = append(out, id)
		}
	}
	return ports, kept, out
}

// writeOpenVAS writes the issues of the OpenVAS step of a scan whose other rows are written. covered is where OpenVAS finished (the
// addresses it scanned to the end, and their open ports): an OpenVAS issue it no longer reports is gone only there; nil (a step that
// failed, was stopped or was cut short everywhere) only adds what it found.
func (s *Service) writeOpenVAS(ctx context.Context, tx *sql.Tx, t Target, runID string, at time.Time, o gbOutcome, covered coverFunc) ([]NewIssue, error) {
	if _, err := loadTarget(ctx, tx, t.ID); err != nil {
		return nil, err
	}
	issues := make([]issueIn, 0, len(o.rows))
	for _, r := range o.rows {
		issues = append(issues, openvasIssue(r))
	}
	hosts, err := storedHostAddrs(ctx, tx, t)
	if err != nil {
		return nil, err
	}
	fresh, reopened, err := writeIssues(ctx, tx, t.ID, runID, store.FormatTS(at), hosts, issues, engineSet{EngineOpenVAS: covered != nil}, map[IssueEngine]coverFunc{EngineOpenVAS: covered})
	if err != nil {
		return nil, err
	}
	again, err := s.auditAgain(ctx, tx, reopened)
	if err != nil {
		return nil, err
	}
	var countErr error
	err = updateSummary(ctx, tx, runID, func(sum *scanSummary) {
		not := slices.DeleteFunc(sum.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "greenbone" && n.Text == gbPending })
		sum.NotChecked, sum.Checks = append(not, o.not...), append(sum.Checks, o.checks...)
		if sum.Counts != nil {
			sum.Counts.NewIssues += len(fresh)
			if err := rowCounts(ctx, tx, t.ID, sum.Counts); err != nil {
				countErr = err
			}
		}
	})
	if err == nil {
		err = countErr
	}
	if err != nil {
		return nil, err
	}
	return issueHolders(ctx, tx, fresh, again)
}

// ---- hosts and addresses ----

// writeHosts upserts the names a domain scan found and returns their ids by name. A name whose lookup failed this time is not in the
// content: its row keeps what the scan before saw.
func writeHosts(ctx context.Context, tx *sql.Tx, target, at string, hosts []HostRow) (map[string]string, error) {
	ids := map[string]string{}
	for _, h := range hosts {
		if h.Name == "" || h.LookupFailed {
			continue
		}
		src := HostSource(h.Source)
		if !src.Valid() {
			src = SourceDNS
		}
		var id string
		err := tx.QueryRowContext(ctx, `SELECT id FROM exp_host WHERE target_id = ? AND name = ?`, target, h.Name).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			id = store.NewID("xh")
			_, err = tx.ExecContext(ctx, `INSERT INTO exp_host (id, target_id, name, source, cname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, target, h.Name, string(src), nullString(h.CNAME), at, at)
		case err == nil:
			_, err = tx.ExecContext(ctx, `UPDATE exp_host SET cname = ?, last_seen = max(last_seen, ?) WHERE id = ?`, nullString(h.CNAME), at, id)
		}
		if err != nil {
			return nil, fmt.Errorf("writing the name %s: %w", h.Name, err)
		}
		ids[h.Name] = id
	}
	return ids, nil
}

// writeAddresses upserts the addresses of the names (and of an IP target, itself).
func writeAddresses(ctx context.Context, tx *sql.Tx, t Target, at string, hosts []HostRow, ids map[string]string) error {
	put := func(host any, ip, family, class string) error {
		res, err := tx.ExecContext(ctx, `UPDATE exp_address SET family = ?, class = ?, last_seen = max(last_seen, ?)
			WHERE target_id = ? AND ifnull(host_id, '') = ifnull(?, '') AND ip = ?`, family, class, at, t.ID, host, ip)
		if err != nil {
			return fmt.Errorf("writing the address %s: %w", ip, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO exp_address (host_id, target_id, ip, family, class, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			host, t.ID, ip, family, class, at, at); err != nil {
			return fmt.Errorf("writing the address %s: %w", ip, err)
		}
		return nil
	}
	if t.Kind == KindIP {
		class := ClassPublic
		if t.Origin == OriginBox {
			class = ClassBox
		}
		return put(nil, t.Value, "ipv4", class)
	}
	for _, h := range hosts {
		id, ok := ids[h.Name]
		if !ok {
			continue
		}
		for _, a := range h.IPs {
			if err := put(id, a.IP, a.Family, a.Class); err != nil {
				return err
			}
		}
		if len(h.IPs) == 0 && h.IP != "" { // a row of an older scanner: only its first address
			if ip, err := netip.ParseAddr(h.IP); err == nil {
				fam := "ipv4"
				if ip.Unmap().Is6() {
					fam = "ipv6"
				}
				if err := put(id, ip.Unmap().String(), fam, ClassPublic); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// hostAddrs is where each name of a scan points (and an IP target, itself): the addresses an issue reported by name is resolved on.
func hostAddrs(t Target, hosts []HostRow) map[string][]string {
	out := map[string][]string{}
	if t.Kind == KindIP {
		out[t.Value] = []string{t.Value}
	}
	for _, h := range hosts {
		for _, a := range h.IPs {
			out[h.Name] = append(out[h.Name], a.IP)
		}
		if len(h.IPs) == 0 && h.IP != "" {
			out[h.Name] = append(out[h.Name], ipKey(h.IP))
		}
	}
	return out
}

// storedHostAddrs is hostAddrs from the stored rows (the OpenVAS step writes after the scan's own rows).
func storedHostAddrs(ctx context.Context, q querier, t Target) (map[string][]string, error) {
	hosts, err := storedHosts(ctx, q, t.ID)
	if err != nil {
		return nil, err
	}
	return hostAddrs(t, hosts), nil
}

// storedHosts reads the names of a target with their addresses, in the shape a scan hands them over: what the previous scans left.
func storedHosts(ctx context.Context, q querier, target string) ([]HostRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT h.name, a.ip, a.family, a.class FROM exp_host h LEFT JOIN exp_address a ON a.host_id = h.id
		WHERE h.target_id = ? ORDER BY h.name, a.id`, target)
	if err != nil {
		return nil, fmt.Errorf("names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HostRow
	for rows.Next() {
		var name string
		var ip, fam, class sql.NullString
		if err := rows.Scan(&name, &ip, &fam, &class); err != nil {
			return nil, fmt.Errorf("names: %w", err)
		}
		if len(out) == 0 || out[len(out)-1].Name != name {
			out = append(out, HostRow{Name: name})
		}
		h := &out[len(out)-1]
		if ip.Valid {
			h.IPs = append(h.IPs, HostIP{IP: ip.String, Family: fam.String, Class: class.String})
			if h.IP == "" && fam.String == "ipv4" {
				h.IP = ip.String
			}
		}
	}
	return out, rows.Err()
}

// ---- services ----

// writeServices upserts the services a scan reported open and closes the open ones it no longer finds on an address it checked. It
// returns the services open now that were not before, the ones it closed, and the ones it no longer lists (closeVanished).
func (s *Service) writeServices(ctx context.Context, tx *sql.Tx, w scanWrite, at string) ([]PortRow, []string, []string, map[string][]int, map[string][]int, error) {
	svc := map[string]ServiceRow{}
	for _, r := range w.c.Services {
		svc[portKey(r.IP, r.Port)] = r
	}
	certs := certsByService(w.target, w.c)
	seen := map[string]bool{}
	var opened []PortRow
	for _, p := range w.c.Ports {
		k := portKey(p.IP, p.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		row := serviceOf(p, svc[k], certs[k])
		var id, state, prevIdent, prevName, prevProduct, prevVersion, prevCPE, prevTitle string
		var prevWeb int
		var prevCert sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT id, state, ident, name, product, version, cpe, title, is_web, cert FROM exp_service
			WHERE target_id = ? AND ip = ? AND port = ? AND proto = 'tcp'`, w.target.ID, row.IP, row.Port).
			Scan(&id, &state, &prevIdent, &prevName, &prevProduct, &prevVersion, &prevCPE, &prevTitle, &prevWeb, &prevCert)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = tx.ExecContext(ctx, `INSERT INTO exp_service (id, target_id, ip, port, proto, name, product, version, cpe, title, cert, is_web, ident, state,
				first_seen, last_seen, last_run_id) VALUES (?, ?, ?, ?, 'tcp', ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
				store.NewID("xs"), w.target.ID, row.IP, row.Port, row.Name, row.Product, row.Version, row.CPE, row.Title, certDoc(row.Cert), boolInt(row.IsWeb), row.Ident,
				at, at, w.runID)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("writing the service %s:%d: %w", row.IP, row.Port, err)
			}
			opened = append(opened, p)
			continue
		}
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("reading the service %s:%d: %w", row.IP, row.Port, err)
		}
		// What this scan read wins; what it did not read (a lighter scan, a probe that got no answer) keeps the earlier reading.
		ident := row.Ident
		if ident == identNone && prevIdent != identNone {
			ident = prevIdent
		}
		web := row.IsWeb || (prevWeb == 1 && row.Ident != identProbed)
		cert := certDoc(mergeCert(row.Cert, prevCert))
		_, err = tx.ExecContext(ctx, `UPDATE exp_service SET name = ?, product = ?, version = ?, cpe = ?, title = ?, cert = ?, is_web = ?, ident = ?,
			state = 'open', last_seen = max(last_seen, ?), last_run_id = ? WHERE id = ?`,
			firstOf(row.Name, prevName), firstOf(row.Product, prevProduct), firstOf(row.Version, prevVersion), firstOf(row.CPE, prevCPE), firstOf(row.Title, prevTitle),
			cert, boolInt(web), ident, at, w.runID, id)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("writing the service %s:%d: %w", row.IP, row.Port, err)
		}
		if state == ServiceClosed {
			opened = append(opened, p)
		}
	}
	v, err := s.closeVanished(ctx, tx, w, seen)
	return opened, v.closed, v.retired, v.network, v.unreached, err
}

// vanished is what closeVanished did: the services it closed, the ones it no longer lists without the target having closed them
// (retired), and those by address: the network's ports, and the ports not reached for 30 days.
type vanished struct {
	closed, retired    []string
	network, unreached map[string][]int
}

// closeVanished decides each open service of the target that this scan did not report from this run's verdict of its port (INV-22):
//
//	| verdict                     | the row                                                                                         |
//	|-----------------------------|-------------------------------------------------------------------------------------------------|
//	| none (the scan did not probe it), open | kept                                                                               |
//	| closed                      | closed at once when two probes of this run missed it, else when the newest scan before with a verdict of it missed it too |
//	| filtered                    | closed by the third filtered scan in a row since it was last seen, at least a day after the first |
//	| unreached, lost, unknown    | kept; no longer listed once it was last seen more than 30 days ago (not counted as closed, no alert) |
//	| network (accepted)          | no longer listed when this scan read its answer and it was the network's, and no scan ever saw it open over a clean path; else kept |
//	| network (refused)           | kept: a network that refuses the port for every address says nothing about the target          |
//
// A service on an address that left the domain is closed at once. A row no longer listed has its issues gone like a closed one.
func (s *Service) closeVanished(ctx context.Context, tx *sql.Tx, w scanWrite, reported map[string]bool) (vanished, error) {
	var out vanished
	open, err := servicesOf(ctx, tx, w.target.ID, true)
	if err != nil {
		return out, err
	}
	now := runStart(ctx, tx, w.runID)
	if now == "" {
		now = store.FormatTS(w.at)
	}
	retire := func(x ServiceView, into *map[string][]int) error {
		if _, err := tx.ExecContext(ctx, `UPDATE exp_service SET state = 'closed' WHERE id = ?`, x.ID); err != nil {
			return fmt.Errorf("retiring the service %s:%d: %w", x.IP, x.Port, err)
		}
		if *into == nil {
			*into = map[string][]int{}
		}
		k := ipKey(x.IP)
		out.retired, (*into)[k] = append(out.retired, x.ID), append((*into)[k], x.Port)
		return nil
	}
	for _, x := range open {
		k := ipKey(x.IP)
		if reported[portKey(x.IP, x.Port)] {
			continue
		}
		v, ok := w.verdicts.of(k, x.Port)
		shut := w.gone[k]
		if !shut && ok {
			var prior []priorVerdict
			if v.v != verdictOpen {
				if prior, err = priorVerdicts(ctx, tx, w.target.ID, w.runID, portKey(k, x.Port)); err != nil {
					return out, err
				}
			}
			switch v.v {
			case verdictClosed:
				shut = v.probes >= 2 || (len(prior) > 0 && prior[0].outcome == verdictClosed && x.LastSeen < prior[0].at)
			case verdictFiltered:
				shut = filteredStreak(prior, x.LastSeen, now)
			case verdictUnreached, verdictLost, verdictUnknown:
				if seen, err := parseTS(x.LastSeen); err == nil && w.at.Sub(seen) > notReachedFor {
					if err := retire(x, &out.unreached); err != nil {
						return out, err
					}
				}
			case verdictNetwork: // only a network that accepts the port for every address can have made the row; one that refuses it cannot.
				// And only when this scan read the target's own answer there and found it the network's: a port it did not probe, or whose
				// comparison failed, says nothing about the target.
				if v.reason == reasonSynAck && v.same && !seenClean(prior) {
					if err := retire(x, &out.network); err != nil {
						return out, err
					}
				}
			}
		}
		if !shut {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exp_service SET state = 'closed' WHERE id = ?`, x.ID); err != nil {
			return out, fmt.Errorf("closing the service %s:%d: %w", x.IP, x.Port, err)
		}
		out.closed = append(out.closed, x.ID)
	}
	return out, nil
}

// goneWithService marks gone the open issues of the services a scan closed: what was found on a port that is closed is no longer
// exposed, whichever engine found it.
func goneWithService(ctx context.Context, tx *sql.Tx, closed []string) error {
	for _, id := range closed {
		if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET state = 'gone' WHERE service_id = ? AND state = 'open'`, id); err != nil {
			return fmt.Errorf("the issues of a closed service: %w", err)
		}
	}
	return nil
}

// serviceRow is a service as the writer stores it.
type serviceRow struct {
	IP                                 string
	Port                               int
	Name, Product, Version, CPE, Title string
	Cert                               *CertView
	IsWeb                              bool
	Ident                              string
}

// serviceOf merges what the scan read on one open port: the port scan's row, service identification's row and the certificate.
func serviceOf(p PortRow, r ServiceRow, cert *CertView) serviceRow {
	out := serviceRow{IP: ipKey(p.IP), Port: p.Port, Name: clipText(firstOf(r.Name, p.Service), 100), Product: firstOf(r.Product, p.Product),
		Version: r.Version, CPE: r.CPE, Title: p.Title, Cert: cert}
	if out.Cert == nil && len(p.CertNames) > 0 { // the names a deep scan's script read, with no expiry: kept for what they name
		out.Cert = &CertView{Names: p.CertNames}
	}
	switch p.Ident {
	case IdentProbed:
		out.Ident = identProbed
	case IdentPort:
		out.Ident = identTable
	case IdentNone:
		out.Ident = identNone
	default:
		switch identOf(r) {
		case IdentProbed:
			out.Ident = identProbed
		case IdentPort:
			out.Ident = identTable
		default:
			out.Ident = identNone
			if p.Product != "" { // the surface scan's own GET read a Server header
				out.Ident = identProbed
			}
		}
	}
	out.IsWeb = answeredHTTP(p, r)
	return out
}

// answeredHTTP says the service answered HTTP: the scan read a page title, a Server header or a redirect on it, the page request read a product,
// or a probe named it an HTTP service. The passive web scan takes exactly these (webPages).
func answeredHTTP(p PortRow, r ServiceRow) bool {
	if p.HTTP || p.Title != "" || p.Server != "" || p.Location != "" {
		return true
	}
	if p.Product != "" && serviceFamily(p.Service) == "http" { // the surface scan's own page request read who answers, whatever nmap's table says
		return true
	}
	return serviceFamily(firstOf(r.Name, p.Service)) == "http" && (r.Method == "probed" || p.Ident == IdentProbed)
}

// certsByService maps the certificates a scan read to the services that showed them: a row named "ip:port" to that service, a row
// named by a host name to port 443 of the name's addresses.
func certsByService(t Target, c Content) map[string]*CertView {
	addrs := hostAddrs(t, c.Hosts)
	names := map[string][]string{}
	for _, p := range c.Ports {
		names[portKey(p.IP, p.Port)] = p.CertNames
	}
	out := map[string]*CertView{}
	for _, x := range c.Certs {
		host, port := x.Host, 443
		if h, ps, err := net.SplitHostPort(x.Host); err == nil {
			if n, err := strconv.Atoi(ps); err == nil {
				host, port = h, n
			}
		}
		ips := addrs[host]
		if a, err := netip.ParseAddr(host); err == nil {
			ips = []string{a.Unmap().String()}
		}
		for _, ip := range ips {
			k := portKey(ip, port)
			if out[k] != nil {
				continue
			}
			n := names[k]
			if len(n) == 0 && net.ParseIP(host) == nil {
				n = []string{host}
			}
			out[k] = &CertView{Names: nz(n), Issuer: x.Issuer, ExpiresAt: x.ExpiresAt}
		}
	}
	return out
}

// mergeCert is the certificate this scan read, with what an earlier scan read that this one did not (the expiry a names-only reading
// lacks); the earlier one when this scan read none.
func mergeCert(now *CertView, prev sql.NullString) *CertView {
	var old *CertView
	if prev.Valid {
		old = new(CertView)
		if json.Unmarshal([]byte(prev.String), old) != nil {
			old = nil
		}
	}
	switch {
	case now == nil:
		return old
	case old != nil && now.ExpiresAt == "":
		return &CertView{Names: firstNames(now.Names, old.Names), Issuer: old.Issuer, ExpiresAt: old.ExpiresAt}
	}
	return now
}

func firstNames(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}

func certDoc(c *CertView) any {
	if c == nil {
		return nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return string(b)
}

// ---- issues ----

// surfaceIssues are the issues of the surface: admin pages open to the Internet, certificates that expire soon, and the findings an
// nmap script confirmed.
func surfaceIssues(c Content, at time.Time) []issueIn {
	var out []issueIn
	for _, a := range c.AdminPanels {
		sev := "medium"
		if a.Risk == "danger" {
			sev = "high"
		}
		product := firstOf(a.Product, "a device")
		out = append(out, issueIn{engine: EngineSurface, key: keyAdminPage + a.URL, ip: a.IP, port: a.Port, severity: sev,
			title: clipText("Admin page of "+product+" open to the Internet", 300),
			detail: IssueDetail{Description: "The administration page of " + product + " answers anyone on the Internet at " + a.URL + ".",
				Solution: "Allow it only from the addresses that need it, or reach it through a VPN.", Evidence: []string{a.URL}}})
	}
	limit := at.Add(CertWarnDays * 24 * time.Hour)
	for _, x := range c.Certs {
		exp, err := parseTS(x.ExpiresAt)
		if err != nil || exp.After(limit) {
			continue
		}
		host, port := x.Host, 443
		if h, ps, err := net.SplitHostPort(x.Host); err == nil {
			if n, err := strconv.Atoi(ps); err == nil {
				host, port = h, n
			}
		}
		sev, title := "medium", "Certificate of "+host+" expires soon"
		if !exp.After(at) {
			sev, title = "high", "Certificate of "+host+" has expired"
		}
		in := issueIn{engine: EngineSurface, key: keyCertExpiry + x.Host, port: port, severity: sev, title: clipText(title, 300),
			detail: IssueDetail{Description: "The TLS certificate " + host + " shows (issued by " + firstOf(x.Issuer, "an unknown issuer") + ") expires at " + x.ExpiresAt + ".",
				Solution: "Renew the certificate before it expires.", Evidence: []string{x.Host}}}
		if _, err := netip.ParseAddr(host); err == nil {
			in.ip = host
		} else {
			in.host = host
		}
		out = append(out, in)
	}
	return append(out, scriptIssues(c.Scripts, keyScript)...)
}

// scriptIssues are the findings nmap's scripts confirmed, in the key space prefix (keyScript: the deep scan's first nmap run;
// keyScriptDisruptive: its disruptive scripts, the last step).
func scriptIssues(rows []ScriptRow, prefix string) []issueIn {
	var out []issueIn
	for _, r := range rows {
		for _, f := range r.Findings {
			if f.State != "vulnerable" {
				continue
			}
			title := firstOf(f.Title, r.ID)
			out = append(out, issueIn{engine: EngineSurface, key: prefix + ipKey(r.IP) + " " + r.ID + ":" + clipText(title, 200), ip: r.IP, port: r.Port, severity: "high",
				title: clipText(title, 300), cves: f.CVEs,
				detail: IssueDetail{Description: "The nmap script " + r.ID + " confirmed this finding.", Evidence: []string{clipText(r.Output, 500)}}})
		}
	}
	return out
}

// nucleiIssues are the templates that matched.
func nucleiIssues(rows []TemplateRow) []issueIn {
	var out []issueIn
	for _, r := range rows {
		if r.Outcome != OutcomeMatched || r.Template == "" {
			continue
		}
		sev := r.Severity
		if !slices.Contains(severities, sev) {
			sev = "info"
			if r.CVE != "" { // a safe template of an exploited CVE confirmed it
				sev = "critical"
			}
		}
		var cves []string
		if r.CVE != "" {
			cves = []string{r.CVE}
		}
		out = append(out, issueIn{engine: EngineNuclei, key: r.Template, ip: r.IP, port: r.Port, severity: sev, cves: cves,
			title:  clipText(firstOf(r.Name, r.CVE, r.Template), 300),
			detail: IssueDetail{Description: "The nuclei template " + r.Template + " matched on this service.", Evidence: []string{fmt.Sprintf("%s:%d", r.IP, r.Port)}}})
	}
	return out
}

// zapIssues are the alerts of the passive web scan, one per alert and site.
func zapIssues(rows []WebFindingRow) []issueIn {
	var out []issueIn
	for _, r := range rows {
		sev := r.Risk
		if !slices.Contains(severities, sev) {
			sev = "info"
		}
		pass := "passive"
		if r.Pass == passActive {
			pass = passActive
		}
		in := issueIn{engine: EngineZAP, key: r.PluginID + "@" + r.Site, severity: sev, title: clipText(firstOf(r.Name, "ZAP alert "+r.PluginID), 300),
			detail: IssueDetail{Description: r.Description, Solution: r.Solution, Evidence: nz(r.URLs), ZAP: &IssueZAP{Risk: r.Risk, Confidence: r.Confidence, Pass: pass, Disruptive: pass == passActive && r.Disruptive}}}
		if u, err := url.Parse(r.Site); err == nil && u.Hostname() != "" {
			port := 80
			if u.Scheme == "https" {
				port = 443
			}
			if p, err := strconv.Atoi(u.Port()); err == nil {
				port = p
			}
			in.port = port
			if _, err := netip.ParseAddr(u.Hostname()); err == nil {
				in.ip = u.Hostname()
			} else {
				in.host = u.Hostname()
			}
		}
		out = append(out, in)
	}
	return out
}

// matchIssues are the exploited CVEs matched on the services (OpenVAS's own CVEs are its issues).
func matchIssues(rows []VulnRow) []issueIn {
	var out []issueIn
	for _, r := range rows {
		if r.Basis == "greenbone" || r.CVE == "" {
			continue
		}
		sev := "critical"
		if r.Basis == "product" || r.Basis == "js_library" || r.Backport != "" {
			sev = "high" // only the product matched, or a distribution may have backported the fix: not proved
		}
		in := issueIn{engine: EngineMatch, key: r.CVE, port: r.Port, severity: sev, cves: []string{r.CVE},
			title:  clipText(firstOf(r.Name, r.CVE), 300),
			detail: IssueDetail{Description: r.Summary, Evidence: []string{fmt.Sprintf("%s:%d (%s)", r.IP, r.Port, r.Basis)}}}
		if _, err := netip.ParseAddr(r.IP); err == nil {
			in.ip = r.IP
		} else {
			in.host = r.IP
		}
		out = append(out, in)
	}
	return out
}

// openvasIssue is one OpenVAS result.
func openvasIssue(r GreenboneRow) issueIn {
	sev := "info"
	switch {
	case r.Severity >= 9:
		sev = "critical"
	case r.Severity >= 7:
		sev = "high"
	case r.Severity >= 4:
		sev = "medium"
	case r.Severity > 0:
		sev = "low"
	}
	return issueIn{engine: EngineOpenVAS, key: firstOf(r.OID, r.Name) + "@" + ipKey(r.IP), ip: r.IP, port: greenbonePort(r.Port), severity: sev, cves: r.CVEs,
		title:  clipText(firstOf(r.Name, r.OID), 300),
		detail: IssueDetail{Description: firstOf(r.Description, gmpDescription(r.Name, "", "")), Solution: r.Solution, Evidence: []string{strings.TrimSpace(r.IP + " " + r.Port)}}}
}

// reopenedIssue is an issue a person marked patched or mitigated that a scan reported again: the flaw is still there, so it is open
// again (as findings does), with how and by whom it had been marked.
type reopenedIssue struct{ id, was, by string }

// writeIssues upserts the issues of one write and marks gone the open issues of the engines in ran that it did not report, when their
// service was seen by this scan or they are about the target as a whole. It returns the ids of the issues that are open now and were
// not before, and among them the ones it opened again: patched or mitigated before this run started, and reported again (a mark made
// while the run ran, during a long OpenVAS step say, is newer than what it saw and stays). Accepted, not relevant and false positive
// keep the person's decision.
func writeIssues(ctx context.Context, tx *sql.Tx, target, runID, at string, hosts map[string][]string, issues []issueIn, ran engineSet, cov map[IssueEngine]coverFunc) ([]string, []reopenedIssue, error) {
	var again []reopenedIssue
	svcIDs, seenNow, err := serviceIndex(ctx, tx, target, runID)
	if err != nil {
		return nil, nil, err
	}
	// A mark made after this run started is newer than what the run saw: only a mark from before it can be proved wrong by it.
	since := at
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(started_at, ?) FROM core_run WHERE id = ?`, at, runID).Scan(&since); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("the start of the run: %w", err)
	}
	reported := map[string]bool{}
	var fresh []string
	for _, in := range issues {
		if in.key == "" {
			continue
		}
		var svc any
		if in.port > 0 {
			for _, ip := range append([]string{in.ip}, hosts[in.host]...) {
				if id, ok := svcIDs[portKey(ip, in.port)]; ok && ip != "" {
					svc = id
					break
				}
			}
		}
		cves, err := json.Marshal(nz(in.cves))
		if err != nil {
			return nil, nil, err
		}
		in.detail.Evidence = nz(in.detail.Evidence)
		detail, err := json.Marshal(in.detail)
		if err != nil {
			return nil, nil, err
		}
		var id, state, res, by, resolvedAt string
		err = tx.QueryRowContext(ctx, `SELECT id, state, coalesce(resolution, ''), coalesce(resolved_by, ''), coalesce(resolved_at, '') FROM exp_issue
			WHERE target_id = ? AND engine = ? AND key = ? AND ifnull(service_id, '') = ifnull(?, '')`,
			target, string(in.engine), clipText(in.key, 600), svc).Scan(&id, &state, &res, &by, &resolvedAt)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			id = store.NewID("xi")
			_, err = tx.ExecContext(ctx, `INSERT INTO exp_issue (id, target_id, service_id, engine, key, title, severity, cves, detail, state, first_seen, last_seen, last_run_id)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`, id, target, svc, string(in.engine), clipText(in.key, 600), in.title, in.severity, string(cves), string(detail), at, at, runID)
			fresh = append(fresh, id)
		case err == nil:
			if state == IssueGone {
				fresh = append(fresh, id)
				state = IssueOpen
			}
			if state == IssueHandled && (res == string(ResolvedPatched) || res == string(ResolvedMitigated)) && resolvedAt < since {
				fresh, again = append(fresh, id), append(again, reopenedIssue{id: id, was: res, by: by})
				state = IssueOpen
				if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET state = 'open', resolution = NULL, resolved_by = NULL, resolved_at = NULL, note = NULL,
					accepted_until = NULL WHERE id = ?`, id); err != nil {
					return nil, nil, fmt.Errorf("opening the issue %s again: %w", id, err)
				}
			}
			_, err = tx.ExecContext(ctx, `UPDATE exp_issue SET title = ?, severity = ?, cves = ?, detail = ?, state = ?, last_seen = max(last_seen, ?), last_run_id = ? WHERE id = ?`,
				in.title, in.severity, string(cves), string(detail), state, at, runID, id)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("writing the issue %s %s: %w", in.engine, in.key, err)
		}
		reported[id] = true
	}
	for e, ok := range ran {
		if !ok {
			continue
		}
		rows, err := tx.QueryContext(ctx, `SELECT i.id, i.key, i.service_id IS NOT NULL, coalesce(x.ip, ''), coalesce(x.port, 0), coalesce(json_extract(i.detail, '$.zap.pass'), ''), coalesce(json_extract(i.detail, '$.zap.disruptive'), 0) = 1 FROM exp_issue i
			LEFT JOIN exp_service x ON x.id = i.service_id WHERE i.target_id = ? AND i.engine = ? AND i.state = 'open'`, target, string(e))
		if err != nil {
			return nil, nil, fmt.Errorf("issues of %s: %w", e, err)
		}
		var gone []string
		for rows.Next() {
			var id string
			var w issueWhere
			if err := rows.Scan(&id, &w.key, &w.service, &w.ip, &w.port, &w.pass, &w.disruptive); err != nil {
				_ = rows.Close()
				return nil, nil, err
			}
			if w.service {
				w.seen = seenNow[svcIDs[portKey(w.ip, w.port)]]
			} else {
				w.ip = keyAddr(e, w.key)
			}
			covered := cov[e]
			if covered == nil { // the default: the issue's service was seen by this scan, or it is about the target as a whole
				covered = func(w issueWhere) bool { return !w.service || w.seen }
			}
			if !reported[id] && covered(w) {
				gone = append(gone, id)
			}
		}
		if err := rows.Close(); err != nil {
			return nil, nil, err
		}
		for _, id := range gone {
			if _, err := tx.ExecContext(ctx, `UPDATE exp_issue SET state = 'gone' WHERE id = ?`, id); err != nil {
				return nil, nil, fmt.Errorf("issue %s gone: %w", id, err)
			}
		}
	}
	return fresh, again, nil
}

// issueWhere is where an open issue is, for the coverage of the engine that reported it.
type issueWhere struct {
	key     string
	service bool   // it is about a service
	seen    bool   // its service was seen open by this scan
	ip      string // the service's address, or the address its key names; "" when neither
	port    int    // the service's port; 0 when none
	pass    string // a ZAP issue's pass (IssueZAP.Pass): "active" is covered only by the active scan
	// disruptive: an active ZAP issue of a disruptive rule (IssueZAP.Disruptive), covered only by an active scan that ran them
	disruptive bool
}

// coverFunc says the engine probed where the issue is in this run: only then does an issue it no longer reports go.
type coverFunc func(issueWhere) bool

// keyAddr is the address an issue's key names when it is about no service: OpenVAS's "<oid>@<ip>", a script finding's
// "nse:<ip> <script>:<title>".
func keyAddr(e IssueEngine, key string) string {
	switch {
	case e == EngineOpenVAS:
		if i := strings.LastIndex(key, "@"); i >= 0 {
			return key[i+1:]
		}
	case e == EngineSurface && strings.HasPrefix(key, keyScript):
		ip, _, _ := strings.Cut(strings.TrimPrefix(key, keyScript), " ")
		return ip
	case e == EngineSurface && strings.HasPrefix(key, keyScriptDisruptive):
		ip, _, _ := strings.Cut(strings.TrimPrefix(key, keyScriptDisruptive), " ")
		return ip
	}
	return ""
}

// scanCoverage is where each engine of one scan probed, from what the scan handed over: an issue an engine no longer reports is gone
// only there (a domain's deep engines reach a few rotated addresses per run, ZAP its pages).
func scanCoverage(w scanWrite) map[IssueEngine]coverFunc {
	c := w.c
	scripted, tplRan, resolved := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, h := range c.Hosts {
		resolved[h.Name] = !h.LookupFailed
	}
	for _, ip := range c.ScriptsRan {
		scripted[ipKey(ip)] = true
	}
	for _, k := range c.TemplatesRan {
		tplRan[k] = true
	}
	pages, activePages, disruptivePages := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, u := range c.WebPages {
		pages[siteOf(u)] = true
	}
	for _, u := range c.WebActivePages {
		activePages[siteOf(u)] = true
	}
	for _, u := range c.WebDisruptivePages {
		disruptivePages[siteOf(u)] = true
	}
	open, compared := map[string]bool{}, map[string]bool{}
	for _, p := range c.Ports {
		open[portKey(p.IP, p.Port)] = true
	}
	for _, r := range c.Services { // the services the comparison with exploited CVEs read this run
		compared[portKey(r.IP, r.Port)] = true
	}
	return map[IssueEngine]coverFunc{
		EngineSurface: func(x issueWhere) bool {
			switch {
			case strings.HasPrefix(x.key, keyScript):
				return scripted[ipKey(x.ip)] && (!x.service || x.seen)
			case strings.HasPrefix(x.key, keyScriptDisruptive): // only a later run of the disruptive scripts closes one (writeDisruptive)
				return false
			case strings.HasPrefix(x.key, keyCertExpiry): // the certificate was read again: its name resolved, and its service answered
				host := strings.TrimPrefix(x.key, keyCertExpiry)
				if _, _, err := net.SplitHostPort(host); err == nil {
					return open[host] && (!x.service || x.seen)
				}
				return (resolved[host] || (w.target.Kind == KindIP && host == w.target.Value)) && (!x.service || x.seen)
			}
			return !x.service || x.seen
		},
		EngineNuclei: func(x issueWhere) bool { // this template ran to the end on this port and found nothing (TemplatesCovered)
			return x.ip != "" && tplRan[portKey(x.ip, x.port)+"|"+x.key]
		},
		EngineZAP: func(x issueWhere) bool { // an alert of the active rules goes only when the active scan looked at its page again
			_, site, ok := strings.Cut(x.key, "@")
			if x.pass == passActive { // and one of a disruptive rule only when that scan ran the disruptive rules
				return ok && activePages[siteOf(site)] && (!x.disruptive || disruptivePages[siteOf(site)])
			}
			return ok && pages[siteOf(site)]
		},
		EngineMatch: func(x issueWhere) bool { // the comparison read the service again this run
			return x.service && x.seen && compared[portKey(x.ip, x.port)]
		},
	}
}

// siteOf is the scheme, host and port of a web address, the one spelling a page and a ZAP site are compared by.
func siteOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// serviceIndex maps "ip:port" to the service id of every service of the target, and says which ones this run saw open.
func serviceIndex(ctx context.Context, q querier, target, runID string) (map[string]string, map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, ip, port, last_run_id = ? AND state = 'open' FROM exp_service WHERE target_id = ? AND proto = 'tcp'`, runID, target)
	if err != nil {
		return nil, nil, fmt.Errorf("services: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ids, seen := map[string]string{}, map[string]bool{}
	for rows.Next() {
		var id, ip string
		var port int
		var now bool
		if err := rows.Scan(&id, &ip, &port, &now); err != nil {
			return nil, nil, fmt.Errorf("services: %w", err)
		}
		ids[portKey(ip, port)] = id
		seen[id] = now
	}
	return ids, seen, rows.Err()
}

// rowCounts sets the numbers of what the rows say is exposed now.
func rowCounts(ctx context.Context, q querier, target string, c *ScanCounts) error {
	err := q.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM exp_host WHERE target_id = ?1),
		(SELECT count(*) FROM exp_service WHERE target_id = ?1 AND state = 'open'),
		(SELECT count(*) FROM exp_issue WHERE target_id = ?1 AND state = 'open')`, target).Scan(&c.Hosts, &c.Services, &c.Issues)
	if err != nil {
		return fmt.Errorf("counting rows: %w", err)
	}
	return nil
}

// updateSummary reads, changes and writes back the summary of a scan.
func updateSummary(ctx context.Context, tx *sql.Tx, runID string, change func(*scanSummary)) error {
	var doc string
	if err := tx.QueryRowContext(ctx, `SELECT summary FROM exp_scan WHERE run_id = ?`, runID).Scan(&doc); err != nil {
		return fmt.Errorf("the summary of %s: %w", runID, err)
	}
	var sum scanSummary
	if err := json.Unmarshal([]byte(doc), &sum); err != nil {
		return fmt.Errorf("the summary of %s: %w", runID, err)
	}
	change(&sum)
	sum.Checks, sum.NotChecked = sanitizeChecks(sum.Checks), sanitizeNotChecked(sum.NotChecked)
	b, err := json.Marshal(sum)
	if err != nil {
		return fmt.Errorf("the summary of %s: %w", runID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_scan SET summary = ? WHERE run_id = ?`, string(b), runID); err != nil {
		return fmt.Errorf("the summary of %s: %w", runID, err)
	}
	return nil
}

// ---- small helpers ----

// ipOf is the target itself when it is an IP, "" for a domain.
func ipOf(t Target) string {
	if t.Kind == KindIP {
		return t.Value
	}
	return ""
}

func firstOf(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

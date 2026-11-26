package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// ScanIDPrefix is how the scan module names an external target ("ext:<id>").
const ScanIDPrefix = "ext:"

// CurrentFor is how long a sighting of an IP, and the result of a full check, count as "the box uses this IP now" for the
// scan-time check (INV-13). It is also the least time between two full checks that scans cause.
const CurrentFor = 5 * time.Minute

// gate decides whether a target may be scanned now (INV-1). Every caller asks it right before something is sent (Scan now and a
// scheduled scan when the run starts, the scan module, each deep step, each step of a typed IP), so the rule is one: the proof is
// checked again here (a domain's TXT record, a typed IP's file or reverse DNS name, the box's own sighting of its IP, INV-13), a pass
// renews it for ValidDays, and a check that does not pass (a lookup that failed, a record or file that is gone, an IP the box no longer
// goes out through) is recorded as the target's last check, a warning on the page, never a refusal while the proof is inside its
// ValidDays (INV-4). Only a target never proved, whose proof was withdrawn, or whose proof has not passed for ValidDays is refused
// (blocked). actor is who asked (a person, or the scan module on behalf of a schedule); the audit trail names it.
func (s *Service) gate(ctx context.Context, actor, id string) (Target, BlockedReason, error) {
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return Target{}, "", err
	}
	if !t.Enabled { // switched off: nothing is sent, and nothing is looked up for it
		return t, BlockedDisabled, nil
	}
	switch r := t.blocked(s.clock()); {
	case r == BlockedUnverified:
		return t, r, nil
	case t.Kind == KindDomain: // looked up even when its days ran out: a record found now is a new proof
		if t, err = s.recheckDomain(ctx, actor, t); err != nil {
			return Target{}, "", err
		}
	case r == BlockedExpired:
		return t, r, nil
	case t.Typed && r != BlockedNoCommitment: // a typed IP: its proof is looked for now, right before the scan (INV-35); not before the confirmation is there
		if t, err = s.liveTypedProof(ctx, actor, t); err != nil {
			return Target{}, "", err
		}
	case t.Kind == KindIP && r == "": // the box's own IP: a sighting now renews it; one the box does not go out through stays scannable
		if _, err := s.stillCurrent(ctx, actor, t); err != nil {
			return Target{}, "", err
		}
		if t, err = loadTarget(ctx, s.cfg.DB.Reader(), id); err != nil {
			return Target{}, "", err
		}
	}
	return t, t.blocked(s.clock()), nil
}

// recheckDomain looks a domain's TXT record up again right before a scan (the name, _vedette-verify.<name>, or a parent down to its
// registered domain) and keeps the result as its last check: found renews the proof for ValidDays; not found (a lookup that failed
// counts as not found) is a warning that says until when the earlier proof holds. The audit row is written when the answer changes.
// The target comes back re-read, with the domain and token the executors' fence checks when the record was found.
func (s *Service) recheckDomain(ctx context.Context, actor string, t Target) (Target, error) {
	pr, err := s.proveDomain(ctx, t)
	if err != nil {
		return Target{}, err
	}
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		var err error
		if pr, err = stillOwner(ctx, tx, t.ID, pr); err != nil {
			return err
		}
		found := pr.found
		now := s.clock()
		msg, action, renew := proofMessage(t, pr, s.momentText(now)), "exposure.verify_ok", now
		switch {
		case !found && len(proofChain(t.Value)) == 0: // a public suffix (an older release's, or one a newer list names): nothing proves it
			if err := withdrawProof(ctx, tx, t.ID, Check{At: store.FormatTS(now), OK: false, Message: pr.failure}); err != nil {
				return err
			}
			return s.audit(ctx, tx, actor, "exposure.verify_fail", t.Value, "dns_txt, right before a scan: a public suffix")
		case !found:
			msg, action, renew = pr.failure+s.stillValid(t, now), "exposure.verify_fail", time.Time{}
		}
		if err := updateCheck(ctx, tx, t.ID, Check{At: store.FormatTS(now), OK: found, Message: msg, Covers: pr.coversBelow(t.Value), Via: keptVia(t, pr)}, renew, ""); err != nil {
			return err
		}
		if err := settleMethod(ctx, tx, t.ID, pr); err != nil { // covered by an ancestor now, or proved by itself
			return err
		}
		if t.LastCheck != nil && t.LastCheck.OK == found { // nothing changed: the check is not a row of its own (L5)
			return nil
		}
		return s.audit(ctx, tx, actor, action, t.Value, "dns_txt, right before a scan")
	})
	if err != nil {
		return Target{}, fmt.Errorf("recording the TXT check: %w", err)
	}
	cur, err := loadTarget(ctx, s.cfg.DB.Reader(), t.ID)
	if err != nil {
		return Target{}, err
	}
	// the target whose token proved it now, and the name the record sits on: what the executors' fence checks
	cur.proofDomain, cur.proofToken, cur.proofAt = pr.gate(cur)
	return cur, nil
}

// stillValid ends the message of a check that did not find the proof of t: until when the proof that passed earlier still lets t be
// scanned (INV-4), or nothing when it never passed or has run out.
func (s *Service) stillValid(t Target, now time.Time) string {
	exp := t.expiresAt(now)
	if exp.IsZero() || !now.Before(exp) {
		return ""
	}
	return fmt.Sprintf(" The proof found on %s stays valid until %s, so scans go on until then.", s.dayText(t.provedAt(now)), s.dayText(exp))
}

// checks is what the latest checks of the box's IPs say, read without probing anything (INV-13): the time of the latest
// check of any kind and of the latest full check. The scan gate and the state shown on a target both ask it, so the page
// says "paused" exactly when the gate would refuse without a new probe.
type checks struct{ now, lastRun, lastDeep, lastFullOK time.Time }

func (s *Service) loadChecks(ctx context.Context, q querier) (checks, error) {
	box, err := loadBoxIP(ctx, q)
	if err != nil {
		return checks{}, fmt.Errorf("exposure: reading auto-detect settings: %w", err)
	}
	deep, err := loadLastDeep(ctx, q)
	if err != nil {
		return checks{}, err
	}
	fullOK, err := loadLastFullOK(ctx, q)
	if err != nil {
		return checks{}, err
	}
	c := checks{now: s.clock(), lastDeep: deep, lastFullOK: fullOK}
	if box.LastRun != nil {
		if c.lastRun, err = parseTS(box.LastRun.At); err != nil {
			c.lastRun = time.Time{}
		}
	}
	return c, nil
}

// fresh: a check that ran within CurrentFor (a time in the future beyond the slack is a clock that was ahead: not fresh).
func (c checks) fresh(at time.Time) bool {
	return !at.IsZero() && !at.After(c.now.Add(clockSlack)) && c.now.Sub(at) <= CurrentFor
}

// saw: a recent check renewed this IP (a renewal sets verified_at to the time of its run).
func (c checks) saw(t Target) bool {
	for _, at := range []time.Time{c.lastRun, c.lastDeep} {
		if c.fresh(at) && !t.VerifiedAt.Before(at) {
			return true
		}
	}
	return false
}

// paused: the latest full check that got an answer did not see the IP, and no check since has (a sighting renews
// verified_at to the time of its run, so it is at or after that full check). It rests on what is stored, not on a
// window: it stays until a later check, light or full, sees the IP. A light check that does not see it, and a check
// that failed, change nothing: only a full check sees every IP of a load balancer. With no answered full check yet,
// nothing is known against the IP (a time in the future beyond the slack is a clock that was ahead: ignored).
func (c checks) paused(t Target) bool {
	return !c.lastFullOK.IsZero() && !c.lastFullOK.After(c.now.Add(clockSlack)) && t.VerifiedAt.Before(c.lastFullOK)
}

// stillCurrent says whether the box is going out through this IP now (INV-13), the counterpart of the TXT re-check of a
// domain: a sighting renews the IP for ValidDays (INV-4). The scan gate asks it for that renewal only: an IP the box does not go
// out through now stays scannable until its days run out. The Shodan check (INV-21) needs it to be true. It is true when the latest
// check, or the latest full check, ran within CurrentFor and saw the IP.
// Otherwise one full check runs (all its rounds, so every IP of a load balancer is seen), as the actor, and not more
// than once in CurrentFor: inside that window the last full check's answer is reused, a "not seen" included. A
// check that cannot tell (services down, no agreement) is "not current": fail closed. It takes no attempt of the
// person's ten an hour.
func (s *Service) stillCurrent(ctx context.Context, actor string, t Target) (bool, error) {
	s.detectMu.Lock()
	defer s.detectMu.Unlock()
	db := s.cfg.DB.Reader()
	cur, err := loadTarget(ctx, db, t.ID) // a detection that ran while we waited for the lock may have seen it
	if err != nil {
		return false, err
	}
	c, err := s.loadChecks(ctx, db)
	if err != nil {
		return false, err
	}
	if c.saw(cur) {
		return true, nil
	}
	if c.fresh(c.lastDeep) {
		return false, nil // a full check ran moments ago and did not see it: the answer stands, nothing is probed again
	}
	res, err := s.detectLocked(ctx, actor, true)
	if err != nil && !isOutcome(err) {
		return false, err
	}
	for _, v := range res.Items {
		if v.ID == t.ID {
			return true, nil
		}
	}
	return false, nil
}

// CheckScannable is what the scan module calls right before it scans an external target (PRE-3, INV-1,
// INV-12). id is the target id, with or without the "ext:" prefix. An unknown target is an error
// wrapping ErrNotFound; otherwise ok says whether it may be scanned, and reason why not.
func (s *Service) CheckScannable(ctx context.Context, actor, id string) (ok bool, reason BlockedReason, err error) {
	_, reason, err = s.gate(ctx, actor, strings.TrimPrefix(id, ScanIDPrefix))
	if err != nil {
		return false, "", fmt.Errorf("exposure: checking whether %s may be scanned: %w", id, err)
	}
	return reason == "", reason, nil
}

// refusal is the API error of a blocked scan (INV-1).
func (s *Service) refusal(t Target, r BlockedReason, now time.Time) error {
	switch r {
	case BlockedUnverified:
		if _, ok := registered(t.Value); t.Kind == KindDomain && !ok { // a stored public suffix is told so, not "finish verification"
			return apiErr(409, "not_verified", "%s", publicSuffixText(t.Value))
		}
		return apiErr(409, "not_verified", "%s has no ownership proof, so it cannot be scanned. Finish verification first.", t.Value)
	case BlockedExpired:
		return apiErr(409, "expired", "The ownership proof of %s expired on %s, so it cannot be scanned: it was last found more than %d days before. Check it again first.", t.Value, s.dayText(t.expiresAt(now)), ValidDays)
	case BlockedNoCommitment:
		if t.Commitment != nil {
			return errNeedAdminReconfirm(t.Value)
		}
		return errNeedAdminFirstScan(t.Value)
	case BlockedDisabled:
		return apiErr(409, "disabled", "%s is switched off, so it is not scanned. Switch it on first.", t.Value)
	}
	return nil
}

// proofRetry ends the refusal of a typed IP whose proof is not found (the Shodan check, which needs it now).
const proofRetry = "Put the token file back (or set the reverse DNS name), then check again."

// ScanEvery is the least time between two scans of one target: a scan asks crt.sh and probes the target, so a click
// that repeats is answered 429 rather than sent again.
const ScanEvery = 10 * time.Minute

// checkSafety reads the shared safety block before a scan (INV-31): an unreadable block refuses every scan (503, nothing is sent); an IP
// target on the exclusion list is refused (400 out_of_scope), the runner's ports included. A domain's excluded addresses are skipped by
// each step (ScannableIP, the web step, the deep step, the templates).
func (s *Service) checkSafety(ctx context.Context, t Target) error {
	sf, err := s.safety(ctx)
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: reading the shared safety settings failed", "error", err)
		return apiErr(503, "scanner_unavailable", "%s", notSafetyRead)
	}
	if t.Kind != KindIP {
		return nil
	}
	ip, err := netip.ParseAddr(t.Value)
	if err != nil {
		return fmt.Errorf("exposure: reading the address %q: %w", t.Value, err)
	}
	if sf.excluded(ip) {
		return errExcluded(ip.String())
	}
	return nil
}

// clipText cuts v to at most n characters.
func clipText(v string, n int) string {
	if r := []rune(v); len(r) > n {
		return string(r[:n])
	}
	return v
}

// ScannableIP says whether ip is a verified IP target that may be scanned now (LEGAL §3): the scan of a domain asks it
// before it port-scans an address one of the domain's names points at. It runs the same gate as a scan of that target (INV-1,
// INV-13: it may run one full check of the box's IPs, as actor), so an address that is not the box's own verified and committed IP,
// inside its proof's ValidDays, is never port-scanned.
func (s *Service) ScannableIP(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
	_, ok, err := s.OwnIPProof(ctx, actor, ip)
	return ok, err
}

// OwnIPProof is ScannableIP with the proof its yes rests on, for the executors' own-IP fences: provenAt is the latest sighting of ip
// as the box's egress (Target.ownProof), from which the address stays the box's own for ValidDays, also while the box goes out
// through another line (INV-13). sensor-active sends it with the nmap and nuclei jobs of the address, and the scan worker takes the
// job on it instead of a sighting of its own right before the scan. provenAt is zero when ok is false and for a typed IP (proved by
// its file or name, not by a sighting).
func (s *Service) OwnIPProof(ctx context.Context, actor string, ip netip.Addr) (provenAt time.Time, ok bool, err error) {
	ip = ip.Unmap()
	if !IsPublicIPv4(ip) {
		return time.Time{}, false, nil
	}
	// INV-31: an address on the shared exclusion list, or any address while the list cannot be read, is never port-scanned
	if sf, err := s.safety(ctx); err != nil || sf.excluded(ip) {
		if err != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: reading the shared safety settings failed", "error", err)
		}
		return time.Time{}, false, nil
	}
	t, found, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), ip.String())
	if err != nil || !found || t.Kind != KindIP {
		return time.Time{}, false, err
	}
	t, reason, err := s.gate(ctx, actor, t.ID)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("exposure: checking whether %s may be scanned: %w", ip, err)
	}
	if reason != "" {
		return time.Time{}, false, nil
	}
	at, err := s.executorProof(ctx, t)
	return at, true, err
}

// executorProof is the proof of t the executors get (egressNow.proofOf: the latest sighting of an IP the box found, while it overlaps
// the box's current egress address); zero for none.
func (s *Service) executorProof(ctx context.Context, t Target) (time.Time, error) {
	if !boxEgress(t) {
		return time.Time{}, nil
	}
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err != nil {
		return time.Time{}, fmt.Errorf("exposure: reading the box's addresses: %w", err)
	}
	now := s.clock()
	at, _, _ := egressNowOf(all, now).proofOf(t, now)
	return at, nil
}

// countsOf computes the numbers of what one scan found (INV-8); certs_expiring counts the certificates that
// expire within CertWarnDays. extraIP is the target itself when it is an IP.
func countsOf(c Content, extraIP string, now time.Time) Counts {
	ips := map[string]bool{}
	for _, h := range c.Hosts {
		if h.IP != "" {
			ips[h.IP] = true
		}
		for _, a := range h.IPs {
			ips[a.IP] = true
		}
	}
	for _, p := range c.Ports {
		ips[p.IP] = true
	}
	if extraIP != "" {
		ips[extraIP] = true
	}
	limit := now.Add(CertWarnDays * 24 * time.Hour)
	expiring := 0
	for _, x := range c.Certs {
		if t, err := parseTS(x.ExpiresAt); err == nil && !t.After(limit) {
			expiring++
		}
	}
	return Counts{Subdomains: len(c.Hosts), IPs: len(ips), Ports: len(c.Ports), AdminPanels: len(c.AdminPanels), CertsExpiring: expiring}
}

// sanitize limits what a scan hands over before it is stored (INV-10, INV-19, SYS-6): text only, bounded in
// length and in rows, ports and dates that make sense; a row that does not is dropped.
func sanitize(c Content) Content {
	txt := func(s string) string {
		s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
		if utf8.RuneCountInString(s) > maxContentText {
			s = string([]rune(s)[:maxContentText])
		}
		return s
	}
	var out Content
	for _, h := range c.Hosts {
		if len(out.Hosts) < maxContentRows {
			out.Hosts = append(out.Hosts, sanitizeHost(h, txt))
		}
	}
	for _, p := range c.Ports {
		if len(out.Ports) < maxContentRows && p.Port >= 1 && p.Port <= 65535 {
			row := PortRow{IP: txt(p.IP), Port: p.Port, Service: txt(p.Service), Product: txt(p.Product)}
			// INV-22: the marks of a port kept from an earlier scan survive a re-save (the Greenbone step re-sanitizes the stored content).
			if _, err := time.Parse(time.DateOnly, p.LastSeen); err == nil {
				row.LastSeen, row.Unchecked = p.LastSeen, p.Unchecked
				row.Misses = max(p.Misses, 0)
			}
			out.Ports = append(out.Ports, sanitizePortIdent(row, p))
		}
	}
	for _, a := range c.AdminPanels {
		if len(out.AdminPanels) < maxContentRows && a.Port >= 1 && a.Port <= 65535 {
			risk := "warn"
			if a.Risk == "danger" {
				risk = "danger"
			}
			out.AdminPanels = append(out.AdminPanels, AdminRow{URL: txt(a.URL), Product: txt(a.Product), IP: txt(a.IP), Port: a.Port, Risk: risk})
		}
	}
	for _, x := range c.Certs {
		t, err := time.Parse(time.RFC3339, x.ExpiresAt)
		if err != nil || len(out.Certs) >= maxContentRows {
			continue
		}
		out.Certs = append(out.Certs, CertRow{Host: txt(x.Host), Issuer: txt(x.Issuer), ExpiresAt: store.FormatTS(t)})
	}
	for _, n := range c.Unresolved {
		if len(out.Unresolved) < maxContentRows && len(n) <= 253 && domainRE.MatchString(n) {
			out.Unresolved = append(out.Unresolved, n)
		}
	}
	for _, h := range c.Listed { // a name listed without a probe: no address
		if r := sanitizeHost(HostRow{Name: h.Name, Source: h.Source, CNAME: h.CNAME}, txt); len(out.Listed) < maxContentRows && len(r.Name) <= 253 && domainRE.MatchString(r.Name) {
			out.Listed = append(out.Listed, r)
		}
	}
	var probed map[string][]int
	for ip, ports := range c.Probed {
		a, err := netip.ParseAddr(ip)
		if err != nil || len(probed) >= maxContentRows {
			continue
		}
		if ps := sanitizeProbed(ports); len(ps) > 0 {
			if probed == nil {
				probed = map[string][]int{}
			}
			probed[a.Unmap().String()] = ps
		}
	}
	return Content{Hosts: nz(out.Hosts), Listed: out.Listed, Ports: nz(out.Ports), AdminPanels: nz(out.AdminPanels), Certs: nz(out.Certs), Unresolved: out.Unresolved,
		Services: sanitizeServices(c.Services), Templates: sanitizeTemplates(c.Templates, sanitizeServices(c.Services)), Checks: sanitizeChecks(c.Checks), NotChecked: sanitizeNotChecked(c.NotChecked), WebFindings: sanitizeWeb(c.WebFindings),
		Greenbone: sanitizeGreenbone(c.Greenbone), Scripts: sanitizeScripts(c.Scripts), WebPages: sanitizeWebPages(c.WebPages), WebActivePages: sanitizeWebPages(c.WebActivePages), WebDisruptivePages: sanitizeWebPages(c.WebDisruptivePages),
		TemplatesRan: boundedKeys(c.TemplatesRan), ScriptsRan: boundedKeys(c.ScriptsRan), Probed: probed}
}

// The ports a scan probed on one address (the outcome of the run item of the address, INV-22): a service a scan checked and did not
// find is missed; one missed by two scans in a row that checked it is closed.
const (
	coverAll  = "checked_all"  // every TCP port: a deep scan of the address, or the runner's port scan when it says it probed them all
	coverList = "checked_list" // the runner's fixed list of common ports (a scan that says it did not probe every port)
	coverWeb  = "checked_web"  // ports 80 and 443, by name: a domain's address that is not the box's, checked by name only
	// coverTop: the runner's fixed list, and the ports the default scan's service step said it probed there (Content.Probed). A port
	// outside the fixed list counts as checked by such a scan only when the scan probed it: in this scan by its Probed, in an earlier
	// one by a run item of kind itemPort (coverage of one port) that the scan wrote for it. A scan whose service step failed, did not
	// finish a port's batch, or ran before Probed existed is coverList and checks only the fixed list.
	coverTop = "checked_top"
	// coverEmpty: a port-scanned address where nothing was open and nothing replied this scan; it checks no port (coverage).
	coverEmpty = "checked_empty"
)

// itemPort is the kind of a run item that says a coverTop scan probed one port outside the fixed list on an address (its subject is
// portKey); the scan writes one for each open service there it probed, the only ports a later scan's closing asks about.
const itemPort = "port"

// coverOutcomes are the address coverages that probe a port.
func coverOutcomes(port int) []string {
	out := []string{coverAll}
	if slices.Contains(commonports.Numbers(), port) {
		out = append(out, coverList, coverTop)
	}
	if port == 80 || port == 443 {
		out = append(out, coverWeb)
	}
	return out
}

// covers says a scan with coverage class on an address, whose service step probed probed there, probed port.
func covers(class string, probed []int, port int) bool {
	if class == "" {
		return false
	}
	if slices.Contains(coverOutcomes(port), class) {
		return true
	}
	_, ok := slices.BinarySearch(probed, port)
	return class == coverTop && ok
}

// ipKey is the one spelling of an address that two scans are compared by (an IPv4-mapped form is the same address).
func ipKey(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

// coverResult is what coverage says of a scan: checked is which ports it probed on each address it reached (coverAll, coverList, coverTop,
// coverWeb, or coverEmpty for an address with nothing open that did not answer), gone the addresses of the services open before that
// left the domain, listed the addresses on which the runner TCP-connected the whole fixed list, settled the addresses whose
// coverEmpty streak ended with this scan (emptyStreak).
type coverResult struct {
	checked map[string]string
	gone    map[string]bool
	listed  map[string]bool
	settled map[string]bool
}

// coverage says, for each address this scan reached, which ports it probed there (coverAll, coverList, coverTop or coverWeb), and which
// addresses of the services open before left the domain (gone: no name of the domain points at them any more). An IP target is
// checked by every scan that wrote its rows; a domain scan port-scans the addresses its names point at that are scannable IP
// targets (the gate the runner asked, ScannableIP) and the addresses its deep scan reached, and checks the others by name on 80 and
// 443. An address the scan did not reach has no entry: the scan says nothing about its ports.
//
// A port-scanned address where nothing was open this scan (INV-22, INV-41): when it answered (Content.Answered: a TCP reset to the
// runner or to nmap) "nothing open" is a result and the address is checked as usual. When it answered nothing at all, the scan may not
// have reached it (a lost NAT loopback, a firewall dropping the probes): coverEmpty, which checks no port, until the third such scan
// in a row at least 24 hours after the first (emptyStreak), which is checked as usual and closes what they all missed (settled).
//
// prevPorts are the services open before this scan, prevHosts the names and addresses the scans before left.
func (s *Service) coverage(ctx context.Context, user string, t Target, runID string, c Content, prevPorts []PortRow, prevHosts []HostRow) coverResult {
	partial := slices.ContainsFunc(c.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "ports" })
	reported, deep, pointed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range c.Ports {
		reported[ipKey(p.IP)] = true
	}
	for _, h := range c.Hosts {
		pointed[ipKey(h.IP)] = true
		for _, a := range h.IPs {
			pointed[ipKey(a.IP)] = true
			if a.Deep == DeepScanned { // This run's deep scan port-scanned it
				deep[ipKey(a.IP)] = true
			}
		}
	}
	// settled: the address answered nothing and this scan ends an empty streak (emptyStreak). A finished sweep of every port that saw
	// nothing there is not trusted (sweepTrusted) for the very reason the streak counts as a miss, so it covers every port then.
	full := func(ip string, settled bool) string {
		trusted, swept := c.Swept[ip]
		switch {
		case swept && !trusted && !settled: // this run's sweep of every port met an address that stopped answering it: the fixed list only
			return coverList
		case deep[ip] || !partial:
			return coverAll
		case len(c.Probed[ip]) > 0: // the default scan's service step said which ports it probed here
			return coverTop
		}
		return coverList
	}
	out := coverResult{checked: map[string]string{}, gone: map[string]bool{}, listed: map[string]bool{}, settled: map[string]bool{}}
	portScanned := func(k string) {
		switch {
		case reported[k] || c.Answered[k]:
			out.checked[k] = full(k, false)
		case s.emptyStreak(ctx, t.ID, runID, k):
			out.checked[k], out.settled[k] = full(k, true), true
		default:
			out.checked[k] = coverEmpty
		}
	}
	defer func() { // an address that stopped answering during the scan: the scan says nothing about its ports (INV-22)
		for k, ports := range c.Lost {
			if len(ports) > 0 {
				out.checked[ipKey(k)] = coverLost
				delete(out.settled, ipKey(k))
			}
		}
	}()
	if t.Kind == KindIP {
		k := ipKey(t.Value)
		out.listed[k] = true // the runner connects to the whole fixed list of an IP target
		portScanned(k)
		return out
	}
	box := func(k string) bool {
		a, err := netip.ParseAddr(k)
		if err != nil {
			return false
		}
		ok, err := s.ScannableIP(ctx, user, a)
		return err == nil && ok
	}
	consider := func(k string, contacted bool) {
		if _, done := out.checked[k]; done {
			return
		}
		isBox := box(k)
		switch {
		case deep[k] || isBox:
			out.listed[k] = isBox // the runner port-scans only the domain's addresses that are scannable IP targets
			portScanned(k)
		case contacted || reported[k]:
			out.checked[k] = coverWeb
		}
	}
	for _, h := range c.Hosts {
		for _, a := range h.IPs {
			if a.Class != ClassPrivate {
				consider(ipKey(a.IP), a.Contacted)
			}
		}
	}
	for k := range reported {
		consider(k, false)
	}
	for _, p := range prevPorts {
		if k := ipKey(p.IP); !pointed[k] && moved(k, pointed, prevHosts, c.Hosts) {
			out.gone[k] = true
		}
	}
	return out
}

// emptyStreakScans and emptyStreakSpan: the scan of an address that found nothing open and got no reply there closes what was open
// only as the emptyStreakScans-th such scan in a row (counting itself), at least emptyStreakSpan after the first of them.
const (
	emptyStreakScans = 3
	emptyStreakSpan  = 24 * time.Hour
)

// emptyStreak says this scan (run runID) of target is the emptyStreakScans-th or later scan in a row that found nothing open on ip and
// got no reply there (run items coverEmpty since the newest scan that checked the address), at least emptyStreakSpan after the first
// of them. A failure to read says no: the ports stay as they are.
func (s *Service) emptyStreak(ctx context.Context, target, runID, ip string) bool {
	var n int
	var first, now sql.NullString
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `WITH runs AS (
		SELECT r.started_at AS at, i.outcome AS outcome FROM core_run_item i JOIN core_run r ON r.id = i.run_id
		WHERE r.module = ? AND r.kind = ? AND r.subject_kind = 'target' AND r.subject_id = ? AND r.id <> ? AND r.started_at IS NOT NULL
			AND r.started_at < (SELECT started_at FROM core_run WHERE id = ?) AND i.subject_kind = 'address' AND i.subject_id = ?
			AND i.outcome IN (?, ?, ?, ?, ?))
	SELECT count(*), min(at), (SELECT started_at FROM core_run WHERE id = ?) FROM runs
	WHERE outcome = ? AND at > coalesce((SELECT max(at) FROM runs WHERE outcome <> ?), '')`,
		ModuleID, RunKind, target, runID, runID, ip, coverAll, coverList, coverTop, coverWeb, coverEmpty, runID, coverEmpty, coverEmpty).Scan(&n, &first, &now)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the scans that found nothing open", "target", target, "ip", ip, "error", err)
		return false
	}
	if n+1 < emptyStreakScans || !first.Valid || !now.Valid {
		return false
	}
	a, err1 := parseTS(first.String)
	b, err2 := parseTS(now.String)
	return err1 == nil && err2 == nil && b.Sub(a) >= emptyStreakSpan
}

// moved says an address left a domain: it had names in the previous observation, and each of them is in this scan with another
// address. An address no known name pointed at (a name's second address), or a name this scan did not resolve (a failed lookup),
// is not "moved": the scan did not check it (INV-22).
func moved(ip string, pointed map[string]bool, before, now []HostRow) bool {
	if pointed[ip] {
		return false
	}
	at := map[string]string{}
	for _, h := range now {
		at[h.Name] = ipKey(h.IP)
	}
	named := false
	for _, h := range before {
		if ipKey(h.IP) != ip {
			continue
		}
		named = true
		if to, ok := at[h.Name]; !ok || to == ip {
			return false
		}
	}
	return named
}

// sanitizeWebPages keeps the scanned pages that are web addresses, bounded.
func sanitizeWebPages(in []string) []string {
	var out []string
	for _, p := range in {
		if u, err := url.Parse(p); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && len(p) <= maxContentText && len(out) < maxContentRows {
			out = append(out, p)
		}
	}
	return out
}

// boundedKeys keeps at most maxContentRows short keys ("ip", or "ip:port|template") the engines made themselves; one over the bound
// is left out, which only keeps an issue open.
func boundedKeys(in []string) []string {
	var out []string
	for _, k := range in {
		if len(k) <= 300 && len(out) < 4*maxContentRows {
			out = append(out, k)
		}
	}
	return out
}

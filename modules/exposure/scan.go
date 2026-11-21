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

// gate decides whether a target may be scanned now (INV-1, INV-13). A domain's TXT record is looked up again here,
// right before the scan, and the result is kept as the target's last check; a lookup that fails counts as "record
// missing" (fail closed). An IP that would otherwise be scannable is checked against the network too: the box must
// still be going out through it. actor is who asked (a person, or the scan module on behalf of a schedule); the audit
// trail names it.
func (s *Service) gate(ctx context.Context, actor, id string) (Target, BlockedReason, error) {
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return Target{}, "", err
	}
	if !t.Enabled { // switched off: nothing is sent, and nothing is looked up for it
		return t, BlockedDisabled, nil
	}
	switch r := t.blocked(s.clock()); {
	case r == BlockedUnverified || r == BlockedExpired:
		return t, r, nil
	case t.Typed && r != BlockedNoCommitment: // a typed IP: its proof is looked for now, right before the scan, like a domain's record (INV-1, INV-35); not before the confirmation is there
		if t, err = s.liveTypedProof(ctx, actor, t); err != nil {
			return Target{}, "", err
		}
	case t.Kind == KindIP && r == "":
		current, err := s.stillCurrent(ctx, actor, t)
		if err != nil {
			return Target{}, "", err
		}
		if !current {
			if t, err = loadTarget(ctx, s.cfg.DB.Reader(), id); err != nil {
				return Target{}, "", err
			}
			return t, BlockedNotCurrent, nil
		}
	case t.Kind == KindDomain:
		pr, err := s.proveDomain(ctx, t) // The name, _vedette-verify.<name>, or a parent down to its registered domain
		if err != nil {
			return Target{}, "", err
		}
		err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
			var err error
			if pr, err = stillOwner(ctx, tx, id, pr); err != nil {
				return err
			}
			found := pr.found
			now := s.clock()
			msg, action := proofMessage(t, pr, s.momentText(now)), "exposure.verify_ok"
			if !found {
				msg, action = pr.failure, "exposure.verify_fail"
			}
			if err := updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: found, Message: msg, Covers: pr.coversBelow(t.Value), Via: pr.via}, time.Time{}, ""); err != nil {
				return err
			}
			if err := settleMethod(ctx, tx, id, pr); err != nil { // covered by an ancestor now, or proved by itself
				return err
			}
			if t.LastCheck != nil && t.LastCheck.OK == found { // nothing changed: the check is not a row of its own (L5)
				return nil
			}
			return s.audit(ctx, tx, actor, action, t.Value, "dns_txt, right before a scan")
		})
		if err != nil {
			return Target{}, "", fmt.Errorf("recording the TXT check: %w", err)
		}
		if t, err = loadTarget(ctx, s.cfg.DB.Reader(), id); err != nil {
			return Target{}, "", err
		}
		// the target whose token proved it now, and the name the record sits on: what the executors' fence checks
		t.proofDomain, t.proofToken, t.proofAt = pr.gate(t)
	}
	return t, t.blocked(s.clock()), nil
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
// domain. The IP stays in the list for 30 days from the last sighting (INV-4); this only decides whether it may be
// scanned now. It is true when the latest check, or the latest full check, ran within CurrentFor and saw the IP.
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
		return apiErr(409, "not_verified", "%s has no ownership proof, so it cannot be scanned. Finish verification first.", t.Value)
	case BlockedExpired:
		return apiErr(409, "expired", "Verification of %s expired on %s, so it cannot be scanned. Verify it again first.", t.Value, s.dayText(t.expiresAt(now)))
	case BlockedTxtMissing:
		if _, ok := registered(t.Value); !ok { // a stored public suffix is told so, not "add the record back"
			return apiErr(409, "txt_missing", "%s", publicSuffixText(t.Value))
		}
		return apiErr(409, "txt_missing", "The DNS TXT record %s is no longer found on %s, on %s.%s or on a parent domain of this box that covers it, so it cannot be scanned. Add the record back, then check again.", txtRecord(t.Token), t.Value, verifyLabel, t.Value)
	case BlockedProofMissing:
		return apiErr(409, "proof_missing", "The proof of %s is not found now, so it cannot be scanned. %s", t.Value, proofRetry)
	case BlockedNoCommitment:
		if t.Commitment != nil {
			return errNeedAdminReconfirm(t.Value)
		}
		return errNeedAdminFirstScan(t.Value)
	case BlockedDisabled:
		return apiErr(409, "disabled", "%s is switched off, so it is not scanned. Switch it on first.", t.Value)
	case BlockedNotCurrent:
		return apiErr(409, "ip_not_current", "This box no longer reaches the Internet through %s; it was last seen %s. Scans of it are paused until the box uses it again.", t.Value, s.momentText(t.VerifiedAt))
	}
	return nil
}

// proofRetry ends the refusal of a typed IP whose proof is not found.
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
// INV-13: it may run one full check of the box's IPs, as actor), so an address that is not the box's own verified, committed and
// current IP is never port-scanned.
func (s *Service) ScannableIP(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
	ip = ip.Unmap()
	if !IsPublicIPv4(ip) {
		return false, nil
	}
	// INV-31: an address on the shared exclusion list, or any address while the list cannot be read, is never port-scanned
	if sf, err := s.safety(ctx); err != nil || sf.excluded(ip) {
		if err != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: reading the shared safety settings failed", "error", err)
		}
		return false, nil
	}
	t, ok, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), ip.String())
	if err != nil || !ok || t.Kind != KindIP {
		return false, err
	}
	_, reason, err := s.gate(ctx, actor, t.ID)
	if err != nil {
		return false, fmt.Errorf("exposure: checking whether %s may be scanned: %w", ip, err)
	}
	return reason == "", nil
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
	return Content{Hosts: nz(out.Hosts), Listed: out.Listed, Ports: nz(out.Ports), AdminPanels: nz(out.AdminPanels), Certs: nz(out.Certs), Unresolved: out.Unresolved,
		Services: sanitizeServices(c.Services), Templates: sanitizeTemplates(c.Templates, sanitizeServices(c.Services)), Checks: sanitizeChecks(c.Checks), NotChecked: sanitizeNotChecked(c.NotChecked), WebFindings: sanitizeWeb(c.WebFindings),
		Greenbone: sanitizeGreenbone(c.Greenbone), Scripts: sanitizeScripts(c.Scripts), WebPages: sanitizeWebPages(c.WebPages),
		TemplatesRan: boundedKeys(c.TemplatesRan), ScriptsRan: boundedKeys(c.ScriptsRan)}
}

// The ports a scan probed on one address (the outcome of the run item of the address, INV-22): a service a scan checked and did not
// find is missed; one missed by two scans in a row that checked it is closed.
const (
	coverAll  = "checked_all"  // every TCP port: a deep scan of the address, or the runner's port scan when it says it probed them all
	coverList = "checked_list" // the runner's fixed list of common ports (a scan that says it did not probe every port)
	coverWeb  = "checked_web"  // ports 80 and 443, by name: a domain's address that is not the box's, checked by name only
)

// coverOutcomes are the coverages that probe a port.
func coverOutcomes(port int) []string {
	out := []string{coverAll}
	if slices.Contains(commonports.Numbers(), port) {
		out = append(out, coverList)
	}
	if port == 80 || port == 443 {
		out = append(out, coverWeb)
	}
	return out
}

// covers says a scan with coverage class probed port.
func covers(class string, port int) bool {
	return class != "" && slices.Contains(coverOutcomes(port), class)
}

// ipKey is the one spelling of an address that two scans are compared by (an IPv4-mapped form is the same address).
func ipKey(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

// coverage says, for each address this scan reached, which ports it probed there (coverAll, coverList or coverWeb), and which
// addresses of the services open before left the domain (gone: no name of the domain points at them any more). An IP target is
// checked by every scan that wrote its rows; a domain scan port-scans the addresses its names point at that are scannable IP
// targets (the gate the runner asked, ScannableIP) and the addresses its deep scan reached, and checks the others by name on 80 and
// 443. An address the scan did not reach has no entry: the scan says nothing about its ports.
//
// prevPorts are the services open before this scan, prevHosts the names and addresses the scans before left.
func (s *Service) coverage(ctx context.Context, user string, t Target, c Content, prevPorts []PortRow, prevHosts []HostRow) (checked map[string]string, gone map[string]bool) {
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
	full := func(ip string) string {
		if deep[ip] || !partial {
			return coverAll
		}
		return coverList
	}
	checked, gone = map[string]string{}, map[string]bool{}
	if t.Kind == KindIP {
		checked[ipKey(t.Value)] = full(ipKey(t.Value))
		return checked, gone
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
		if _, done := checked[k]; done {
			return
		}
		switch {
		case deep[k] || box(k):
			checked[k] = full(k)
		case contacted || reported[k]:
			checked[k] = coverWeb
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
			gone[k] = true
		}
	}
	return checked, gone
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

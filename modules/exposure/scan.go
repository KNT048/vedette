package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
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
	switch r := t.blocked(s.clock()); {
	case r == BlockedUnverified || r == BlockedExpired:
		return t, r, nil
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
		found, failure := s.lookupTXT(ctx, t)
		err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
			now := s.clock()
			msg, action := fmt.Sprintf("Found the TXT record %s on %s.", txtRecord(t.Token), t.Value), "exposure.verify_ok"
			if !found {
				msg, action = fmt.Sprintf("The TXT record %s was not found on %s.", txtRecord(t.Token), t.Value), "exposure.verify_fail"
				if failure != "" {
					msg = failure
				}
			}
			if err := updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: found, Message: msg}, time.Time{}, ""); err != nil {
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
		return apiErr(409, "txt_missing", "The DNS TXT record %s is no longer on %s, so it cannot be scanned. Add the record back, then check again.", txtRecord(t.Token), t.Value)
	case BlockedNoCommitment:
		if t.Commitment != nil {
			return errNeedAdminReconfirm(t.Value)
		}
		return errNeedAdminFirstScan(t.Value)
	case BlockedNotCurrent:
		return apiErr(409, "ip_not_current", "This box no longer reaches the Internet through %s; it was last seen %s. Scans of it are paused until the box uses it again.", t.Value, s.momentText(t.VerifiedAt))
	}
	return nil
}

// ScanEvery is the least time between two scans of one target (D-229): a scan asks crt.sh and probes the target, so a click
// that repeats is answered 429 rather than sent again.
const ScanEvery = 10 * time.Minute

// Scan scans one target now for a caller that is not a person at the button (the commitment must already exist). See ScanNow.
func (s *Service) Scan(ctx context.Context, user, id string) (Snapshot, error) {
	return s.ScanNow(ctx, Actor{Email: user}, id, "")
}

// ScanNow scans one target now and waits for the snapshot: it is StartScan followed by waiting for the run, for callers that
// are not a page (tests, a schedule). The page calls StartScan and polls the run (POST …/scan answers 202).
func (s *Service) ScanNow(ctx context.Context, who Actor, id, noticeVersion string) (Snapshot, error) {
	run, err := s.startScan(ctx, who, id, noticeVersion)
	if err != nil {
		return Snapshot{}, err
	}
	select {
	case <-run.done:
	case <-ctx.Done():
		return Snapshot{}, fmt.Errorf("exposure: waiting for the scan: %w", context.Cause(ctx))
	}
	if run.err != nil {
		return Snapshot{}, fmt.Errorf("exposure: scanning %s: %w", run.view.TargetValue, run.err)
	}
	return run.snap, nil
}

// StartScan is POST …/scan (PRE-1, INV-1, INV-12, INV-17, INV-18): the gate first, then one scan at a time on the box (409 busy) and at
// most one per target every ScanEvery (429 rate_limited), then the runner the scan module registered, which runs in the background
// (execute). It returns the run at once; a refusal is the same error as before and is audited as exposure.scan with its outcome
// (LEGAL §3). Without a runner the answer is 501 after the gate. When the only thing missing is the commitment and who.Admin is set,
// this press is the confirmation (D-473): it needs two-step sign-in and the notice version the page showed (confirmByScan), then the
// gate runs again with the commitment in place. For anyone else the answer is 400 commitment_required.
func (s *Service) StartScan(ctx context.Context, who Actor, id, noticeVersion string) (ScanRun, error) {
	run, err := s.startScan(ctx, who, id, noticeVersion)
	if err != nil {
		return ScanRun{}, err
	}
	return s.runView(run), nil
}

func (s *Service) startScan(ctx context.Context, who Actor, id, noticeVersion string) (*scanRun, error) {
	t, reason, err := s.gate(ctx, who.Email, id)
	if err != nil {
		return nil, fmt.Errorf("exposure: scanning: %w", err)
	}
	if reason == BlockedNoCommitment && who.Admin {
		if err = s.confirmByScan(ctx, who, t, noticeVersion); err == nil {
			t, reason, err = s.gate(ctx, who.Email, id)
		}
		if err != nil {
			s.auditFailedScan(ctx, who.Email, t, err)
			return nil, fmt.Errorf("exposure: scanning %s: %w", t.Value, err)
		}
	}
	run, err := s.begin(ctx, who.Email, t, reason)
	if err != nil {
		s.auditFailedScan(ctx, who.Email, t, err)
		return nil, fmt.Errorf("exposure: scanning %s: %w", t.Value, err)
	}
	return run, nil
}

// auditFailedScan writes the exposure.scan row of an attempt that ended without a snapshot: refused by the gate, busy, too soon,
// the scan module off, or failed. The write outlives a caller that hung up; a failure to write is logged.
func (s *Service) auditFailedScan(ctx context.Context, user string, t Target, cause error) {
	detail := "failed: the scan stopped (" + clipText(cause.Error(), 200) + ")"
	var ae *APIError
	var sb *stoppedBy
	switch {
	case errors.As(cause, &sb):
		detail = "stopped by " + sb.by
	case errors.As(cause, &ae):
		detail = "not done: " + ae.Code + ": " + clipText(ae.Message, 300)
	}
	s.auditScanRow(ctx, user, t.Value, detail)
}

func (s *Service) auditScanRow(ctx context.Context, user, target, detail string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), publishTimeout)
	defer cancel()
	err := s.write(actx, func(tx *sql.Tx, _ func(string, any)) error {
		return s.audit(actx, tx, user, "exposure.scan", target, detail)
	})
	if err != nil {
		s.cfg.Log.ErrorContext(actx, "auditing an exposure scan failed", "target", target, "error", err)
	}
}

func clipText(v string, n int) string {
	if r := []rune(v); len(r) > n {
		return string(r[:n])
	}
	return v
}

// ScannableIP says whether ip is a verified IP target that may be scanned now (D-57 (7), LEGAL §3): the scan of a domain asks it
// before it port-scans an address one of the domain's names points at. It runs the same gate as a scan of that target (INV-1,
// INV-13: it may run one full check of the box's IPs, as actor), so an address that is not the box's own verified, committed and
// current IP is never port-scanned.
func (s *Service) ScannableIP(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
	ip = ip.Unmap()
	if !IsPublicIPv4(ip) {
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

// countsOf computes the numbers of a snapshot (INV-8); certs_expiring counts the certificates that
// expire within CertWarnDays. extraIP is the target itself when it is an IP.
func countsOf(c Content, extraIP string, now time.Time) Counts {
	ips := map[string]bool{}
	for _, h := range c.Hosts {
		ips[h.IP] = true
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
			out.Hosts = append(out.Hosts, HostRow{Name: txt(h.Name), IP: txt(h.IP)})
		}
	}
	for _, p := range c.Ports {
		if len(out.Ports) < maxContentRows && p.Port >= 1 && p.Port <= 65535 {
			out.Ports = append(out.Ports, PortRow{IP: txt(p.IP), Port: p.Port, Service: txt(p.Service), Product: txt(p.Product)})
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
	return Content{Hosts: nz(out.Hosts), Ports: nz(out.Ports), AdminPanels: nz(out.AdminPanels), Certs: nz(out.Certs),
		Services: sanitizeServices(c.Services), Checks: sanitizeChecks(c.Checks), NotChecked: sanitizeNotChecked(c.NotChecked)}
}

// scope says what the scan did with an address whose ports the previous observation listed (INV-22).
type scope int

const (
	scopeChecked scope = iota // the scan port-scanned it: a port it does not report was missed
	scopeKept                 // still the domain's address but not scannable now (lapsed, paused, deleted, skipped): the scan did not check it
	scopeGone                 // no longer an address of the domain: its ports leave with the host
)

// ipKey is the one spelling of an address that two scans are compared by (an IPv4-mapped form is the same address).
func ipKey(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

// coveredBy decides, for each address of the previous observation that this scan reported no port on, whether the scan checked it.
// An IP target is checked by every successful scan; a domain scan port-scans only the addresses its names point at that are
// scannable IP targets (the gate the runner asked, ScannableIP). A scan that did not check an address says nothing about its ports.
func (s *Service) coveredBy(ctx context.Context, user string, t Target, c Content, prev Snapshot) map[string]scope {
	reported := map[string]bool{}
	for _, p := range c.Ports {
		reported[ipKey(p.IP)] = true
	}
	pointed := map[string]bool{}
	for _, h := range c.Hosts {
		pointed[ipKey(h.IP)] = true
	}
	out := map[string]scope{}
	for _, p := range prev.Ports {
		k := ipKey(p.IP)
		if _, done := out[k]; done {
			continue
		}
		switch {
		case reported[k] || (t.Kind == KindIP && k == ipKey(t.Value)):
			out[k] = scopeChecked
		case t.Kind != KindDomain || moved(k, pointed, prev.Hosts, c.Hosts):
			out[k] = scopeGone
		default:
			out[k] = scopeKept
			if a, err := netip.ParseAddr(k); err == nil {
				if ok, err := s.ScannableIP(ctx, user, a); err == nil && ok {
					out[k] = scopeChecked
				}
			}
		}
	}
	return out
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

// carryNotSeen keeps, in the newest scan, the ports of the previous observation that this scan did not report (INV-22, D-560): one
// scan that missed a port (packet loss, a slow host) must not read as a fix. A port on an address the scan checked gets one more
// miss and is dropped (closed) at the second miss in a row, scans counted, not days; a port on an address the scan did not check is
// kept as it was, with no miss; a port the scan reports is a normal row. A port a scan reports again starts from zero. The service
// read on a kept port is kept too, so its exploited CVEs stay until the port is closed. Kept rows count as open ports.
func carryNotSeen(c Content, prev Snapshot, how map[string]scope) Content {
	type key struct {
		ip   string
		port int
	}
	have := map[key]bool{}
	for _, p := range c.Ports {
		have[key{ipKey(p.IP), p.Port}] = true
	}
	kept := map[key]bool{}
	for _, p := range prev.Ports {
		k := key{ipKey(p.IP), p.Port}
		if have[k] || len(c.Ports) >= maxContentRows {
			continue
		}
		if p.LastSeen == "" {
			p.LastSeen = prev.Date
		}
		switch how[k.ip] {
		case scopeGone:
			continue
		case scopeKept:
			p.Unchecked = true
		case scopeChecked:
			p.Unchecked = false
			if p.Misses >= 1 {
				continue // missed by two scans in a row: closed
			}
			p.Misses = 1
		}
		have[k] = true
		kept[k] = true
		c.Ports = append(c.Ports, p)
	}
	haveSvc := map[key]bool{}
	for _, x := range c.Services {
		haveSvc[key{ipKey(x.IP), x.Port}] = true
	}
	for _, x := range prev.Services {
		k := key{ipKey(x.IP), x.Port}
		if kept[k] && !haveSvc[k] && len(c.Services) < maxContentRows {
			haveSvc[k] = true
			c.Services = append(c.Services, x)
		}
	}
	return c
}

// keptPorts counts the rows of a snapshot that an earlier scan reported (INV-22).
func keptPorts(ports []PortRow) int {
	n := 0
	for _, p := range ports {
		if p.LastSeen != "" {
			n++
		}
	}
	return n
}

// ---- reading results (INV-8) ----

// Snapshots lists the scan days of a target, newest first.
func (s *Service) Snapshots(ctx context.Context, id string) ([]SnapshotMeta, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: listing snapshots: %w", err)
	}
	return listSnapshotMetas(ctx, db, id)
}

// SnapshotOf returns the result of one day, or an error wrapping ErrNoSnapshot.
func (s *Service) SnapshotOf(ctx context.Context, id, date string) (Snapshot, error) {
	snap, ok, err := loadSnapshot(ctx, s.cfg.DB.Reader(), id, date)
	if err != nil {
		return Snapshot{}, fmt.Errorf("exposure: reading snapshot: %w", err)
	}
	if !ok {
		return Snapshot{}, fmt.Errorf("exposure: reading snapshot: %w", ErrNoSnapshot)
	}
	s.withVulns(ctx, &snap)
	return snap, nil
}

// Diff compares two scan days of a target: what appeared, what is gone, what changed (the expiry of a
// certificate, the product or version of a service). The earlier day is always the "from" side. Both days must exist and differ.
func (s *Service) Diff(ctx context.Context, id, from, to string) (Diff, error) {
	db := s.cfg.DB.Reader()
	a, okA, err := loadSnapshot(ctx, db, id, from)
	if err != nil {
		return Diff{}, fmt.Errorf("exposure: comparing: %w", err)
	}
	b, okB, err := loadSnapshot(ctx, db, id, to)
	if err != nil {
		return Diff{}, fmt.Errorf("exposure: comparing: %w", err)
	}
	if !okA || !okB {
		return Diff{}, fmt.Errorf("exposure: comparing: %w", ErrNoSnapshots)
	}
	if a.Date == b.Date {
		return Diff{}, fmt.Errorf("exposure: comparing: %w", ErrSameDate)
	}
	if a.Date > b.Date {
		a, b = b, a
	}
	s.withVulns(ctx, &a) // INV-20: both days against today's list, so a vuln comes or goes with its service
	s.withVulns(ctx, &b)
	return diff(a, b), nil
}

type diffEntry struct {
	DiffItem
	exp string
	// service and vuln entries: where ("ip:port"); service entries: product and version
	at, product, version string
	lastSeen             string // port entries kept from an earlier scan: the day a scan last saw it (INV-22)
	missed               bool   // port entries: the last scan that checked the address missed it
}

// VersionNotRead is the "to" of a service whose version the newer scan did not read, where the older one did (INV-20): not a
// change of version, and its exploited CVEs are not "gone".
const VersionNotRead = "version not read this time"

// PortNotSeen is the "to" of a port that an earlier scan saw and the newer scan missed (INV-22): not "closed" until a second scan also misses it.
const PortNotSeen = "missed by the last scan"

// entries lists what a snapshot shows, keyed so two days can be compared (the keys are those of the mock).
func entries(s Snapshot) (map[string]diffEntry, []string) {
	m := map[string]diffEntry{}
	var order []string
	add := func(e diffEntry) {
		if _, dup := m[e.Key]; !dup {
			order = append(order, e.Key)
		}
		m[e.Key] = e
	}
	for _, h := range s.Hosts {
		add(diffEntry{DiffItem: DiffItem{Kind: "subdomain", Key: "h:" + h.Name, Label: h.Name, Detail: h.IP}})
	}
	for _, p := range s.Ports {
		key := fmt.Sprintf("p:%s:%d", p.IP, p.Port)
		detail := p.Service
		if p.Product != "" {
			detail += ", " + p.Product
		}
		add(diffEntry{DiffItem: DiffItem{Kind: "port", Key: key, Label: fmt.Sprintf("%s:%d", p.IP, p.Port), Detail: strings.TrimPrefix(detail, ", ")}, lastSeen: p.LastSeen, missed: p.Misses > 0})
	}
	for _, a := range s.AdminPanels {
		add(diffEntry{DiffItem: DiffItem{Kind: "admin", Key: "a:" + a.URL, Label: a.URL, Detail: a.Product}})
	}
	for _, c := range s.Certs {
		add(diffEntry{DiffItem: DiffItem{Kind: "cert", Key: "c:" + c.Host, Label: c.Host, Detail: c.Issuer}, exp: c.ExpiresAt})
	}
	for _, x := range s.Services {
		label := fmt.Sprintf("%s:%d", x.IP, x.Port)
		add(diffEntry{DiffItem: DiffItem{Kind: "service", Key: "s:" + label, Label: label, Detail: serviceText(x)}, at: label, product: x.Product, version: x.Version})
	}
	for _, v := range s.Vulns {
		label := fmt.Sprintf("%s:%d", v.IP, v.Port)
		add(diffEntry{DiffItem: DiffItem{Kind: "vuln", Key: "v:" + label + ":" + v.CVE, Label: v.CVE + " on " + label, Detail: v.Name}, at: label})
	}
	return m, order
}

func diff(a, b Snapshot) Diff {
	A, orderA := entries(a)
	B, order := entries(b)
	d := Diff{From: a.Date, To: b.Date, Added: []DiffItem{}, Removed: []DiffItem{}, Changed: []DiffChange{}}
	for _, k := range order {
		v := B[k]
		o, ok := A[k]
		switch {
		case !ok:
			d.Added = append(d.Added, v.DiffItem)
		case v.Kind == "port" && !o.missed && v.missed: // seen before, missed by the last scan: still open until a second scan agrees
			d.Changed = append(d.Changed, DiffChange{DiffItem: v.DiffItem, From: o.Detail, To: PortNotSeen})
		case v.Kind == "cert" && o.exp != v.exp:
			d.Changed = append(d.Changed, DiffChange{DiffItem: v.DiffItem, From: o.exp, To: v.exp})
		case v.Kind == "service" && versionUnread(o, v):
			d.Changed = append(d.Changed, DiffChange{DiffItem: v.DiffItem, From: o.Detail, To: VersionNotRead})
		case v.Kind == "service" && o.product == v.product && o.version == "": // a version read now that was not before: no change
		case v.Kind == "service" && o.Detail != v.Detail:
			d.Changed = append(d.Changed, DiffChange{DiffItem: v.DiffItem, From: o.Detail, To: v.Detail})
		}
	}
	for _, k := range orderA {
		o := A[k]
		if _, ok := B[k]; ok {
			continue
		}
		if s, ok := B["s:"+o.at]; o.Kind == "vuln" && ok && versionUnread(A["s:"+o.at], s) {
			continue // its service's version was not read this time: the CVE is not known to be gone
		}
		if o.Kind == "port" && o.missed { // the older day had it as missed once and the newer one has none: confirmed closed
			o.Detail = fmt.Sprintf("%s (closed: missed by two scans in a row, last seen %s)", o.Detail, o.lastSeen)
		}
		d.Removed = append(d.Removed, o.DiffItem)
	}
	return d
}

// versionUnread: the same product on the same port, with a version before and none now.
func versionUnread(o, v diffEntry) bool {
	return o.product != "" && o.product == v.product && o.version != "" && v.version == ""
}

package exposure

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// The deep scan of each address a verified domain's names resolve to, at the domain's testing terms depth
// (INV-27 depth; one rule for every name, whatever serves it; the terms say a provider's permission is the
// customer's to have). Without accepted terms nothing here runs: the basic scope stays as it was. With them, each public IPv4 address
// gets what the box's own IP gets (all TCP ports and nmap -sV with its scripts, the comparison with exploited CVEs, nuclei, then
// OpenVAS when it is on), through the seams that already exist, with the run's Mode. The web scan by name stays the by-name passive
// pass (INV-24) until the active ZAP scan exists: a second passive run of the same pages would only repeat it.
// Many names on one address are one deep address. At most MaxDeepIPs addresses a run get the steps, the least recently tried first;
// an address the re-check refuses does not take a place (at most maxDeepRefusals a run); the rest wait their turn and say so. An
// address reached only through a name that points (CNAME) outside the domain never gets the disruptive checks: the
// owner of that other name chooses the address.
//
// The fence: an address that is the box's own verified IP (ScannableIP) takes the box's pipeline and its fences.
// Any other address needs Config.DomainFence: without it nothing beyond the by-name checks goes there. With it, right before each step
// core checks again (deepGate) that the address is a public IPv4, that the domain is verified and its terms accepted now, and that a
// name under the domain still resolves to it, and hands the step the domain's scope with the box-bound token (ScanTarget.Domain),
// which the executors check on their own.

// Caps of a domain's deep scan per run.
const (
	// MaxDeepIPs is the most addresses that get the deep scan in one run (port scan, nmap -sV, nuclei, OpenVAS).
	MaxDeepIPs = 3
	// maxDeepRefusals is the most addresses the re-check may refuse in one run before the rest wait for the next run:
	// a refusal sends nothing, so it does not take one of the MaxDeepIPs places.
	maxDeepRefusals = 2 * MaxDeepIPs

	maxCapLines       = 8                // "not scanned this run" lines, one per address; the rest are one line
	nameLookupTimeout = 10 * time.Second // the core-side re-check that a name still resolves to the address
	maxLabelNames     = 3                // names written in an address's label; the rest are counted
)

// What a domain's deep scan did with an address in this run (HostIP.Deep, contract.ts HostIp.deep).
const (
	DeepScanned = "scanned" // the deep steps ran (each says what it found or why it did not)
	DeepWaiting = "waiting" // left by the cap: next in line (HostIP.NextInLine)
	DeepFence   = "fence"   // not the box's own IP, and this box has no domain fence: by-name checks only
	DeepRefused = "refused" // the core-side re-check refused it right before the first step: nothing was sent
	// DeepIncomplete: the re-check passed but service identification did not finish (not set up, not run, timed out, failed): nothing
	// is known of its ports, so it is not "scanned", its earlier ports are kept unchecked (INV-22) and it goes back in line.
	DeepIncomplete = "incomplete"
)

var deepStates = []string{DeepScanned, DeepWaiting, DeepFence, DeepRefused, DeepIncomplete}

// The lines of a domain's deep scan (kind "deep").
const (
	notDeepFence   = "Addresses of names under this domain that are not this box's (%s): not scanned at depth: this box needs the Vedette host's domain fence (update the box). Their names are checked by name on ports 80 and 443 only."
	notDeepCap     = "%s: not scanned this run (at most %d addresses get the deep scan in one run), %s; next in line (%d)."
	notDeepCapMore = "%s: not scanned this run either (at most %d addresses get the deep scan in one run); they follow, the least recently scanned first."
	notDeepPrivate = "Private addresses (%s): listed, never contacted."
	notDeepNone    = "Deep scan of the names' addresses: no name under this domain resolves to a public IPv4 address."

	deepNotPublic = "it is not a public IPv4 address, so nothing was sent."
	deepTerms     = "the testing terms of this domain are no longer accepted (withdrawn, or new terms to accept), so nothing was sent."
	deepGone      = "this domain can no longer be scanned (its ownership proof was withdrawn or has not been found for 90 days, or it was removed, switched off or needs the scan confirmed again), so nothing was sent."
	deepNotBox    = "this address is no longer this box's own verified IP, so nothing was sent."
	deepUnchecked = "the box could not check this domain's ownership, its testing terms or this box's own address right now, so nothing was sent."
	// deepSettingsUnread: the address is an IP target too, whose stored deep-scan settings cannot be read.
	deepSettingsUnread = "this address is also an IP target of this box, and its stored deep-scan settings cannot be read, so nothing was sent. Save that target's settings again."
	deepNoFence        = "this box needs the Vedette host's domain fence (update the box), so nothing was sent."
	deepNoLookup       = "the box cannot look up names to check that one still resolves to this address, so nothing was sent."
	deepMoved          = "no name under this domain resolves to this address any more (looked up right before the step), so nothing was sent."
	deepNoAnswer       = "the DNS resolver did not answer the check that a name still resolves to this address, so nothing was sent."
	deepFenceDown      = "the Vedette host did not give this domain's fence token, so nothing was sent."
	deepNoNmap         = "service identification did not finish, so its ports are not known this run: it goes back in line."
	notDeepOutside     = "%s: reached only through a name that points (CNAME) outside this domain, so the disruptive checks were not run there."
	// notDeepNotOwn follows an address of a domain that is not a proven address of this box (hosting, a CDN, a typed IP): the
	// disruptive checks go only to the box's own public IPs inside their proof.
	notDeepNotOwn  = "not a proven address of this box, so the deep scan ran there without the disruptive checks."
	notDeepNAT     = "this box's gateway is in 100.64.0.0/10 (carrier-grade NAT) or could not be read, so the deep scan ran there without the disruptive checks."
	notDeepNoCNAME = "%s: the box could not confirm right before the scan that its name stays inside this domain (CNAME lookup), so the disruptive checks were not run there."
)

var fenceTokenRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// deepAddr is one public IPv4 address of a domain's names: the names that led to it (sorted), whether the runner saw it as the box's
// own (a hint for the order and the fence line only: deepGate decides), when it was last deep-scanned and last tried ("" never), and
// whether a name that led to it stays inside the domain (no CNAME, or a CNAME to a name under the domain).
type deepAddr struct {
	ip     netip.Addr
	names  []string
	box    bool
	last   string
	tried  string
	inZone bool
}

// turn is when the address last had its turn: the later of its last deep scan and its last try (one time format: strings sort as
// times), so a refused or incomplete address goes to the back of the line too.
func (a deepAddr) turn() string { return max(a.last, a.tried) }

// label is how the lines name an address: "203.0.113.5 (www.acme.example, api.acme.example and 2 more names)".
func (a deepAddr) label() string {
	n := a.names
	more := ""
	if len(n) > maxLabelNames {
		more = " and " + plural(len(n)-maxLabelNames, "more name")
		n = n[:maxLabelNames]
	}
	return a.ip.String() + " (" + strings.Join(n, ", ") + more + ")"
}

// underDomain: name is the domain itself or a name under it.
func underDomain(name, domain string) bool {
	return len(name) <= 253 && domainRE.MatchString(name) && (name == domain || strings.HasSuffix(name, "."+domain))
}

// scopeNames is the name a deep step's scope was issued for, which the next re-check of that step looks up again.
func scopeNames(st ScanTarget) []string {
	if st.Domain == nil {
		return nil
	}
	return []string{st.Domain.Name}
}

// deepGate is the core half of the domain fence, right before each deep step to ip: ip is a public IPv4;
// the domain is verified, committed and its terms accepted now (ModeNow re-reads them, with the TXT record); then either ip is the
// box's own verified IP (ScannableIP), or this box has a DomainFence, a name of names under the domain resolves to ip now, and the
// fence gives the domain's token. It returns the ScanTarget of the step (the mode as it is now, never above the run's; the scope for
// an address that is not the box's) or the reason nothing may be sent. Every failure is a refusal (fail closed); only a stopped run is
// an error.
func (s *Service) deepGate(ctx context.Context, st ScanTarget, ip netip.Addr, names []string) (ScanTarget, string, error) {
	ip = ip.Unmap()
	if !IsPublicIPv4(ip) {
		return st, deepNotPublic, nil
	}
	t, reason, err := s.gate(ctx, st.User, st.ID) // ModeNow's own reading, with the reason kept apart
	switch {
	case ctx.Err() != nil:
		return st, "", ctx.Err()
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: reading the terms before a deep step failed", "target", st.Value, "ip", ip, "error", err)
		return st, deepUnchecked, nil
	case reason != "":
		return st, deepGone, nil
	}
	m := narrow(t.mode(), t.Deep) // the terms and the deep-scan settings as they are now
	if !m.Full {
		return st, deepTerms, nil
	}
	out := st
	out.Mode, out.Domain = m.And(st.Mode), nil
	box, err := s.ScannableIP(ctx, st.User, ip)
	switch {
	case ctx.Err() != nil:
		return st, "", ctx.Err()
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: checking whether a domain's address is the box's own failed", "target", st.Value, "ip", ip, "error", err)
		return st, deepUnchecked, nil
	case box:
		if it, found, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), ip.String()); err != nil { // the address is an IP target too: both targets' settings
			s.cfg.Log.ErrorContext(ctx, "exposure: reading the settings of a domain's address that is an IP target failed", "target", st.Value, "ip", ip, "error", err)
			return st, deepUnchecked, nil
		} else if found {
			if it.Deep.Problem != nil { // never a scan without that target's exclusions
				return st, deepSettingsUnread, nil
			}
			out = withSettings(out, it.Deep)
		}
		if tt, typed := s.typedAddr(ctx, ip); typed { // a typed IP of the box's list, not the box's own egress: its own proof goes to the executors
			tm := tt.mode() // a separate asset with its own consent: the stricter of the two targets' terms
			if !tm.Full {
				return st, deepTerms, nil
			}
			out = dropDisruptive(out, dropNotOwn) // a typed IP proves control of a web port, not that the address is the customer's own
			scope, why := s.typedScope(ctx, tt)
			if scope == nil {
				return st, why, nil
			}
			out.Domain = scope
			return out, "", nil
		}
		if out.Mode.Disruptive && len(names) > 0 && !s.cnameInZone(ctx, names, st.Value) { // r2-M1: the box's own IP reached through a name: the same CNAME rule
			out = dropDisruptive(out, dropCNAME)
		}
		if out.Mode.Disruptive { // the box's own IP behind carrier-grade NAT is the provider's (runMode's rule, at this step)
			if _, shared, err := s.sharedGateway(ctx); err != nil || shared {
				out = dropDisruptive(out, dropNAT)
			}
		}
		return out, "", nil
	case len(names) == 0: // a step of the box's pipeline (no scope) whose address is not the box's any more
		return st, deepNotBox, nil
	case s.cfg.DomainFence == nil:
		return st, deepNoFence, nil
	}
	hr, ok := s.cfg.Resolver.(HostResolver)
	if !ok {
		return st, deepNoLookup, nil
	}
	name, failed := "", false
	for _, n := range names {
		if !underDomain(n, st.Value) || !st.Names.Scans(n) { // a name the scan does not own (a child's) never gets a scope from it
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, nameLookupTimeout)
		addrs, err := hr.LookupNetIP(lctx, "ip4", n)
		cancel()
		if ctx.Err() != nil {
			return st, "", ctx.Err()
		}
		if err != nil {
			failed = true
			continue
		}
		if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == ip }) {
			name = n
			break
		}
	}
	switch {
	case name == "" && failed:
		return st, deepNoAnswer, nil
	case name == "":
		return st, deepMoved, nil
	}
	// The domain whose token proves the target now, and the name its record sits on when that is not the domain itself (checked there
	// by the executors, which accept any name under it): the target itself, with its own record there or on a parent name of it; a
	// parent target of the box; or another target of the box whose token sits on a name above both. A gate result that does not fit
	// the target (no proof, a name not above it) falls back to the target's own token, which the executors then check as it is.
	fd, proofAt := st.Value, ""
	switch {
	case t.proofDomain == "":
	case t.proofAt != "" && underDomain(st.Value, t.proofAt) && underDomain(t.proofDomain, t.proofAt):
		fd, proofAt = t.proofDomain, t.proofAt
	case t.proofAt == "" && underDomain(st.Value, t.proofDomain):
		fd = t.proofDomain
	}
	tok, err := s.cfg.DomainFence.Token(ctx, fd)
	if ctx.Err() != nil {
		return st, "", ctx.Err()
	}
	if err != nil || !fenceTokenRE.MatchString(tok) {
		s.cfg.Log.ErrorContext(ctx, "exposure: the domain fence gave no token", "target", st.Value, "error", err)
		return st, deepFenceDown, nil
	}
	if fd != st.Value { // the parent deleted since the gate: the host just listed it again, so give its slot back
		if _, ok, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), fd); err != nil || !ok {
			if err == nil {
				s.forgetDomain(ctx, fd)
			}
			return st, deepGone, nil
		}
	}
	out.Domain = &DomainScope{Domain: fd, Name: name, Token: tok, ProofAt: proofAt, Chain: s.cnameChain(ctx, name)}
	// An address that is not the box's own (hosting, a CDN, a proxy): the deep scan without the disruptive checks, whatever the
	// terms. They go only to an address proven as the customer's own, the box's public IP inside its proof (above).
	return dropDisruptive(out, dropNotOwn), "", nil
}

// Why deepGate took the disruptive checks out of a step (ScanTarget.dropped).
const (
	dropNotOwn = "not_own" // not a proven address of this box
	dropCNAME  = "cname"   // the box's IP reached through a name whose CNAME could not be seen to stay inside the domain
	dropNAT    = "nat"     // the box's gateway is in 100.64.0.0/10 or could not be read
)

// dropDisruptive takes the disruptive checks out of a step that the run allowed them on, saying why.
func dropDisruptive(st ScanTarget, why string) ScanTarget {
	if st.Mode.Disruptive {
		st.Mode, st.dropped = st.Mode.withoutDisruptive(), why
	}
	return st
}

// withSettings narrows a step by the deep-scan settings of a second target that holds its address (the box's IP target reached
// through a domain's name): its groups are cleared too, and its exclusions and speed add to the step's.
func withSettings(st ScanTarget, d DeepSettings) ScanTarget {
	st.Mode = narrow(st.Mode, d)
	both := intersect(DeepSettings{DoS: true, Logins: true, WebActive: true, DataChange: true, OpenVAS: true, SkipPorts: st.SkipPorts, SkipPaths: st.SkipPaths,
		Speed: map[bool]string{true: SpeedGentle, false: SpeedNormal}[st.Gentle]}, d)
	st.SkipPorts, st.SkipPaths, st.Gentle = both.SkipPorts, both.SkipPaths, both.Gentle()
	st.Groups &= d.Groups()
	return st
}

// CNAMEResolver looks up a name's canonical name; *net.Resolver satisfies it (it answers the name itself when there is no CNAME).
type CNAMEResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// maxCNAMEChecks bounds the names cnameInZone looks up for one step (a bound, not one lookup per name of a CDN address).
const maxCNAMEChecks = 3

// cnameInZone says, right before a step, that a name under domain among names is seen now to resolve inside the domain: its canonical
// name (the end of its CNAME chain) is itself or a name under the domain. A lookup error, a time-out, an answer that is
// not a host name, an outside name or a Resolver without LookupCNAME all say no: then the disruptive checks are dropped (fail closed),
// because the owner of an outside name chooses the address.
func (s *Service) cnameInZone(ctx context.Context, names []string, domain string) bool {
	cr, ok := s.cfg.Resolver.(CNAMEResolver)
	if !ok {
		return false
	}
	tried := 0
	for _, n := range names {
		if !underDomain(n, domain) || tried >= maxCNAMEChecks {
			continue
		}
		tried++
		lctx, cancel := context.WithTimeout(ctx, nameLookupTimeout)
		cn, err := cr.LookupCNAME(lctx, n)
		cancel()
		cn = strings.ToLower(strings.TrimSuffix(cn, "."))
		if err == nil && (cn == n || underDomain(cn, domain)) {
			return true
		}
	}
	return false
}

// cnameChain is name's CNAME chain for the probe log: "name -> canonical name", the name alone when it has no CNAME, "" when
// the lookup failed or the Resolver has no LookupCNAME. The standard resolver answers the end of the chain, not each hop.
func (s *Service) cnameChain(ctx context.Context, name string) string {
	cr, ok := s.cfg.Resolver.(CNAMEResolver)
	if !ok {
		return ""
	}
	lctx, cancel := context.WithTimeout(ctx, nameLookupTimeout)
	defer cancel()
	cn, err := cr.LookupCNAME(lctx, name)
	cn = strings.ToLower(strings.TrimSuffix(cn, "."))
	switch {
	case err != nil || cn != "" && (len(cn) > 253 || !domainRE.MatchString(cn)):
		return ""
	case cn == "" || cn == name:
		return name
	}
	return name + " -> " + cn
}

// clearDeep drops what a runner says about the deep scan from its rows (the runner's report is untrusted, INV-10): the deep state of
// a run is exposure's own, set by deepDomain. Rows are copied, so the runner's slices are never written.
func clearDeep(hosts []HostRow) []HostRow {
	out := slices.Clone(hosts)
	for i := range out {
		out[i].IPs = slices.Clone(out[i].IPs)
		for j := range out[i].IPs {
			out[i].IPs[j].Deep, out[i].IPs[j].LastDeep, out[i].IPs[j].LastTried, out[i].IPs[j].NextInLine = "", "", "", 0
		}
	}
	return out
}

// deepCandidates lists the public IPv4 addresses of the names under domain, one per address with every name that led to it, the least
// recently tried first (never first), then by address; and counts the private IPv4 addresses (never dialed). An address the runner
// gave without kinds (a row of an older snapshot) is a candidate too: deepGate decides what it is.
func deepCandidates(hosts []HostRow, domain string, last, tried map[string]string) (out []deepAddr, private int) {
	at := map[netip.Addr]int{}
	priv := map[netip.Addr]bool{}
	add := func(ip netip.Addr, name string, box, inZone bool) {
		i, ok := at[ip]
		if !ok {
			i = len(out)
			at[ip] = i
			out = append(out, deepAddr{ip: ip, last: last[ip.String()], tried: tried[ip.String()]})
		}
		if !slices.Contains(out[i].names, name) {
			out[i].names = append(out[i].names, name)
		}
		out[i].box = out[i].box || box
		out[i].inZone = out[i].inZone || inZone
	}
	for _, h := range hosts {
		name := strings.ToLower(h.Name)
		if !underDomain(name, domain) || h.LookupFailed {
			continue
		}
		cname := strings.ToLower(strings.TrimSuffix(h.CNAME, "."))
		inZone := cname == "" || underDomain(cname, domain)
		ips := h.IPs
		if len(ips) == 0 && h.IP != "" {
			ips = []HostIP{{IP: h.IP}}
		}
		for _, a := range ips {
			ip, err := netip.ParseAddr(a.IP)
			if err != nil || !ip.Unmap().Is4() {
				continue
			}
			ip = ip.Unmap()
			if !IsPublicIPv4(ip) {
				priv[ip] = true
				continue
			}
			add(ip, name, a.Class == ClassBox, inZone)
		}
	}
	for i := range out {
		slices.Sort(out[i].names)
	}
	slices.SortFunc(out, func(a, b deepAddr) int { return cmp.Or(cmp.Compare(a.turn(), b.turn()), a.ip.Compare(b.ip)) })
	return out, len(priv)
}

// deepDomain is the deep scan of a domain whose testing terms are accepted, after its by-name checks and before the rows are
// written: the addresses in turn (deepCandidates), each through deepIP, until MaxDeepIPs got the steps or maxDeepRefusals were refused;
// the others are marked and get their lines. It returns the addresses whose service identification finished, for OpenVAS after the
// snapshot is stored. Only a stop of the run ends it with an error.
func (s *Service) deepDomain(ctx context.Context, st ScanTarget, c Content) (Content, []deepAddr, error) {
	last, tried, err := s.deepHistory(ctx, st.ID) // one fixed time format (store.FormatTS): the strings sort as times
	if err != nil {
		return c, nil, err
	}
	addrs, private := deepCandidates(c.Hosts, st.Value, last, tried)
	var lines []NotCheckedRow
	state := map[string]HostIP{}
	var fence []string
	var queue []deepAddr
	// INV-31: an address on the shared exclusion list gets nothing; a list that cannot be read stops the deep step (nothing sent)
	sf, err := s.safety(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return c, nil, ctx.Err()
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: reading the shared safety settings failed", "target", st.Value, "error", err)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: notSafetyRead})
		noAddressStep(ctx, notSafetyRead)
		return c, nil, nil
	}
	rs := runStepsOf(ctx)
	now := store.FormatTS(s.clock())
	for _, a := range addrs {
		if sf.excluded(a.ip) {
			state[a.ip.String()] = HostIP{Deep: DeepRefused, LastTried: now}
			lines = append(lines, NotCheckedRow{Kind: "deep", Text: clipText(fmt.Sprintf(notDeepExcluded, a.label()), maxLineText)})
			continue
		}
		if s.cfg.DomainFence == nil && !a.box {
			fence = append(fence, a.ip.String())
			state[a.ip.String()] = HostIP{Deep: DeepFence}
			continue
		}
		queue = append(queue, a)
	}
	if len(addrs) == 0 {
		lines = append(lines, NotCheckedRow{Kind: "deep", Text: notDeepNone})
	}
	if len(fence) > 0 {
		lines = append(lines, NotCheckedRow{Kind: "deep", Text: clipText(fmt.Sprintf(notDeepFence, strings.Join(fence, ", ")), maxLineText)})
	}
	var scanned []deepAddr
	took, refused, waiting := 0, 0, 0
	for _, a := range queue {
		if took >= MaxDeepIPs || refused >= maxDeepRefusals {
			waiting++
			state[a.ip.String()] = HostIP{Deep: DeepWaiting, NextInLine: waiting}
			if waiting <= maxCapLines {
				when := "never scanned at depth"
				if t, err := parseTS(a.last); err == nil {
					when = "last scanned at depth " + s.momentText(t)
				}
				lines = append(lines, NotCheckedRow{Kind: "deep", Text: clipText(fmt.Sprintf(notDeepCap, a.label(), MaxDeepIPs, when, waiting), maxLineText)})
			}
			continue
		}
		key, nc, nn := addressKey(a.ip.String()), len(c.Checks), len(c.NotChecked)
		rs.add(ctx, stepDef{key, "Deep scan of " + a.label()})
		rs.start(ctx, key)
		got, err := s.deepIP(withinAddress(ctx, rs, key), deepMode(st, a), a, &c)
		if err != nil {
			return c, scanned, err // the run ends the step: stopped, or failed
		}
		if why := s.observerOf(ctx).sweepCut(a.ip.String()); why != "" && got == DeepScanned { // its sweep did not see everything it probed
			rs.incompleteOn(key, why)
			rs.problem(clipText(a.label()+": "+why, maxLineText))
		}
		addressStepEnd(ctx, rs, key, a.label(), got, c.Checks[nc:], c.NotChecked[nn:])
		switch got {
		case DeepRefused: // nothing was sent: it does not take a place
			refused++
			state[a.ip.String()] = HostIP{Deep: DeepRefused, LastTried: now}
		case DeepIncomplete: // nmap did not finish: not "scanned", its earlier ports stay kept, back in line
			took++
			state[a.ip.String()] = HostIP{Deep: DeepIncomplete, LastTried: now}
		default:
			took++
			lastDeep := now
			if src := s.observerOf(ctx).reusedOf(a.ip.String()); src != nil { // its address-level layer is as old as the run it came from
				lastDeep = store.FormatTS(src.started)
			}
			state[a.ip.String()] = HostIP{Deep: DeepScanned, LastDeep: lastDeep, LastTried: now}
			scanned = append(scanned, a)
		}
		if !a.inZone && st.Mode.Disruptive {
			lines = append(lines, NotCheckedRow{Kind: "deep", Text: clipText(fmt.Sprintf(notDeepOutside, a.label()), maxLineText)})
		}
	}
	if waiting > maxCapLines {
		lines = append(lines, NotCheckedRow{Kind: "deep", Text: fmt.Sprintf(notDeepCapMore, plural(waiting-maxCapLines, "more address"), MaxDeepIPs)})
	}
	if waiting > 0 {
		rs.add(ctx, stepDef{stepKeyWaiting, stepNameWaiting})
		rs.skip(ctx, stepKeyWaiting, fmt.Sprintf("%s wait for the next scans: one scan deep-scans at most %d addresses, those scanned longest ago first.",
			nouns(waiting, "address", "addresses"), MaxDeepIPs))
	}
	if len(queue) == 0 {
		noAddressStep(ctx, firstNotChecked(Content{NotChecked: lines}, notDeepNone, "deep"))
	}
	if private > 0 {
		lines = append(lines, NotCheckedRow{Kind: "deep", Text: fmt.Sprintf(notDeepPrivate, plural(private, "address"))})
	}
	for i, h := range c.Hosts {
		for j, a := range h.IPs {
			ip, err := netip.ParseAddr(a.IP)
			if err != nil || !ip.Unmap().Is4() {
				continue
			}
			k := ip.Unmap().String()
			v := state[k]
			c.Hosts[i].IPs[j].Deep, c.Hosts[i].IPs[j].NextInLine = v.Deep, v.NextInLine
			c.Hosts[i].IPs[j].LastDeep = cmp.Or(v.LastDeep, last[k])
			c.Hosts[i].IPs[j].LastTried = cmp.Or(v.LastTried, tried[k])
		}
	}
	c.NotChecked = append(c.NotChecked, lines...)
	return c, scanned, nil
}

// addressStepEnd ends the step of one of a domain's addresses by what its deep scan did, with the line it added (checks, not: the
// lines of this address), without the address in front that the step's name already says.
func addressStepEnd(ctx context.Context, rs *runSteps, key, label, got string, checks []CheckRow, not []NotCheckedRow) {
	own := func(text string) string { return strings.TrimPrefix(text, label+": ") }
	last := func(or string, kinds ...string) string {
		for i := len(not) - 1; i >= 0; i-- {
			if slices.Contains(kinds, not[i].Kind) {
				return own(not[i].Text)
			}
		}
		return or
	}
	switch got {
	case DeepRefused:
		rs.skip(ctx, key, last("Not scanned at depth: the re-check right before refused it.", "deep"))
	case DeepIncomplete:
		rs.end(ctx, key, corerun.Partial, last(deepNoNmap, "services", "deep"))
	default:
		note := "Services identified and templates run."
		for _, r := range checks {
			if r.Kind == "services" {
				note = own(r.Text)
			}
		}
		rs.end(ctx, key, corerun.Done, note)
	}
}

// noAddressStep is the one step of a domain's deep scan that reached no address: skipped, with why.
func noAddressStep(ctx context.Context, why string) {
	rs := runStepsOf(ctx)
	rs.add(ctx, stepDef{addressKey("none"), "Deep scan of the names' addresses"})
	rs.skip(ctx, addressKey("none"), why)
}

// deepMode is the run's ScanTarget for one address: an address reached only through a name that points (CNAME) outside the domain
// never gets the disruptive checks, whatever the terms: the owner of that other name chooses the address.
func deepMode(st ScanTarget, a deepAddr) ScanTarget {
	if !a.inZone {
		st.Mode = st.Mode.withoutDisruptive()
	}
	return st
}

// deepIP is the deep scan of one address: the re-check, then service identification and the templates (identifyIP, with the
// scope; the templates re-check on their own). What the steps found is added to c, each line with the address and its names in front.
// It says what happened: DeepRefused (the re-check refused it before anything was sent), DeepIncomplete (service identification did
// not finish, so nothing is known of its ports) or DeepScanned. Only a stop of the run returns an error.
func (s *Service) deepIP(ctx context.Context, st ScanTarget, a deepAddr, c *Content) (string, error) {
	label := a.label()
	stD, line, err := s.deepGate(ctx, st, a.ip, a.names)
	if err != nil {
		return DeepRefused, err
	}
	if line != "" {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: clipText(label+": not scanned at depth: "+line, maxLineText)})
		return DeepRefused, nil
	}
	if extra := slices.DeleteFunc(slices.Clone(stD.SkipPorts), st.Skips); len(extra) > 0 { // the address's IP target skips more
		s.observerOf(ctx).noteSkipped(a.ip.String(), extra)
		c.Ports = slices.DeleteFunc(c.Ports, func(p PortRow) bool { return ipKey(p.IP) == a.ip.String() && stD.Skips(p.Port) })
		c.AdminPanels = slices.DeleteFunc(c.AdminPanels, func(p AdminRow) bool { return ipKey(p.IP) == a.ip.String() && stD.Skips(p.Port) })
	}
	sub := Content{}
	for _, p := range c.Ports {
		if ipKey(p.IP) == a.ip.String() {
			sub.Ports = append(sub.Ports, p)
		}
	}
	switch stD.dropped { // the run allowed the disruptive checks; this address does not get them
	case dropNotOwn:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: clipText(label+": "+notDeepNotOwn, maxLineText)})
	case dropCNAME: // r2-M1: the CNAME re-check could not confirm the name stays in the domain
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: clipText(fmt.Sprintf(notDeepNoCNAME, label), maxLineText)})
	case dropNAT:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: clipText(label+": "+notDeepNAT, maxLineText)})
	}
	how := "this box's own verified IP"
	if stD.Domain != nil {
		how = "through the domain fence, name " + stD.Domain.Name
	}
	// INV-47: a fresh deep scan of the address itself at an equal or wider scope gives the address-level layer; the web layer runs here
	if src, why := s.reuseFor(ctx, st, stD, a, sub.Ports); src != nil {
		return s.reuseIP(ctx, stD, a, src, sub, how, c)
	} else if why != "" {
		s.cfg.Log.InfoContext(ctx, "exposure: a domain's address is scanned, not reused", "target", st.Value, "ip", a.ip, "why", why)
	}
	sub.Checks = append(sub.Checks, CheckRow{Kind: "deep", At: store.FormatTS(s.clock()), Text: "deep scan at the testing terms depth (" + how + ")."})
	if sub, err = s.identifyIP(ctx, stD, a.ip, sub); err != nil {
		return DeepIncomplete, err
	}
	mergeAddress(c, sub, label, a.ip.String())
	// "scanned" only when nmap -sV really ran on the address (its Checked line); otherwise nothing is known of its ports
	if !slices.ContainsFunc(sub.Checks, func(r CheckRow) bool { return r.Kind == "services" }) {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: clipText(label+": "+deepNoNmap, maxLineText)})
		return DeepIncomplete, nil
	}
	return DeepScanned, nil
}

// greenboneDomain is OpenVAS on the addresses a domain's deep scan reached this run, one after the other, after the snapshot of
// the other steps is stored: each re-checked right before (deepGate), then greenboneAt. Their outcomes are one, each line with the
// address in front; each checks the ports this run found open on its address. Their state is the strongest of theirs
// (gbRunOf). Only a stop of the run returns an error, with what was done before it.
func (s *Service) greenboneDomain(ctx context.Context, st ScanTarget, addrs []deepAddr, ports []PortRow) (out gbOutcome, err error) {
	var audits, states []string
	defer func() { // Each address's state; one the stop never reached did not run
		for _, a := range addrs[len(out.addrs):] {
			out.addrs = append(out.addrs, GreenboneAddr{IP: a.ip.String(), State: GBRunNotRun})
		}
		out.state = gbRunOf(states)
	}()
	merge := func(a deepAddr, o gbOutcome) {
		states = append(states, o.state)
		out.addrs = append(out.addrs, GreenboneAddr{IP: a.ip.String(), State: o.state})
		out.rows = append(out.rows, o.rows...)
		out.checks = append(out.checks, o.checks...)
		for _, n := range o.not {
			n.Text = clipText(a.label()+": "+n.Text, maxLineText)
			out.not = append(out.not, n)
		}
		for _, m := range o.missed {
			out.missed = append(out.missed, clipText(a.label()+": "+m, maxLineText))
		}
		if o.audit != "" {
			audits = append(audits, a.ip.String()+": "+o.audit)
		}
		out.audit = strings.Join(audits, "; ")
	}
	for _, a := range addrs {
		stD, line, err := s.deepGate(ctx, deepMode(st, a), a.ip, a.names)
		if err != nil {
			out.audit = strings.Join(append(audits, a.ip.String()+": stopped"), "; ")
			states = append(states, GBRunStopped)
			out.addrs = append(out.addrs, GreenboneAddr{IP: a.ip.String(), State: GBRunStopped})
			return out, err
		}
		if line != "" {
			merge(a, gbOutcome{not: []NotCheckedRow{{Kind: "greenbone", Text: "OpenVAS did not scan: " + line}}, audit: "not done: the re-check refused it", state: GBRunNotRun})
			continue
		}
		if src := s.observerOf(ctx).reusedOf(a.ip.String()); src != nil && src.openVAS { // INV-47: its results came with the address's own deep scan
			merge(a, gbOutcome{not: []NotCheckedRow{{Kind: "greenbone", Text: "OpenVAS did not scan again: " + s.reuseLine(src) + "."}}, audit: "reused from run " + src.runID, state: GBRunNotRun})
			continue
		}
		o, err := s.greenboneAt(ctx, stD, a.ip, gbPorts(ports, a.ip, stD.SkipPorts))
		merge(a, o)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

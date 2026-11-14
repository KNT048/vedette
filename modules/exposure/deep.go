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

	"github.com/knt048/vedette/core/store"
)

// The deep scan of each address a verified domain's names resolve to, at the domain's testing terms depth (FULL-5 slice 3, D-571,
// INV-27 depth; kien 2026-11-14: one rule for every name, whatever serves it; LEGAL-2: the terms say a provider's permission is the
// customer's to have). Without accepted terms nothing here runs: the K-4 scope stays as it was. With them, each public IPv4 address
// gets what the box's own IP gets (all TCP ports and nmap -sV with its scripts, the comparison with exploited CVEs, nuclei, then
// OpenVAS when it is on), through the seams that already exist, with the run's Mode. The web scan by name stays the by-name passive
// pass (INV-24) until the active ZAP scan exists (FULL-3): a second passive run of the same pages would only repeat it (review r1 M1).
// Many names on one address are one deep address. At most MaxDeepIPs addresses a run get the steps, the least recently tried first;
// an address the re-check refuses does not take a place (at most maxDeepRefusals a run); the rest wait their turn and say so. An
// address reached only through a name that points (CNAME) outside the domain never gets the disruptive checks (review r1 M4): the
// owner of that other name chooses the address.
//
// The fence (plan 2026-11-14 §5): an address that is the box's own verified IP (ScannableIP) takes the box's pipeline and its fences.
// Any other address needs Config.DomainFence: without it nothing beyond the by-name checks goes there. With it, right before each step
// core checks again (deepGate) that the address is a public IPv4, that the domain is verified and its terms accepted now, and that a
// name under the domain still resolves to it, and hands the step the domain's scope with the box-bound token (ScanTarget.Domain),
// which the executors check on their own.

// Caps of a domain's deep scan per run (plan 2026-11-14 §4).
const (
	// MaxDeepIPs is the most addresses that get the deep scan in one run (port scan, nmap -sV, nuclei, OpenVAS).
	MaxDeepIPs = 3
	// maxDeepRefusals is the most addresses the re-check may refuse in one run before the rest wait for the next run (review r1 M3):
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
	// is known of its ports, so it is not "scanned", its earlier ports are kept unchecked (INV-22) and it goes back in line (review r1 M2).
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

	deepNotPublic  = "it is not a public IPv4 address, so nothing was sent."
	deepTerms      = "the testing terms of this domain are no longer accepted (withdrawn, or new terms to accept), so nothing was sent."
	deepGone       = "this domain can no longer be scanned (its TXT record is gone, or it was removed, paused or needs the scan confirmed again), so nothing was sent."
	deepNotBox     = "this address is no longer this box's own verified IP, so nothing was sent."
	deepUnchecked  = "the box could not check this domain's ownership, its testing terms or this box's own address right now, so nothing was sent."
	deepNoFence    = "this box needs the Vedette host's domain fence (update the box), so nothing was sent."
	deepNoLookup   = "the box cannot look up names to check that one still resolves to this address, so nothing was sent."
	deepMoved      = "no name under this domain resolves to this address any more (looked up right before the step), so nothing was sent."
	deepNoAnswer   = "the DNS resolver did not answer the check that a name still resolves to this address, so nothing was sent."
	deepFenceDown  = "the Vedette host did not give this domain's fence token, so nothing was sent."
	deepNoNmap     = "service identification did not finish, so its ports are not known this run: it goes back in line."
	notDeepOutside = "%s: reached only through a name that points (CNAME) outside this domain, so the disruptive checks were not run there."
)

var fenceTokenRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// deepAddr is one public IPv4 address of a domain's names: the names that led to it (sorted), whether the runner saw it as the box's
// own (a hint for the order and the fence line only: deepGate decides), when it was last deep-scanned and last tried ("" never), and
// whether a name that led to it stays inside the domain (no CNAME, or a CNAME to a name under the domain; review r1 M4).
type deepAddr struct {
	ip     netip.Addr
	names  []string
	box    bool
	last   string
	tried  string
	inZone bool
}

// turn is when the address last had its turn: the later of its last deep scan and its last try (one time format: strings sort as
// times), so a refused or incomplete address goes to the back of the line too (review r1 M3).
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

// deepGate is the core half of the domain fence (D-571, plan 2026-11-14 §5), right before each deep step to ip: ip is a public IPv4;
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
	t, reason, err := s.gate(ctx, st.User, st.ID) // ModeNow's own reading, with the reason kept apart (review r1 L4)
	switch {
	case ctx.Err() != nil:
		return st, "", ctx.Err()
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: reading the terms before a deep step failed", "target", st.Value, "ip", ip, "error", err)
		return st, deepUnchecked, nil
	case reason != "":
		return st, deepGone, nil
	}
	m := t.mode()
	if !m.Full {
		return st, deepTerms, nil
	}
	out := st
	out.Mode, out.Domain = ScanMode{Full: true, Disruptive: m.Disruptive && st.Mode.Disruptive}, nil
	box, err := s.ScannableIP(ctx, st.User, ip)
	switch {
	case ctx.Err() != nil:
		return st, "", ctx.Err()
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: checking whether a domain's address is the box's own failed", "target", st.Value, "ip", ip, "error", err)
		return st, deepUnchecked, nil
	case box:
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
		if !underDomain(n, st.Value) {
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
	tok, err := s.cfg.DomainFence.Token(ctx, st.Value)
	if ctx.Err() != nil {
		return st, "", ctx.Err()
	}
	if err != nil || !fenceTokenRE.MatchString(tok) {
		s.cfg.Log.ErrorContext(ctx, "exposure: the domain fence gave no token", "target", st.Value, "error", err)
		return st, deepFenceDown, nil
	}
	out.Domain = &DomainScope{Domain: st.Value, Name: name, Token: tok}
	return out, "", nil
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
// gave without kinds (a row older than D-567) is a candidate too: deepGate decides what it is.
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

// deepDomain is the deep scan of a domain whose testing terms are accepted (D-571), after its by-name checks and before the snapshot is
// stored: the addresses in turn (deepCandidates), each through deepIP, until MaxDeepIPs got the steps or maxDeepRefusals were refused;
// the others are marked and get their lines. It returns the addresses whose service identification finished, for OpenVAS after the
// snapshot is stored. Only a stop of the run ends it with an error.
func (s *Service) deepDomain(ctx context.Context, st ScanTarget, c Content) (Content, []deepAddr, error) {
	prev, ok, err := previousSnapshot(ctx, s.cfg.DB.Reader(), st.ID, s.clock().In(s.cfg.Location).Format(dayFormat))
	if err != nil {
		return c, nil, err
	}
	last, tried := map[string]string{}, map[string]string{}
	if ok {
		for _, h := range prev.Hosts {
			for _, a := range h.IPs {
				k := ipKey(a.IP)
				last[k] = max(last[k], a.LastDeep) // one fixed time format (store.FormatTS): the strings sort as times
				tried[k] = max(tried[k], a.LastTried)
			}
		}
	}
	addrs, private := deepCandidates(c.Hosts, st.Value, last, tried)
	var lines []NotCheckedRow
	state := map[string]HostIP{}
	var fence []string
	var queue []deepAddr
	for _, a := range addrs {
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
	now := store.FormatTS(s.clock())
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
		got, err := s.deepIP(ctx, deepMode(st, a), a, &c)
		if err != nil {
			return c, scanned, err
		}
		switch got {
		case DeepRefused: // nothing was sent: it does not take a place (review r1 M3)
			refused++
			state[a.ip.String()] = HostIP{Deep: DeepRefused, LastTried: now}
		case DeepIncomplete: // review r1 M2: nmap did not finish: not "scanned", its earlier ports stay kept, back in line
			took++
			state[a.ip.String()] = HostIP{Deep: DeepIncomplete, LastTried: now}
		default:
			took++
			state[a.ip.String()] = HostIP{Deep: DeepScanned, LastDeep: now, LastTried: now}
			scanned = append(scanned, a)
		}
		if !a.inZone && st.Mode.Disruptive {
			lines = append(lines, NotCheckedRow{Kind: "deep", Text: clipText(fmt.Sprintf(notDeepOutside, a.label()), maxLineText)})
		}
	}
	if waiting > maxCapLines {
		lines = append(lines, NotCheckedRow{Kind: "deep", Text: fmt.Sprintf(notDeepCapMore, plural(waiting-maxCapLines, "more address"), MaxDeepIPs)})
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

// deepMode is the run's ScanTarget for one address: an address reached only through a name that points (CNAME) outside the domain
// never gets the disruptive checks, whatever the tick (review r1 M4): the owner of that other name chooses the address.
func deepMode(st ScanTarget, a deepAddr) ScanTarget {
	if !a.inZone {
		st.Mode.Disruptive = false
	}
	return st
}

// deepIP is the deep scan of one address (D-571): the re-check, then service identification and the templates (identifyIP, with the
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
	sub := Content{}
	for _, p := range c.Ports {
		if ipKey(p.IP) == a.ip.String() {
			sub.Ports = append(sub.Ports, p)
		}
	}
	how := "this box's own verified IP"
	if stD.Domain != nil {
		how = "through the domain fence, name " + stD.Domain.Name
	}
	sub.Checks = append(sub.Checks, CheckRow{Kind: "deep", At: store.FormatTS(s.clock()), Text: "deep scan at the testing terms depth (" + how + ")."})
	if sub, err = s.identifyIP(ctx, stD, a.ip, sub); err != nil {
		return DeepIncomplete, err
	}
	have := map[string]bool{}
	for _, p := range c.Ports {
		have[fmt.Sprintf("%s:%d", ipKey(p.IP), p.Port)] = true
	}
	for _, r := range sub.Services { // an open port the deep scan found is an open port of the domain (counts, the day diff, INV-22)
		if k := fmt.Sprintf("%s:%d", r.IP, r.Port); !have[k] && r.IP == a.ip.String() {
			have[k] = true
			c.Ports = append(c.Ports, PortRow{IP: r.IP, Port: r.Port, Service: r.Name, Product: strings.TrimSpace(r.Product + " " + r.Version)})
		}
	}
	c.Services = append(c.Services, sub.Services...)
	c.Scripts = append(c.Scripts, sub.Scripts...)
	c.Templates = append(c.Templates, sub.Templates...)
	for _, r := range sub.Checks {
		r.Text = clipText(label+": "+r.Text, maxLineText)
		c.Checks = append(c.Checks, r)
	}
	for _, r := range sub.NotChecked {
		r.Text = clipText(label+": "+r.Text, maxLineText)
		c.NotChecked = append(c.NotChecked, r)
	}
	// review r1 M2: "scanned" only when nmap -sV really ran on the address (its Checked line); otherwise nothing is known of its ports
	if !slices.ContainsFunc(sub.Checks, func(r CheckRow) bool { return r.Kind == "services" }) {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "deep", Text: clipText(label+": "+deepNoNmap, maxLineText)})
		return DeepIncomplete, nil
	}
	return DeepScanned, nil
}

// greenboneDomain is OpenVAS on the addresses a domain's deep scan reached this run (D-571), one after the other, after the snapshot of
// the other steps is stored: each re-checked right before (deepGate), then greenboneAt. Their outcomes are one, each line with the
// address in front. Only a stop of the run returns an error, with what was done before it.
func (s *Service) greenboneDomain(ctx context.Context, st ScanTarget, addrs []deepAddr) (gbOutcome, error) {
	var out gbOutcome
	var audits []string
	merge := func(a deepAddr, o gbOutcome) {
		out.rows = append(out.rows, o.rows...)
		out.checks = append(out.checks, o.checks...)
		for _, n := range o.not {
			n.Text = clipText(a.label()+": "+n.Text, maxLineText)
			out.not = append(out.not, n)
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
			return out, err
		}
		if line != "" {
			merge(a, gbOutcome{not: []NotCheckedRow{{Kind: "greenbone", Text: "OpenVAS did not scan: " + line}}, audit: "not done: the re-check refused it"})
			continue
		}
		o, err := s.greenboneAt(ctx, stD, a.ip)
		merge(a, o)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

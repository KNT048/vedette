package surface

import (
	"context"
	"crypto/rand"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/content/wordlist"
)

// Discovery of a verified domain's names beyond certificate transparency (D-567 (1), exposure INV-27). Every lookup goes through the
// box's own resolver (Config.Resolver: the system resolver), so nothing new leaves the box but ordinary DNS queries: A, AAAA and the
// final CNAME of each name, the apex's MX and NS, a wildcard check and the common names of content/wordlist. No zone
// transfer, no NSEC walking, no passive-DNS service. DNS answers are untrusted (SYS-6): names are kept only when they pass nameRE,
// and every list is clipped.
const (
	maxAddrs      = 16               // addresses kept per name (IPv4 first); a bigger answer is clipped
	maxMailNS     = 10               // MX and NS hosts kept each
	labelEvery    = time.Second / 20 // the wordlist: at most 20 lookups a second (D-567 (1))
	wildcardLabel = 20               // characters of each random label of the wildcard check
)

// The kinds of a name's address (exposure INV-27, kien 2026-11-14: whatever serves a name, a CDN or not, does not matter): box is
// this box's own verified, current IP (exposure's ScannableIP); public any other public address; private an address that is not
// public, never dialed.
const (
	ClassBox     = "box"
	ClassPublic  = "public"
	ClassPrivate = "private"
)

// Where a name was found.
const (
	SourceCT       = "ct"       // a certificate-transparency log (crt.sh)
	SourceDNS      = "dns"      // the domain itself
	SourceMX       = "mx"       // a mail host of the apex, under the domain
	SourceNS       = "ns"       // a name server of the apex, under the domain
	SourceWordlist = "wordlist" // a common name that resolves
)

// Addr is one address of a name with its kind (ClassBox, ClassPublic or ClassPrivate).
type Addr struct {
	IP    netip.Addr
	Class string
}

// dnsAnswer is what the resolver said about one name.
type dnsAnswer struct {
	addrs []netip.Addr
	cname string
}

// discovery is the list of a domain's names before classification.
type discovery struct {
	names   []string // the domain first, the others sorted
	source  map[string]string
	answers map[string]dnsAnswer
	skipped bool // the wordlist was skipped: the domain answers any name (wildcard DNS)
}

// discover adds the apex's MX and NS hosts under the domain (one outside it is another company's server: not listed) and the common names to the names from CT, and resolves them all. More than maxNames names
// in all is ErrTooManyNames: the listing is whole or nothing (D-229 (6)).
func (s *Scanner) discover(ctx context.Context, domain string, ct []string) (discovery, error) {
	d := discovery{source: map[string]string{}, answers: map[string]dnsAnswer{}}
	add := func(n, src string) {
		if _, ok := d.source[n]; !ok {
			d.source[n] = src
			d.names = append(d.names, n)
		}
	}
	for _, n := range ct {
		add(n, SourceCT)
	}
	add(domain, SourceDNS)
	d.source[domain] = SourceDNS // the domain itself, whether or not a certificate names it
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	mx, _ := s.resolve.LookupMX(rctx, domain)
	cancel()
	rctx, cancel = context.WithTimeout(ctx, resolveTimeout)
	ns, _ := s.resolve.LookupNS(rctx, domain)
	cancel()
	hosts := func(kind string, raw []string) {
		for _, h := range raw[:min(len(raw), maxMailNS)] {
			h = cleanName(h)
			if h != "" && (h == domain || strings.HasSuffix(h, "."+domain)) {
				add(h, kind)
			}
		}
	}
	mxHosts := make([]string, 0, len(mx))
	for _, m := range mx {
		if m != nil {
			mxHosts = append(mxHosts, m.Host)
		}
	}
	nsHosts := make([]string, 0, len(ns))
	for _, n := range ns {
		if n != nil {
			nsHosts = append(nsHosts, n.Host)
		}
	}
	hosts(SourceMX, mxHosts)
	hosts(SourceNS, nsHosts)
	if s.wildcard(ctx, domain) {
		d.skipped = true
	} else {
		var tries []string
		for _, l := range wordlist.Labels() {
			if n := l + "." + domain; len(n) <= 253 && d.source[n] == "" {
				tries = append(tries, n)
			}
		}
		for n, a := range s.lookupAll(ctx, tries, labelEvery, false) {
			if len(a.addrs) > 0 {
				add(n, SourceWordlist)
				d.answers[n] = a
			}
		}
	}
	if len(d.names) > maxNames {
		return discovery{}, ErrTooManyNames
	}
	var rest []string
	for _, n := range d.names {
		if _, done := d.answers[n]; !done {
			rest = append(rest, n)
		}
	}
	for n, a := range s.lookupAll(ctx, rest, 0, true) {
		d.answers[n] = a
	}
	for n, a := range d.answers { // the wordlist asked addresses only: its names get their CNAME here
		if d.source[n] == SourceWordlist {
			a.cname = s.cname(ctx, n)
			d.answers[n] = a
		}
	}
	d.names = slices.DeleteFunc(d.names, func(n string) bool { return n == domain })
	slices.Sort(d.names)
	d.names = append([]string{domain}, d.names...)
	return d, ctx.Err()
}

// wildcard says the domain answers names that cannot exist: two random labels, either one resolving means wildcard DNS, so the
// wordlist would find every label (D-567 (1)).
func (s *Scanner) wildcard(ctx context.Context, domain string) bool {
	for range 2 {
		n := randomLabel() + "." + domain
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		a, err := s.resolve.LookupNetIP(rctx, "ip", n)
		cancel()
		if err == nil && len(a) > 0 {
			return true
		}
	}
	return false
}

func randomLabel() string {
	const set = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, wildcardLabel)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	for i := range b {
		b[i] = set[int(b[i])%len(set)]
	}
	return "vedette-" + string(b)
}

// lookupAll looks up the IPv4 and IPv6 addresses of every name (and, with withCNAME, its final CNAME), a few at a time and, with
// every > 0, at most one start per tick. A name that does not resolve has no addresses.
func (s *Scanner) lookupAll(ctx context.Context, names []string, every time.Duration, withCNAME bool) map[string]dnsAnswer {
	out := make(map[string]dnsAnswer, len(names))
	var mu sync.Mutex
	sem := make(chan struct{}, resolveParallel)
	var tick <-chan time.Time
	if every > 0 {
		t := time.NewTicker(every)
		defer t.Stop()
		tick = t.C
	}
	var wg sync.WaitGroup
loop:
	for _, n := range names {
		if tick != nil {
			select {
			case <-ctx.Done():
				break loop
			case <-tick:
			}
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			a := dnsAnswer{addrs: s.addrs(ctx, n)}
			if withCNAME {
				a.cname = s.cname(ctx, n)
			}
			mu.Lock()
			out[n] = a
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// addrs returns a name's addresses, IPv4 first, each family sorted (so the first IPv4 is stable from one scan to the next), at most
// maxAddrs.
func (s *Scanner) addrs(ctx context.Context, n string) []netip.Addr {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	a, err := s.resolve.LookupNetIP(rctx, "ip", n)
	if err != nil {
		return nil
	}
	for i := range a {
		a[i] = a[i].Unmap()
	}
	a = slices.DeleteFunc(a, func(x netip.Addr) bool { return !x.IsValid() })
	slices.SortFunc(a, func(x, y netip.Addr) int {
		if x.Is4() != y.Is4() {
			if x.Is4() {
				return -1
			}
			return 1
		}
		return x.Compare(y)
	})
	a = slices.Compact(a)
	return a[:min(len(a), maxAddrs)]
}

// cname returns the final canonical name of n, or "" when it has none (the resolver answers the name itself) or the answer is not a
// host name.
func (s *Scanner) cname(ctx context.Context, n string) string {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	c, err := s.resolve.LookupCNAME(rctx, n)
	if err != nil {
		return ""
	}
	if c = cleanName(c); c == n {
		return ""
	}
	return c
}

// cleanName is a host name from a DNS answer, lower case without the final dot, or "" when it is not a plain host name.
func cleanName(h string) string {
	if len(h) > 254 {
		return ""
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if len(h) > 253 || !nameRE.MatchString(h) {
		return ""
	}
	return h
}

// publicV6 is an IPv6 address on the Internet: global unicast, not unique-local, not the documentation range. IPv6 is listed, never
// dialed (exposure INV-27).
func publicV6(a netip.Addr) bool {
	return a.Is6() && a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("2001:db8::/32").Contains(a)
}

// classify gives each address of a name its kind: private when it is not public (never dialed), box when it is one the caller may
// port-scan (exposure's ScannableIP), public otherwise.
func (s *Scanner) classify(addrs []netip.Addr, box map[netip.Addr]bool) []Addr {
	out := make([]Addr, 0, len(addrs))
	for _, ip := range addrs {
		a := Addr{IP: ip, Class: ClassPublic}
		switch {
		case ip.Is4() && !s.public(ip), !ip.Is4() && !publicV6(ip):
			a.Class = ClassPrivate
		case box[ip]:
			a.Class = ClassBox
		}
		out = append(out, a)
	}
	return out
}

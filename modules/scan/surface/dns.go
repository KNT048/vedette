package surface

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/content/wordlist"
)

// Discovery of a verified domain's names beyond certificate transparency (D-567 (1), exposure INV-27). Every lookup goes through the
// box's own resolver (Config.Resolver: the system resolver), so nothing new leaves the box but ordinary DNS queries: A, AAAA and the
// final CNAME of each name, the apex's MX and NS, a wildcard check and the common names of content/wordlist. Names are asked fully
// qualified (a final dot), so the resolver's search list never applies. No zone transfer, no NSEC walking, no passive-DNS service.
// DNS answers are untrusted (SYS-6): names are kept only when they pass nameRE, and every list is clipped.
//
// Time: the whole DNS phase has dnsBudget (MX and NS and the wildcard check in parallel, ≤ 5 s each; up to maxNames names, 32 at a
// time, addresses and CNAME of a name in parallel, ≤ 5 s: 10 rounds, ≤ 50 s; the common names with what is left, 8 at a time and
// at most 20 a second). What it did not reach is said, never guessed: a name whose lookup did not answer is left out (its earlier
// state is kept, exposure INV-22) and counted; a wordlist cut short says so.
const (
	maxAddrs      = 16               // addresses kept per name (IPv4 first); a bigger answer is clipped
	maxMailNS     = 10               // MX and NS hosts kept each
	labelEvery    = time.Second / 20 // the wordlist: at most 20 lookups a second (D-567 (1))
	labelParallel = 8                // the wordlist: lookups at once
	wildcardLabel = 20               // characters of each random label of the wildcard check
	dnsBudget     = 60 * time.Second // the whole DNS phase of a domain scan
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

// Why the common names were not all tried (Result.Wordlist); "" when they were.
const (
	WordlistWildcard = "wildcard"  // the domain answers any name
	WordlistNoAnswer = "no_answer" // the wildcard check got no clear answer (time-out, server failure): skipped, fail closed
	WordlistCut      = "cut"       // the DNS phase reached dnsBudget before every common name was tried
)

// Addr is one address of a name with its kind (ClassBox, ClassPublic or ClassPrivate). Contacted: the D-229 check by name (GET / on 80
// and 443) went to this address, the name's first public IPv4.
type Addr struct {
	IP        netip.Addr
	Class     string
	Contacted bool
}

// dnsAnswer is what the resolver said about one name. failed: the address lookup gave no clear answer (time-out, server failure, or
// not asked before the budget ran out), as opposed to "no such name" or "no address".
type dnsAnswer struct {
	addrs  []netip.Addr
	cname  string
	failed bool
}

// discovery is the list of a domain's names before classification.
type discovery struct {
	names    []string // the domain first, the others sorted
	source   map[string]string
	answers  map[string]dnsAnswer
	wordlist string // "" or why the common names were not all tried
}

// rooted is a name as asked: fully qualified, so the resolver's search list never applies.
func rooted(n string) string { return n + "." }

// isNotFound says a lookup answered "no such name" (or no record of the type), as opposed to failing.
func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// discover adds the apex's MX and NS hosts under the domain (one outside it is another company's server: not listed) and the common
// names to the names from CT, and resolves them all, within dnsBudget. More than maxNames names in all is ErrTooManyNames: the
// listing is whole or nothing (D-229 (6)).
func (s *Scanner) discover(ctx context.Context, domain string, ct []string) (discovery, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsBudget)
	defer cancel()
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
	var mx, ns []string
	wild := ""
	var wg sync.WaitGroup
	wg.Go(func() { mx = s.mailNS(ctx, domain, true) })
	wg.Go(func() { ns = s.mailNS(ctx, domain, false) })
	wg.Go(func() { wild = s.wildcard(ctx, domain) })
	wg.Wait()
	for _, h := range mx {
		add(h, SourceMX)
	}
	for _, h := range ns {
		add(h, SourceNS)
	}
	for n, a := range s.lookupAll(ctx, d.names, resolveParallel, 0) {
		d.answers[n] = a
	}
	d.wordlist = wild
	if wild == "" {
		var tries []string
		for _, l := range wordlist.Labels() {
			if n := l + "." + domain; len(n) <= 253 && d.source[n] == "" {
				tries = append(tries, n)
			}
		}
		for n, a := range s.lookupAll(ctx, tries, labelParallel, labelEvery) {
			switch {
			case a.failed:
				d.wordlist = WordlistCut // not every common name got an answer: the list is not complete
			case len(a.addrs) > 0:
				add(n, SourceWordlist)
				d.answers[n] = a
			}
		}
	}
	if len(d.names) > maxNames {
		return discovery{}, ErrTooManyNames
	}
	d.names = slices.DeleteFunc(d.names, func(n string) bool { return n == domain })
	slices.Sort(d.names)
	d.names = append([]string{domain}, d.names...)
	return d, nil
}

// mailNS returns the apex's MX (mx) or NS hosts that are the domain or under it, at most maxMailNS read, each a valid host name.
func (s *Scanner) mailNS(ctx context.Context, domain string, mx bool) []string {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	var raw []string
	if mx {
		rs, _ := s.resolve.LookupMX(rctx, rooted(domain))
		for _, r := range rs {
			if r != nil {
				raw = append(raw, r.Host)
			}
		}
	} else {
		rs, _ := s.resolve.LookupNS(rctx, rooted(domain))
		for _, r := range rs {
			if r != nil {
				raw = append(raw, r.Host)
			}
		}
	}
	var out []string
	for _, h := range raw[:min(len(raw), maxMailNS)] {
		if h = cleanName(h); h != "" && (h == domain || strings.HasSuffix(h, "."+domain)) {
			out = append(out, h)
		}
	}
	return out
}

// wildcard asks two random names under the domain, in parallel. Only "no such name" for both means the domain does not answer any
// name; an address means wildcard DNS; anything else (time-out, server failure) is no clear answer, and the wordlist is skipped too
// (fail closed: a wildcard missed would list every common name).
func (s *Scanner) wildcard(ctx context.Context, domain string) string {
	var mu sync.Mutex
	var why string
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
			defer cancel()
			a, err := s.resolve.LookupNetIP(rctx, "ip", rooted(randomLabel()+"."+domain))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && len(a) > 0:
				why = WordlistWildcard
			case err != nil && !isNotFound(err) && why == "":
				why = WordlistNoAnswer
			}
		})
	}
	wg.Wait()
	return why
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

// lookupAll looks up the addresses and the final CNAME of every name (both at once), parallel at a time and, with every > 0, at
// most one start per tick. A name not reached before ctx ends is failed.
func (s *Scanner) lookupAll(ctx context.Context, names []string, parallel int, every time.Duration) map[string]dnsAnswer {
	out := make(map[string]dnsAnswer, len(names))
	var mu sync.Mutex
	sem := make(chan struct{}, parallel)
	var tick <-chan time.Time
	if every > 0 {
		t := time.NewTicker(every)
		defer t.Stop()
		tick = t.C
	}
	var wg sync.WaitGroup
	for _, n := range names {
		if tick != nil {
			select {
			case <-ctx.Done():
			case <-tick:
			}
		}
		select {
		case <-ctx.Done():
			mu.Lock()
			out[n] = dnsAnswer{failed: true}
			mu.Unlock()
			continue
		case sem <- struct{}{}:
		}
		wg.Go(func() {
			defer func() { <-sem }()
			var a dnsAnswer
			var inner sync.WaitGroup
			inner.Go(func() { a.addrs, a.failed = s.addrs(ctx, n) })
			inner.Go(func() { a.cname = s.cname(ctx, n) })
			inner.Wait()
			mu.Lock()
			out[n] = a
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// addrs returns a name's addresses, IPv4 first, each family sorted (so the first IPv4 is stable from one scan to the next), at most
// maxAddrs; failed when the lookup gave no clear answer.
func (s *Scanner) addrs(ctx context.Context, n string) ([]netip.Addr, bool) {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	a, err := s.resolve.LookupNetIP(rctx, "ip", rooted(n))
	if err != nil {
		return nil, !isNotFound(err)
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
	return a[:min(len(a), maxAddrs)], false
}

// cname returns the final canonical name of n, or "" when it has none (the resolver answers the name itself), the lookup failed, or
// the answer is not a host name.
func (s *Scanner) cname(ctx context.Context, n string) string {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	c, err := s.resolve.LookupCNAME(rctx, rooted(n))
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

// notPublicV6 are the IPv6 special-purpose ranges that are not an address of a host on the Internet (IANA IPv6 Special-Purpose
// Address Registry): translation and tunnel prefixes that embed IPv4 (NAT64, 6to4, Teredo), discard, benchmarking, ORCHID,
// documentation, and the deprecated site-local range.
var notPublicV6 = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("fec0::/10"),
}

// publicV6 is an IPv6 address of a host on the Internet: global unicast, not unique-local, not a special-purpose range. IPv6 is
// listed, never dialed (exposure INV-27): this is the kind shown on the page only.
func publicV6(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && a.IsGlobalUnicast() && !a.IsPrivate() &&
		!slices.ContainsFunc(notPublicV6, func(p netip.Prefix) bool { return p.Contains(a) })
}

// classify gives each address of a name its kind: private when it is not public (never dialed), box when it is one the caller may
// port-scan (exposure's ScannableIP), public otherwise. contacted is the address the check by name went to, if any.
func (s *Scanner) classify(addrs []netip.Addr, box map[netip.Addr]bool, contacted netip.Addr) []Addr {
	out := make([]Addr, 0, len(addrs))
	for _, ip := range addrs {
		a := Addr{IP: ip, Class: ClassPublic, Contacted: contacted.IsValid() && ip == contacted}
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

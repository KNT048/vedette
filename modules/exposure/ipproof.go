package exposure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/domainfence"
)

// Ownership proof of a public IP a person typed in (CONTRACT INV-35). Two ways, either one is enough:
//
//   - A token file served on the IP itself, http or https, at /.well-known/vedette-verify.txt: the ACME HTTP-01 model (RFC 8555
//     section 8.3). The body is the target's own token. No redirect leaves the IP, the body is capped and every request is short. The
//     certificate of a bare IP cannot be verified, which is fine here: the token is the proof, not the channel.
//   - Forward-confirmed reverse DNS (RFC 8601 section 2.7.3): the IP's PTR is a name under a domain this box proves now, and that name
//     resolves back to the IP.
//
// A name of a proved domain that has an A record pointing at the IP proves nothing: whoever runs a name's DNS can point it at any
// address. A proof is stateless like a domain's: the answer now is the only fact used, and the scan gate asks again right before a scan.

const (
	ipProofPath = domainfence.ProofPath
	// ipProofMaxBody bounds what is read of the proof file; a token is 16 hex digits, so anything longer is not it.
	ipProofMaxBody = domainfence.ProofMaxBody
	// ipProofTimeout bounds each request or lookup of a check; ipProofBudget the whole check.
	ipProofTimeout = domainfence.ProofTimeout
	ipProofBudget  = 20 * time.Second
	// maxPTRNames bounds the PTR names looked at (an address can have many) and ptrCoverers the domains asked to prove one name.
	maxPTRNames  = 5
	ptrCoverers  = 3
	maxHintNames = 10
)

// IPRecheckLeft is how long before a typed IP's proof expires the box starts to check it again by itself, and IPRecheckRetry how
// often it tries again while the proof is not found. The proof lasts ValidDays from its last pass. A domain's record is checked the same way.
const (
	IPRecheckLeft  = 7 * 24 * time.Hour
	IPRecheckRetry = 6 * time.Hour
)

// IPFetcher gets the proof file of an IP. rawURL is http(s)://<ip>/.well-known/vedette-verify.txt; it answers the body (at most
// ipProofMaxBody+1 bytes) of a 200, and an error for anything else. Tests pass a fake: no test reaches a real address.
type IPFetcher interface {
	Fetch(ctx context.Context, rawURL string, ip netip.Addr) ([]byte, error)
}

// ReverseResolver looks up the PTR names of an address and the addresses of a name; *net.Resolver satisfies it. A Resolver without
// them proves nothing by reverse DNS (fail closed).
type ReverseResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// httpIPFetcher is the real IPFetcher, the executors' own (domainfence.HTTPFetcher): it dials the IP whatever the URL says, never uses a
// proxy, takes no certificate as proof and follows a redirect only to the same IP and a web port.
type httpIPFetcher = domainfence.HTTPFetcher

// IPProofHint is where the token file of a typed IP goes and the names that could prove it by reverse DNS.
type IPProofHint struct {
	Path    string   `json:"path"`    // /.well-known/vedette-verify.txt
	Content string   `json:"content"` // the token, the whole body of the file
	URLs    []string `json:"urls"`    // the two addresses asked: http and https
	// PTRDomains are the domains of this box that are proved now as far as the box knows (their last check passed): a reverse DNS
	// name of the IP under one of them proves it.
	PTRDomains []string `json:"ptr_domains"`
}

func ipProofHintOf(t Target, all []Target) *IPProofHint {
	if !t.Typed {
		return nil
	}
	h := &IPProofHint{Path: ipProofPath, Content: t.Token, URLs: []string{"http://" + t.Value + ipProofPath, "https://" + t.Value + ipProofPath}, PTRDomains: []string{}}
	for _, o := range all {
		if o.Kind == KindDomain && !o.VerifiedAt.IsZero() && o.LastCheck != nil && o.LastCheck.OK && len(h.PTRDomains) < maxHintNames {
			h.PTRDomains = append(h.PTRDomains, o.Value)
		}
	}
	return h
}

// ipProof is the result of looking for the proof of a typed IP.
type ipProof struct {
	ok      bool
	method  string // methodIPFile or methodIPPTR when ok
	message string // what was found, or why nothing was (cleaned, bounded)
	// ptrName, coverDomain and coverAt are, for methodIPPTR, the PTR name, the domain whose token proved it now and the name that record sits
	// on when it is not that domain's own: what the executors check again.
	ptrName, coverDomain, coverAt string
}

// proveIP looks for the proof of the typed IP t among the box's targets: the token file first (both schemes at once), then reverse
// DNS. Nothing found is "not proved" with what was asked and what came back: fail closed, never an error.
func (s *Service) proveIP(ctx context.Context, t Target, all []Target) ipProof {
	ip, err := netip.ParseAddr(t.Value)
	if err != nil || !IsPublicIPv4(ip) || !t.Typed || t.Token == "" {
		return ipProof{message: fmt.Sprintf("%s is not a typed public IPv4 address, so there is nothing to prove.", t.Value)}
	}
	ctx, cancel := context.WithTimeout(ctx, ipProofBudget)
	defer cancel()
	fetch := s.cfg.IPFetch
	if fetch == nil {
		fetch = httpIPFetcher{}
	}
	var notes [2]string
	var okAt [2]bool
	var wg sync.WaitGroup
	for i, scheme := range []string{"http", "https"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := scheme + "://" + t.Value + ipProofPath
			fctx, c := context.WithTimeout(ctx, ipProofTimeout+time.Second)
			defer c()
			body, err := fetch.Fetch(fctx, u, ip)
			switch {
			case err != nil:
				notes[i] = fmt.Sprintf("%s: %s.", u, cleanDNS(err.Error(), 160))
			case !tokenMatches(body, t.Token):
				notes[i] = fmt.Sprintf("%s: the file is there but does not contain this target's token.", u)
			default:
				okAt[i] = true
			}
		}()
	}
	wg.Wait()
	for i, scheme := range []string{"http", "https"} {
		if okAt[i] {
			return ipProof{ok: true, method: methodIPFile, message: fmt.Sprintf("Found the token file at %s://%s%s.", scheme, t.Value, ipProofPath)}
		}
	}
	ptr, via, at := s.proveByPTR(ctx, ip, all)
	if via != "" {
		return ipProof{ok: true, method: methodIPPTR, ptrName: ptr, coverDomain: via, coverAt: at, message: fmt.Sprintf("The reverse DNS name of %s is %s, which belongs to %s, a domain this box has proved, and it resolves back to %s.", t.Value, ptr, via, t.Value)}
	}
	return ipProof{message: fmt.Sprintf("Vedette found no proof of %s. Token file: put this target's token as the only content of %s on that address, over http or https. %s %s Reverse DNS: %s", t.Value, ipProofPath, notes[0], notes[1], ptr)}
}

func tokenMatches(body []byte, token string) bool { return domainfence.TokenInFile(body, token) }

// proveByPTR is forward-confirmed reverse DNS: ip has a PTR name under a domain of this box that is proved right now (its own proof
// covers the names under it), and that name resolves back to ip. It answers the name and the domain that covers it, or, when nothing
// proves the IP, "" and the sentence that says why.
func (s *Service) proveByPTR(ctx context.Context, ip netip.Addr, all []Target) (name, via, at string) {
	rr, ok := s.cfg.Resolver.(ReverseResolver)
	if !ok {
		return "The resolver of this box cannot look up reverse DNS.", "", ""
	}
	lctx, cancel := context.WithTimeout(ctx, ipProofTimeout)
	names, err := rr.LookupAddr(lctx, ip.String())
	cancel()
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return fmt.Sprintf("%s has no reverse DNS (PTR) name.", ip), "", ""
	case err != nil && len(names) == 0:
		return fmt.Sprintf("the reverse DNS lookup of %s failed (%s).", ip, cleanDNS(err.Error(), 120)), "", ""
	}
	var why []string
	for _, raw := range names {
		if len(why) >= maxPTRNames {
			break
		}
		n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if len(n) > 253 || !domainRE.MatchString(n) {
			why = append(why, fmt.Sprintf("%q is not a host name", cleanDNS(raw, 60)))
			continue
		}
		dom, domAt := s.coveringDomain(ctx, n, all)
		if dom == "" {
			why = append(why, fmt.Sprintf("%s is not under a domain this box has proved", n))
			continue
		}
		fctx, c := context.WithTimeout(ctx, ipProofTimeout)
		addrs, err := rr.LookupNetIP(fctx, "ip4", n)
		c()
		switch {
		case err != nil:
			why = append(why, fmt.Sprintf("%s could not be resolved back (%s)", n, cleanDNS(err.Error(), 100)))
		case !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == ip }):
			why = append(why, fmt.Sprintf("%s does not resolve back to %s", n, ip))
		default:
			return n, dom, domAt
		}
	}
	if len(why) == 0 {
		return fmt.Sprintf("%s has no reverse DNS (PTR) name.", ip), "", ""
	}
	return cleanDNS(fmt.Sprintf("the PTR name of %s was not accepted: %s.", ip, strings.Join(why, "; ")), 400), "", ""
}

// coveringDomain is the domain (and the name its record sits on when not its own) of the target of this box whose proof, checked now, covers name (name is the domain or under it): its own
// record on its own name (which covers the names under it), or the record of another target on a name above it. A target proved
// only by its own token on a parent name proves that target alone, not what sits under it. "" when none does.
func (s *Service) coveringDomain(ctx context.Context, name string, all []Target) (domain, at string) {
	n := 0
	for _, d := range all {
		if d.Kind != KindDomain || d.VerifiedAt.IsZero() || !Covers(d.Value, name) {
			continue
		}
		if n++; n > ptrCoverers {
			break
		}
		pr := s.prove(ctx, d, all)
		if pr.found && Covers(pr.proven, name) && (!pr.own || pr.coversBelow(d.Value)) {
			dom, _, at := pr.gate(d) // the domain whose token it is and where it sits: what the executors check
			return dom, at
		}
	}
	return "", ""
}

// proofNext is when the box looks at a proof again by itself (RunProofRecheck): IPRecheckLeft before it expires, then every
// IPRecheckRetry while a check does not find it. Zero for a target that is neither a proved typed IP nor a proved domain.
func (t Target) proofNext(now time.Time) time.Time {
	exp := t.expiresAt(now)
	if !t.Typed && t.Kind != KindDomain || exp.IsZero() {
		return time.Time{}
	}
	due := exp.Add(-IPRecheckLeft)
	if t.LastCheck != nil {
		if at, err := parseTS(t.LastCheck.At); err == nil && at.After(due) {
			return at.Add(IPRecheckRetry)
		}
	}
	return due
}

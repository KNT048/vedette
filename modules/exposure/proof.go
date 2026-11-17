package exposure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

// Ownership proof of a domain (D-628, J6, kien G10), the way Google Search Console's domain properties, Detectify and Tenable work:
//
//   - A TXT record vedette-verify=<token> proves the name it sits on and every name under it, down to any depth. A verified
//     beyondnetglobal.com covers git.beyondnetglobal.com: no second record.
//   - The record may also sit at _vedette-verify.<name>: a name that is a CNAME (git.beyondnetglobal.com CNAME beyondhcm.ddns.net)
//     can hold no other record, so DNS providers refuse a TXT beside it, but _vedette-verify.git.beyondnetglobal.com is a name of its
//     own and takes one.
//   - A proof never covers across a public suffix, ICANN's (com, co.uk) or a private one (ddns.net, github.io, herokuapp.com): those
//     are names many customers register under, and one customer must never cover another's. The registered domain is the name one
//     label below the longest public suffix of the Public Suffix List with both its sections (golang.org/x/net/publicsuffix); the
//     ICANN section alone would make ddns.net a registered domain whose record covers every customer's name under it. A record on
//     a public suffix proves nothing, and a public suffix is never a target.
//   - The token that counts at a name is a token of one of this box's domain targets at or under that name. Every token is the
//     box's own (random, or bound to the box by the domain fence), so a record with it was put there by whoever runs that name's
//     DNS for this box. A parent target removed from the box takes its token with it: names it covered are covered no more at
//     their next check (before every scan, INV-1 (c)).

// verifyLabel is the label of the dedicated proof name: _vedette-verify.<name>.
const verifyLabel = "_vedette-verify"

// maxProofLevels bounds the names of a proof's chain (the name and its parents down to the registered domain): a name deeper than
// that is proved by a record at one of its nearest parents, at itself or at its registered domain.
const maxProofLevels = 8

// registered is the registered domain of name ("beyondnetglobal.com" for git.beyondnetglobal.com, "beyondhcm.ddns.net" for
// x.beyondhcm.ddns.net); ok is false when name is a public suffix or not under any.
func registered(name string) (string, bool) {
	r, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || r == "" {
		return "", false
	}
	return r, true
}

// IsPublicSuffix says whether name is itself a public suffix of the list (co.uk, ddns.net, github.io): never a target (D-628).
func IsPublicSuffix(name string) bool {
	s, _ := publicsuffix.PublicSuffix(name)
	return s == name
}

// under says whether name is parent or a name under it.
func under(name, parent string) bool { return name == parent || strings.HasSuffix(name, "."+parent) }

// Covers says whether a proof of the name proven covers name: name is proven or under it, and proven is name's registered domain
// or under it (never a public suffix above it).
func Covers(proven, name string) bool {
	r, ok := registered(name)
	return ok && under(name, proven) && under(proven, r)
}

// proofChain is the names whose records can prove name, nearest first: name, then each parent down to its registered domain
// (at most maxProofLevels, the registered domain always last). Empty for a public suffix.
func proofChain(name string) []string {
	r, ok := registered(name)
	if !ok || !under(name, r) {
		return nil
	}
	var out []string
	for n := name; ; {
		out = append(out, n)
		if n == r {
			break
		}
		_, rest, _ := strings.Cut(n, ".")
		n = rest
	}
	if len(out) > maxProofLevels {
		out = append(out[:maxProofLevels-1], r)
	}
	return out
}

// ProofHint is where the record of a domain target goes (TargetView.proof, D-628): the DNS zone (its registered domain), the Name
// (host) to type in that zone ("@" for the zone itself, "git" for git.beyondnetglobal.com), the dedicated name ("_vedette-verify"
// or "_vedette-verify.git") for a name that is a CNAME, and the verified domain target of this box that covers it already, if any.
type ProofHint struct {
	Zone      string  `json:"zone"`
	Host      string  `json:"host"`
	AltHost   string  `json:"alt_host"`
	CoveredBy *string `json:"covered_by"`
}

// proofHint is the hint of a domain target; others are the box's targets (for covered_by). nil for an IP or a public suffix.
func proofHint(t Target, others []Target) *ProofHint {
	r, ok := registered(t.Value)
	if t.Kind != KindDomain || !ok {
		return nil
	}
	h := &ProofHint{Zone: r, Host: "@", AltHost: verifyLabel}
	if t.Value != r {
		h.Host = strings.TrimSuffix(t.Value, "."+r)
		h.AltHost = verifyLabel + "." + h.Host
	}
	best := ""
	for _, o := range others {
		if o.Kind == KindDomain && o.ID != t.ID && !o.VerifiedAt.IsZero() && o.LastCheck != nil && o.LastCheck.OK && Covers(o.Value, t.Value) && len(o.Value) > len(best) {
			best = o.Value
		}
	}
	if best != "" {
		h.CoveredBy = &best
	}
	return h
}

// proof is the result of looking for a record that proves a domain target.
type proof struct {
	found  bool
	at     string // the name the record sits on ("_vedette-verify.git.beyondnetglobal.com", "beyondnetglobal.com")
	proven string // the name it proves: at without the _vedette-verify label
	via    string // the target whose token it is, when not the checked one's own
	// failure says, when nothing was found, which names were asked and what came back (cleaned, bounded).
	failure string
}

// answer is one TXT lookup.
type answer struct {
	vals []string
	err  error
}

// prove looks for a record proving t (D-628): at each name of its chain, the name and _vedette-verify.<name>, a TXT value
// vedette-verify=<token> with the token of one of the box's domain targets at or under that name (all: the box's targets, t among
// them). The lookups run side by side, each within dnsTimeout. Nothing found is "not proved" with the names asked and what came back:
// fail closed, never an error.
func (s *Service) prove(ctx context.Context, t Target, all []Target) proof {
	chain := proofChain(t.Value)
	if len(chain) == 0 {
		return proof{failure: fmt.Sprintf("%s is a public suffix (like com or ddns.net): names under it belong to different owners, so no record can prove it.", t.Value)}
	}
	var names []string
	for _, n := range chain {
		names = append(names, n, verifyLabel+"."+n)
	}
	got := make([]answer, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lctx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()
			got[i].vals, got[i].err = s.cfg.Resolver.LookupTXT(lctx, n)
		}()
	}
	wg.Wait()
	for i, n := range names {
		proven := strings.TrimPrefix(n, verifyLabel+".")
		for _, v := range got[i].vals {
			tok, ok := strings.CutPrefix(strings.TrimSpace(v), "vedette-verify=")
			if !ok {
				continue
			}
			for _, o := range all {
				if o.Kind == KindDomain && o.Token == tok && Covers(proven, o.Value) {
					p := proof{found: true, at: n, proven: proven}
					if o.ID != t.ID {
						p.via = o.Value
					}
					return p
				}
			}
		}
	}
	return proof{failure: s.whyNot(ctx, t, chain, names, got)}
}

// whyNot says which names were asked and what came back at the target's own name, its _vedette-verify name and its registered
// domain (D-628 (4)): a TXT record that is not this one, none, a CNAME to another name, a name that does not exist, a timeout. Every
// value from DNS is untrusted (INV-10): cleaned and bounded before it is shown or stored.
func (s *Service) whyNot(ctx context.Context, t Target, chain, names []string, got []answer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "No TXT record vedette-verify=%s was found. Vedette asked %s", t.Token, strings.Join(dnsNames(names, 4), ", "))
	if len(names) > 4 {
		fmt.Fprintf(&b, " and %d parent names up to %s", len(names)-4, chain[len(chain)-1])
	}
	b.WriteString(". ")
	for i, n := range names {
		if i >= 2 && n != chain[len(chain)-1] { // the name, its _vedette-verify name and the registered domain say enough
			continue
		}
		fmt.Fprintf(&b, "%s: %s. ", n, s.outcome(ctx, n, i == 0, got[i]))
	}
	return strings.TrimSpace(b.String())
}

func dnsNames(names []string, n int) []string { return names[:min(len(names), n)] }

// outcome is what one lookup gave, in words. own: the target's own name, whose CNAME is looked up to say why a record cannot sit
// there.
func (s *Service) outcome(ctx context.Context, name string, own bool, a answer) string {
	cname := ""
	if own {
		cname = s.cnameOf(ctx, name)
	}
	var de *net.DNSError
	switch {
	case a.err == nil && len(a.vals) == 0:
		return "no TXT record"
	case a.err == nil:
		first := cleanDNS(a.vals[0], 60)
		what := fmt.Sprintf("%d TXT records, none of them this one (the first is %q)", len(a.vals), first)
		if len(a.vals) == 1 {
			what = fmt.Sprintf("one TXT record, not this one: %q", first)
		}
		if cname != "" {
			what += fmt.Sprintf("; it is a CNAME to %s, so those are %s's records", cname, cname)
		}
		return what
	case errors.As(a.err, &de) && de.IsTimeout, errors.Is(a.err, context.DeadlineExceeded):
		return fmt.Sprintf("no answer within %d seconds (timeout)", int(dnsTimeout.Seconds()))
	case cname != "":
		return fmt.Sprintf("a CNAME to %s, so a TXT record cannot sit on this name: put it on %s.%s instead, or verify a parent domain", cname, verifyLabel, name)
	case errors.As(a.err, &de) && de.IsNotFound:
		if own && s.cnameMissing(ctx, name) {
			return "the name does not exist (NXDOMAIN)"
		}
		return "no TXT record"
	case errors.As(a.err, &de):
		return "the lookup failed (" + cleanDNS(de.Err, 60) + ")"
	}
	return "the lookup failed"
}

// cnameOf is the canonical name of name when it differs (a CNAME), "" otherwise or when it cannot be read.
func (s *Service) cnameOf(ctx context.Context, name string) string {
	r, ok := s.cfg.Resolver.(CNAMEResolver)
	if !ok {
		return ""
	}
	lctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	cn, err := r.LookupCNAME(lctx, name)
	cn = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cn), "."))
	if err != nil || cn == "" || cn == name || len(cn) > 253 || !domainRE.MatchString(cn) {
		return ""
	}
	return cn
}

// cnameMissing says the name itself does not exist: its CNAME lookup answers "no such host" (NXDOMAIN; a name that exists without
// a CNAME answers itself).
func (s *Service) cnameMissing(ctx context.Context, name string) bool {
	r, ok := s.cfg.Resolver.(CNAMEResolver)
	if !ok {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	_, err := r.LookupCNAME(lctx, name)
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// cleanDNS makes a value from DNS safe to show and store (INV-10): no control or formatting characters, spaces folded, at most n
// characters.
func cleanDNS(v string, n int) string {
	v = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return ' '
		case !unicode.IsPrint(r) && r != ' ':
			return -1
		}
		return r
	}, v)
	v = strings.Join(strings.Fields(v), " ")
	if r := []rune(v); len(r) > n {
		return string(r[:n]) + "…"
	}
	return v
}

// proofMessage is the check message of a found proof.
func proofMessage(t Target, p proof) string {
	switch {
	case p.via != "":
		return fmt.Sprintf("Found the TXT record of %s on %s: it proves %s and every name under it, %s included.", p.via, p.at, p.proven, t.Value)
	case p.proven != t.Value:
		return fmt.Sprintf("Found the TXT record %s on %s: it proves %s and every name under it, %s included.", txtRecord(t.Token), p.at, p.proven, t.Value)
	}
	return fmt.Sprintf("Found the TXT record %s on %s.", txtRecord(t.Token), p.at)
}

package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/net/publicsuffix"

	"github.com/knt048/vedette/core/domainfence"
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
//   - A target is proved by its own token on its own name, or (D-632, kien's G10 reopen) on any parent name down to its registered
//     domain, the zone apex "@" first among them in the instructions: control of the apex TXT proves every name of the zone, the
//     Google Workspace and Microsoft 365 model, and a name that is a CNAME can hold no TXT. It is also proved by the record of a
//     domain target of this box on a parent name, with that target's own token (D-628). Every token is the box's own (random, or
//     bound to the box by the domain fence), so a record with it was put there by whoever runs that name's DNS for this box. A
//     parent target removed from the box takes its token with it: names it covered are covered no more at their next check
//     (before every scan, INV-1 (c)).

// verifyLabel is the label of the dedicated proof name: _vedette-verify.<name> (domainfence.VerifyLabel, the executors' copy).
const verifyLabel = domainfence.VerifyLabel

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

// ProofHint is where the record of a domain target goes (TargetView.proof, D-628, D-632): the DNS zone (its registered domain), the
// Name (host) to type in that zone ("@", the zone apex, for every target: the apex proves every name of the zone and takes a record
// whatever the subdomain is), the dedicated name ("_vedette-verify" or "_vedette-verify.git") as the alternative, and the verified
// domain target of this box that covers it already, if any.
type ProofHint struct {
	Zone      string  `json:"zone"`
	Host      string  `json:"host"`
	AltHost   *string `json:"alt_host"` // nil when _vedette-verify.<name> would pass 253 characters: no such name can exist
	CoveredBy *string `json:"covered_by"`
}

// proofHint is the hint of a domain target; others are the box's targets (for covered_by). nil for an IP or a public suffix.
func proofHint(t Target, others []Target) *ProofHint {
	r, ok := registered(t.Value)
	if t.Kind != KindDomain || !ok {
		return nil
	}
	h := &ProofHint{Zone: r, Host: "@"} // D-632: the record goes on the zone apex, which proves every name of the zone
	alt := verifyLabel
	if t.Value != r {
		alt = verifyLabel + "." + strings.TrimSuffix(t.Value, "."+r)
	}
	if len(verifyLabel)+1+len(t.Value) <= 253 { // review r1 L of #941: never a Name that cannot exist
		h.AltHost = &alt
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
	proven string // the name it proves: the value of the target whose record it is (the checked one, or a parent that covers it)
	via    string // that target's value when it is not the checked one
	// owner and token are that target's id and token: the domain and token the executors' fence checks for the scan (D-628).
	owner, token string
	// own: the token is the checked target's own; with proven a parent name, its record on that parent (D-632).
	own bool
	// failure says, when nothing was found, which names were asked and what came back (cleaned, bounded).
	failure string
}

// answer is one TXT lookup.
type answer struct {
	vals []string
	err  error
}

// proofResolver is the box's resolver as domainfence.Owned asks it. A Resolver without LookupCNAME cannot tell a record from one
// reached through a CNAME, so its CNAME lookups fail and nothing is proved (fail closed).
type proofResolver struct{ r Resolver }

func (p proofResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return p.r.LookupTXT(ctx, name)
}

func (p proofResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if c, ok := p.r.(CNAMEResolver); ok {
		return c.LookupCNAME(ctx, name)
	}
	return "", errors.New("exposure: the resolver cannot look up CNAMEs")
}

// candidate is a record that would prove the checked target: a token (the checked target's own, or a parent target's) on a name of
// its chain (its own name, or a parent name down to its registered domain).
type candidate struct {
	name string
	t    Target // whose token
	got  domainfence.Proof
}

// prove looks for a record proving t (D-628) with the one rule of core/domainfence.Owned, which the executors apply too: t's own
// record (on t or on _vedette-verify.<t>), or the record of a domain target of this box on a parent name of t, down to t's registered
// domain (all: the box's targets). Each candidate is checked side by side, each lookup within dnsTimeout. Nothing found is "not
// proved" with the names asked and what came back: fail closed, never an error.
func (s *Service) prove(ctx context.Context, t Target, all []Target) proof {
	chain := proofChain(t.Value)
	if len(chain) == 0 {
		return proof{failure: publicSuffixText(t.Value)}
	}
	byValue := map[string]Target{}
	for _, o := range all {
		if o.Kind == KindDomain {
			byValue[o.Value] = o
		}
	}
	var cands []candidate
	for _, n := range chain { // the nearest first; on each name the target's own token (D-632), then a parent target's (D-628)
		cands = append(cands, candidate{name: n, t: t})
		if o, ok := byValue[n]; ok && o.ID != t.ID {
			cands = append(cands, candidate{name: n, t: o})
		}
	}
	var wg sync.WaitGroup
	for i := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cands[i].got = domainfence.Owned(ctx, proofResolver{s.cfg.Resolver}, cands[i].name, cands[i].t.Token, dnsTimeout)
		}()
	}
	wg.Wait()
	for _, c := range cands { // the nearest first: the target's own record, then the nearest parent's
		if c.got.At == "" {
			continue
		}
		p := proof{found: true, at: c.got.At, proven: c.name, owner: c.t.ID, token: c.t.Token, own: c.t.ID == t.ID}
		if !p.own {
			p.via = c.t.Value
		}
		return p
	}
	return proof{failure: s.whyNot(ctx, t, cands)}
}

// stillOwner re-reads, in the write transaction of a check, the target whose record proved another one (review r1 L of #941): a
// parent removed, or given a new token, while the lookups ran proves nothing. The target's own record needs no re-read.
func stillOwner(ctx context.Context, tx *sql.Tx, checked string, p proof) (proof, error) {
	if !p.found || p.owner == checked {
		return p, nil
	}
	o, err := loadTarget(ctx, tx, p.owner)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return p, err
	case o.Token == p.token && o.Value == p.proven:
		return p, nil
	}
	return proof{failure: fmt.Sprintf("The record of %s covered this name, but %s was removed from the box while it was checked, so it covers it no more.", p.proven, p.proven)}, nil
}

// publicSuffixText is the check message, and the scan refusal, of a target that is a public suffix (stored before D-628, or one a
// newer Public Suffix List lists).
func publicSuffixText(name string) string {
	return fmt.Sprintf("%s is a public suffix (like com or ddns.net): names under it belong to different owners, so no record can prove it and it cannot be scanned. Remove it and add your own domain.", name)
}

// whyNot says which names were asked and what came back (D-628 (4)): at the target's own name and its _vedette-verify name a TXT
// record that is not this one, none, a CNAME to another name, a name that does not exist, a timeout, or a record refused (reached
// through a CNAME, or a wildcard); then each domain of the box above it that could cover it. Every value from DNS is untrusted
// (INV-10): cleaned and bounded before it is shown or stored.
func (s *Service) whyNot(ctx context.Context, t Target, cands []candidate) string {
	names := []string{t.Value}
	if alt := verifyLabel + "." + t.Value; len(alt) <= 253 {
		names = append(names, alt)
	}
	if r, ok := registered(t.Value); ok && r != t.Value { // D-632: the zone apex "@", where the instructions put the record
		names = append(names, r)
	}
	got := make([]answer, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lctx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()
			got[i].vals, got[i].err = s.cfg.Resolver.LookupTXT(lctx, n+".") // rooted: no search domain (as domainfence.Owned)
		}()
	}
	wg.Wait()
	var b strings.Builder
	fmt.Fprintf(&b, "No TXT record vedette-verify=%s was found. Vedette asked %s", t.Token, strings.Join(names, ", "))
	if n := len(proofChain(t.Value)) - 2; n > 0 {
		fmt.Fprintf(&b, " (and %s between them)", plural(n, "parent name"))
	}
	b.WriteString(". ")
	for i, n := range names {
		fmt.Fprintf(&b, "%s: %s. ", n, s.outcome(ctx, n, i == 0, got[i]))
	}
	for _, c := range cands { // a record of this token found but refused (reached through a CNAME, a wildcard), or a failed lookup
		if c.t.ID != t.ID {
			continue
		}
		if d := c.got.Detail; strings.Contains(d, "CNAME to another name") || strings.Contains(d, "wildcard") || c.got.Unchecked {
			b.WriteString("Not counted: " + cleanDNS(d, 200) + ". ")
		}
	}
	var above []string
	for _, c := range cands {
		if c.t.ID != t.ID {
			above = append(above, c.t.Value)
		}
	}
	if len(above) == 0 {
		b.WriteString("No domain of this box above it covers it. ")
	} else {
		fmt.Fprintf(&b, "The box's %s, which would cover it, has no record of its own now either. ", strings.Join(above, " and "))
	}
	return strings.TrimSpace(b.String())
}

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
		return fmt.Sprintf("a CNAME to %s, so a TXT record cannot sit on this name: put it on @ of the zone (the registered domain) or on %s.%s instead", cname, verifyLabel, name)
	case errors.As(a.err, &de) && de.IsNotFound:
		if own && s.cnameMissing(ctx, name) {
			return "the name does not exist (NXDOMAIN), or has no address or TXT record"
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
	cn, err := r.LookupCNAME(lctx, name+".")
	cn = strings.ToLower(strings.TrimRight(strings.TrimSpace(cn), "."))
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
	_, err := r.LookupCNAME(lctx, name+".")
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
	case p.own && p.proven != t.Value: // D-632
		return fmt.Sprintf("Found the TXT record %s on %s: this target's own record on a parent name, which proves %s.", txtRecord(t.Token), p.at, t.Value)
	case p.via != "":
		return fmt.Sprintf("Found the TXT record of %s on %s: it proves %s and every name under it, %s included.", p.via, p.at, p.proven, t.Value)
	}
	return fmt.Sprintf("Found the TXT record %s on %s.", txtRecord(t.Token), p.at)
}

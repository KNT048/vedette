package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/domainfence/proofat"
	"github.com/knt048/vedette/core/store"
)

// Ownership proof of a domain, the way Google Search Console's domain properties, Detectify and Tenable work:
//
//   - A TXT record vedette-verify=<token> proves the name it sits on and every name under it, down to any depth. A verified
//     example.org covers git.example.org: no second record.
//   - The record may also sit at _vedette-verify.<name>: a name that is a CNAME (git.example.org CNAME example.ddns.net)
//     can hold no other record, so DNS providers refuse a TXT beside it, but _vedette-verify.git.example.org is a name of its
//     own and takes one.
//   - A proof never covers across a public suffix, ICANN's (com, co.uk) or a private one (ddns.net, github.io, herokuapp.com): those
//     are names many customers register under, and one customer must never cover another's. The registered domain is the name one
//     label below the longest public suffix of the Public Suffix List with both its sections (golang.org/x/net/publicsuffix); the
//     ICANN section alone would make ddns.net a registered domain whose record covers every customer's name under it. A record on
//     a public suffix proves nothing, and a public suffix is never a target.
//   - A target is proved by its own token on its own name, or on any parent name down to its registered
//     domain, the zone apex "@" first among them in the instructions: control of the apex TXT proves every name of the zone, the
//     Google Workspace and Microsoft 365 model, and a name that is a CNAME can hold no TXT. It is also proved by the record of a
//     domain target of this box on its own name, with that target's own token. Every token is the box's own (random, or
//     bound to the box by the domain fence), so a record with it was put there by whoever runs that name's DNS for this box. A
//     parent target removed from the box takes its token with it: names it covered are covered no more at their next check
//     (before every scan, INV-1 (c)).
//   - A proof is stateless: the record found now is the only fact used. The token of any domain target of this box, on any name
//     above that target (down to the registered domain) that is also the checked name or above it, proves the checked name and
//     every name under that name: a TXT record on example.com with the token of git.example.com proves example.com, www.example.com
//     and git.example.com's siblings, with no second record. Nothing stored decides it: no last check of the other target, no name
//     remembered. A target removed from the box takes its token with it. The executors (core/domainfence) accept the same shape: the
//     token bound to the other target's domain, looked up on that name, for any name under it. A box holds one organisation's
//     targets: there is no other tenant's proof to meet.

// verifyLabel is the label of the dedicated proof name: _vedette-verify.<name> (domainfence.VerifyLabel, the executors' copy).
const verifyLabel = domainfence.VerifyLabel

// maxProofLevels bounds the names of a proof's chain (the name and its parents down to the registered domain): a name deeper than
// that is proved by a record at one of its nearest parents, at itself or at its registered domain.
const maxProofLevels = 8

// registered is the registered domain of name ("example.org" for git.example.org, "example.ddns.net" for
// x.example.ddns.net); ok is false when name is a public suffix or not under any.
func registered(name string) (string, bool) { return proofat.Registered(name) }

// under says whether name is parent or a name under it.
func under(name, parent string) bool { return name == parent || strings.HasSuffix(name, "."+parent) }

// Covers says whether a proof of the name proven covers name: name is proven or under it, and proven is name's registered domain
// or under it (never a public suffix above it).
func Covers(proven, name string) bool { return proofat.Within(name, proven) } // the executors' rule too

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

// ProofHint is where the record of a domain target goes (TargetView.proof): the DNS zone (its registered domain), the
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
	h := &ProofHint{Zone: r, Host: "@"} // The record goes on the zone apex, which proves every name of the zone
	alt := verifyLabel
	if t.Value != r {
		alt = verifyLabel + "." + strings.TrimSuffix(t.Value, "."+r)
	}
	if len(verifyLabel)+1+len(t.Value) <= 253 { // never a Name that cannot exist
		h.AltHost = &alt
	}
	best := ""
	for _, o := range others {
		// Only a box domain whose last check found its own record on its own name covers the names under it
		if o.Kind == KindDomain && o.ID != t.ID && !o.VerifiedAt.IsZero() && o.LastCheck != nil && o.LastCheck.OK && o.LastCheck.Covers && Covers(o.Value, t.Value) && len(o.Value) > len(best) {
			best = o.Value
		}
	}
	if best == "" && t.LastCheck != nil && t.LastCheck.OK && t.LastCheck.Via != "" { // proved by another target's token at its last check
		for _, o := range others {
			if o.Kind == KindDomain && o.ID != t.ID && o.Value == t.LastCheck.Via {
				best = o.Value
			}
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
	at     string // the name the record sits on ("_vedette-verify.git.example.org", "example.org")
	proven string // the name it proves: the value of the target whose record it is (the checked one, or a parent that covers it)
	via    string // that target's value when it is not the checked one
	// owner and token are that target's id and token: the domain and token the executors' fence checks for the scan.
	owner, token string
	// own: the token is the checked target's own; with proven a parent name, its record on that parent.
	own bool
	// reused: the record is another target's own token on a name above that target which is the checked name or above it (proven is
	// that name, via the other target's value): not a parent target's own name and not the checked target's own token.
	reused bool
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
	name   string
	t      Target // whose token
	reused bool   // t's token on a name above t (name) that is the checked name or above it
	got    domainfence.Proof
}

// maxReuse bounds the other targets' tokens a check looks for on the names above the checked one: every other target of the box (the
// per-check lookup memo makes each extra token free: a name is asked once whatever the number of tokens). A smaller bound would let
// coverOthers verify names whose own gate then cannot find the donor.
const maxReuse = MaxTargets

// maxReuseListed is how many other targets' tokens a failed check names one by one; more are said in one line.
const maxReuseListed = 3

// reuseCands lists, for the chain name n, the other domain targets of the box that sit strictly under n: their token on n proves
// the checked name too (n is the checked name or above it, down to its registered domain, so under n are all names n covers). The
// target whose own name is n is the parent candidate, not this one. The donor must be under n by the executors' own bound
// (proofat.Within: never across a private public suffix below the registered domain). The nearest names first.
func reuseCands(t Target, chain []string, all []Target) []candidate {
	var out []candidate
	for _, n := range chain {
		for _, o := range all {
			if len(out) == maxReuse {
				return out
			}
			if o.Kind == KindDomain && o.ID != t.ID && o.Value != n && proofat.Within(o.Value, n) {
				out = append(out, candidate{name: n, t: o, reused: true})
			}
		}
	}
	return out
}

// memoResolver is the box's resolver for the lookups of one check: the same name asked for several tokens (the checked
// target's and each other target's at the same name) is looked up once, the answer shared.
type memoResolver struct {
	r     proofResolver
	mu    sync.Mutex
	txt   map[string]*memoTXT
	cname map[string]*memoCNAME
}

type memoTXT struct {
	once sync.Once
	vals []string
	err  error
}

type memoCNAME struct {
	once sync.Once
	cn   string
	err  error
}

func newMemoResolver(r Resolver) *memoResolver {
	return &memoResolver{r: proofResolver{r}, txt: map[string]*memoTXT{}, cname: map[string]*memoCNAME{}}
}

func (m *memoResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	m.mu.Lock()
	e, ok := m.txt[name]
	if !ok {
		e = &memoTXT{}
		m.txt[name] = e
	}
	m.mu.Unlock()
	e.once.Do(func() { e.vals, e.err = m.r.LookupTXT(ctx, name) })
	return e.vals, e.err
}

func (m *memoResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	m.mu.Lock()
	e, ok := m.cname[name]
	if !ok {
		e = &memoCNAME{}
		m.cname[name] = e
	}
	m.mu.Unlock()
	e.once.Do(func() { e.cn, e.err = m.r.LookupCNAME(ctx, name) })
	return e.cn, e.err
}

// prove looks for a record proving t with the one rule of core/domainfence.Owned, which the executors apply too: t's own
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
	reused := reuseCands(t, chain, all)
	var cands []candidate
	for _, n := range chain { // the nearest first; on each name the target's own token, a parent target's, then the tokens of targets under it
		cands = append(cands, candidate{name: n, t: t})
		if o, ok := byValue[n]; ok && o.ID != t.ID {
			cands = append(cands, candidate{name: n, t: o})
		}
		for _, c := range reused {
			if c.name == n {
				cands = append(cands, c)
			}
		}
	}
	memo := newMemoResolver(s.cfg.Resolver)
	// One DNS budget for the whole check: every lookup, the explanation of a failure included, ends by one
	// deadline, and the lookups still running stop as soon as the nearest valid record is known.
	bctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	done := make([]chan struct{}, len(cands))
	for i := range cands {
		done[i] = make(chan struct{})
		go func() {
			defer close(done[i])
			cands[i].got = domainfence.Owned(bctx, memo, cands[i].name, cands[i].t.Token, dnsTimeout)
		}()
	}
	for i := range cands { // the nearest first: the target's own record, then the nearest parent's
		<-done[i]
		c := cands[i]
		if c.got.At == "" {
			continue
		}
		cancel()
		p := proof{found: true, at: c.got.At, proven: c.name, owner: c.t.ID, token: c.t.Token, own: c.t.ID == t.ID, reused: c.reused}
		if !p.own {
			p.via = c.t.Value
		}
		return p
	}
	return proof{failure: s.whyNot(bctx, memo, t, cands)}
}

// gate is what the executors' fence checks for a scan of t once p proved it: the domain whose token it is, that token, and the name the
// record sits on when it is not the domain itself (at). The target's own token on its own name: itself; on a parent name: itself with at
// that name; a parent target's: that target; another target's token on a name above both: that target with at that name.
func (p proof) gate(t Target) (domain, token, at string) {
	switch {
	case !p.found:
		return "", "", ""
	case p.own:
		if p.proven != t.Value {
			at = p.proven
		}
		return t.Value, p.token, at
	case p.reused:
		return p.via, p.token, p.proven
	}
	return p.via, p.token, ""
}

// coversBelow says the record found is the checked target's own on its own name (or its _vedette-verify name), which covers the
// names under it; its own token on a parent name proves it only.
func (p proof) coversBelow(value string) bool { return p.found && p.own && p.proven == value }

// stillOwner re-reads, in the write transaction of a check, the target whose record proved another one: a
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
	case o.Token == p.token && o.Value == p.via:
		return p, nil
	}
	return proof{failure: fmt.Sprintf("The TXT record of %s on %s covered this name, but %s was removed from the box while it was checked (or given a new token), so it covers it no more.", p.via, p.proven, p.via)}, nil
}

// publicSuffixText is the check message, and the scan refusal, of a target that is a public suffix (stored by an older release, or one a
// newer Public Suffix List lists).
func publicSuffixText(name string) string {
	return fmt.Sprintf("%s is a public suffix (like com or ddns.net): names under it belong to different owners, so no record can prove it and it cannot be scanned. Remove it and add your own domain.", name)
}

// whyNot says which names were asked and what came back: at the target's own name and its _vedette-verify name a TXT
// record that is not this one, none, a CNAME to another name, a name that does not exist, a timeout, or a record refused (reached
// through a CNAME, or a wildcard); then each domain of the box above it that could cover it. Every value from DNS is untrusted
// (INV-10): cleaned and bounded before it is shown or stored.
func (s *Service) whyNot(ctx context.Context, memo *memoResolver, t Target, cands []candidate) string {
	names := []string{t.Value}
	if alt := verifyLabel + "." + t.Value; len(alt) <= 253 {
		names = append(names, alt)
	}
	if r, ok := registered(t.Value); ok && r != t.Value { // The zone apex "@", where the instructions put the record
		names = append(names, r)
	}
	got := make([]answer, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i].vals, got[i].err = memo.LookupTXT(ctx, n+".") // rooted: no search domain (as domainfence.Owned); ctx: the check's budget
		}()
	}
	wg.Wait()
	var b strings.Builder
	fmt.Fprintf(&b, "No TXT record vedette-verify=%s was found. Vedette asked %s", t.Token, strings.Join(names, ", "))
	chain := proofChain(t.Value)
	if r := chain[len(chain)-1]; r != t.Value && len(verifyLabel)+1+len(r) <= 253 { // every name asked is said
		b.WriteString(", " + verifyLabel + "." + r)
	}
	if n := len(chain) - 2; n > 0 {
		fmt.Fprintf(&b, ", and %s between them, each also with %s before it", plural(n, "parent name"), verifyLabel)
	}
	b.WriteString(". ")
	for i, n := range names {
		fmt.Fprintf(&b, "%s: %s. ", n, s.outcome(ctx, n, i == 0, got[i]))
	}
	for _, c := range cands { // a record of this token found but refused (reached through a CNAME, a wildcard), or a failed lookup
		if c.t.ID != t.ID {
			continue
		}
		if c.got.Refused || c.got.Unchecked {
			b.WriteString("Not counted: " + cleanDNS(c.got.Detail, 200) + ". ")
		}
	}
	var above, viaRecords []string
	for _, c := range cands {
		switch {
		case c.reused:
			viaRecords = append(viaRecords, fmt.Sprintf("%s's token on %s (%s)", c.t.Value, c.name, cleanDNS(c.got.Detail, 200)))
		case c.t.ID != t.ID:
			above = append(above, c.t.Value)
		}
	}
	switch n := len(viaRecords); {
	case n == 0:
	case n <= maxReuseListed: // a few: each with what was found there
		b.WriteString("Also looked for the record of another target of this box that would cover it: " + strings.Join(viaRecords, "; ") + ". ")
	default: // many: one line
		fmt.Fprintf(&b, "Also looked for the tokens of the %s of this box on the names above it: none of them is there now. ", plural(n, "other target"))
	}
	if len(above) == 0 {
		b.WriteString("No domain of this box above it covers it. ")
	} else {
		// A box domain covers the names under it only with its own record on its own name (or its _vedette-verify
		// name), never with a record on a parent of it
		fmt.Fprintf(&b, "The box's %s would cover it only with its own record on that name itself (or %s before it); there is none there now. ", strings.Join(above, " and "), verifyLabel)
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

// reusedMessage is the check message of a name covered by a record that proved another target of the box.
func reusedMessage(name, when string) string {
	return fmt.Sprintf("Ownership already proven by the TXT record at %s (checked %s).", name, when)
}

// proofMessage is the check message of a found proof.
func proofMessage(t Target, p proof, when string) string {
	switch {
	case p.reused:
		return reusedMessage(p.proven, when)
	case p.own && p.proven != t.Value:
		return fmt.Sprintf("Found the TXT record %s on %s: this target's own record on a parent name, which proves %s.", txtRecord(t.Token), p.at, t.Value)
	case p.via != "":
		return fmt.Sprintf("Found the TXT record of %s on %s: it proves %s and every name under it, %s included.", p.via, p.at, p.proven, t.Value)
	}
	return fmt.Sprintf("Found the TXT record %s on %s.", txtRecord(t.Token), p.at)
}

// coveredByAncestor says the record that proved t (p, after stillOwner) is the own record, on its own name, of a target that is an
// ancestor of t in the tree as stored in tx: t is then covered by that ancestor and has no method of its own (exp_target.method NULL).
// t's own token (on its name or on a parent name) and another target's token on a name above both prove t by itself (dns_txt).
func coveredByAncestor(ctx context.Context, tx *sql.Tx, id string, p proof) (bool, error) {
	if !p.found || p.own || p.reused || p.via == "" || p.proven != p.via {
		return false, nil
	}
	all, err := listTargets(ctx, tx)
	if err != nil {
		return false, err
	}
	byID := map[string]Target{}
	for _, o := range all {
		byID[o.ID] = o
	}
	for _, a := range ancestors(byID[id], byID) {
		if a.ID == p.owner && a.Value == p.via {
			return true, nil
		}
	}
	return false, nil
}

// recordDomainMethod writes how a domain target is proved after a check that found its record: dns_txt by itself, NULL when an
// ancestor's record covers it.
func recordDomainMethod(ctx context.Context, tx *sql.Tx, id string, covered bool) error {
	m := methodDNS
	if covered {
		m = ""
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET method = ? WHERE id = ? AND kind = 'domain'`, nullString(m), id); err != nil {
		return fmt.Errorf("recording how %s is proved: %w", id, err)
	}
	return nil
}

// settleMethod records, in tx, how the domain target id is proved after a check that found p.
func settleMethod(ctx context.Context, tx *sql.Tx, id string, p proof) error {
	if !p.found {
		return nil
	}
	covered, err := coveredByAncestor(ctx, tx, id, p)
	if err != nil {
		return err
	}
	return recordDomainMethod(ctx, tx, id, covered)
}

// uncover records, in the transaction that removes the domain target gone, that the targets its record proved at their last check are
// proved no more: their scans were refused from their next start anyway (the token went with the target), and the page says so now.
func (s *Service) uncover(ctx context.Context, tx *sql.Tx, gone Target) error {
	if gone.Kind != KindDomain {
		return nil
	}
	all, err := listTargets(ctx, tx)
	if err != nil {
		return err
	}
	now := s.clock()
	for _, o := range all {
		if o.Kind != KindDomain || o.LastCheck == nil || !o.LastCheck.OK || o.LastCheck.Via != gone.Value {
			continue
		}
		msg := fmt.Sprintf("The TXT record of %s proved this name, and %s was removed from the box, so it needs its own proof: add the record shown, then check again.", gone.Value, gone.Value)
		if err := updateCheck(ctx, tx, o.ID, Check{At: store.FormatTS(now), OK: false, Message: msg}, time.Time{}, ""); err != nil {
			return err
		}
	}
	return nil
}

// Package domainfence is the executors' half of the domain fence: the check the scan
// container's worker (nmap, nuclei) and vedette-host (ZAP, OpenVAS) make on their own, right before a tool starts on a public address
// that is not the box's own egress, because a name under a verified domain resolves to it. Core is not trusted for any of it: the
// token it sends must be the one this box derives from its fence key (a TXT value is public, so another customer's visible token
// would otherwise pass), the domain's TXT record must carry it now, and the name must resolve to the address now. Core never holds
// the key (vedette-host makes it, the scan container gets it read-only, core's container never mounts it).
//
// It is a leaf: the standard library, core/localnet, its sibling proofat and golang.org/x/net/dns/dnsmessage (the DNS message parser
// the standard library itself vendors) only, because the sensor binary links it (TestBinaryDependencies there).
package domainfence

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/domainfence/proofat"
	"github.com/knt048/vedette/core/localnet"
)

const (
	// KeySize is the length of the fence key: 32 random bytes.
	KeySize = 32
	// TokenLen is the length of a box-bound token: the first 16 hex digits of the HMAC (64 bits), the length of every domain token
	// exposure stores (exp_target's CHECK since migration 0001).
	TokenLen = 16
	// CacheFor is how long a yes stands for one (domain, name, ip): a run of many nuclei jobs or ZAP pages asks DNS once in it.
	CacheFor = 5 * time.Minute
	// LookupTimeout bounds each DNS lookup of a check.
	LookupTimeout = 10 * time.Second
	// Recheck is how often a long run (a deep nmap, an OpenVAS task) checks again while it runs: the own_ip re-check's period.
	Recheck = 3 * time.Minute
	// VerifyLabel is the label of a domain's dedicated proof name, _vedette-verify.<domain>: the record may sit there when
	// the domain is a CNAME.
	VerifyLabel = "_vedette-verify"
	// tokenLabel is what the HMAC is taken over, before the domain (plan §5).
	tokenLabel = "vedette-verify\x00" //nolint:gosec // the public label the HMAC is taken over, not a credential
)

// The refusal reasons (sensor-protocol.md 6.5, host-api §6.16). Every one means nothing was sent.
const (
	InvalidJob   = "invalid_job"         // the job's fields are not of the grammar
	TokenForeign = "token_foreign"       // the token is not this box's for the domain (another box's, or a token made before the fence)
	NotOwned     = "target_not_owned"    // the domain's TXT records do not carry vedette-verify=<token> now (a typed IP: its proof is not found now)
	NameMoved    = "name_moved"          // the name does not resolve to the address now (that item only)
	Unchecked    = "ownership_unchecked" // a DNS lookup failed or timed out: nothing is known, so nothing is sent
	CNAMEOutside = "cname_outside"       // a disruptive job for a name whose CNAME leaves the domain (review r1 M4)
)

// Reasons is the closed set of refusal reasons a check can give.
var Reasons = []string{InvalidJob, TokenForeign, NotOwned, NameMoved, Unchecked, CNAMEOutside}

var (
	domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`) // exposure's domainRE
	tokenRE  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Token is the box-bound token of domain: hex(HMAC-SHA256(key, "vedette-verify\x00"+domain)), its first TokenLen digits.
func Token(key []byte, domain string) string {
	m := hmac.New(sha256.New, key)
	_, _ = io.WriteString(m, tokenLabel+domain)
	return hex.EncodeToString(m.Sum(nil))[:TokenLen]
}

// ValidDomain says whether s is a domain name of exposure's grammar (lower case, at most 253 bytes).
func ValidDomain(s string) bool { return len(s) <= 253 && domainRE.MatchString(s) }

// Under says whether name is domain itself or a name under it (both of the grammar).
func Under(name, domain string) bool {
	return ValidDomain(name) && ValidDomain(domain) && (name == domain || strings.HasSuffix(name, "."+domain))
}

// Job is what a domain_ip job carries (plan §5: {domain, name, ip, token}; the ports are the tool's own). Disruptive asks the CNAME
// rule too: a disruptive job is refused for a name whose canonical name is outside the domain.
type Job struct {
	Domain     string
	Name       string
	IP         netip.Addr
	Token      string
	Disruptive bool
	// ProofAt is a parent name of Domain where Domain's token sits (the zone apex: a name that is a CNAME can hold no
	// TXT, and control of the apex proves every name of the zone, the Google Workspace and Microsoft 365 model): the record
	// vedette-verify=<Token> is looked for there instead of on Domain, with the same rules (Owned). "" = on Domain. The token stays
	// Domain's; ProofAt is never Domain itself, and never on or above a public suffix. With ProofAt set, Name is bounded by ProofAt, not
	// by Domain: the record of one domain of the box on a name above both covers every name under that name (a name proved by the
	// record of a sibling target, the domain being that target's). Whoever answers for ProofAt's DNS put this box's token there, and
	// could as well have put the token of Name itself, so no name is covered that the same person could not have proved.
	ProofAt string
	// Typed, when set, makes this the job of a public IP a person typed in (typed.go): Domain and Name are the IP literal, Token the
	// box-bound token of that literal, and the check is the IP's own proof instead of a domain's record.
	Typed *TypedProof
}

// Valid is point 1 of the check, the grammar: the domain, a name that is the domain or under it, a public IPv4 address
// (localnet.Public, the own_ip rule), a token of 16 lower-case hex digits.
func (j Job) Valid() error {
	if j.Typed != nil {
		return j.validTyped()
	}
	switch {
	case !ValidDomain(j.Domain):
		return errors.New("the domain is not a domain name")
	case j.ProofAt == "" && !Under(j.Name, j.Domain):
		return errors.New("the name is not the domain or a name under it")
	case j.ProofAt != "" && (!Under(j.Name, j.ProofAt) || !proofat.Within(j.Name, j.ProofAt)):
		return errors.New("the name is not under the proof name, down to its registered domain")
	case !j.IP.Is4() || !localnet.Public(j.IP):
		return errors.New("the address is not a public IPv4 address")
	case !tokenRE.MatchString(j.Token):
		return errors.New("the token is not 16 hex digits")
	case j.ProofAt != "" && (j.ProofAt == j.Domain || !ValidDomain(j.ProofAt) || !proofat.Within(j.Domain, j.ProofAt)):
		return errors.New("the proof name is not a parent name of the domain")
	}
	return nil
}

// Resolver is the system resolver as the fence needs it; *net.Resolver satisfies it. Tests pass a fake: no test asks real DNS.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Outcome is the answer of a check: Reason "" is a yes. Chain is the CNAME chain of the name as the system resolver gives it (the
// name, then its canonical name when it differs: the standard resolver answers the end of the chain, not each hop), for the
// executor's fence log and the probe log; Detail says why in words for a log line (never sent anywhere).
type Outcome struct {
	Reason string
	Chain  []string
	Detail string
	Cached bool
}

// ChainText is the chain as one probe-log text: "www.acme.example" or "www.acme.example -> acme.edgekey.net".
func (o Outcome) ChainText() string { return strings.Join(o.Chain, " -> ") }

type cacheKey struct {
	domain, proofAt, name string
	ip                    netip.Addr
}

type cacheEntry struct {
	at    time.Time
	chain []string
	out   bool // the canonical name is outside the domain
}

// Fence checks domain_ip jobs. Create it with New.
type Fence struct {
	key     []byte
	r       Resolver
	now     func() time.Time
	listed  func(domain string) bool
	fetcher FileFetcher

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

// New builds a Fence over key (KeySize bytes) and r. listed says whether vedette-host has issued a token for a domain (its own list,
// review r1 H1): a domain off the list is refused like a foreign token, and nil refuses every domain (fail closed). now nil means
// time.Now.
func New(key []byte, r Resolver, listed func(domain string) bool, now func() time.Time) (*Fence, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("domainfence: the key must be %d bytes, got %d", KeySize, len(key))
	}
	if r == nil {
		return nil, errors.New("domainfence: a resolver is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Fence{key: slices.Clone(key), r: r, now: now, listed: listed, cache: map[cacheKey]cacheEntry{}}, nil
}

// Token is Token with the fence's key.
func (f *Fence) Token(domain string) string { return Token(f.key, domain) }

// Check is the whole fence, in the order of plan §5: grammar, the box-bound token, the domain's TXT record carries it, the name resolves
// (A, the system resolver, LookupTimeout) to a set that holds the address, and for a disruptive job the name's canonical name stays
// inside the domain. A yes of the last CacheFor for the same (domain, name, ip) stands when cached is true (the re-check of a running
// tool passes false); any answer that is not a yes forgets it. Every failure is a refusal: fail closed.
func (f *Fence) Check(ctx context.Context, j Job, cached bool) Outcome {
	if err := j.Valid(); err != nil {
		return Outcome{Reason: InvalidJob, Detail: err.Error()}
	}
	if !hmac.Equal([]byte(j.Token), []byte(f.Token(j.Domain))) {
		return Outcome{Reason: TokenForeign, Detail: "the token is not this box's token for " + j.Domain}
	}
	if f.listed == nil || !f.listed(j.Domain) { // review r1 H1: only a domain vedette-host has issued a token for (capped, audited)
		return Outcome{Reason: TokenForeign, Detail: "vedette-host has not issued a token for " + j.Domain}
	}
	k := cacheKey{j.Domain, j.ProofAt, j.Name, j.IP}
	if cached {
		f.mu.Lock()
		e, ok := f.cache[k]
		f.mu.Unlock()
		if ok && f.now().Sub(e.at) < CacheFor && !e.at.After(f.now()) {
			if j.Disruptive && e.out {
				return Outcome{Reason: CNAMEOutside, Chain: e.chain, Detail: "the name's canonical name is outside the domain", Cached: true}
			}
			return Outcome{Chain: e.chain, Cached: true}
		}
	}
	o, e := f.check(ctx, j)
	f.mu.Lock()
	if o.Reason == "" || o.Reason == CNAMEOutside {
		e.at = f.now()
		f.cache[k] = e
	} else {
		delete(f.cache, k)
	}
	f.mu.Unlock()
	return o
}

func (f *Fence) check(ctx context.Context, j Job) (Outcome, cacheEntry) {
	if j.Typed != nil {
		return f.checkTyped(ctx, j), cacheEntry{}
	}
	lookup := func(fn func(context.Context) error) error {
		lctx, cancel := context.WithTimeout(ctx, LookupTimeout)
		defer cancel()
		return fn(lctx)
	}
	owner := j.Domain
	if j.ProofAt != "" { // Domain's own record on a parent name
		owner = j.ProofAt
	}
	switch pr := Owned(ctx, f.r, owner, j.Token, LookupTimeout); {
	case pr.Unchecked:
		return Outcome{Reason: Unchecked, Detail: pr.Detail}, cacheEntry{}
	case pr.At == "":
		return Outcome{Reason: NotOwned, Detail: pr.Detail}, cacheEntry{}
	}
	var addrs []netip.Addr
	err := lookup(func(c context.Context) (err error) { addrs, err = f.r.LookupNetIP(c, "ip4", j.Name); return })
	if err != nil && !notFound(err) {
		return Outcome{Reason: Unchecked, Detail: "the address lookup of " + j.Name + " failed"}, cacheEntry{}
	}
	if !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == j.IP }) {
		return Outcome{Reason: NameMoved, Detail: j.Name + " does not resolve to " + j.IP.String() + " now"}, cacheEntry{}
	}
	var cn string
	err = lookup(func(c context.Context) (err error) { cn, err = f.r.LookupCNAME(c, j.Name); return })
	if err != nil {
		return Outcome{Reason: Unchecked, Detail: "the CNAME lookup of " + j.Name + " failed"}, cacheEntry{}
	}
	cn = strings.ToLower(strings.TrimSuffix(cn, "."))
	chain := []string{j.Name}
	if cn != "" && cn != j.Name {
		if len(cn) > 253 || !domainRE.MatchString(cn) {
			return Outcome{Reason: Unchecked, Detail: "the CNAME answer of " + j.Name + " is not a host name"}, cacheEntry{}
		}
		chain = append(chain, cn)
	}
	bound := j.Domain // a name under the domain stays inside the domain; a name covered through ProofAt, inside ProofAt
	if !Under(j.Name, j.Domain) {
		bound = j.ProofAt
	}
	e := cacheEntry{chain: chain, out: !Under(chain[len(chain)-1], bound)}
	if j.Disruptive && e.out {
		return Outcome{Reason: CNAMEOutside, Chain: chain, Detail: j.Name + " points (CNAME) outside " + bound}, e
	}
	return Outcome{Chain: chain}, e
}

// ProofResolver is what Owned asks; *net.Resolver satisfies it.
type ProofResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Proof is the answer of Owned: At is the name the record was found on ("" when none); Unchecked says a lookup failed, so nothing is
// known (fail closed); Refused says a record of the token was found but does not count; Detail says why in words for a log line
// (callers decide from the fields, never from Detail).
type Proof struct {
	At        string
	Unchecked bool
	Refused   bool // reached through a CNAME, or answered by a wildcard
	Detail    string
	// Authoritative: At was found at the zone's own name servers while the box's resolver still answered without it (an older
	// answer it keeps cached).
	Authoritative bool
	// Servers are the zone's own name servers that answered when they were asked (the resolver's answer proved nothing); empty
	// when they were not asked or none answered with authority.
	Servers []string
	// Propagating: some of the zone's name servers serve the record, not all of them yet.
	Propagating bool
}

// source is where Owned reads a name's TXT records and whether it is a CNAME: the box's resolver, or the zone's own name servers.
// all is the values the source answers; some (the zone's servers only) the values at least one of its servers answers.
type source struct {
	txt   func(name string) (all, some []string, err error)
	cname func(name string) (bool, error) // the name is a CNAME to another name
}

// Owned is THE ownership rule of a domain's record, the one every party applies: exposure (Check and the scan gate, for the
// target itself and for a parent target that covers it), the scan container's worker (deep steps) and vedette-host (ZAP pages,
// OpenVAS). domain is owned when the TXT record vedette-verify=<token> is answered at the name asked itself:
//
//   - on domain, or on _vedette-verify.<domain> (a domain that is a CNAME can hold no other record; skipped when that name would
//     pass 253 characters);
//   - never through a CNAME: the name asked must not be one (its LookupCNAME answers itself, or "no such host" for a name with no
//     address), else the TXT belongs to whoever runs the CNAME's target (a dangling CNAME, a vendor's name);
//   - on _vedette-verify.<domain>, never a wildcard: a random sibling under domain must not answer the same value. A wildcard
//     "*.domain" answers every name under it, the dedicated one included; a wildcard CNAME there is already refused by the rule
//     above, a wildcard TXT by this one. On domain itself a wildcard of its parent answers only when domain has no record of its
//     own, so a wildcard CNAME is refused by the CNAME rule and a wildcard TXT is the zone owner's own record.
//
// The names are asked through the box's resolver first. When that proves nothing and r is also an Authority, the same names are
// asked of the zone's own name servers with the same rules (authority.go): a record just put in place counts as soon as every one of
// them serves it, not when the resolver's cached answer runs out.
//
// Every lookup has timeout. A lookup that fails (not "no such host") makes the answer Unchecked unless the other name proves it.
func Owned(ctx context.Context, r ProofResolver, domain, token string, timeout time.Duration) Proof {
	// Every name is asked rooted (a trailing dot), so the resolver's search list (resolv.conf "search lan") never applies: a name
	// with no address would otherwise be tried again as <name>.<search domain>, whose answer is not the domain's (review r2 L3 of #941).
	p := owned(domain, token, source{
		txt: func(name string) ([]string, []string, error) {
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			v, err := r.LookupTXT(c, name+".")
			return v, v, err
		},
		cname: func(name string) (bool, error) {
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			cn, err := r.LookupCNAME(c, name+".")
			cn = strings.ToLower(strings.TrimRight(strings.TrimSpace(cn), "."))
			switch {
			case err != nil && !notFound(err):
				return false, err
			case err == nil && cn != "" && cn != name:
				return true, nil
			}
			return false, nil
		},
	}, nil)
	a, ok := r.(Authority)
	if p.At != "" || !ok {
		return p
	}
	answers := map[string]AuthAnswer{} // one question per name: its TXT values and its CNAME come in the same answer (owned asks in turn)
	ask := func(name string) (AuthAnswer, error) {
		if got, ok := answers[name]; ok {
			return got, nil
		}
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		got, err := a.AuthTXT(c, name+".")
		if err != nil {
			return AuthAnswer{}, err
		}
		answers[name] = got
		return got, nil
	}
	var servers []string
	ap := owned(domain, token, source{
		txt: func(name string) ([]string, []string, error) {
			got, err := ask(name)
			return got.TXT, got.Some, err
		},
		cname: func(name string) (bool, error) {
			got, err := ask(name)
			return got.CNAME, err
		},
	}, func(name string) {
		if got, ok := answers[name]; ok {
			for _, s := range got.Servers {
				if !slices.Contains(servers, s) {
					servers = append(servers, s)
				}
			}
		}
	})
	slices.Sort(servers)
	if ap.At != "" {
		ap.Authoritative, ap.Servers = true, servers
		return ap
	}
	// The resolver's verdict stands (fail closed); what the zone's servers said goes with it.
	p.Servers, p.Propagating = servers, ap.Propagating
	if ap.Refused && !p.Refused {
		p.Refused, p.Detail = true, ap.Detail
	}
	return p
}

// owned applies the rule of Owned to one source. seen, when set, is told each name of domain asked (not the random sibling).
func owned(domain, token string, src source, seen func(name string)) Proof {
	want := "vedette-verify=" + token
	has := func(vals []string) bool {
		return slices.ContainsFunc(vals, func(v string) bool { return strings.TrimSpace(v) == want })
	}
	names := []string{domain}
	if alt := VerifyLabel + "." + domain; len(alt) <= 253 {
		names = append(names, alt)
	}
	failed, why, propagating := "", "", false
	for i, at := range names {
		vals, some, err := src.txt(at)
		if seen != nil {
			seen(at)
		}
		switch {
		case err != nil && !notFound(err):
			failed = at
			continue
		case !has(vals):
			propagating = propagating || has(some)
			continue
		}
		isCNAME, err := src.cname(at)
		switch {
		case err != nil:
			failed = at
			continue
		case isCNAME:
			why = at + " is a CNAME to another name, so its TXT record is not its own"
			continue
		}
		if i == 1 {
			sib := VerifyLabel + "-" + randomLabel() + "." + domain
			if len(sib) <= 253 {
				_, ssome, err := src.txt(sib)
				switch {
				case err != nil && !notFound(err):
					failed = at
					continue
				case has(ssome): // any server answering the random name with the value is a wildcard
					why = at + " answers through a wildcard (a random name beside it gives the same record)"
					continue
				}
			}
		}
		return Proof{At: at}
	}
	if failed != "" {
		return Proof{Unchecked: true, Detail: "the DNS lookup at " + failed + " failed", Propagating: propagating}
	}
	if why != "" {
		return Proof{Refused: true, Detail: why, Propagating: propagating}
	}
	return Proof{Detail: strings.Join(names, " and ") + " have no TXT record vedette-verify=<the token>", Propagating: propagating}
}

// randomLabel is 16 random hex digits: the sibling name of the wildcard check.
func randomLabel() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b)
}

// notFound is the resolver's "no such name / no such record" (*net.DNSError IsNotFound): an answer, not a failure.
func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// Watch re-checks j (without the cache) on every value of ticks (every Recheck in production) until ctx ends. The first answer that
// is not a yes calls stop and is returned; a zero Outcome means ctx ended first (the tool finished, was stopped or ran out of time).
func (f *Fence) Watch(ctx context.Context, j Job, ticks <-chan time.Time, stop func()) Outcome {
	for {
		select {
		case <-ctx.Done():
			return Outcome{}
		case <-ticks:
		}
		o := f.Check(ctx, j, false)
		if ctx.Err() != nil {
			return Outcome{}
		}
		if o.Reason != "" {
			stop()
			return o
		}
	}
}

// LoadKey reads a fence key: a regular file (not a link) of exactly KeySize bytes.
func LoadKey(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("domainfence: the key: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() != KeySize {
		return nil, fmt.Errorf("domainfence: the key %s is not a regular file of %d bytes", path, KeySize)
	}
	b, err := os.ReadFile(path) //nolint:gosec // the path is the process's own configuration, Lstat-ed as a regular file above
	if err != nil {
		return nil, fmt.Errorf("domainfence: the key: %w", err)
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("domainfence: the key %s is not %d bytes", path, KeySize)
	}
	return b, nil
}

// MaxListSize bounds the domain list file the executors read (MaxDomains lines of at most 253 bytes, with room).
const MaxListSize = 64 << 10

// ParseList reads a domain list: one domain of the grammar per line, nothing else. A line that is not one fails the whole list.
func ParseList(b []byte) (map[string]bool, error) {
	if len(b) > MaxListSize {
		return nil, errors.New("domainfence: the domain list is too large")
	}
	out := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "" && len(b) == 0 {
			break
		}
		if !ValidDomain(l) {
			return nil, fmt.Errorf("domainfence: the domain list holds %.60q, not a domain name", l)
		}
		out[l] = true
	}
	return out, nil
}

// ParseIPList reads the typed-IP list: one canonical public IPv4 address per line, nothing else.
func ParseIPList(b []byte) (map[string]bool, error) {
	if len(b) > MaxListSize {
		return nil, errors.New("domainfence: the IP list is too large")
	}
	out := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "" && len(b) == 0 {
			break
		}
		if !ValidIPLiteral(l) {
			return nil, fmt.Errorf("domainfence: the IP list holds %.60q, not a public IPv4 address", l)
		}
		out[l] = true
	}
	return out, nil
}

// ListText is the file form of a domain list: sorted, one per line.
func ListText(domains map[string]bool) []byte {
	l := make([]string, 0, len(domains))
	for d := range domains {
		l = append(l, d)
	}
	slices.Sort(l)
	if len(l) == 0 {
		return nil
	}
	return []byte(strings.Join(l, "\n") + "\n")
}

// FileList is a listed func over a list file (the scan container's read-only copy): the file is read again at every check, so a
// domain the host adds counts at once. A copy that cannot be read (missing, not a regular file, not a list) is read once more after a
// second (review r2 L-2: the host replaces it by a rename, and a re-check of a running scan must not be killed by an instant of it),
// and then lists nothing (fail closed).
func FileList(path string) func(domain string) bool {
	return fileList(path, ParseList, func() { <-time.After(time.Second) })
}

// FileLists is a listed func over the domain list file and the typed-IP list file beside it (an IP literal is looked up in the second,
// a domain in the first): the IPs have a file of their own so a scan container older than the typed-IP check keeps parsing the domain list.
func FileLists(domains, ips string) func(domain string) bool {
	d := FileList(domains)
	i := fileList(ips, ParseIPList, func() { <-time.After(time.Second) })
	return func(name string) bool {
		if ValidIPLiteral(name) {
			return i(name)
		}
		return d(name)
	}
}

func fileList(path string, parse func([]byte) (map[string]bool, error), wait func()) func(domain string) bool {
	return func(domain string) bool {
		l, err := readList(path, parse)
		if err != nil {
			wait()
			l, err = readList(path, parse)
		}
		return err == nil && l[domain]
	}
}

func readList(path string, parse func([]byte) (map[string]bool, error)) (map[string]bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxListSize {
		return nil, errors.New("domainfence: the domain list is not a regular file of a sane size")
	}
	b, err := os.ReadFile(path) //nolint:gosec // the process's own configured path, Lstat-ed as a regular file above
	if err != nil {
		return nil, err
	}
	return parse(b)
}

// NewKey is KeySize random bytes.
func NewKey() []byte {
	b := make([]byte, KeySize)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return b
}

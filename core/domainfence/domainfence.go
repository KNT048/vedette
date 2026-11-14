// Package domainfence is the executors' half of the domain fence (FULL-5 slice 2, D-591, plan 2026-11-14 §5): the check the scan
// container's worker (nmap, nuclei) and vedette-host (ZAP, OpenVAS) make on their own, right before a tool starts on a public address
// that is not the box's own egress, because a name under a verified domain resolves to it. Core is not trusted for any of it: the
// token it sends must be the one this box derives from its fence key (a TXT value is public, so another customer's visible token
// would otherwise pass), the domain's TXT record must carry it now, and the name must resolve to the address now. Core never holds
// the key (vedette-host makes it, the scan container gets it read-only, core's container never mounts it).
//
// It is a leaf: the standard library and core/localnet only, because the sensor binary links it (TestBinaryDependencies there).
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

	"github.com/knt048/vedette/core/localnet"
)

const (
	// KeySize is the length of the fence key: 32 random bytes.
	KeySize = 32
	// TokenLen is the length of a box-bound token: the first 16 hex digits of the HMAC (64 bits), the length of every domain token
	// exposure stores (exp_target's CHECK since migration 0001; D-591 says why not 32).
	TokenLen = 16
	// CacheFor is how long a yes stands for one (domain, name, ip): a run of many nuclei jobs or ZAP pages asks DNS once in it.
	CacheFor = 5 * time.Minute
	// LookupTimeout bounds each DNS lookup of a check.
	LookupTimeout = 10 * time.Second
	// Recheck is how often a long run (a deep nmap, an OpenVAS task) checks again while it runs: the own_ip re-check's period.
	Recheck = 3 * time.Minute
	// tokenLabel is what the HMAC is taken over, before the domain (plan §5).
	tokenLabel = "vedette-verify\x00" //nolint:gosec // the public label the HMAC is taken over, not a credential
)

// The refusal reasons (sensor-protocol.md 6.5, host-api §6.16). Every one means nothing was sent.
const (
	InvalidJob   = "invalid_job"         // the job's fields are not of the grammar
	TokenForeign = "token_foreign"       // the token is not this box's for the domain (another box's, or a token made before the fence)
	NotOwned     = "target_not_owned"    // the domain's TXT records do not carry vedette-verify=<token> now
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
}

// Valid is point 1 of the check, the grammar: the domain, a name that is the domain or under it, a public IPv4 address
// (localnet.Public, the own_ip rule), a token of 16 lower-case hex digits.
func (j Job) Valid() error {
	switch {
	case !ValidDomain(j.Domain):
		return errors.New("the domain is not a domain name")
	case !Under(j.Name, j.Domain):
		return errors.New("the name is not the domain or a name under it")
	case !j.IP.Is4() || !localnet.Public(j.IP):
		return errors.New("the address is not a public IPv4 address")
	case !tokenRE.MatchString(j.Token):
		return errors.New("the token is not 16 hex digits")
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
	domain, name string
	ip           netip.Addr
}

type cacheEntry struct {
	at    time.Time
	chain []string
	out   bool // the canonical name is outside the domain
}

// Fence checks domain_ip jobs. Create it with New.
type Fence struct {
	key []byte
	r   Resolver
	now func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

// New builds a Fence over key (KeySize bytes) and r. now nil means time.Now.
func New(key []byte, r Resolver, now func() time.Time) (*Fence, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("domainfence: the key must be %d bytes, got %d", KeySize, len(key))
	}
	if r == nil {
		return nil, errors.New("domainfence: a resolver is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Fence{key: slices.Clone(key), r: r, now: now, cache: map[cacheKey]cacheEntry{}}, nil
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
	k := cacheKey{j.Domain, j.Name, j.IP}
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
	lookup := func(fn func(context.Context) error) error {
		lctx, cancel := context.WithTimeout(ctx, LookupTimeout)
		defer cancel()
		return fn(lctx)
	}
	var txt []string
	err := lookup(func(c context.Context) (err error) { txt, err = f.r.LookupTXT(c, j.Domain); return })
	if err != nil && !notFound(err) {
		return Outcome{Reason: Unchecked, Detail: "the TXT lookup of " + j.Domain + " failed"}, cacheEntry{}
	}
	if !slices.ContainsFunc(txt, func(v string) bool { return strings.TrimSpace(v) == "vedette-verify="+j.Token }) {
		return Outcome{Reason: NotOwned, Detail: j.Domain + " has no TXT record vedette-verify=<this box's token>"}, cacheEntry{}
	}
	var addrs []netip.Addr
	err = lookup(func(c context.Context) (err error) { addrs, err = f.r.LookupNetIP(c, "ip4", j.Name); return })
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
	e := cacheEntry{chain: chain, out: !Under(chain[len(chain)-1], j.Domain)}
	if j.Disruptive && e.out {
		return Outcome{Reason: CNAMEOutside, Chain: chain, Detail: j.Name + " points (CNAME) outside " + j.Domain}, e
	}
	return Outcome{Chain: chain}, e
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

// NewKey is KeySize random bytes.
func NewKey() []byte {
	b := make([]byte, KeySize)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return b
}

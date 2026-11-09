package auth

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// Login rate limit (API_CONVENTIONS section 8): 10 failures with less than 15 quiet minutes between them for
// one (IP, email) pair, then a wait that doubles with every further failure (30 s, 1 min, 2 min, ... at most 10 min). Blocked attempts
// are refused before any password work and do not count, so hammering cannot extend the wait.
//
// A guess is counted when it starts (begin) and given back when the password turns out right (refund), not
// counted after the check: otherwise parallel guesses would all pass the check before any is recorded.
// An IPv6 client is counted twice: per address (10, like IPv4) and per /64 with the same email (100), so
// one host rotating inside its /64 is still bounded, but it cannot lock the whole /64 out with 10 guesses.
// The second-step code has its own per-account counter (twofaKey, no IP): rotating the source address does
// not reset it. Account counters (twofaKey, accountKey) live in a map of their own that is never evicted:
// it is as small as the number of users, and flooding the client map must not reset a guess limit.
const (
	loginMaxFailures = 10
	netMaxFailures   = 100 // per (IPv6 /64, email); see netKeySuffix
	loginWindow      = 15 * time.Minute
	loginBaseWait    = 30 * time.Second
	loginMaxWait     = 10 * time.Minute // below loginWindow, so waiting it out never resets the count
	limiterMaxKeys   = 10_000

	// twofaKey and accountKey are the "IP" part of the per-account limiters: two-step codes, and the
	// password a signed-in user types for a sensitive change.
	twofaKey   = "twofa"
	accountKey = "account"
	// setupCeiling is the most guesses of the first-run setup code the whole box accepts in setupCeilingWindow
	// (D-75): a safety net far above what an owner types, not the per-client limit.
	setupCeiling       = 1000
	setupCeilingWindow = time.Hour
	// deviceKeyPrefix starts the "IP" part of a limiter key that belongs to one device cookie (D-77).
	deviceKeyPrefix = "dev:"
	// netKeySuffix marks a per-/64 key (made by ipLimitKeys); it gets the higher limit.
	netKeySuffix = "/64"
)

type failures struct {
	count        int
	max          int
	last         time.Time // the newest failure
	blockedUntil time.Time
}

// limiter keeps the failure counts in memory.
// ponytail: counts reset on restart and are per process; an attacker who can flood 10,000 distinct
// (IP, email) pairs can evict client entries (the ones with the fewest failures go first). Upgrade path: a
// core_login_failure table pruned by a job.
type limiter struct {
	mu   sync.Mutex
	now  func() time.Time
	m    map[string]*failures // clients: evictable
	acct map[string]*failures // accounts: never evicted

	ceilingFrom time.Time // start of the current hour of setup guesses (beginCeiling)
	ceilingN    int
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, m: map[string]*failures{}, acct: map[string]*failures{}}
}

func limiterKey(ip, email string) string {
	email = strings.ToLower(email)
	if len(email) > 320 {
		email = email[:320]
	}
	return ip + "|" + email
}

func (l *limiter) mapFor(ip string) map[string]*failures {
	if isAcct(ip) {
		return l.acct
	}
	return l.m
}

func maxFor(ip string) int {
	if strings.HasSuffix(ip, netKeySuffix) {
		return netMaxFailures
	}
	return loginMaxFailures
}

// check returns a 429 rate_limited error while the pair is blocked, else nil.
func (l *limiter) check(ip, email string) *apierr.Error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.mapFor(ip)[limiterKey(ip, email)]
	if f == nil {
		return nil
	}
	now := l.now()
	if now.Before(f.blockedUntil) {
		return rateLimited(f.blockedUntil.Sub(now))
	}
	return nil
}

// attempt is one counted guess, to give back with refund.
type attempt struct {
	l         *limiter
	ip, email string
	setBlock  time.Time // the wait this begin set, zero when it set none
	prevBlock time.Time // what the wait was before
}

// begin is check plus counting the attempt as a failure right away, under one lock, so that a burst of
// parallel guesses cannot all pass the check. Call refund when the guess was right.
func (l *limiter) begin(ip, email string) (attempt, *apierr.Error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := attempt{l: l, ip: ip, email: email}
	if f := l.mapFor(ip)[limiterKey(ip, email)]; f != nil {
		if now := l.now(); now.Before(f.blockedUntil) {
			return a, rateLimited(f.blockedUntil.Sub(now))
		}
		a.prevBlock = f.blockedUntil
	}
	a.setBlock = l.failLocked(ip, email)
	return a, nil
}

// beginAll begins the attempt on every key (the client keys of one request); when one of them is blocked,
// the ones already counted are given back and the 429 is returned.
func (l *limiter) beginAll(email string, ips []string) ([]attempt, *apierr.Error) {
	done := make([]attempt, 0, len(ips))
	for _, ip := range ips {
		a, e := l.begin(ip, email)
		if e != nil {
			refundAll(done)
			return nil, e
		}
		done = append(done, a)
	}
	return done, nil
}

func refundAll(as []attempt) {
	for _, a := range as {
		a.refund()
	}
}

// refund takes back the count of one begin whose guess was right (or was not judged at all). A wait that
// this begin set is lifted again (to what it was), unless another failure has moved it since; an entry
// whose count is back to zero is dropped.
func (a attempt) refund() {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	m, key := l.mapFor(a.ip), limiterKey(a.ip, a.email)
	f := m[key]
	if f == nil {
		return
	}
	if f.count > 0 {
		f.count--
	}
	if !a.setBlock.IsZero() && f.blockedUntil.Equal(a.setBlock) {
		f.blockedUntil = a.prevBlock
	}
	if f.count == 0 && !l.now().Before(f.blockedUntil) {
		delete(m, key)
	}
}

// fail records a failed attempt.
func (l *limiter) fail(ip, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failLocked(ip, email)
}

func (l *limiter) failAll(email string, ips []string) {
	for _, ip := range ips {
		l.fail(ip, email)
	}
}

// failLocked counts one failure and returns the new wait when it set one (zero otherwise).
func (l *limiter) failLocked(ip, email string) time.Time {
	now := l.now()
	m, key := l.mapFor(ip), limiterKey(ip, email)
	f := m[key]
	if f == nil {
		if len(m) >= limiterMaxKeys && !isAcct(ip) {
			l.evictLocked(now)
		}
		f = &failures{last: now, max: maxFor(ip)}
		m[key] = f
	}
	if now.Sub(f.last) > loginWindow {
		f.count = 0 // a quiet window: start over
	}
	f.last = now
	f.count++
	if over := f.count - f.max; over >= 0 {
		wait := loginMaxWait
		if over < 6 { // 30 s << 5 = 16 min, already above the cap
			wait = min(loginMaxWait, loginBaseWait<<over)
		}
		f.blockedUntil = now.Add(wait)
		return f.blockedUntil
	}
	return time.Time{}
}

func isAcct(ip string) bool { return ip == twofaKey || ip == accountKey }

// reset forgets the pair after a successful sign-in.
func (l *limiter) reset(ip, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.mapFor(ip), limiterKey(ip, email))
}

func (l *limiter) resetAll(email string, ips []string) {
	for _, ip := range ips {
		l.reset(ip, email)
	}
}

// evictLocked makes room in the client map: drop expired entries first; if it is still full, drop a tenth
// of it, entries that are not waiting first and, among them, the fewest failures first (an attacker's
// one-failure junk goes before a real attack in progress).
func (l *limiter) evictLocked(now time.Time) {
	for k, f := range l.m {
		if now.Sub(f.last) > loginWindow && !now.Before(f.blockedUntil) {
			delete(l.m, k)
		}
	}
	if len(l.m) < limiterMaxKeys {
		return
	}
	type cand struct {
		key     string
		blocked bool
		count   int
	}
	all := make([]cand, 0, len(l.m))
	for k, f := range l.m {
		all = append(all, cand{k, now.Before(f.blockedUntil), f.count})
	}
	slices.SortFunc(all, func(a, b cand) int {
		if a.blocked != b.blocked {
			if a.blocked {
				return 1
			}
			return -1
		}
		return a.count - b.count
	})
	for _, c := range all[:len(all)-limiterMaxKeys*9/10] {
		delete(l.m, c.key)
	}
}

func rateLimited(wait time.Duration) *apierr.Error {
	secs := int((wait + time.Second - 1) / time.Second)
	return apierr.New(429, CodeRateLimited, fmt.Sprintf("Too many failed sign-in attempts. Try again in %s.", humanWait(secs))).With("retry_after", secs)
}

func humanWait(secs int) string {
	if secs < 60 {
		return fmt.Sprintf("%d seconds", secs)
	}
	m := (secs + 59) / 60
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

// BeginSetupAttempt counts one guess of the first-run setup code (D-75) before it is judged: per client
// address like a sign-in (the address, and for IPv6 its /64, with the same limits and growing wait), and
// against a high ceiling for the whole box (setupCeiling guesses an hour) as a safety net. One shared
// counter at the sign-in limit would let any stranger who reaches the port keep setup closed for the
// owner; a 100-bit code needs no global cap to resist guessing. It returns a refund to call when the guess
// was right (or never judged), or 429 rate_limited.
func (s *Service) BeginSetupAttempt(ip netip.Addr) (refund func(), err error) {
	if !ip.IsValid() {
		return nil, errNoIP()
	}
	if e := s.limit.beginCeiling(); e != nil {
		return nil, e
	}
	as, e := s.limit.beginAll("code", ipLimitKeys(ip))
	if e != nil {
		s.limit.refundCeiling()
		return nil, e
	}
	return func() {
		refundAll(as)
		s.limit.refundCeiling()
	}, nil
}

// beginCeiling counts one setup guess against the box-wide ceiling of an hour.
func (l *limiter) beginCeiling() *apierr.Error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.ceilingFrom.IsZero() || now.Sub(l.ceilingFrom) >= setupCeilingWindow {
		l.ceilingFrom, l.ceilingN = now, 0
	}
	if l.ceilingN >= setupCeiling {
		return rateLimited(l.ceilingFrom.Add(setupCeilingWindow).Sub(now))
	}
	l.ceilingN++
	return nil
}

func (l *limiter) refundCeiling() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ceilingN > 0 {
		l.ceilingN--
	}
}

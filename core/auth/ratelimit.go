package auth

import (
	"fmt"
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
// The second-step code has its own per-account counter (twofaKey, no IP): rotating the source address does
// not reset it.
const (
	loginMaxFailures = 10
	loginWindow      = 15 * time.Minute
	loginBaseWait    = 30 * time.Second
	loginMaxWait     = 10 * time.Minute // below loginWindow, so waiting it out never resets the count
	limiterMaxKeys   = 10_000
)

type failures struct {
	count        int
	last         time.Time // the newest failure
	blockedUntil time.Time
}

// limiter keeps the failure counts in memory.
// ponytail: counts reset on restart and are per process; an attacker who can flood 10,000 distinct
// (IP, email) pairs can evict entries. Upgrade path: a core_login_failure table pruned by a job.
type limiter struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*failures
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, m: map[string]*failures{}}
}

func limiterKey(ip, email string) string {
	email = strings.ToLower(email)
	if len(email) > 320 {
		email = email[:320]
	}
	return ip + "|" + email
}

// check returns a 429 rate_limited error while the pair is blocked, else nil.
func (l *limiter) check(ip, email string) *apierr.Error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[limiterKey(ip, email)]
	if f == nil {
		return nil
	}
	now := l.now()
	if now.Before(f.blockedUntil) {
		return rateLimited(f.blockedUntil.Sub(now))
	}
	return nil
}

// twofaKey is the "IP" part of the per-account limiter of two-step codes.
const twofaKey = "twofa"

// begin is check plus counting the attempt as a failure right away, under one lock, so that a burst of
// parallel guesses cannot all pass the check. Call refund when the guess was right.
func (l *limiter) begin(ip, email string) *apierr.Error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.m[limiterKey(ip, email)]; f != nil {
		if now := l.now(); now.Before(f.blockedUntil) {
			return rateLimited(f.blockedUntil.Sub(now))
		}
	}
	l.failLocked(ip, email)
	return nil
}

// refund takes back the count of one begin whose guess was right (or was not judged at all). The wait that
// begin may have set goes with it when the count is back under the limit.
func (l *limiter) refund(ip, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[limiterKey(ip, email)]
	if f == nil {
		return
	}
	if f.count > 0 {
		f.count--
	}
	if f.count < loginMaxFailures {
		f.blockedUntil = time.Time{}
	}
}

// fail records a failed attempt.
func (l *limiter) fail(ip, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failLocked(ip, email)
}

func (l *limiter) failLocked(ip, email string) {
	now := l.now()
	key := limiterKey(ip, email)
	f := l.m[key]
	if f == nil {
		l.evictLocked(now)
		f = &failures{last: now}
		l.m[key] = f
	}
	if now.Sub(f.last) > loginWindow {
		f.count = 0 // a quiet window: start over
	}
	f.last = now
	f.count++
	if over := f.count - loginMaxFailures; over >= 0 {
		wait := loginMaxWait
		if over < 6 { // 30 s << 5 = 16 min, already above the cap
			wait = min(loginMaxWait, loginBaseWait<<over)
		}
		f.blockedUntil = now.Add(wait)
	}
}

// reset forgets the pair after a successful sign-in.
func (l *limiter) reset(ip, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, limiterKey(ip, email))
}

// evictLocked makes room: drop expired entries first, then arbitrary ones.
func (l *limiter) evictLocked(now time.Time) {
	if len(l.m) < limiterMaxKeys {
		return
	}
	for k, f := range l.m {
		if now.Sub(f.last) > loginWindow && !now.Before(f.blockedUntil) {
			delete(l.m, k)
		}
	}
	for k := range l.m {
		if len(l.m) < limiterMaxKeys {
			return
		}
		delete(l.m, k)
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

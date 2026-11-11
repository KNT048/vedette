package mcpserver

import (
	"context"
	"sync"
	"time"
)

// Limits of one token (D-232). The minute bucket keeps a looping agent from hammering the box and counts every authenticated
// request, refused or not; the daily cap bounds the audit rows one token can write (MaxTokens x callsPerDay rows a day at
// most). ponytail: in memory, so a restart resets the counts; upgrade path: keep the day's count in mcp_tokens if a restart
// loop ever matters.
const (
	burst        = 30   // requests at once
	perMinute    = 30   // refill of the bucket
	callsPerDay  = 2000 // tool calls per token per UTC day
	maxInFlight  = 4    // requests being answered at once, all tokens together
	maxPerToken  = 2    // of which one token may hold
	slotWait     = 2 * time.Second
	slotWaitStep = 20 * time.Millisecond
)

type bucket struct {
	tokens   float64
	at       time.Time
	day      string
	calls    int
	inFlight int
}

type limiter struct {
	now      func() time.Time
	mu       sync.Mutex
	b        map[string]*bucket
	inFlight int
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, b: map[string]*bucket{}}
}

func (l *limiter) bucket(id string, now time.Time) *bucket {
	b := l.b[id]
	if b == nil {
		b = &bucket{tokens: burst, at: now}
		l.b[id] = b
	}
	if d := now.Sub(b.at); d > 0 { // a clock that steps back refills nothing and takes nothing
		b.tokens = min(burst, b.tokens+d.Minutes()*perMinute)
		b.at = now
	}
	if day := now.UTC().Format(time.DateOnly); b.day != day {
		b.day, b.calls = day, 0
	}
	return b
}

// allow takes one request of token id from its bucket. When it refuses, retry is how long to wait.
func (l *limiter) allow(id string) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket(id, l.now())
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / perMinute * float64(time.Minute))
	}
	b.tokens--
	return true, 0
}

// call counts one tool call toward the token's daily cap; past it, retry is the time until the next UTC day.
func (l *limiter) call(id string) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.bucket(id, now)
	if b.calls >= callsPerDay {
		return false, now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour).Sub(now)
	}
	b.calls++
	return true, 0
}

// acquire waits up to slotWait for a free answer slot (maxInFlight in all, maxPerToken for one token) and returns its
// release; ok is false when none freed up. A slot is taken only after the body is read, so a slow sender holds none.
func (l *limiter) acquire(ctx context.Context, id string) (release func(), ok bool) {
	deadline := time.Now().Add(slotWait)
	for {
		l.mu.Lock()
		b := l.b[id]
		if b != nil && l.inFlight < maxInFlight && b.inFlight < maxPerToken {
			l.inFlight++
			b.inFlight++
			l.mu.Unlock()
			return func() {
				l.mu.Lock()
				l.inFlight--
				b.inFlight--
				l.mu.Unlock()
			}, true
		}
		l.mu.Unlock()
		if b == nil || time.Now().After(deadline) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(slotWaitStep):
		}
	}
}

// forget drops the counters of a token that no longer exists.
func (l *limiter) forget(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.b[id]; b != nil && b.inFlight == 0 {
		delete(l.b, id)
	}
}

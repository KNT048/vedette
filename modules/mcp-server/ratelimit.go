package mcpserver

import (
	"sync"
	"time"
)

// Limits of one token (D-232). The minute bucket keeps a looping agent from hammering the box; the daily cap bounds the audit
// rows one token can write (MaxTokens x callsPerDay rows a day at most). ponytail: in memory, so a restart resets the counts;
// upgrade path: keep the day's count in mcp_tokens if a restart loop ever matters.
const (
	burst       = 30   // requests at once
	perMinute   = 30   // refill of the bucket
	callsPerDay = 2000 // tool calls per token per UTC day
	maxInFlight = 4    // requests served at once, all tokens together
)

type bucket struct {
	tokens float64
	at     time.Time
	day    string
	calls  int
}

type limiter struct {
	now      func() time.Time
	mu       sync.Mutex
	b        map[string]*bucket
	inFlight chan struct{}
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, b: map[string]*bucket{}, inFlight: make(chan struct{}, maxInFlight)}
}

// allow takes one request of token id from its bucket; call is true for a tool call, which also counts toward the daily cap.
// When it refuses, retry is how long to wait.
func (l *limiter) allow(id string, call bool) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.b[id]
	if b == nil {
		b = &bucket{tokens: burst, at: now}
		l.b[id] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Minutes()*perMinute)
	b.at = now
	if day := now.UTC().Format(time.DateOnly); b.day != day {
		b.day, b.calls = day, 0
	}
	if call && b.calls >= callsPerDay {
		next := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		return false, next.Sub(now)
	}
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / perMinute * float64(time.Minute))
	}
	b.tokens--
	if call {
		b.calls++
	}
	return true, 0
}

// forget drops the counters of a token that no longer exists.
func (l *limiter) forget(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.b, id)
}

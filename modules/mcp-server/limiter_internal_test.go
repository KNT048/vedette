package mcpserver

import (
	"testing"
	"time"
)

// Review M2: one token holds at most maxPerToken answer slots, all tokens maxInFlight; a full server waits up to slotWait,
// and a slot freed while waiting is taken.
func TestContract_AnswerSlots(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	l := newLimiter(func() time.Time { return now })
	for _, id := range []string{"a", "b", "c"} {
		l.allow(id)
	}
	var held []func()
	for range maxPerToken {
		rel, ok := l.acquire(t.Context(), "a")
		if !ok {
			t.Fatal("a could not take its slots")
		}
		held = append(held, rel)
	}
	start := time.Now()
	if _, ok := l.acquire(t.Context(), "a"); ok {
		t.Fatal("a took a third slot")
	}
	if waited := time.Since(start); waited < slotWait-100*time.Millisecond {
		t.Fatalf("gave up after %v, not %v", waited, slotWait)
	}
	for range maxInFlight - maxPerToken {
		rel, ok := l.acquire(t.Context(), "b")
		if !ok {
			t.Fatal("b found no slot while a held only its share")
		}
		held = append(held, rel)
	}
	go func() { <-time.After(200 * time.Millisecond); held[0]() }()
	if rel, ok := l.acquire(t.Context(), "c"); !ok {
		t.Fatal("c did not get the slot freed while it waited")
	} else {
		rel()
	}
	if _, ok := l.acquire(t.Context(), "unknown"); ok {
		t.Fatal("a token with no bucket took a slot")
	}
}

// A clock that steps back neither refills nor drains the bucket; the daily cap resets at the UTC day.
func TestContract_LimiterClock(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 11, 23, 59, 0, 0, time.UTC)
	l := newLimiter(func() time.Time { return now })
	for range burst {
		if ok, _ := l.allow("a"); !ok {
			t.Fatal("burst refused")
		}
	}
	now = now.Add(-time.Hour)
	if ok, _ := l.allow("a"); ok {
		t.Fatal("a step back refilled the bucket")
	}
	now = now.Add(time.Hour)
	for range callsPerDay {
		l.call("a")
	}
	if ok, retry := l.call("a"); ok || retry != time.Minute {
		t.Fatalf("over the cap: %v %v", ok, retry)
	}
	now = now.Add(time.Minute)
	if ok, _ := l.call("a"); !ok {
		t.Fatal("the cap did not reset at the UTC day")
	}
}

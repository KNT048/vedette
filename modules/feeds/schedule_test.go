package feeds

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

func TestBackoffDoublesAndCaps(t *testing.T) {
	t.Parallel()
	want := map[int]time.Duration{
		0: 0, -3: 0, 1: 5 * time.Minute, 2: 10 * time.Minute, 3: 20 * time.Minute, 4: 40 * time.Minute,
		5: 80 * time.Minute, 6: 160 * time.Minute, 7: 320 * time.Minute, 8: BackoffMax, 20: BackoffMax, 1 << 30: BackoffMax,
	}
	for n, d := range want {
		if got := Backoff(n); got != d {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, d)
		}
	}
}

func TestContract_INV8_ErrorBacksOffAndSuccessResets(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	var s State
	if !s.Due(t0, 6) || !s.NextAttempt(6).IsZero() {
		t.Fatal("a feed never pulled is due immediately")
	}
	s = s.Record(t0, nil)
	if got := s.NextAttempt(6); !got.Equal(t0.Add(6 * time.Hour)) {
		t.Fatalf("after success: %v", got)
	}
	if s.Due(t0.Add(6*time.Hour-time.Second), 6) || !s.Due(t0.Add(6*time.Hour), 6) {
		t.Error("due boundary")
	}
	now := t0.Add(6 * time.Hour)
	var delays []time.Duration
	for i := 0; i < 5; i++ {
		s = s.Record(now, boom)
		next := s.NextAttempt(24)
		delays = append(delays, next.Sub(now))
		if s.Due(next.Add(-time.Second), 24) || !s.Due(next, 24) {
			t.Fatalf("failure %d: due boundary", i+1)
		}
		now = next
	}
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute}
	for i := range want {
		if delays[i] != want[i] {
			t.Errorf("delays = %v", delays)
			break
		}
	}
	if !s.LastSuccess.Equal(t0) || s.Failures != 5 {
		t.Errorf("state = %+v", s)
	}
	s = s.Record(now, nil)
	if s.Failures != 0 || !s.NextAttempt(24).Equal(now.Add(24*time.Hour)) {
		t.Errorf("success must reset: %+v", s)
	}
}

func TestBackoffNeverExceedsTheInterval(t *testing.T) {
	t.Parallel()
	s := State{LastAttempt: t0, LastSuccess: t0.Add(-time.Hour), Failures: 7}
	if got := s.NextAttempt(1).Sub(t0); got != time.Hour {
		t.Errorf("1 h feed retried after %v", got)
	}
	if got := s.NextAttempt(24).Sub(t0); got != 320*time.Minute {
		t.Errorf("24 h feed retried after %v", got)
	}
	// A feed whose very first pull failed is retried by back-off, not at once or never.
	first := State{}.Record(t0, errors.New("x"))
	if got := first.NextAttempt(6).Sub(t0); got != 5*time.Minute {
		t.Errorf("first failure: %v", got)
	}
}

func TestIntervalIsClamped(t *testing.T) {
	t.Parallel()
	s := State{LastSuccess: t0, LastAttempt: t0}
	if got := s.NextAttempt(0).Sub(t0); got != time.Hour {
		t.Errorf("0 h -> %v", got)
	}
	if got := s.NextAttempt(100000).Sub(t0); got != 168*time.Hour {
		t.Errorf("huge -> %v", got)
	}
}

func TestContract_INV9_Staleness(t *testing.T) {
	t.Parallel()
	last := t0
	cases := []struct {
		name  string
		now   time.Time
		hours int
		stale bool
	}{
		{"fresh", last.Add(30 * time.Minute), 1, false},
		{"exactly due", last.Add(time.Hour), 1, false},
		{"overdue by 60 min", last.Add(2 * time.Hour), 1, false},
		{"overdue by 61 min", last.Add(2*time.Hour + time.Minute), 1, true},
		{"daily feed, 23 h", last.Add(23 * time.Hour), 24, false},
		{"daily feed, 25 h 01 m", last.Add(25*time.Hour + time.Minute), 24, true},
	}
	for _, c := range cases {
		if got := IsStale(c.now, last, c.hours); got != c.stale {
			t.Errorf("%s: IsStale = %v", c.name, got)
		}
	}
	if !IsStale(t0, time.Time{}, 6) {
		t.Error("never fetched is stale")
	}
	// A job that follows NextAttempt keeps data within MaxDataAge of due while the source answers.
	var s State
	for now := t0; now.Before(t0.Add(72 * time.Hour)); now = now.Add(time.Minute) {
		if s.Due(now, 6) {
			s = s.Record(now, nil)
		}
		if s.Failures == 0 && !s.LastSuccess.IsZero() && IsStale(now, s.LastSuccess, 6) {
			t.Fatalf("stale at %v with a healthy source", now)
		}
	}
}

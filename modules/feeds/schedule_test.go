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
	if !s.Due(t0, 6, nil) {
		t.Fatal("a feed never pulled is due immediately")
	}
	s = s.Record(t0, nil)
	// After a success the regular pull is the schedule's: due only once it came due after that pull.
	if s.Due(t0.Add(6*time.Hour), 6, nil) {
		t.Error("a source with nothing due is not pulled")
	}
	before, after := t0.Add(-time.Minute), t0.Add(6*time.Hour)
	if s.Due(t0.Add(6*time.Hour), 6, &before) || !s.Due(t0.Add(6*time.Hour), 6, &after) {
		t.Error("due boundary: the schedule came due before the last pull, or after it")
	}
	now := t0.Add(6 * time.Hour)
	var delays []time.Duration
	for i := 0; i < 5; i++ {
		s = s.Record(now, boom)
		next := s.RetryAt(24)
		delays = append(delays, next.Sub(now))
		if s.Due(next.Add(-time.Second), 24, nil) || !s.Due(next, 24, nil) {
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
	if s.Failures != 0 || s.Due(now.Add(time.Hour), 24, nil) {
		t.Errorf("success must reset: %+v", s)
	}
}

func TestBackoffNeverExceedsTheInterval(t *testing.T) {
	t.Parallel()
	s := State{LastAttempt: t0, LastSuccess: t0.Add(-time.Hour), Failures: 7}
	if got := s.RetryAt(1).Sub(t0); got != time.Hour {
		t.Errorf("1 h feed retried after %v", got)
	}
	if got := s.RetryAt(24).Sub(t0); got != 320*time.Minute {
		t.Errorf("24 h feed retried after %v", got)
	}
	// A feed whose very first pull failed is retried by back-off, not at once or never.
	first := State{}.Record(t0, errors.New("x"))
	if got := first.RetryAt(6).Sub(t0); got != 5*time.Minute {
		t.Errorf("first failure: %v", got)
	}
}

func TestIntervalIsClamped(t *testing.T) {
	t.Parallel()
	s := State{LastSuccess: t0, LastAttempt: t0, Failures: 1}
	if got := s.RetryAt(0).Sub(t0); got != 5*time.Minute { // the interval floor (1 h) is above the first back-off
		t.Errorf("0 h -> %v", got)
	}
	s.Failures = 20
	if got := s.RetryAt(100000).Sub(t0); got != BackoffMax { // the interval ceiling (168 h) is above the back-off cap
		t.Errorf("huge -> %v", got)
	}
	if got := s.RetryAt(0).Sub(t0); got != time.Hour {
		t.Errorf("0 h with a long back-off -> %v", got)
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
	// A job that pulls when the schedule says keeps data within MaxDataAge of due while the source answers.
	var s State
	var lastDue *time.Time
	for now := t0; now.Before(t0.Add(72 * time.Hour)); now = now.Add(time.Minute) {
		if now.Sub(t0)%(6*time.Hour) == 0 { // the schedule's own rhythm
			d := now
			lastDue = &d
		}
		if s.Due(now, 6, lastDue) {
			s = s.Record(now, nil)
		}
		if s.Failures == 0 && !s.LastSuccess.IsZero() && IsStale(now, s.LastSuccess, 6) {
			t.Fatalf("stale at %v with a healthy source", now)
		}
	}
}

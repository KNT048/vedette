package feeds

import "time"

// Schedule rules as pure functions of an injected clock (INV-8, INV-9).
const (
	// BackoffBase is the first retry delay after a failed pull.
	BackoffBase = 5 * time.Minute
	// BackoffMax caps the retry delay (never longer than the feed's own interval).
	BackoffMax = 6 * time.Hour
	// MaxDataAge is INV-9: data should be at most 60 minutes old beyond the
	// moment its pull was due.
	MaxDataAge = 60 * time.Minute
)

// State is what the module remembers about a feed's pulls (feeds_fetch rows).
type State struct {
	LastSuccess time.Time // zero when never
	LastAttempt time.Time // zero when never
	Failures    int       // consecutive failures since the last success
}

// Record returns the state after a pull finished at now (err == nil is success,
// which resets the back-off).
func (s State) Record(now time.Time, err error) State {
	s.LastAttempt = now
	if err == nil {
		s.LastSuccess, s.Failures = now, 0
	} else {
		s.Failures++
	}
	return s
}

// Backoff is the retry delay after n consecutive failures: 5 min doubling,
// capped at BackoffMax.
func Backoff(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	shift := failures - 1
	if shift > 16 {
		shift = 16
	}
	d := BackoffBase << shift
	if d > BackoffMax || d <= 0 {
		d = BackoffMax
	}
	return d
}

func interval(hours int) time.Duration {
	if hours < 1 {
		hours = 1
	}
	if hours > 168 {
		hours = 168
	}
	return time.Duration(hours) * time.Hour
}

// NextAttempt is when the feed is next due. Never pulled: the zero time (due
// now). After a success: last success plus the interval. After failures: last
// attempt plus the back-off, which never exceeds the feed's interval.
func (s State) NextAttempt(intervalHours int) time.Time {
	iv := interval(intervalHours)
	if s.Failures > 0 {
		b := Backoff(s.Failures)
		if b > iv {
			b = iv
		}
		return s.LastAttempt.Add(b)
	}
	if s.LastSuccess.IsZero() {
		return time.Time{}
	}
	return s.LastSuccess.Add(iv)
}

// Due reports whether a pull should start at now. A success or attempt time in the
// future (a clock that was wrong) counts as due, so pulls never wait for the clock.
func (s State) Due(now time.Time, intervalHours int) bool {
	if s.LastSuccess.After(now) || s.LastAttempt.After(now) { // recorded while the clock was wrong
		return true
	}
	return !now.Before(s.NextAttempt(intervalHours))
}

// IsStale is the INV-9 check: an enabled feed is stale when its data is older
// than its interval plus MaxDataAge (the pull is overdue by more than an hour).
// A feed that never succeeded is stale.
func IsStale(now, lastSuccess time.Time, intervalHours int) bool {
	if lastSuccess.IsZero() || lastSuccess.After(now) { // never, or recorded while the clock was wrong
		return true
	}
	return now.Sub(lastSuccess) > interval(intervalHours)+MaxDataAge
}

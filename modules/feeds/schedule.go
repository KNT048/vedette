package feeds

import (
	"fmt"
	"time"
)

// The back-off after a failed pull and the staleness rule, as pure functions of an injected clock (INV-8, INV-9). When a feed is
// pulled regularly is its schedule (feedschedule.go).
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

// RetryAt is when a feed that failed is tried again: the last attempt plus the back-off, which never exceeds the feed's interval.
func (s State) RetryAt(intervalHours int) time.Time {
	iv := interval(intervalHours)
	b := Backoff(s.Failures)
	if b > iv {
		b = iv
	}
	return s.LastAttempt.Add(b)
}

// Due reports whether a pull should start at now. When the feed's last pull was a success the regular pull is the feed's schedule
// (core_schedule, feeds.source:<id>): lastDue is when it last came due, and the feed is due when that is after its last pull. A feed
// that never pulled is due at once, and one that failed is due when its back-off is over. A success or attempt time in the future (a
// clock that was wrong) counts as due, so pulls never wait for the clock.
func (s State) Due(now time.Time, intervalHours int, lastDue *time.Time) bool {
	if s.LastSuccess.After(now) || s.LastAttempt.After(now) { // recorded while the clock was wrong
		return true
	}
	if s.Failures > 0 {
		return !now.Before(s.RetryAt(intervalHours))
	}
	if s.LastSuccess.IsZero() {
		return true
	}
	last := s.LastSuccess
	if s.LastAttempt.After(last) {
		last = s.LastAttempt
	}
	return lastDue != nil && lastDue.After(last)
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

// fetchFloor is the earliest time a source that allows fewer downloads (Source.MinHours: Spamhaus DROP) may be asked again: MinHours
// after its last good pull, and never sooner than an hour after any attempt (Spamhaus: automated downloads at least an hour apart), a
// failed one included. ok is false for every other source.
func (r sourceRow) fetchFloor() (at time.Time, ok bool) {
	h := builtinMinHours(r.ID)
	if !r.Builtin || h == 0 {
		return time.Time{}, false
	}
	if r.LastSuccess != nil {
		at = r.LastSuccess.Add(time.Duration(h) * time.Hour)
	}
	if r.LastFetch != nil && r.LastFetch.Add(time.Hour).After(at) {
		at = r.LastFetch.Add(time.Hour)
	}
	return at, true
}

// builtinMinHours is Source.MinHours of a built-in source, 0 for any other id.
func builtinMinHours(id string) int {
	b, _ := BuiltinByID(id)
	return b.MinHours
}

// TooSoonError is a pull refused because the source allows fewer downloads (fetchFloor); nothing was asked. The text names the time
// the next pull is possible.
type TooSoonError struct {
	Name  string
	Hours int
	At    time.Time
}

func (e *TooSoonError) Error() string {
	return fmt.Sprintf("%s can be fetched once every %d hours, and the list on the box is still in use. Fetch it again after %s.",
		e.Name, e.Hours, e.At.UTC().Format("2 Jan 2006 15:04 UTC"))
}

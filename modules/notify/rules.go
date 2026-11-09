// Package notify is the library part of the notify module (WP-22a): delivery
// rules as pure functions (severity filter, quiet hours, grouping), the notice
// model, the send record and the email approval tokens. The channel adapters
// live in the channel subpackage. Nothing here touches a database or core;
// WP-22 wires these functions to them.
package notify

import (
	"errors"
	"fmt"
	"time"
)

// Severity is a notice severity (contract.ts Severity).
type Severity string

// Severities, highest first.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	case Info:
		return 0
	}
	return -1
}

// Valid reports whether s is one of the five severities.
func (s Severity) Valid() bool { return s.rank() >= 0 }

// MeetsMin implements INV-4: a channel receives a notice only when its severity
// is at least the channel's min_severity (critical|high|medium|low). An invalid
// severity or minimum never passes (fail closed), and "info" is below every
// possible minimum, so it is never sent to a channel.
func MeetsMin(sev, floor Severity) bool {
	return sev.Valid() && floor != Info && floor.Valid() && sev.rank() >= floor.rank()
}

// Quiet is the quiet-hours rule (contract.ts Quiet). From and To are "HH:MM" in the box's local time.
type Quiet struct {
	Enabled       bool   `json:"enabled"`
	From          string `json:"from"`
	To            string `json:"to"`
	AllowCritical bool   `json:"allow_critical"`
}

// ErrBadQuiet means the quiet-hours rule is malformed.
var ErrBadQuiet = errors.New("notify: invalid quiet hours")

// minutes parses "HH:MM" into minutes since midnight.
func minutes(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("%w: %q is not HH:MM", ErrBadQuiet, s)
	}
	d := func(c byte) (int, bool) { return int(c - '0'), c >= '0' && c <= '9' }
	h1, ok1 := d(s[0])
	h2, ok2 := d(s[1])
	m1, ok3 := d(s[3])
	m2, ok4 := d(s[4])
	h, m := h1*10+h2, m1*10+m2
	if !ok1 || !ok2 || !ok3 || !ok4 || h > 23 || m > 59 {
		return 0, fmt.Errorf("%w: %q is not HH:MM", ErrBadQuiet, s)
	}
	return h*60 + m, nil
}

// Validate checks the rule (INV-5): both times are HH:MM, and when enabled they differ. The window may cross midnight.
func (q Quiet) Validate() error {
	f, err := minutes(q.From)
	if err != nil {
		return err
	}
	t, err := minutes(q.To)
	if err != nil {
		return err
	}
	if q.Enabled && f == t {
		return fmt.Errorf("%w: start and end must differ", ErrBadQuiet)
	}
	return nil
}

// Active reports whether now falls inside the quiet window. now carries the
// box's time zone; the window is [From, To) and may cross midnight. A rule that
// is disabled or invalid is never active.
func (q Quiet) Active(now time.Time) bool {
	if !q.Enabled || q.Validate() != nil {
		return false
	}
	f, _ := minutes(q.From)
	t, _ := minutes(q.To)
	m := now.Hour()*60 + now.Minute()
	if f < t {
		return m >= f && m < t
	}
	return m >= f || m < t // overnight
}

// EndsAt returns the next instant the quiet window ends, in now's location,
// or the zero time when the window is not active at now.
func (q Quiet) EndsAt(now time.Time) time.Time {
	if !q.Active(now) {
		return time.Time{}
	}
	t, _ := minutes(q.To)
	end := time.Date(now.Year(), now.Month(), now.Day(), t/60, t%60, 0, 0, now.Location())
	if !end.After(now) {
		end = time.Date(now.Year(), now.Month(), now.Day()+1, t/60, t%60, 0, 0, now.Location())
	}
	return end
}

// Verdict is what to do with a notice on one channel right now.
type Verdict int

// Verdicts.
const (
	Send Verdict = iota // send immediately
	Hold                // keep it and send it grouped when quiet hours end
	Skip                // below the channel's min_severity: never sent here
)

func (v Verdict) String() string { return [...]string{"send", "hold", "skip"}[v] }

// Decide combines INV-4 and INV-5 (and D-57 item 8) for one channel: below
// min_severity is skipped; during quiet hours it is held until the window ends,
// except a critical notice when allow_critical is set, which goes at once. The
// returned time is the release time of a held notice (zero otherwise).
func Decide(now time.Time, minSev Severity, q Quiet, sev Severity) (Verdict, time.Time) {
	if !MeetsMin(sev, minSev) {
		return Skip, time.Time{}
	}
	if q.Active(now) && (!q.AllowCritical || sev != Critical) {
		return Hold, q.EndsAt(now)
	}
	return Send, time.Time{}
}

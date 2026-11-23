package findings

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxNote is the longest note, counted in UTF-16 code units like the GUI.
	MaxNote = 500
	// MinReasonNote is the shortest note for false_positive, not_relevant and accepted, and for a person's confirmation.
	MinReasonNote = 3
	// MaxAcceptDays is how far ahead a risk can be accepted.
	MaxAcceptDays = 365
	// SystemUser is the actor of what Vedette does by itself.
	SystemUser = "system"

	maxEvidenceField = 4096
	maxTemplate      = 128
	tsLayout         = "2006-01-02T15:04:05.000Z"
)

// AcceptanceEnds is when a risk accepted until the day until ends: once that day is over everywhere on Earth, at its end
// in UTC-12, which is the next day at 12:00 UTC. It is never early for anyone and at most about a day late for UTC+14.
func AcceptanceEnds(until time.Time) time.Time {
	return dayOf(until).AddDate(0, 0, 1).Add(12 * time.Hour)
}

// dayOf is the UTC day of t, at 00:00.
func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// validUntil checks the last day of an accepted risk against now: a day from today to MaxAcceptDays+1 days ahead in UTC
// (tomorrow and MaxAcceptDays in any time zone), given as a day (00:00 UTC).
func validUntil(until, now time.Time) error {
	today := dayOf(now)
	if until.IsZero() || !until.Equal(dayOf(until)) || until.Before(today) || until.After(today.AddDate(0, 0, MaxAcceptDays+1)) {
		return fmt.Errorf("findings: accepting the risk until %s: %w", until.Format(time.DateOnly), ErrBadUntil)
	}
	return nil
}

const truncMarker = "...[truncated]"

// truncate caps an evidence field at maxEvidenceField bytes (marker included), cutting on a character boundary.
func truncate(s string) string {
	if len(s) <= maxEvidenceField {
		return s
	}
	cut := maxEvidenceField - len(truncMarker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncMarker
}

// jsLen counts UTF-16 code units, like JavaScript's String.length, so the Go service and the GUI agree on the note limits.
func jsLen(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r >= 0x10000 {
			n++
		}
	}
	return n
}

// jsTrim trims what JavaScript's String.trim trims.
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) && r != 0x85 || r == 0xFEFF })
}

// isText reports whether every string is valid UTF-8 without NUL. Scan evidence comes from a probe's reply, so it is untrusted;
// SQLite JSON and the audit log both refuse such bytes.
func isText(ss ...string) bool {
	for _, s := range ss {
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			return false
		}
	}
	return true
}

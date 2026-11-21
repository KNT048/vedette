package schedule

import (
	"context"
	"errors"
	"time"
)

// Querier is a transaction or a database handle: what the readers below take.
type Querier = querier

// Entry is a saved schedule as its owner reads it to decide what to do: when it last came due and whether it is on.
type Entry struct {
	Enabled     bool
	PausedUntil *time.Time
	Rule        Rule
	NextDueAt   *time.Time
	LastDueAt   *time.Time
}

func entryOf(r row) Entry {
	return Entry{Enabled: r.Enabled, PausedUntil: r.PausedUntil, Rule: r.Rule, NextDueAt: r.NextDueAt, LastDueAt: r.LastDueAt}
}

// Lookup returns the saved schedule of key; ok is false when nobody saved it yet.
func Lookup(ctx context.Context, q Querier, key string) (e Entry, ok bool, err error) {
	r, err := getRow(ctx, q, key)
	if errors.Is(err, errNoRow) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}
	return entryOf(r), true, nil
}

// LookupAll returns the saved schedules whose owner_key starts with prefix (an owner with subjects: "feeds.source:"), by key.
func LookupAll(ctx context.Context, q Querier, prefix string) (map[string]Entry, error) {
	rows, err := listRows(ctx, q, `WHERE substr(owner_key, 1, ?) = ?`, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Entry, len(rows))
	for _, r := range rows {
		out[r.OwnerKey] = entryOf(r)
	}
	return out, nil
}

// Span is the window that contains t, or the next one after it: when it opens and closes, in the zone loc (UTC for nil). ok is
// false when the window never opens (no valid day or hours).
func (w Window) Span(t time.Time, loc *time.Location) (start, end time.Time, ok bool) {
	if loc == nil {
		loc = time.UTC
	}
	s, e, ok := w.opening(t, loc)
	return s.UTC(), e.UTC(), ok
}

// Length is how long one window lasts; 0 for hours that are not valid.
func (w Window) Length() time.Duration {
	from, ok1 := clock(w.From)
	to, ok2 := clock(w.To)
	if !ok1 || !ok2 {
		return 0
	}
	if to <= from {
		to += MinuteOfDay
	}
	return time.Duration(to-from) * time.Minute
}

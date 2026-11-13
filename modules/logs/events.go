package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

var windows = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// searchBusy is the answer when a search cannot start or cannot finish in time: the code already exists (the box is busy,
// 503), the message tells the person what to change.
func searchBusy() error {
	return apierr.New(503, "server_busy", "The box is busy searching the logs. Choose a shorter time range or a more specific keyword, then try again.")
}

// asciiLower folds the letters A-Z only, like SQLite's lower(): the keyword and the line are folded the same way, so a
// search is case-insensitive for ASCII letters and exact for every other character (Vietnamese included). The upgrade
// path for full Unicode folding is an FTS5 index with the unicode61 tokenizer.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// Events searches the stored lines (GET /logs/events): the time window (never longer than the retention), one source or
// all, and a keyword matched in the line and in the source's name, case-insensitively for ASCII letters. It returns the
// EventsPage newest; with no keyword Total counts the matching rows up to CountCap (INV-5). A keyword search is a scan, so at most
// MaxSearches run at once on a box and each has SearchTimeout: it walks back from the newest line (scanNewest) and, when the time is
// up first, answers with what it found and where to continue (D-441); only a search that could not search anything is 503 server_busy.
func (s *Service) Events(ctx context.Context, q EventQuery) (EventsView, error) {
	span, ok := windows[q.Window]
	if !ok {
		return EventsView{}, apierr.New(400, "bad_window", "The time range must be 1h, 24h or 7d.")
	}
	days, err := s.Retention(ctx)
	if err != nil {
		return EventsView{}, err
	}
	if keep := time.Duration(days) * 24 * time.Hour; span > keep {
		span = keep
	}
	sctx, cancel := context.WithTimeout(ctx, s.searchTimeout)
	defer cancel()
	select {
	case s.searchSem <- struct{}{}:
		defer func() { <-s.searchSem }()
	case <-sctx.Done():
		return EventsView{}, searchBusy()
	}
	v, err := s.search(sctx, q, span)
	// Out of time: the driver may answer with the deadline error or, when the deadline cuts a scan that is running, with its own
	// "interrupted" error; either way the search's deadline has passed and the caller's context has not.
	if err != nil && ctx.Err() == nil && errors.Is(sctx.Err(), context.DeadlineExceeded) {
		s.cfg.Log.WarnContext(ctx, "logs: a search ran out of time", "err", err)
		return EventsView{}, searchBusy()
	}
	return v, err
}

func (s *Service) search(ctx context.Context, q EventQuery, span time.Duration) (EventsView, error) {
	needle := asciiLower(strings.TrimSpace(q.Q))
	if utf8.RuneCountInString(needle) > 200 {
		needle = string([]rune(needle)[:200])
	}
	rows, err := s.loadSources(ctx)
	if err != nil {
		return EventsView{}, err
	}
	names := make(map[string]string, len(rows))
	var byName []string // sources whose name contains the keyword
	for _, r := range rows {
		names[r.ID] = r.Name
		if needle != "" && strings.Contains(asciiLower(r.Name), needle) {
			byName = append(byName, r.ID)
		}
	}
	vol := s.cfg.Volume.Reader()
	// The window is a range of the ts index; the newest lines come first by walking that index backwards.
	out := EventsView{Events: []Event{}}
	where, args := "ts >= ?", []any{store.FormatTS(s.now().Add(-span))}
	if q.Source != "" {
		where += " AND source_id = ?"
		args = append(args, q.Source)
	}
	if needle == "" {
		if q.Cursor != "" {
			return EventsView{}, errBadCursor()
		}
		return s.listNewest(ctx, vol, out, where, args, names)
	}
	return s.scanNewest(ctx, out, where, args, needle, byName, names, q.Cursor)
}

func errBadCursor() error {
	return apierr.New(400, "bad_cursor", "That search position is not valid. Search again from the start.")
}

// cursor is a position in the ts index: the lines strictly older than (ts, id) are the ones not searched yet.
type cursor struct {
	ts string // store.FormatTS
	id int64
}

func (c cursor) String() string { return c.ts + "_" + strconv.FormatInt(c.id, 10) }

// parseCursor reads the NextCursor of an earlier answer; anything else is a 400 (the value is only ever bound as an argument).
func parseCursor(s string) (cursor, error) {
	ts, idText, ok := strings.Cut(s, "_")
	if !ok {
		return cursor{}, errBadCursor()
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", ts)
	id, err2 := strconv.ParseInt(idText, 10, 64)
	if err != nil || err2 != nil || id < 0 || store.FormatTS(t) != ts {
		return cursor{}, errBadCursor()
	}
	return cursor{ts: ts, id: id}, nil
}

// scanNewest is the keyword search (D-441): it walks the window newest first in steps of s.scanRows rows of the ts index, keeps the
// lines that match and stops at EventsPage matches, at the start of the window, or when the time budget of ctx is spent. In the last
// two cases the answer says how far back it looked (SearchedBackTo) and gives the cursor (NextCursor) that continues from there, so a
// keyword that matches nothing over days of a big box is an honest "searched back to ..." and not a 503. A budget spent before the
// first step is done is still 503 server_busy (nothing was searched).
func (s *Service) scanNewest(ctx context.Context, out EventsView, where string, args []any, needle string, byName []string, names map[string]string, after string) (EventsView, error) {
	vol := s.cfg.Volume.Reader()
	cond := "instr(lower(line), ?) > 0"
	matchArgs := []any{needle}
	if len(byName) > 0 {
		cond += " OR source_id IN (?" + strings.Repeat(", ?", len(byName)-1) + ")"
		for _, id := range byName {
			matchArgs = append(matchArgs, id)
		}
	}
	// hi is the exclusive upper end of what is still to search; the zero value means "from the newest line".
	var hi cursor
	if after != "" {
		c, err := parseCursor(after)
		if err != nil {
			return EventsView{}, err
		}
		hi = c
	}
	rowsPer := max(s.scanRows, 1)
	upTo := func() (string, []any) { // the part of the range that is above hi
		if hi.ts == "" {
			return "", nil
		}
		return " AND ts <= ? AND (ts, id) < (?, ?)", []any{hi.ts, hi.ts, hi.id}
	}
	for step := 0; ; step++ {
		if ctx.Err() != nil || (s.timeUp != nil && s.timeUp(step)) {
			return s.partial(out, hi, step)
		}
		hiSQL, hiArgs := upTo()
		rangeArgs := append(append([]any{}, args...), hiArgs...)
		// The lower end of this step: the rowsPer-th row below hi; no such row = the step reaches the start of the window.
		var lo cursor
		err := vol.QueryRowContext(ctx, `SELECT ts, id FROM logs_events WHERE `+where+hiSQL+` ORDER BY ts DESC, id DESC LIMIT 1 OFFSET `+strconv.Itoa(rowsPer-1), rangeArgs...).Scan(&lo.ts, &lo.id)
		last := errors.Is(err, sql.ErrNoRows)
		if err != nil && !last {
			return s.stepFailed(ctx, out, hi, step, err)
		}
		stepWhere, stepArgs := where+hiSQL, rangeArgs
		if !last {
			// The window's own start is swapped for this step's lower end: with two lower bounds on ts SQLite picks the first one and
			// the step would read the whole window (measured: 700 ms for a step of 18,000 rows, 14 ms with the tight bound).
			stepWhere = "ts >= ?" + strings.TrimPrefix(where, "ts >= ?") + hiSQL + " AND (ts, id) >= (?, ?)"
			stepArgs = append([]any{lo.ts}, rangeArgs[1:]...)
			stepArgs = append(stepArgs, lo.ts, lo.id)
		}
		stepArgs = append(stepArgs, matchArgs...)
		room := EventsPage - len(out.Events)
		got, err := s.readMatches(ctx, vol, stepWhere+" AND ("+cond+")", stepArgs, room+1, names) // one more than fits: tells whether lines remain
		if err != nil {
			return s.stepFailed(ctx, out, hi, step, err)
		}
		more := len(got) > room
		if more {
			got = got[:room]
		}
		out.Events = append(out.Events, got...)
		out.Total = len(out.Events)
		if more || len(out.Events) >= EventsPage {
			// Page full: continue below the last line shown. Only a page that is exactly the last matches of the window has no cursor.
			if last && !more {
				return out, nil
			}
			return s.withNext(out, cursorOf(got[len(got)-1])), nil
		}
		if last {
			return out, nil
		}
		hi = lo
	}
}

// partial is the answer when the time is up between two steps: what was found so far and where to continue. Nothing searched at all
// (step 0) is the busy error.
func (s *Service) partial(out EventsView, hi cursor, step int) (EventsView, error) {
	if step == 0 {
		return EventsView{}, searchBusy()
	}
	return s.withNext(out, hi), nil
}

// stepFailed turns the deadline error of an interrupted step into the partial answer; any other error is a real error. The step that
// was cut is dropped whole (its lines are searched again from hi when the person continues).
func (s *Service) stepFailed(ctx context.Context, out EventsView, hi cursor, step int, err error) (EventsView, error) {
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return s.partial(out, hi, step)
	}
	return EventsView{}, fmt.Errorf("logs: searching lines: %w", err)
}

func cursorOf(e Event) cursor {
	id, _ := strconv.ParseInt(strings.TrimPrefix(e.ID, "le-"), 10, 64)
	return cursor{ts: store.FormatTS(e.TS), id: id}
}

func (s *Service) withNext(out EventsView, c cursor) EventsView {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", c.ts)
	if err == nil {
		out.SearchedBackTo = &t
	}
	next := c.String()
	out.NextCursor = &next
	return out
}

// readMatches reads up to limit matching lines, newest first.
func (s *Service) readMatches(ctx context.Context, vol *sql.DB, where string, args []any, limit int, names map[string]string) ([]Event, error) {
	list, err := vol.QueryContext(ctx, `SELECT id, ts, source_id, line FROM logs_events WHERE `+where+` ORDER BY ts DESC, id DESC LIMIT `+strconv.Itoa(limit), args...) //nolint:gosec // where is built from constants and ? placeholders only; every value is a bound argument
	if err != nil {
		return nil, err
	}
	defer func() { _ = list.Close() }()
	var evs []Event
	for list.Next() {
		var id int64
		var ts string
		var e Event
		if err := list.Scan(&id, &ts, &e.SourceID, &e.Line); err != nil {
			return nil, err
		}
		if e.TS, err = time.Parse("2006-01-02T15:04:05.000Z", ts); err != nil {
			return nil, err
		}
		e.ID = "le-" + strconv.FormatInt(id, 10)
		e.SourceName = names[e.SourceID]
		if e.SourceName == "" {
			e.SourceName = e.SourceID // the source was deleted: its lines stay (INV-4), named by id as in the mock
		}
		e.withHeader()
		evs = append(evs, e)
	}
	return evs, list.Err()
}

// listNewest is the search with no keyword: the newest lines of the window, an index walk (5-7 ms at 5 million lines).
func (s *Service) listNewest(ctx context.Context, vol *sql.DB, out EventsView, where string, args []any, names map[string]string) (EventsView, error) {
	if err := vol.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM logs_events WHERE `+where+` LIMIT `+strconv.Itoa(CountCap)+`)`, args...).Scan(&out.Total); err != nil {
		return EventsView{}, fmt.Errorf("logs: counting lines: %w", err)
	}
	evs, err := s.readMatches(ctx, vol, where, args, EventsPage, names)
	if err != nil {
		return EventsView{}, fmt.Errorf("logs: searching lines: %w", err)
	}
	out.Events = append(out.Events, evs...)
	return out, nil
}

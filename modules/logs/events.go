package logs

import (
	"context"
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
// EventsPage newest; Total counts the matching rows up to CountCap (INV-5). A search is a scan, so at most MaxSearches run
// at once on a box and each has SearchTimeout; past either, 503 server_busy.
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
	if err != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
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
	if needle != "" {
		cond := "instr(lower(line), ?) > 0"
		args = append(args, needle)
		if len(byName) > 0 {
			cond += " OR source_id IN (?" + strings.Repeat(", ?", len(byName)-1) + ")"
			for _, id := range byName {
				args = append(args, id)
			}
		}
		where += " AND (" + cond + ")"
	}
	if err := vol.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM logs_events WHERE `+where+` LIMIT `+strconv.Itoa(CountCap)+`)`, args...).Scan(&out.Total); err != nil {
		return EventsView{}, fmt.Errorf("logs: counting lines: %w", err)
	}
	list, err := vol.QueryContext(ctx, `SELECT id, ts, source_id, line FROM logs_events WHERE `+where+` ORDER BY ts DESC, id DESC LIMIT `+strconv.Itoa(EventsPage), args...) //nolint:gosec // where is built from constants and ? placeholders only; every value is a bound argument
	if err != nil {
		return EventsView{}, fmt.Errorf("logs: searching lines: %w", err)
	}
	defer func() { _ = list.Close() }()
	for list.Next() {
		var id int64
		var ts string
		var e Event
		if err := list.Scan(&id, &ts, &e.SourceID, &e.Line); err != nil {
			return EventsView{}, fmt.Errorf("logs: searching lines: %w", err)
		}
		if e.TS, err = time.Parse("2006-01-02T15:04:05.000Z", ts); err != nil {
			return EventsView{}, fmt.Errorf("logs: searching lines: %w", err)
		}
		e.ID = "le-" + strconv.FormatInt(id, 10)
		e.SourceName = names[e.SourceID]
		if e.SourceName == "" {
			e.SourceName = e.SourceID // the source was deleted: its lines stay (INV-4), named by id as in the mock
		}
		out.Events = append(out.Events, e)
	}
	return out, list.Err()
}

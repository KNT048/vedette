package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
)

// ErrBatchTooLarge is returned by Ingest for more than MaxBatch lines.
var ErrBatchTooLarge = errors.New("logs: batch has more than the allowed number of lines")

// sanitizeLine turns the text a device sent into the text that is stored (INV-1: a device is an untrusted source). Invalid
// UTF-8 becomes U+FFFD, NUL and other control characters except tab become a space (a line is shown and exported as text;
// it is never interpreted), and a line longer than MaxLineBytes is cut on a character boundary and marked.
func sanitizeLine(s string) string {
	early := false
	if len(s) > maxIngestLineBytes { // before the walks below: a huge line costs 4x the kept size at most
		cut := maxIngestLineBytes
		for k := 0; k < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(s[cut]); k++ { // a rune is at most 4 bytes: three steps back at most
			cut--
		}
		s, early = s[:cut], true
	}
	s = strings.ToValidUTF8(s, "�")
	if strings.IndexFunc(s, isControl) >= 0 {
		s = strings.Map(func(r rune) rune {
			if isControl(r) {
				return ' '
			}
			return r
		}, s)
	}
	s = strings.TrimRight(s, " ")
	if len(s) <= MaxLineBytes && !early { // a line that was cut before is always marked, whatever is left of it
		return s
	}
	const mark = " ...[cut]"
	if cut := MaxLineBytes - len(mark); len(s) > cut {
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s + mark
}

// isControl says whether a rune must not reach a stored line: every control (Cc: C0, DEL, C1 with NEL), format (Cf: the
// bidirectional overrides and isolates, zero-width characters, byte order mark, soft hyphen) and line or paragraph
// separator (Zl, Zp) except tab. A device could otherwise make a line read reversed, hide text from the search, or
// start what looks like a second line in the page and in the export. They become a space.
func isControl(r rune) bool {
	return r != '\t' && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}

// Ingest stores a batch of received lines in one transaction on logs.db: at most one write per batch, never on the
// main database, so a flood never waits for the core writer and never holds it. Lines of a source that is not declared
// are dropped and counted (FORBID-5). At most MaxBatch lines (ErrBatchTooLarge). A line's time is its receive time,
// receive time, and one outside [now - retention, now] (zero, in the future, older than the retention) is now: a line
// dated on the retention boundary would be deleted by the next purge. When the stored bytes pass
// MaxEventBytes a purge starts in the background (at most one at a time); Ingest never waits for it.
func (s *Service) Ingest(ctx context.Context, lines []Line) (IngestResult, error) {
	var res IngestResult
	if len(lines) > MaxBatch {
		return res, ErrBatchTooLarge
	}
	if len(lines) == 0 {
		return res, nil
	}
	known, err := s.sourceIDs(ctx)
	if err != nil {
		return res, err
	}
	now := s.ts()
	days, err := s.Retention(ctx)
	if err != nil {
		return res, err
	}
	oldest := now.Add(-time.Duration(days) * 24 * time.Hour)
	type key struct {
		source string
		bucket int64
	}
	buckets := map[key]int{}
	seen := map[string]time.Time{}
	keep := make([]Line, 0, len(lines))
	for _, l := range lines {
		if !known[l.SourceID] {
			res.Unknown++
			continue
		}
		if l.At.IsZero() || l.At.After(now) || l.At.Before(oldest) {
			l.At = now // the time is the receive time: one outside [now - retention, now] is a bug of the sender or of the listener
		}
		l.At = l.At.UTC().Truncate(time.Millisecond)
		l.Text = sanitizeLine(l.Text)
		keep = append(keep, l)
		buckets[key{l.SourceID, l.At.Unix() / bucketSeconds}]++
		if l.At.After(seen[l.SourceID]) {
			seen[l.SourceID] = l.At
		}
	}
	if len(keep) == 0 {
		return res, nil
	}
	var stored int64
	err = s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		ins, err := tx.PrepareContext(ctx, `INSERT INTO logs_events (ts, source_id, line) VALUES (?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("logs: storing lines: %w", err)
		}
		defer func() { _ = ins.Close() }()
		added := 0
		for _, l := range keep {
			added += len(l.Text)
			if _, err := ins.ExecContext(ctx, store.FormatTS(l.At), l.SourceID, l.Text); err != nil {
				return fmt.Errorf("logs: storing a line: %w", err)
			}
		}
		if err := tx.QueryRowContext(ctx, `UPDATE logs_volume SET line_bytes = line_bytes + ? WHERE id = 1 RETURNING line_bytes`, added).Scan(&stored); err != nil {
			return fmt.Errorf("logs: counting bytes: %w", err)
		}
		for k, n := range buckets {
			if _, err := tx.ExecContext(ctx, `INSERT INTO logs_source_buckets (source_id, bucket, lines) VALUES (?, ?, ?) ON CONFLICT (source_id, bucket) DO UPDATE SET lines = lines + excluded.lines`, k.source, k.bucket, n); err != nil {
				return fmt.Errorf("logs: counting lines: %w", err)
			}
		}
		for id, at := range seen {
			if _, err := tx.ExecContext(ctx, `INSERT INTO logs_source_seen (source_id, last_received) VALUES (?, ?) ON CONFLICT (source_id) DO UPDATE SET last_received = max(last_received, excluded.last_received)`, id, store.FormatTS(at)); err != nil {
				return fmt.Errorf("logs: noting the last line: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return IngestResult{}, err
	}
	res.Stored = len(keep)
	if stored > s.maxBytes {
		s.startPurge(ctx)
	}
	return res, nil
}

// purgeBudget bounds a purge that Ingest started; purgeGap is the least time between two such starts.
const (
	purgeBudget = 30 * time.Minute
	purgeGap    = time.Minute
)

// startPurge runs a purge in the background unless one is under way (the flag is shared with the hourly job: coalesced, a
// flood over the bound starts one purge, not one per batch) or one started less than purgeGap ago (the 90% target leaves
// room for a minute of flood, but not for a purge per batch when a source outruns it). It never blocks the caller, which
// holds no lock and may not wait for the core writer that the audit rows of the purge need (INV-12).
//
// ponytail: the goroutine's context has a deadline (purgeBudget) but is not cancelled when the module is turned off or at
// shutdown: core/jobs cancels only the context of its own jobs. A purge is transactional in chunks, so a stop in the middle
// is safe; the cancel needs `Scheduler.Wake` (.ai/deferred/fix-logs-production-safety.md).
func (s *Service) startPurge(parent context.Context) {
	if !s.purging.CompareAndSwap(false, true) {
		return
	}
	if now := s.now(); !s.lastStart.IsZero() && now.Sub(s.lastStart) < purgeGap {
		s.purging.Store(false)
		return
	}
	s.lastStart = s.now() // only read and written by the holder of the flag
	// Detached from the batch's context (the purge outlives the call), with its own budget.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), purgeBudget)
	go func() {
		defer s.purging.Store(false)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				s.cfg.Log.ErrorContext(ctx, "logs: the purge started by a full volume panicked", "panic", fmt.Sprint(r))
			}
		}()
		if _, err := s.Purge(ctx); err != nil {
			s.cfg.Log.WarnContext(ctx, "logs: the purge started by a full volume failed", "err", err)
		}
	}()
}

// sourceIDs is the set of declared source ids (one small read on the main database; reads do not wait for its writer).
func (s *Service) sourceIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.cfg.Config.Reader().QueryContext(ctx, `SELECT id FROM logs_sources`)
	if err != nil {
		return nil, fmt.Errorf("logs: reading sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("logs: reading sources: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

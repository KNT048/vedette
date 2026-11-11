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
	if len(s) <= MaxLineBytes {
		return s
	}
	const mark = " ...[cut]"
	cut := MaxLineBytes - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
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
// are dropped and counted (FORBID-5). At most MaxBatch lines (ErrBatchTooLarge). A line's time is its receive time; a
// zero time or one in the future is now.
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
		if l.At.IsZero() || l.At.After(now) {
			l.At = now
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
	err = s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		ins, err := tx.PrepareContext(ctx, `INSERT INTO logs_events (ts, source_id, line) VALUES (?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("logs: storing lines: %w", err)
		}
		defer func() { _ = ins.Close() }()
		for _, l := range keep {
			if _, err := ins.ExecContext(ctx, store.FormatTS(l.At), l.SourceID, l.Text); err != nil {
				return fmt.Errorf("logs: storing a line: %w", err)
			}
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
	return res, nil
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

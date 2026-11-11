package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/logs/signature"
)

// Limits of the signature counters (INV-1: a device is an untrusted source, so what it can add to the tables is bounded).
const (
	// MaxSignaturesPerDay is how many (signature, destination) rows one source can have in a UTC day; the lines past it are counted
	// under OtherSignature. ponytail: 2,000, one constant; a real device has tens to hundreds of kinds of line.
	MaxSignaturesPerDay = 2000
	// MaxSignaturesPerBucket is the same for one 5-minute bucket of the counters that Counts reads.
	MaxSignaturesPerBucket = 500
	// OtherSignature is where the lines past the caps are counted.
	OtherSignature = "(other)"
	// MaxSampleBytes is how much of the first line of a row is kept as its sample.
	MaxSampleBytes = 300
	// CountsMinWindow and CountsMaxWindow bound what Counts answers (the counters are 5 minutes wide and kept 48 hours).
	CountsMinWindow = 5 * time.Minute
	CountsMaxWindow = 24 * time.Hour
)

// ErrBadWindow is returned by Counts for a window outside CountsMinWindow..CountsMaxWindow.
var ErrBadWindow = errors.New("logs: the window must be between 5 minutes and 24 hours")

type dailyKey struct{ day, source, signature, dest string }

type dailyVal struct {
	n      int
	first  time.Time
	sample string
}

type bucketKey struct {
	source    string
	bucket    int64
	signature string
}

// sigBatch is what one batch of lines adds to the counters: a flood of identical lines is one entry.
type sigBatch struct {
	daily  map[dailyKey]*dailyVal
	bucket map[bucketKey]int
}

// tally turns a batch of sanitized lines into counter increments. kinds maps a declared source id to its device kind. Pure: no
// database (the memo makes a flood of identical lines cost one signature, not one per line).
func (s *Service) tally(kinds map[string]string, keep []Line) sigBatch {
	type memoKey struct{ kind, text string }
	memo := map[memoKey]signature.Result{}
	b := sigBatch{daily: map[dailyKey]*dailyVal{}, bucket: map[bucketKey]int{}}
	for _, l := range keep {
		kind := kinds[l.SourceID]
		r, ok := memo[memoKey{kind, l.Text}]
		if !ok {
			r = s.sigs.Of(kind, l.Text)
			memo[memoKey{kind, l.Text}] = r
		}
		k := dailyKey{l.At.UTC().Format("2006-01-02"), l.SourceID, r.Signature, r.Dest}
		if v := b.daily[k]; v != nil {
			v.n++
			if l.At.Before(v.first) {
				v.first, v.sample = l.At, sampleOf(l.Text)
			}
		} else {
			b.daily[k] = &dailyVal{n: 1, first: l.At, sample: sampleOf(l.Text)}
		}
		b.bucket[bucketKey{l.SourceID, l.At.Unix() / bucketSeconds, r.Signature}]++
	}
	return b
}

func sampleOf(text string) string {
	if len(text) <= MaxSampleBytes {
		return text
	}
	n := MaxSampleBytes
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n]
}

// storeSignatures adds a batch to the counters inside the transaction of the batch (the writer of logs.db, never the main one).
// A key that is new for its day and source, past the cap of rows, is counted under OtherSignature instead.
func (s *Service) storeSignatures(ctx context.Context, tx *sql.Tx, b sigBatch) error {
	rows := map[[2]string]int{} // rows of (day, source) and (bucket, source), read when first needed
	rowsOf := func(q string, a, c any, limit int) (int, error) {
		var n int
		if err := tx.QueryRowContext(ctx, q, a, c, limit).Scan(&n); err != nil {
			return 0, fmt.Errorf("logs: counting signature rows: %w", err)
		}
		return n, nil
	}
	for k, v := range b.daily {
		first := store.FormatTS(v.first)
		res, err := tx.ExecContext(ctx, `UPDATE logs_signature_daily SET count = count + ?, first_seen = min(first_seen, ?) WHERE day = ? AND source_id = ? AND signature = ? AND dest = ?`, v.n, first, k.day, k.source, k.signature, k.dest)
		if err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			continue
		}
		rk := [2]string{"d" + k.day, k.source}
		if _, ok := rows[rk]; !ok {
			if rows[rk], err = rowsOf(`SELECT count(*) FROM (SELECT 1 FROM logs_signature_daily WHERE day = ? AND source_id = ? LIMIT ?)`, k.day, k.source, MaxSignaturesPerDay); err != nil {
				return err
			}
		}
		sig, dest, sample := k.signature, k.dest, v.sample
		if rows[rk] >= MaxSignaturesPerDay {
			sig, dest = OtherSignature, ""
			res, err := tx.ExecContext(ctx, `UPDATE logs_signature_daily SET count = count + ?, first_seen = min(first_seen, ?) WHERE day = ? AND source_id = ? AND signature = ? AND dest = ?`, v.n, first, k.day, k.source, sig, dest)
			if err != nil {
				return fmt.Errorf("logs: counting signatures: %w", err)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample) VALUES (?, ?, ?, ?, ?, ?, ?)`, k.day, k.source, sig, dest, v.n, first, sample); err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
		rows[rk]++
	}
	for k, n := range b.bucket {
		res, err := tx.ExecContext(ctx, `UPDATE logs_signature_buckets SET count = count + ? WHERE source_id = ? AND bucket = ? AND signature = ?`, n, k.source, k.bucket, k.signature)
		if err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
		if c, _ := res.RowsAffected(); c > 0 {
			continue
		}
		rk := [2]string{fmt.Sprintf("b%d", k.bucket), k.source}
		if _, ok := rows[rk]; !ok {
			if rows[rk], err = rowsOf(`SELECT count(*) FROM (SELECT 1 FROM logs_signature_buckets WHERE bucket = ?1 AND source_id = ?2 LIMIT ?3)`, k.bucket, k.source, MaxSignaturesPerBucket); err != nil {
				return err
			}
		}
		sig := k.signature
		if rows[rk] >= MaxSignaturesPerBucket {
			sig = OtherSignature
			res, err := tx.ExecContext(ctx, `UPDATE logs_signature_buckets SET count = count + ? WHERE source_id = ? AND bucket = ? AND signature = ?`, n, k.source, k.bucket, sig)
			if err != nil {
				return fmt.Errorf("logs: counting signatures: %w", err)
			}
			if c, _ := res.RowsAffected(); c > 0 {
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_signature_buckets (source_id, bucket, signature, count) VALUES (?, ?, ?, ?)`, k.source, k.bucket, sig, n); err != nil {
			return fmt.Errorf("logs: counting signatures: %w", err)
		}
		rows[rk]++
	}
	return nil
}

// Counts is the read port of response's log_threshold: how many lines of one signature a source received in the last window.
// source is the id of the declared source (ls-…), signature is the text the digest shows. The counters are 5 minutes wide, so the
// window is rounded out to whole buckets: the answer covers the window and at most 5 minutes before it. A window under 5
// minutes or over 24 hours is ErrBadWindow; a signature never seen is 0, not an error.
func (s *Service) Counts(ctx context.Context, source, signature string, window time.Duration) (int, error) {
	if window < CountsMinWindow || window > CountsMaxWindow {
		return 0, ErrBadWindow
	}
	var n sql.NullInt64
	err := s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT sum(count) FROM logs_signature_buckets WHERE source_id = ? AND signature = ? AND bucket >= ?`,
		source, signature, s.now().Add(-window).Unix()/bucketSeconds).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("logs: counting a signature: %w", err)
	}
	return int(n.Int64), nil
}

package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// PurgeEvery is the pause between two purge runs (the job also runs when the module starts).
const PurgeEvery = time.Hour

// PurgeResult says what a purge removed.
type PurgeResult struct {
	Expired int // lines older than the retention
	Over    int // oldest lines over MaxEvents
}

// Purge deletes the lines older than the retention (INV-4) and, whatever the retention, the oldest ones beyond MaxEvents
// (a flood must not fill the disk). It deletes in chunks of s.chunk rows, one transaction each, so the writer of logs.db is
// free between two chunks and ctx is honoured between them. It also drops counters older than two days and the
// "last received" of sources that no longer exist.
//
// Audit (SYS-3): the two databases cannot share a transaction, so a purge that has something to delete first writes
// "logs.purge_started" (cutoff and cap) to the main database, and nothing is deleted if that fails; whatever the purge
// then does, on every way out (done, an error, a cancelled context), it writes "logs.purge" with the counts, under a
// context that outlives the cancellation. A crash between the two leaves the started row and no end row, which says a
// purge was under way.
func (s *Service) Purge(ctx context.Context) (res PurgeResult, err error) {
	days, err := s.Retention(ctx)
	if err != nil {
		return res, err
	}
	cutoff := store.FormatTS(s.now().Add(-time.Duration(days) * 24 * time.Hour))
	var expired int
	if err := s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM logs_events WHERE ts < ? LIMIT 1)`, cutoff).Scan(&expired); err != nil {
		return res, fmt.Errorf("logs: looking for expired lines: %w", err)
	}
	var newest sql.NullInt64
	if err := s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT max(id) FROM logs_events`).Scan(&newest); err != nil {
		return res, fmt.Errorf("logs: reading the newest line: %w", err)
	}
	over := newest.Valid && newest.Int64 > s.maxEvents
	if expired > 0 || over {
		err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: "logs.purge_started", Target: "logs",
				Detail: fmt.Sprintf("lines older than %s (%d days); at most %d lines kept", cutoff, days, s.maxEvents)})
		})
		if err != nil {
			return res, err // nothing is deleted without a trace
		}
		defer func() {
			if res.Expired+res.Over == 0 {
				return
			}
			actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			aerr := s.cfg.Config.Write(actx, func(tx *sql.Tx) error {
				return s.cfg.Audit.Append(actx, tx, audit.Entry{User: "system", Action: "logs.purge", Target: "logs",
					Detail: fmt.Sprintf("%d lines older than %d days, %d over the limit of %d lines", res.Expired, days, res.Over, s.maxEvents)})
			})
			if aerr != nil {
				err = errors.Join(err, aerr)
			}
		}()
	}
	if res.Expired, err = s.deleteChunks(ctx, `DELETE FROM logs_events WHERE id IN (SELECT id FROM logs_events WHERE ts < ? ORDER BY ts, id LIMIT ?)`, cutoff); err != nil {
		return res, err
	}
	if over {
		if res.Over, err = s.deleteChunks(ctx, `DELETE FROM logs_events WHERE id IN (SELECT id FROM logs_events WHERE id <= ? ORDER BY id LIMIT ?)`, newest.Int64-s.maxEvents); err != nil {
			return res, err
		}
	}
	if err := s.dropStale(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// deleteChunks runs a "delete up to purgeChunk rows" statement (arg, then the chunk size) until it deletes fewer.
func (s *Service) deleteChunks(ctx context.Context, stmt string, arg any) (int, error) {
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var n int64
		err := s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
			r, err := tx.ExecContext(ctx, stmt, arg, s.chunk)
			if err != nil {
				return fmt.Errorf("logs: purging lines: %w", err)
			}
			n, err = r.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += int(n)
		if s.afterChunk != nil {
			s.afterChunk()
		}
		if n < int64(s.chunk) {
			return total, nil
		}
	}
}

func (s *Service) dropStale(ctx context.Context) error {
	ids, err := s.sourceIDs(ctx)
	if err != nil {
		return err
	}
	return s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM logs_source_buckets WHERE bucket < ?`, s.now().Add(-48*time.Hour).Unix()/bucketSeconds); err != nil {
			return fmt.Errorf("logs: dropping old counters: %w", err)
		}
		q, args := `DELETE FROM logs_source_seen`, []any(nil)
		if len(ids) > 0 {
			q += ` WHERE source_id NOT IN (?` + strings.Repeat(", ?", len(ids)-1) + `)` //nolint:gosec // the placeholders are generated; the ids are bound arguments
			for id := range ids {
				args = append(args, id)
			}
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("logs: dropping old source marks: %w", err)
		}
		return nil
	})
}

// Jobs returns the jobs of the module (core runs one only while the module is on).
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: ModuleID, Name: "purge", Every: PurgeEvery, Run: func(ctx context.Context) error {
		_, err := svc.Purge(ctx)
		return err
	}}}
}

package logs

import (
	"context"
	"database/sql"
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
// (a flood must not fill the disk). It deletes in chunks of purgeChunk rows, one transaction each, so the writer of
// logs.db is free between two chunks and ctx is honoured between them. It also drops counters older than two days and the
// "last received" of sources that no longer exist. A purge that removed lines leaves one audit row (SYS-3).
func (s *Service) Purge(ctx context.Context) (PurgeResult, error) {
	var res PurgeResult
	days, err := s.Retention(ctx)
	if err != nil {
		return res, err
	}
	cutoff := store.FormatTS(s.now().Add(-time.Duration(days) * 24 * time.Hour))
	if res.Expired, err = s.deleteChunks(ctx, `DELETE FROM logs_events WHERE id IN (SELECT id FROM logs_events WHERE ts < ? ORDER BY ts, id LIMIT ?)`, cutoff); err != nil {
		return res, err
	}
	var newest sql.NullInt64
	if err := s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT max(id) FROM logs_events`).Scan(&newest); err != nil {
		return res, fmt.Errorf("logs: reading the newest line: %w", err)
	}
	if newest.Valid && newest.Int64 > s.maxEvents {
		if res.Over, err = s.deleteChunks(ctx, `DELETE FROM logs_events WHERE id IN (SELECT id FROM logs_events WHERE id <= ? ORDER BY id LIMIT ?)`, newest.Int64-s.maxEvents); err != nil {
			return res, err
		}
	}
	if err := s.dropStale(ctx); err != nil {
		return res, err
	}
	if res.Expired+res.Over > 0 {
		err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: "logs.purge", Target: "logs",
				Detail: fmt.Sprintf("%d lines older than %d days, %d over the limit of %d lines", res.Expired, days, res.Over, s.maxEvents)})
		})
		if err != nil {
			return res, err
		}
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
			r, err := tx.ExecContext(ctx, stmt, arg, purgeChunk)
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
		if n < purgeChunk {
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
			q += ` WHERE source_id NOT IN (?` + strings.Repeat(", ?", len(ids)-1) + `)`
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

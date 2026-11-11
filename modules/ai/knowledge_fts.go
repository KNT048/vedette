package ai

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// The FTS5 index is derived data: the chunk table holds the text, so the index can always be rebuilt from it. Something outside this
// module can damage it (core's "Delete all data" empties the shadow tables of a virtual table as if they were data tables, which
// leaves a table whose every insert fails with an FTS5 corruption error), so the module heals itself: a failed use of the index is
// repaired once and tried once more, and the index is checked when the service starts (D-209).

const ftsTable = "ai_knowledge_chunk_fts"

// isFTSCorrupt reports whether err is SQLite telling that the full-text index is damaged.
func isFTSCorrupt(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "fts5") && (strings.Contains(m, "corrupt") || strings.Contains(m, "malformed")) || strings.Contains(m, "database disk image is malformed")
}

// repairFTS drops the index, creates it again exactly as migration 0005 does and fills it from the chunk table, in one transaction.
// Dropping first matters: a table whose own bookkeeping rows are gone cannot be rebuilt in place.
func (s *Service) repairFTS(ctx context.Context) error {
	s.cfg.Log.WarnContext(ctx, "ai: the knowledge index is damaged; rebuilding it from the stored text")
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`DROP TABLE IF EXISTS ` + ftsTable,
			`CREATE VIRTUAL TABLE ` + ftsTable + ` USING fts5 (text, content = 'ai_knowledge_chunk', content_rowid = 'id', tokenize = 'unicode61 remove_diacritics 2')`,
			`INSERT INTO ` + ftsTable + `(` + ftsTable + `) VALUES ('rebuild')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("ai: rebuild knowledge index: %w", err)
			}
		}
		return nil
	})
}

// withFTSRepair runs fn; when it fails because the index is damaged, the index is rebuilt and fn runs once more.
func (s *Service) withFTSRepair(ctx context.Context, fn func() error) error {
	err := fn()
	if !isFTSCorrupt(err) {
		return err
	}
	if rerr := s.repairFTS(ctx); rerr != nil {
		return rerr
	}
	return fn()
}

// checkFTS runs at start: an index that fails its own integrity check is rebuilt. Normally the index is small or empty.
func (s *Service) checkFTS(ctx context.Context) error {
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO `+ftsTable+`(`+ftsTable+`, rank) VALUES ('integrity-check', 1)`)
		return err //nolint:wrapcheck // only tested for failure
	})
	if err == nil {
		return nil
	}
	return s.repairFTS(ctx)
}

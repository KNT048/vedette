package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// contentVersions is the version of what a pull of each decoder stores and how it parses its source: its tables and columns, the
// parser, the pages or files it reads. Bump a decoder's number in the same change as any of those (a new table or column a pull
// fills, a parser that reads more of the same file, a new source page): the stored data was read by the old code, so every box reads
// the feed again right after the update instead of after its interval, and never keeps an old parse because the source answers
// "not modified" (INV-32). A feed's stored version is feeds_source.content_version.
//
// Two ways the new code reads the data again, by how the feed pulls:
//   - a feed that reads its whole source at each pull is due at the next check (its back-off after failures still holds) and is asked
//     without its validators (no ETag/Last-Modified, so never a 304); the good pull records the version.
//   - an incremental feed (contentResets) starts its own full reload at the next check, in one transaction with the new version: the
//     reload then runs as the feed's own schedule runs one (pauses, Retry-After and the request gate of NVD included).
//
// The feed's switch, its key and its privacy rules stay in charge: a feed that is off is not reloaded until it is turned on, and a
// distribution feed no device needs is not fetched (its data is read again once a device needs it).
var contentVersions = map[Decoder]int{
	DecoderParser:        1, // the built-in IOC lists and every custom feed
	DecoderKEV:           1,
	DecoderEPSS:          1,
	DecoderNuclei:        1,
	DecoderNVD:           1,
	DecoderCVEOrg:        1,
	DecoderVulnCheck:     1,
	DecoderUbuntuOSV:     1,
	DecoderUbuntuVEX:     1,
	DecoderDebianTracker: 1,
	DecoderAlpineOSV:     1,
	DecoderEPSSAll:       2, // 2: FIRST's day of the scores (feeds_epss_baseline.score_date)
	DecoderNVDRecent:     1,
	DecoderWinRel:        2, // 2: the monthly updates and hotpatches of the release pages (feeds_winrel_update)
}

// contentResets are the incremental feeds: a pull asks only for what changed at the source, so a new version starts the feed's own
// full reload (in the transaction that records the version) instead of dropping validators.
var contentResets = map[Decoder]func(ctx context.Context, tx *sql.Tx) error{
	// nvd-kev: one full pull at the next check (the full_due mark of INV-28, cleared by the first full pull that is stored)
	DecoderNVD: func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE feeds_source SET full_due = 1 WHERE id = ?`, nvdFeedID)
		return err
	},
	// nvd-recent: the cursor goes, so the next pull loads the 12 months again (INV-24); the CVEs stored stay until replaced
	DecoderNVDRecent: func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM feeds_recent_cursor`)
		return err
	},
	// cve-org: every record is due again (read oldest first, cveOrgMaxPerPull a pull, at the feed's hourly pace)
	DecoderCVEOrg: func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE feeds_cveorg_checked SET checked_at = ?`, "1970-01-01T00:00:00.000Z")
		return err
	},
}

// decoderOf is the decoder a feed row pulls with: a built-in's own, DecoderParser for a custom feed (and for a built-in the code no
// longer lists, which Seed deletes).
func decoderOf(r sourceRow) Decoder {
	if r.Builtin {
		if b, ok := BuiltinByID(r.ID); ok {
			return b.Decoder
		}
	}
	return DecoderParser
}

// contentVersionOf is the version the code reads the feed's source with (contentVersions).
func contentVersionOf(r sourceRow) int { return contentVersions[decoderOf(r)] }

// reload says the stored data of the feed was read by other code than this one: the feed is read again in full (INV-32).
func (r sourceRow) reload() bool { return r.ContentVersion != contentVersionOf(r) }

// startReloads starts the full reload of every incremental feed that is on and whose stored version is not the code's, each in one
// transaction with its new version (a feed edited meanwhile is left for the next check), and returns their ids: RunPull treats them
// as due now. A feed that is off keeps its old version until it is turned on.
func (s *Service) startReloads(ctx context.Context, rows []sourceRow) (map[string]bool, error) {
	var started map[string]bool
	for _, r := range rows {
		reset := contentResets[decoderOf(r)]
		if !r.Enabled || !r.Builtin || reset == nil || !r.reload() {
			continue
		}
		done := false
		err := s.DB.Write(ctx, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, `UPDATE feeds_source SET content_version = ? WHERE id = ? AND rev = ? AND content_version = ?`,
				contentVersionOf(r), r.ID, r.Rev, r.ContentVersion)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err != nil || n == 0 {
				return err // edited or reloaded meanwhile
			}
			done = true
			return reset(ctx, tx)
		})
		if err != nil {
			return started, fmt.Errorf("feeds: starting the reload of %s: %w", r.ID, err)
		}
		if done {
			s.Log.InfoContext(ctx, "the feed is read again in full: this version of Vedette stores or parses it differently", "feed", r.ID,
				"stored_version", r.ContentVersion, "version", contentVersionOf(r))
			if started == nil {
				started = map[string]bool{}
			}
			started[r.ID] = true
		}
	}
	return started, nil
}

// contentVersionsStored reads the stored content version of every feed (feeds_source.content_version), on its own and not with
// sourceCols, so the code that reads the feed rows still works on the schema before migration 0021.
func (s *Store) contentVersionsStored(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, content_version FROM feeds_source`)
	if err != nil {
		return nil, fmt.Errorf("feeds: content versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var v int
		if err := rows.Scan(&id, &v); err != nil {
			return nil, fmt.Errorf("feeds: content versions: %w", err)
		}
		out[id] = v
	}
	return out, rows.Err()
}

// withVersion is r with its stored content version.
func (s *Store) withVersion(ctx context.Context, r sourceRow) (sourceRow, error) {
	err := s.db.Reader().QueryRowContext(ctx, `SELECT content_version FROM feeds_source WHERE id = ?`, r.ID).Scan(&r.ContentVersion)
	if err != nil {
		return r, fmt.Errorf("feeds: content version of %s: %w", r.ID, err)
	}
	return r, nil
}

// stampUnpulled gives every feed that was never pulled (a built-in Seed just added, a custom feed not pulled yet) the code's content
// version: it holds no data, so there is nothing to read again, and an incremental feed's first pull is its normal first fill.
func (s *Store) stampUnpulled(ctx context.Context) error {
	rows, err := s.sources(ctx)
	if err != nil {
		return err
	}
	stored, err := s.contentVersionsStored(ctx)
	if err != nil {
		return err
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range rows {
			if stored[r.ID] != 0 || r.LastFetch != nil {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET content_version = ? WHERE id = ? AND content_version = 0 AND last_fetch IS NULL`,
				contentVersionOf(r), r.ID); err != nil {
				return fmt.Errorf("feeds: content version of %s: %w", r.ID, err)
			}
		}
		return nil
	})
}

// reloadDue is State.Due for a feed whose stored data must be read again now: only the back-off after failures holds it back, or,
// after reloads in a row that were good but short (shortReload), the same back-off of their count from the last attempt.
func (s *Service) reloadDue(r sourceRow, now time.Time) bool {
	st := r.state()
	st.LastSuccess = time.Time{}
	if st.Failures == 0 {
		s.shortMu.Lock()
		st.Failures = s.shortReloads[r.ID]
		s.shortMu.Unlock()
	}
	return st.Due(now, r.IntervalHours)
}

// shortReload counts a reload of feed id that was good but did not read and store the whole source (INV-32).
func (s *Service) shortReload(id string) {
	s.shortMu.Lock()
	defer s.shortMu.Unlock()
	if s.shortReloads == nil {
		s.shortReloads = map[string]int{}
	}
	s.shortReloads[id]++
}

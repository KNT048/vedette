package main

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The feeds catalogue as the pulls store it, for the wiring tests that need a known exploited list and NVD answer.

// seedKEVRow writes a CISA-list entry: the catalogue row, the list entry, its exploited signal, and nuclei's public-exploit signal
// when template.
func seedKEVRow(ctx context.Context, tx *sql.Tx, cve, vendor, product, name string, added time.Time, ransomware, template bool) error {
	const list, source = "cisa", "cisa-kev"
	now := store.FormatTS(time.Now().UTC())
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, updated_at) VALUES (?, ?) ON CONFLICT(cve) DO NOTHING`, cve, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, ransomware, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cve, list, source, vendor, product, name, added.Format(time.DateOnly), ransomware, now); err != nil {
		return err
	}
	first := added.Format(time.DateOnly) + "T00:00:00.000Z"
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES (?, 'exploited', ?, ?, ?, ?, 1)`,
		cve, source, first, now, now); err != nil {
		return err
	}
	if !template {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES (?, 'public_exploit', 'nuclei-templates', ?, ?, ?, 1)`,
		cve, now, now, now)
	return err
}

// seedNVD records NVD's answer for cve, status Analyzed (a catalogue row is made when there is none): its published time (zero leaves
// it as stored) and, when score > 0, NVD's CVSS 3.1 score.
func seedNVD(ctx context.Context, tx *sql.Tx, cve string, published time.Time, score float64) error {
	const status = "Analyzed"
	now := store.FormatTS(time.Now().UTC())
	var pub any
	if !published.IsZero() {
		pub = store.FormatTS(published.UTC())
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET published = coalesce(excluded.published, published), modified = excluded.modified, nvd_status = excluded.nvd_status,
nvd_at = excluded.nvd_at, updated_at = excluded.updated_at`, cve, pub, now, status, now, now); err != nil {
		return err
	}
	if score <= 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES (?, 'nvd', '3.1', ?, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
ON CONFLICT(cve, source, version) DO UPDATE SET score = excluded.score`, cve, score)
	return err
}

// seedRange writes one NVD range of cve with no "running on" condition (its catalogue row must exist).
func seedRange(ctx context.Context, tx *sql.Tx, cve, cpe, startIncl, startExcl, endIncl, endExcl string) error {
	const platforms = "[]"
	f := strings.SplitN(strings.TrimPrefix(cpe, "cpe:2.3:"), ":", 4)
	for len(f) < 3 {
		f = append(f, "")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms)
VALUES (?, 'nvd', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, f[0], strings.ToLower(f[1]), strings.ToLower(f[2]), cpe, startIncl, startExcl, endIncl, endExcl, platforms)
	return err
}

// seedRecentDone says the catalogue pull of the window is complete (the plan reads the window only then).
func seedRecentDone(ctx context.Context, tx *sql.Tx, at time.Time) error {
	ts := store.FormatTS(at.UTC())
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total)
VALUES ('recent', 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'done', ?, ?, ?, 0, 0)`, ts, ts, ts)
	return err
}

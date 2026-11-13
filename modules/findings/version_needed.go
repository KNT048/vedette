package findings

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// NeedVersionRow is one stored "add the version" item of a device (D-500): GET /findings `version_needed`.
type NeedVersionRow struct {
	AssetID, SoftwareID, Software, Version string
	CVEs                                   int
	UpdatedAt                              time.Time
}

// replaceVersionNeeded rewrites the items of one device from a match run, in the run's transaction.
func replaceVersionNeeded(ctx context.Context, tx *sql.Tx, assetID string, items []VersionNeeded, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_version_needed WHERE asset_id = ?`, assetID); err != nil {
		return fmt.Errorf("findings: clearing version-needed items: %w", err)
	}
	for _, n := range items {
		if len(n.CVEs) == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_version_needed (asset_id, software_id, software, version, cves, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			assetID, n.SoftwareID, n.Software, n.Version, len(n.CVEs), store.FormatTS(now)); err != nil {
			return fmt.Errorf("findings: storing a version-needed item: %w", err)
		}
	}
	return nil
}

// ListVersionNeeded returns the "add the version" items of one device, or of every device when assetID is empty,
// the largest first.
func (s *Service) ListVersionNeeded(ctx context.Context, assetID string) ([]NeedVersionRow, error) {
	q := `SELECT asset_id, software_id, software, version, cves, updated_at FROM fnd_version_needed`
	var args []any
	if assetID != "" {
		q += ` WHERE asset_id = ?`
		args = append(args, assetID)
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, q+` ORDER BY cves DESC, asset_id, software_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading version-needed items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []NeedVersionRow{}
	for rows.Next() {
		var r NeedVersionRow
		var ts string
		if err := rows.Scan(&r.AssetID, &r.SoftwareID, &r.Software, &r.Version, &r.CVEs, &ts); err != nil {
			return nil, fmt.Errorf("findings: reading version-needed items: %w", err)
		}
		if r.UpdatedAt, err = parseTS(ts); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

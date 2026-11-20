package response

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/knt048/vedette/core/lifecycle"
)

// DeviceMerged is response's part of a device merge (core/lifecycle, inside the inventory's write): the plans, events and requests of
// device m.From are about device m.Into now; each keeps the device name it stored. A deleted device needs nothing here: they are a
// log of what was proposed and done, kept with that name.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if m.From == "" || m.Into == "" || m.From == m.Into {
		return nil
	}
	for _, q := range []string{
		`UPDATE resp_plans SET asset_id = ?2 WHERE asset_id = ?1`,
		`UPDATE resp_events SET asset_id = ?2 WHERE asset_id = ?1`,
		`UPDATE resp_actions SET asset_id = ?2 WHERE asset_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, m.From, m.Into); err != nil {
			return fmt.Errorf("response: move the requests of a merged device: %w", err)
		}
	}
	return nil
}

// FindingFolded is response's part of a merge that folds finding f.From into f.Into (same device and CVE): its plans, events and
// requests name the finding that stays.
func (s *Service) FindingFolded(ctx context.Context, tx *sql.Tx, f lifecycle.FindingFold) error {
	for _, q := range []string{
		`UPDATE resp_plans SET finding_id = ?2 WHERE finding_id = ?1`,
		`UPDATE resp_events SET finding_id = ?2 WHERE finding_id = ?1`,
		`UPDATE resp_actions SET finding_id = ?2 WHERE finding_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, f.From, f.Into); err != nil {
			return fmt.Errorf("response: follow a folded finding: %w", err)
		}
	}
	return nil
}

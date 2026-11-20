package conn

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/knt048/vedette/core/lifecycle"
)

// DeviceMerged is the connections' part of a device merge (core/lifecycle, inside the inventory's write): a connection a person linked
// to device m.From is linked to m.Into, the device it joined.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if m.From == "" || m.Into == "" || m.From == m.Into {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE core_connection SET asset_id = ? WHERE asset_id = ?`, m.Into, m.From); err != nil {
		return fmt.Errorf("conn: link the connections of a merged device: %w", err)
	}
	return nil
}

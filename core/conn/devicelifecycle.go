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

// DeviceDeleted is the connections' part of a device delete (core/lifecycle, inside the inventory's write): a connection linked to
// the deleted device stays, linked to no device.
func (s *Service) DeviceDeleted(ctx context.Context, tx *sql.Tx, d lifecycle.Delete) error {
	if _, err := tx.ExecContext(ctx, `UPDATE core_connection SET asset_id = NULL WHERE asset_id = ?`, d.Device); err != nil {
		return fmt.Errorf("conn: unlink the connections of a deleted device: %w", err)
	}
	return nil
}

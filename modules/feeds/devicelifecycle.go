package feeds

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/knt048/vedette/core/lifecycle"
)

// DeviceMerged is feeds' part of a device merge (core/lifecycle, inside the inventory's write): an "I have this" answer that declared
// device m.From declares m.Into, the device it joined, so the answer's scope (HaveSince) follows the device.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if m.From == "" || m.Into == "" || m.From == m.Into {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE feeds_weekly_answer SET device_id = ? WHERE device_id = ?`, m.Into, m.From); err != nil {
		return fmt.Errorf("feeds: follow the device an answer declared: %w", err)
	}
	return nil
}

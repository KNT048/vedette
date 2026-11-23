package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/core/run"
)

// PendingRunsAboutGoneDevices counts the module's runs about a device that have not started or wait (queued, waiting) while the device
// is not in devices, the ids of every device that exists: deleting a device stops them in the same transaction (DeviceDeleted), and a
// merge gives them to the device that stays (DeviceMerged). A running one is not counted: it holds its lane until its work ends, and
// a restart stops it. It only reads, so the selfcheck runs it on its read-only handle with the inventory's list of devices.
func PendingRunsAboutGoneDevices(ctx context.Context, db *sql.DB, devices []string) (int64, error) {
	ids, err := json.Marshal(append([]string{}, devices...))
	if err != nil {
		return 0, err
	}
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM core_run WHERE module = ? AND subject_kind = 'device' AND status IN (?, ?)
		AND subject_id NOT IN (SELECT value FROM json_each(?))`, ModuleID, string(run.Queued), string(run.Waiting), string(ids)).Scan(&n); err != nil {
		return 0, fmt.Errorf("sensoractive: count runs about gone devices: %w", err)
	}
	return n, nil
}

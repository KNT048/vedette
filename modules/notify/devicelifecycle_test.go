package notify_test

import (
	"database/sql"

	"github.com/knt048/vedette/core/lifecycle"
)

// deleteDevice runs notify's part of an inventory delete in a write of its own, as the inventory does in its write.
func (e *env) deleteDevice(id, actor string) {
	e.t.Helper()
	e.write(func(tx *sql.Tx) error {
		return e.svc.DeviceDeleted(e.ctx(), tx, lifecycle.Delete{Device: id, Actor: actor})
	})
}

// mergeDevices runs notify's part of an inventory merge in a write of its own, as the inventory does in its write.
func (e *env) mergeDevices(from, into string) {
	e.t.Helper()
	e.write(func(tx *sql.Tx) error {
		return e.svc.DeviceMerged(e.ctx(), tx, lifecycle.Merge{From: from, Into: into})
	})
}

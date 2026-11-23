package main

import (
	"context"
	"database/sql"

	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
	"github.com/knt048/vedette/modules/notify"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// registerLifecycle adds the modules' parts of a device merge or delete to d.Lifecycle (core/lifecycle): the inventory runs them
// inside its own write, so every module's rows change with the device or none does. They run whether or not their module is on: the
// rows exist either way. Sensor-active adds its own when its service is built (sensorActiveService). Exposure keeps no device id (the
// gateway link is read from the inventory); agent-intake's only one is the device a token was made for (a delete clears it by its foreign key).
func registerLifecycle(d *deps, notifySvc *notify.Service, fs *feeds.Service) {
	h := d.Lifecycle
	if h == nil {
		return
	}
	if d.Findings != nil {
		h.Register(lifecycle.Participant{Name: "findings", DeviceMerged: d.Findings.DeviceMerged, DeviceDeleted: d.Findings.DeviceDeleted,
			LinesDeleted: d.Findings.LinesDeleted, MergeCommitted: d.Findings.MergeCommitted, DeleteCommitted: d.Findings.DeleteCommitted})
	}
	h.Register(lifecycle.Participant{Name: "mitigation", FindingFolded: mitigation.FindingFolded})
	if notifySvc != nil {
		h.Register(lifecycle.Participant{Name: "notify", DeviceMerged: notifySvc.DeviceMerged, DeviceDeleted: notifySvc.DeviceDeleted, FindingFolded: notifySvc.FindingFolded})
	}
	if d.Response != nil {
		h.Register(lifecycle.Participant{Name: "response", DeviceMerged: d.Response.DeviceMerged, FindingFolded: d.Response.FindingFolded,
			FindingMoved: d.Response.FindingMoved})
	}
	if d.Conn != nil {
		h.Register(lifecycle.Participant{Name: "connections", DeviceMerged: d.Conn.DeviceMerged, DeviceDeleted: d.Conn.DeviceDeleted})
	}
	if fs != nil {
		h.Register(lifecycle.Participant{Name: "feeds", DeviceMerged: fs.DeviceMerged, DeviceDeleted: fs.DeviceDeleted})
	}
	h.Register(idsParticipant(idsService(*d)))
	if d.AgentIntake != nil {
		h.Register(lifecycle.Participant{Name: "agent-intake", DeviceMerged: d.AgentIntake.DeviceMerged}) // the tokens made for a device
	}
}

// sensorActiveParticipant is sensor-active's part of a device merge or delete: its queued check, SNMP settings and device checks.
func sensorActiveParticipant(svc *sensoractive.Service) lifecycle.Participant {
	return lifecycle.Participant{Name: "sensor-active", DeviceMerged: svc.DeviceMerged, DeviceDeleted: svc.DeviceDeleted,
		MergeCommitted: svc.MergeCommitted, DeleteCommitted: svc.DeleteCommitted}
}

// A device delete stops sensor-active's queued and waiting runs about the device inside the inventory's write (sensorActiveParticipant):
// the selfcheck counts the ones left about a device that is gone, with the inventory's list of devices (no module reads another's tables).
func init() {
	selfcheck.Register(selfcheck.Invariant{Name: "sensor-active.no_pending_run_about_a_deleted_device", Count: pendingRunsAboutGoneDevices})
}

func pendingRunsAboutGoneDevices(ctx context.Context, db *sql.DB) (int64, error) {
	devices, err := inventory.ReadDeviceIDs(ctx, db)
	if err != nil {
		return 0, err
	}
	return sensoractive.PendingRunsAboutGoneDevices(ctx, db, devices)
}

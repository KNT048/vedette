package main

import (
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/mitigation"
	"github.com/knt048/vedette/modules/notify"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// registerLifecycle adds the modules' parts of a device merge or delete to d.Lifecycle (core/lifecycle): the inventory runs them
// inside its own write, so every module's rows change with the device or none does. They run whether or not their module is on: the
// rows exist either way. Sensor-active adds its own when its service is built (sensorActiveService). Exposure and agent-intake keep
// no device id (the gateway link is read from the inventory; an agent binds through the inventory's own row), so they have no part.
func registerLifecycle(d *deps, notifySvc *notify.Service, fs *feeds.Service) {
	h := d.Lifecycle
	if h == nil {
		return
	}
	if d.Findings != nil {
		h.Register(lifecycle.Participant{Name: "findings", DeviceMerged: d.Findings.DeviceMerged, DeviceDeleted: d.Findings.DeviceDeleted,
			MergeCommitted: d.Findings.MergeCommitted, DeleteCommitted: d.Findings.DeleteCommitted})
	}
	h.Register(lifecycle.Participant{Name: "mitigation", FindingFolded: mitigation.FindingFolded})
	if notifySvc != nil {
		h.Register(lifecycle.Participant{Name: "notify", DeviceMerged: notifySvc.DeviceMerged, DeviceDeleted: notifySvc.DeviceDeleted, FindingFolded: notifySvc.FindingFolded})
	}
	if d.Response != nil {
		h.Register(lifecycle.Participant{Name: "response", DeviceMerged: d.Response.DeviceMerged, FindingFolded: d.Response.FindingFolded})
	}
	if d.Conn != nil {
		h.Register(lifecycle.Participant{Name: "connections", DeviceMerged: d.Conn.DeviceMerged, DeviceDeleted: d.Conn.DeviceDeleted})
	}
	if fs != nil {
		h.Register(lifecycle.Participant{Name: "feeds", DeviceMerged: fs.DeviceMerged, DeviceDeleted: fs.DeviceDeleted})
	}
}

// sensorActiveParticipant is sensor-active's part of a device merge or delete: its queued check, SNMP settings and device checks.
func sensorActiveParticipant(svc *sensoractive.Service) lifecycle.Participant {
	return lifecycle.Participant{Name: "sensor-active", DeviceMerged: svc.DeviceMerged, DeviceDeleted: svc.DeviceDeleted,
		MergeCommitted: svc.MergeCommitted, DeleteCommitted: svc.DeleteCommitted}
}

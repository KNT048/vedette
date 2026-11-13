package response_test

import (
	"context"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/response"
)

// D-511 (#714 round 2, L1): the unknown_device trigger's kind field is the kind a type acts as (an IP phone: iot), but "unknown" for a
// type marked no_auto_isolate (a PBX), so a rule "kind in iot" cannot reach what the device_type test leaves out.
func TestUnknownDeviceKindFieldHonoursNoAutoIsolate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.dir.devices["a-phone"] = response.DeviceInfo{ID: "a-phone", IP: "192.168.18.109", MAC: "00:0b:82:e1:cf:26", Kind: "ip_phone", Seen: e.clock.Now()}
	e.dir.devices["a-pbx"] = response.DeviceInfo{ID: "a-pbx", IP: "192.168.18.110", MAC: "00:0b:82:e1:cf:27", Kind: "pbx", Seen: e.clock.Now()}
	unsub := e.svc.Subscribe(e.bus)
	defer unsub()
	for _, id := range []string{"a-phone", "a-pbx"} {
		e.must(e.bus.Publish(context.Background(), events.Event{Name: "inventory.asset.discovered", Data: map[string]any{"asset_id": id}}))
	}
	for id, want := range map[string]string{"a-phone": "iot", "a-pbx": "unknown"} {
		if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE asset_id = ? AND json_extract(fields, '$.kind') = ?`, id, want); n != 1 {
			t.Errorf("%s: no unknown_device event with kind %q", id, want)
		}
	}
}

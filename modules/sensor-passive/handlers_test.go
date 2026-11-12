package sensorpassive_test

import (
	"testing"

	sp "github.com/knt048/vedette/modules/sensor-passive"
)

// GET /inventory/sensors answers with the shape of contract.ts: one card, null interface and last_seen
// before the sensor has said anything, an empty interface list (the cards come from its heartbeat), SPAN verdict off.
func TestSensorsHandler(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	out, err := sp.NewSensorHandlers(e.svc).InventoryGetInventorySensors(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Sensors) != 1 {
		t.Fatalf("%d sensors", len(out.Sensors))
	}
	s := out.Sensors[0]
	if s.ID != sp.SensorID || s.Name != "vedette-test" || !s.Interface.Null || s.Span || string(s.Status) != "offline" || !s.LastSeen.Null ||
		len(s.Interfaces) != 0 || string(s.SpanStatus.Verdict) != "off" || s.DevicesSeen != 0 {
		t.Errorf("sensor %+v", s)
	}
	e.sensorBeat()
	out, err = sp.NewSensorHandlers(e.svc).InventoryGetInventorySensors(t.Context())
	if err != nil || len(out.Sensors[0].Interfaces) != 2 || string(out.Sensors[0].Status) != "online" || out.Sensors[0].Version.Value != "1.0.0" {
		t.Errorf("after the heartbeat: %+v %v", out.Sensors, err)
	}
}

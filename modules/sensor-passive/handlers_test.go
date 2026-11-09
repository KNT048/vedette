package sensorpassive_test

import (
	"testing"

	sp "github.com/knt048/vedette/modules/sensor-passive"
)

// GET /inventory/sensors answers with the shape of contract.ts: one card, null interface and last_seen
// before any capture, the interface list from the host, SPAN verdict off.
func TestSensorsHandler(t *testing.T) {
	t.Parallel()
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
		len(s.Interfaces) != 2 || string(s.SpanStatus.Verdict) != "off" || s.DevicesSeen != 0 {
		t.Errorf("sensor %+v", s)
	}
}

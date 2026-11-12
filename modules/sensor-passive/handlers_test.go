package sensorpassive_test

import (
	"errors"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
	sp "github.com/knt048/vedette/modules/sensor-passive"
)

// GET /inventory/sensors answers with the shape of contract.ts: one card, null interface and last_seen
// before the sensor has said anything (never_connected, not offline: D-387), an empty interface list (the cards come
// from its heartbeat), SPAN verdict off.
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
	if s.ID != sp.SensorID || s.Name != "vedette-test" || !s.Interface.Null || s.Span || s.Chosen || string(s.Status) != "never_connected" || !s.LastSeen.Null ||
		len(s.Interfaces) != 0 || string(s.SpanStatus.Verdict) != "off" || s.DevicesSeen != 0 {
		t.Errorf("sensor %+v", s)
	}
	e.sensorBeat()
	out, err = sp.NewSensorHandlers(e.svc).InventoryGetInventorySensors(t.Context())
	if err != nil || len(out.Sensors[0].Interfaces) != 2 || string(out.Sensors[0].Status) != "online" || out.Sensors[0].Version.Value != "1.0.0" {
		t.Errorf("after the heartbeat: %+v %v", out.Sensors, err)
	}
	// The display name follows Config.Name (the box's name, #471): a new name is written to the same row, nothing else changes; an
	// empty one is "vedette".
	for _, c := range []struct{ give, want string }{{"office-box", "office-box"}, {"", "vedette"}} {
		e.name.Store(&c.give)
		out, err = sp.NewSensorHandlers(e.svc).InventoryGetInventorySensors(t.Context())
		if err != nil || len(out.Sensors) != 1 || out.Sensors[0].ID != sp.SensorID || out.Sensors[0].Name != c.want || string(out.Sensors[0].Status) != "online" {
			t.Errorf("name %q: %+v %v", c.give, out.Sensors, err)
		}
	}
}

// PATCH /inventory/sensors/{id} (D-387, D-393): without a host the card is chosen among the heartbeat's cards (SPAN or not), a refusal is a
// plain sentence under bad_interface, and with a host it is 409 set_in_box_network and nothing changes.
func TestPatchSensorChoosesTheSpanCardOnlyWithoutAHost(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	h := sp.NewSensorHandlers(e.svc)
	ctx := server.WithPrincipal(t.Context(), server.Principal{ID: "u1", Email: "admin@example.org", Role: "admin"})
	patch := func(iface string, span bool) (*oas.InventoryPatchInventorySensorsIDOK, error) {
		req := &oas.InventoryPatchInventorySensorsIDReq{Span: span}
		if iface == "" {
			req.Interface.SetToNull()
		} else {
			req.Interface.SetTo(iface)
		}
		return h.InventoryPatchInventorySensorsID(ctx, req, oas.InventoryPatchInventorySensorsIDParams{ID: sp.SensorID})
	}
	code := func(err error) (int, string, string) {
		ae, ok := apierr.As(err)
		if !ok {
			return 0, "", ""
		}
		return ae.Status, ae.Code, ae.Message
	}

	if _, err := patch("eth1", true); err == nil {
		t.Fatal("with a host: accepted")
	} else if st, c, _ := code(err); st != 409 || c != "set_in_box_network" {
		t.Fatalf("with a host: %v", err)
	}
	if list, _ := e.svc.Status(t.Context()); list[0].Span {
		t.Fatalf("with a host the refusal changed the sensor: %+v", list[0])
	}
	e.host.setListErr(errors.New("vedette-host gave no list of cards")) // configured but silent: still an appliance
	if _, err := patch("eth1", true); err == nil {
		t.Fatal("a configured host that gives no list: accepted")
	} else if st, c, _ := code(err); st != 409 || c != "set_in_box_network" {
		t.Fatalf("a configured host that gives no list: %v", err)
	}
	e.host.setListErr(nil)

	e.host.setNoHost(true)
	if _, err := patch("eth1", true); err == nil {
		t.Fatal("no heartbeat yet: accepted")
	} else if st, c, m := code(err); st != 400 || c != "bad_interface" || m != "The sensor has not reported its network cards in the last 90 seconds; check that it runs, wait for its next heartbeat (30 s) and try again." {
		t.Fatalf("no heartbeat yet: %d %s %q", st, c, m)
	}
	e.sensorBeat() // eth0 with the box's address, eth1 without one
	if _, err := patch("eth0", true); err == nil {
		t.Fatal("SPAN on the card with an address: accepted")
	} else if st, c, m := code(err); st != 400 || c != "bad_interface" || m != `"eth0" has an IP address; a SPAN port has none.` {
		t.Fatalf("SPAN on the card with an address: %d %s %q", st, c, m)
	}
	got, err := patch("eth1", true)
	if err != nil || got.ID != sp.SensorID || got.Interface.Value != "eth1" || !got.Span || !got.Chosen {
		t.Fatalf("SPAN on eth1: %+v %v", got, err)
	}
	// D-393: a card with an address is chosen to listen on, without SPAN; "" goes back to the default card (not a choice).
	if got, err = patch("eth0", false); err != nil || got.Interface.Value != "eth0" || got.Span || !got.Chosen {
		t.Fatalf("listen on eth0: %+v %v", got, err)
	}
	if got, err = patch("", false); err != nil || got.Span || got.Chosen {
		t.Fatalf("SPAN off: %+v %v", got, err)
	}
	if _, err := h.InventoryPatchInventorySensorsID(ctx, &oas.InventoryPatchInventorySensorsIDReq{}, oas.InventoryPatchInventorySensorsIDParams{ID: "sn-other"}); err == nil {
		t.Fatal("another sensor: accepted")
	} else if st, c, _ := code(err); st != 404 || c != "not_found" {
		t.Fatalf("another sensor: %v", err)
	}
}

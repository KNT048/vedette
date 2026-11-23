package inventory_test

import (
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// A device found with no IPv4 address (a switch an LLDP frame named by its MAC) is announced discovered with NoAddress, so nothing
// queues a network check that cannot reach it; a device found at an address is announced without it.
func TestDiscovered_SaysWhenTheDeviceHasNoAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const lldpMAC = "3c:8a:b0:00:00:47"
	e.record(obsv(lldpMAC, observe.Hostname, "ex4200-access", observe.Passive, 0.8), obsv(lldpMAC, observe.Model, "EX4200-48T", observe.Passive, 0.8))
	e.record(dhcp("3c:8a:b0:00:00:48", "192.0.2.48", "")...)
	ev := e.discovered()
	if a := ev[e.idByMAC(lldpMAC)]; !a.NoAddress {
		t.Errorf("discovered event of the device without an address: %+v", a)
	}
	if a := ev[e.idOf("192.0.2.48")]; a.NoAddress || a.AssetID == "" {
		t.Errorf("discovered event of the device at an address: %+v", a)
	}
}

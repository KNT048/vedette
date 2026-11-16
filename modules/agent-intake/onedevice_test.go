package agentintake_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
)

// D-598 (issue #829): osquery installed on a machine a scan found reports onto that device, and when DHCP gives the machine a new
// address before any sensor sees the move, its next report still lands on that device (found by the node the box enrolled, INV-12),
// which moves to the new address: one device, never a second.
func TestContract_D598_AnEnrolledMachineThatMovesStaysOneDevice(t *testing.T) {
	w := newWorld(t)
	const peerB = "192.0.2.44"
	const card = "00:16:3e:aa:bb:01" // burned in (macA is QEMU's locally administered 52:54:00, which the name rule would join anyway)
	report := func(key, peer string) map[string]any {
		return logBody(key, snap("interfaces", ifaceRow(card, peer)), snap("system_info", map[string]string{"hostname": "srv-1"}),
			snap("os_version", map[string]string{"name": "Ubuntu", "version": "24.04.1 LTS (Noble Numbat)", "major": "24", "minor": "4", "patch": "1", "build": "", "platform": "ubuntu", "arch": "x86_64"}))
	}
	if err := w.inv.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{MAC: card, IP: netip.MustParseAddr(peerA)},
		Field: observe.MAC, Value: card, Source: observe.Passive, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	scanned, _ := w.device(peerA)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, report(key, peerA))
	if d, ok := w.device(peerA); !ok || d.ID != scanned.ID || w.deviceCount() != 1 {
		t.Fatalf("the first report: on %s (want %s), %d devices", d.ID, scanned.ID, w.deviceCount())
	}
	w.clock.Advance(2 * time.Hour)
	w.post("/intake/osquery/log", peerB, report(key, peerB))
	d, ok := w.device(peerB)
	if !ok || d.ID != scanned.ID || w.deviceCount() != 1 {
		t.Fatalf("after the move: at %s %v id %s (want %s), %d devices", peerB, ok, d.ID, scanned.ID, w.deviceCount())
	}
}

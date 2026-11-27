package agentintake_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// Removing a device whose osquery agent reports (INV-27, inventory INV-59). Stop: the device's node goes, so its next log or config
// call gets node_invalid and no device comes back; a token made for that device alone goes too; a token other machines use stays, the
// other machine keeps reporting, and this machine cannot enrol with that token again. Keep: the agent adds the device back on its next
// report, and nothing is kept. The audit row of the delete names the choice.
func TestContract_RemovingADeviceWithAnAgent(t *testing.T) {
	t.Parallel()
	const peerB = "192.0.2.44"
	const cardA, cardB = "00:16:3e:aa:bb:01", "00:16:3e:aa:bb:02" // burned in
	report := func(key, card, peer, host string) map[string]any {
		return logBody(key, snap("interfaces", ifaceRow(card, peer)), snap("system_info", map[string]string{"hostname": host}))
	}
	// heard is the passive sensor hearing the machine on the wire.
	heard := func(t *testing.T, w *world, card, peer string) {
		t.Helper()
		if err := w.inv.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{MAC: card, IP: netip.MustParseAddr(peer)},
			Field: observe.MAC, Value: card, Source: observe.Passive, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	// found is the device the sensor made of it, seen before the agent was installed.
	found := func(t *testing.T, w *world, card, peer string) inventory.Device {
		t.Helper()
		heard(t, w, card, peer)
		d, ok := w.device(peer)
		if !ok {
			t.Fatalf("no device at %s", peer)
		}
		return d
	}
	deleted := func(w *world, like string) int {
		return w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.delete' AND detail LIKE ?`, "%"+like+"%")
	}

	t.Run("stop, with a token made for the device", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		d := found(t, w, cardA, peerA)
		tk, secret, err := w.svc.IssueTokenFor(t.Context(), "admin@acme.example", "srv-1 token", 7, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		key := w.enroll(secret, "srv-1", peerA)
		w.post("/intake/osquery/log", peerA, report(key, cardA, peerA, "srv-1"))
		if err := w.inv.DeleteDevice(t.Context(), "admin@acme.example", d.ID, inventory.AgentStop); err != nil {
			t.Fatal(err)
		}
		if r := w.post("/intake/osquery/log", peerA, report(key, cardA, peerA, "srv-1")); !r.invalid() {
			t.Fatalf("log with the old node key: %d %s", r.code, r.raw)
		}
		if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); !r.invalid() {
			t.Fatalf("config with the old node key: %d %s", r.code, r.raw)
		}
		heard(t, w, cardA, peerA) // the passive sensor hears it again
		if n := w.deviceCount(); n != 0 {
			t.Fatalf("%d devices after the removal, want none", n)
		}
		if w.count(`SELECT count(*) FROM intake_agent_tokens WHERE id = ?`, tk.ID) != 0 {
			t.Fatal("the token made for the device is still there")
		}
		if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-1")); !r.invalid() {
			t.Fatalf("enrolling again with the revoked token: %d %s", r.code, r.raw)
		}
		if deleted(w, "its agent was stopped and its token srv-1 token revoked") != 1 {
			t.Fatal("the audit row does not name the choice")
		}
	})

	t.Run("stop, with a token other machines use", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		d := found(t, w, cardA, peerA)
		tk, secret := w.token("office", 7)
		keyA := w.enroll(secret, "srv-1", peerA)
		w.post("/intake/osquery/log", peerA, report(keyA, cardA, peerA, "srv-1"))
		keyB := w.enroll(secret, "srv-2", peerB)
		w.post("/intake/osquery/log", peerB, report(keyB, cardB, peerB, "srv-2"))
		if err := w.inv.DeleteDevice(t.Context(), "admin@acme.example", d.ID, inventory.AgentStop); err != nil {
			t.Fatal(err)
		}
		if r := w.post("/intake/osquery/log", peerA, report(keyA, cardA, peerA, "srv-1")); !r.invalid() {
			t.Fatalf("log with the removed machine's node key: %d %s", r.code, r.raw)
		}
		if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-1")); !r.invalid() {
			t.Fatalf("the removed machine enrols again with the shared token: %d %s", r.code, r.raw)
		}
		if w.count(`SELECT count(*) FROM intake_agent_tokens WHERE id = ?`, tk) != 1 {
			t.Fatal("a token other machines use was revoked")
		}
		if r := w.post("/intake/osquery/log", peerB, report(keyB, cardB, peerB, "srv-2")); r.invalid() {
			t.Fatal("the other machine is refused")
		}
		if _, ok := w.device(peerA); ok || w.deviceCount() != 1 {
			t.Fatalf("%d devices; the removed one is back: %v", w.deviceCount(), ok)
		}
		removed, err := w.inv.RemovedDevices(t.Context())
		if err != nil || len(removed) != 1 || removed[0].Agent != "stopped" {
			t.Fatalf("removed = %+v, %v", removed, err)
		}
		if deleted(w, "its agent was stopped") != 1 || deleted(w, "revoked") != 0 {
			t.Fatal("the audit row does not name the choice")
		}
		// Forgetting the removal lets the machine enrol again
		if err := w.inv.ForgetRemoved(t.Context(), "admin@acme.example", removed[0].ID); err != nil {
			t.Fatal(err)
		}
		w.enroll(secret, "srv-1", peerA)
	})

	t.Run("keep", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		d := found(t, w, cardA, peerA)
		_, secret := w.token("office", 7)
		key := w.enroll(secret, "srv-1", peerA)
		w.post("/intake/osquery/log", peerA, report(key, cardA, peerA, "srv-1"))
		if err := w.inv.DeleteDevice(t.Context(), "operator@acme.example", d.ID, inventory.AgentKeep); err != nil {
			t.Fatal(err)
		}
		if removed, err := w.inv.RemovedDevices(t.Context()); err != nil || len(removed) != 0 {
			t.Fatalf("removed = %+v, %v: a removal with the agent left running keeps nothing", removed, err)
		}
		if r := w.post("/intake/osquery/log", peerA, report(key, cardA, peerA, "srv-1")); r.invalid() {
			t.Fatal("the agent left running is refused")
		}
		if _, ok := w.device(peerA); !ok {
			t.Fatal("the agent's next report did not add the device back, as the dialog says")
		}
		if deleted(w, "its agent was left running") != 1 {
			t.Fatal("the audit row does not name the choice")
		}
	})
}

package agentintake_test

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

// releases wraps the inventory's Approver and keeps the agents agent-intake released (and passes them on).
type releases struct {
	observe.Approver
	mu  sync.Mutex
	got []string
}

func (r *releases) ReleaseAgents(ctx context.Context, agents []string) error {
	r.mu.Lock()
	r.got = append(r.got, agents...)
	r.mu.Unlock()
	return r.Approver.(observe.AgentReleaser).ReleaseAgents(ctx, agents)
}

func (r *releases) has(agent string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.got, agent)
}

// withReleases puts a releases recorder in front of the world's inventory.
func withReleases(r *releases) func(*agentintake.Config) {
	return func(c *agentintake.Config) { r.Approver = c.Approver; c.Approver = r }
}

// nodeID is the id of the only node.
func (w *world) nodeID() string {
	w.t.Helper()
	var id string
	if err := w.db.Reader().QueryRowContext(w.t.Context(), `SELECT id FROM intake_osquery_nodes`).Scan(&id); err != nil {
		w.t.Fatal(err)
	}
	return id
}

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

// D-598, review #831 M4: a machine that enrols again (same token and host_identifier) gets a new node; the old node's binding is
// released, so the new node's first report binds the same device: when the machine then moves to another address before any sensor
// sees it, its report still lands on that device.
func TestContract_D598_ReEnrolmentRebindsTheDevice(t *testing.T) {
	w := newWorld(t)
	const card, peerB = "00:16:3e:aa:bb:01", "192.0.2.44"
	report := func(key, peer string) map[string]any {
		return logBody(key, snap("interfaces", ifaceRow(card, peer)), snap("system_info", map[string]string{"hostname": "srv-1"}))
	}
	_, secret := w.token("srv", 7)
	first := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, report(first, peerA))
	d, _ := w.device(peerA)
	w.clock.Advance(2 * time.Minute)
	second := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, report(second, peerA))
	w.clock.Advance(time.Hour)
	w.post("/intake/osquery/log", peerB, report(second, peerB))
	if moved, ok := w.device(peerB); !ok || moved.ID != d.ID || w.deviceCount() != 1 {
		t.Errorf("after the move: at %s %v id %s (want %s), %d devices", peerB, ok, moved.ID, d.ID, w.deviceCount())
	}
}

// D-598, review #831 round 2: revoking a token releases its nodes' bindings in the inventory, and so does pruning a silent node.
func TestContract_D598_RevokeAndPruneReleaseTheNodes(t *testing.T) {
	r := &releases{}
	w := newWorld(t, withReleases(r))
	id, secret := w.token("srv", 7)
	w.enroll(secret, "srv-1", peerA)
	node := w.nodeID()
	if err := w.svc.RevokeToken(t.Context(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if !r.has("osquery:" + node) {
		t.Errorf("revoke released %v, want osquery:%s", r.got, node)
	}

	p := &releases{}
	w = newWorld(t, withReleases(p))
	_, secret = w.token("srv", 0)
	w.enroll(secret, "srv-1", peerA)
	node = w.nodeID()
	w.pruneFor(agentintake.NodeSilentDays*24*time.Hour + 4*time.Hour)
	if w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 0 || !p.has("osquery:"+node) {
		t.Errorf("prune released %v, want osquery:%s", p.got, node)
	}
}

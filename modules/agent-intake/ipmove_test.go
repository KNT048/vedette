package agentintake_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
)

// #829: a laptop with osquery that DHCP moves. The passive sensor sees its card at the new address first (a DHCP request is
// broadcast); its next reports, before the hourly interfaces answer, land on its device at once (the node is the strongest identity),
// config asks for its interfaces every minute until a report binds it again, and the report that carries them keeps the node bound (a
// sensor seeing the machine where it reports from is a move, not a spoof). A copied key used from another address still writes nothing.
func TestContract_829_AnOsqueryMachineThatMovesReportsAtOnce(t *testing.T) {
	w := newWorld(t)
	const peerB, peerC = "192.0.2.44", "192.0.2.77"
	const card = "00:16:3e:aa:bb:01" // burned in
	sees := func(ip string) {
		t.Helper()
		if err := w.inv.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{MAC: card, IP: netip.MustParseAddr(ip)},
			Field: observe.MAC, Value: card, Source: observe.Passive, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	interfaces := func(ip string) map[string]any { return snap("interfaces", ifaceRow(card, ip)) }
	sees(peerA)
	scanned, _ := w.device(peerA)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, logBody(key, interfaces(peerA), snap("system_info", map[string]string{"hostname": "srv-1"})))
	w.clock.Advance(2 * time.Hour) // past the first report's hour: interfaces hourly
	if got := w.intervalsFrom(key, peerA)["interfaces"]; got != 3600 {
		t.Fatalf("interfaces every %v s from the bound address, want 3600", got)
	}

	sees(peerB) // DHCP moved the machine; the sensor saw it
	if got := w.intervalsFrom(key, peerB)["interfaces"]; got != 60 {
		t.Errorf("interfaces every %v s from a new address, want 60 until a report binds it", got)
	}
	w.post("/intake/osquery/log", peerB, logBody(key, snap("deb_packages", debRow("openssh-server", "1:9.7p1-1"))))
	d, ok := w.device(peerB)
	if s, has := swByProduct(d, "OpenSSH"); !ok || d.ID != scanned.ID || !has || *s.Version != "9.7p1" {
		t.Fatalf("a report from the new address before its interfaces answer: device %v %s, software %+v", ok, d.ID, d.Software)
	}

	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	w.post("/intake/osquery/log", peerB, logBody(key, interfaces(peerB), snap("deb_packages", debRow("openssh-server", "1:9.8p1-1"))))
	d, _ = w.device(peerB)
	if s, _ := swByProduct(d, "OpenSSH"); d.ID != scanned.ID || *s.Version != "9.8p1" || w.deviceCount() != 1 {
		t.Fatalf("the report with interfaces: device %s software %+v, %d devices", d.ID, d.Software, w.deviceCount())
	}
	if got := w.intervalsFrom(key, peerB)["interfaces"]; got != 3600 {
		t.Errorf("interfaces every %v s once bound again, want 3600", got)
	}

	// Still bound (a legitimate move is no spoof): DHCP moves it again, no sensor sees it, and its report with interfaces moves the
	// same device instead of making a second.
	w.clock.Advance(6 * time.Minute)
	const peerD = "192.0.2.45"
	w.post("/intake/osquery/log", peerD, logBody(key, interfaces(peerD), snap("system_info", map[string]string{"hostname": "srv-1"})))
	if d, ok := w.device(peerD); !ok || d.ID != scanned.ID || w.deviceCount() != 1 {
		t.Fatalf("a legitimate move dropped the node's binding as a spoof: at %s %v id %s, %d devices", peerD, ok, d.ID, w.deviceCount())
	}

	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerC, logBody(key, snap("deb_packages", debRow("openssh-server", "1:9.9p1-1"))))
	d, _ = w.device(peerD)
	if s, _ := swByProduct(d, "OpenSSH"); *s.Version != "9.8p1" || w.deviceCount() != 1 {
		t.Errorf("a key used from an address no sensor saw the device at wrote: %+v, %d devices", d.Software, w.deviceCount())
	}
}

// intervalsFrom is the schedule config gives the node asking from remote.
func (w *world) intervalsFrom(key, remote string) map[string]float64 {
	w.t.Helper()
	r := w.post("/intake/osquery/config", remote, map[string]any{"node_key": key})
	sch, _ := r.body["schedule"].(map[string]any)
	if r.code != 200 || r.invalid() {
		w.t.Fatalf("config: %d %s", r.code, r.raw)
	}
	out := map[string]float64{}
	for name, q := range sch {
		out[name], _ = q.(map[string]any)["interval"].(float64)
	}
	return out
}

// Review r1 H1 of #872: a copied node key used from an address the node did not declare stores nothing on the node: its kernel_info (or
// os_revision) does not become the kernel the device's next list is matched with.
func TestContract_829_ACopiedKeyFromElsewhereStoresNoKernel(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("kernel_info", map[string]string{"version": "7.0.0-43-generic"})))
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", "192.0.2.99", logBody(key, snap("kernel_info", map[string]string{"version": "7.0.0-30-generic"}),
		snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "1", "arch": "64-bit"})))
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE kernel = '7.0.0-43-generic' AND win_version = ''`); n != 1 {
		t.Errorf("a key used from another address changed the node's kernel or Windows release")
	}
}

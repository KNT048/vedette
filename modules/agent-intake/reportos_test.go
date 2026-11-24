package agentintake_test

import (
	"testing"
	"time"
)

// softwareRow is the version (PkgVersion when set, else Version) of peerA's device's software row with this vendor and product prefix.
func (w *world) softwareRow(vendor, product string) string {
	w.t.Helper()
	d, ok := w.device(peerA)
	if !ok {
		w.t.Fatal("no device")
	}
	in, _, err := w.inv.MatchInput(w.t.Context(), d.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, s := range in.Software {
		if s.Vendor == vendor && len(s.Product) >= len(product) && s.Product[:len(product)] == product {
			if s.PkgVersion != "" {
				return s.PkgVersion
			}
			return s.Version
		}
	}
	w.t.Fatalf("no %s %s row: %+v", vendor, product, in.Software)
	return ""
}

// open says whether the device's ask is open (GET asked_at) and the node's package query is on the 60 s interval.
func (w *world) askIsOpen(key, path, query string) bool {
	w.t.Helper()
	r := w.req("viewer", "GET", path)
	if r.code != 200 {
		w.t.Fatalf("GET: %d %s", r.code, r.raw)
	}
	fast := w.intervals(key)[query] == 60
	if (r.body["asked_at"] != nil) != fast {
		w.t.Fatalf("GET says asked_at %v but %s runs every %v s", r.body["asked_at"], query, w.intervals(key)[query])
	}
	return fast
}

// Review r1 M1 of #953 (INV-23): osquery sends the package list and kernel_info on separately splayed intervals. An ask closes only on
// a list the inventory took after the node's kernel answer came since the ask, so the Kernel row ends on the running kernel in either
// order: list first (taken with the old kernel, the ask stays open, the next list taken is built with the new kernel), or kernel first.
func TestContract_INV23_LinuxAskWaitsForTheKernel(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv01", peerA)
	images := snap("deb_packages",
		map[string]string{"name": "linux-image-7.0.0-30-generic", "version": "7.0.0-30.30", "arch": "amd64", "source": "linux-signed"},
		map[string]string{"name": "linux-image-7.0.0-43-generic", "version": "7.0.0-43.43", "arch": "amd64", "source": "linux-signed"})
	kernel := func(rel string) map[string]any { return snap("kernel_info", map[string]string{"version": rel}) }
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), kernel("7.0.0-30-generic"), images))
	if got := w.softwareRow("Linux", "Kernel"); got != "7.0.0-30.30" {
		t.Fatalf("running 30: %s", got)
	}
	w.clock.Advance(61 * time.Minute)
	d, _ := w.device(peerA)
	path := "/inventory/agents/devices/" + d.ID + "/report"

	// Order 1: the machine rebooted into 43; the ask; the list comes first, then the kernel, then the next lists.
	if r := w.req("operator", "POST", path); r.code != 200 {
		t.Fatalf("ask: %d %s", r.code, r.raw)
	}
	w.clock.Advance(2 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, images))
	if !w.askIsOpen(key, path, "deb_packages") {
		t.Fatal("the list alone, with the old kernel, closed the ask")
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, kernel("7.0.0-43-generic")))
	if !w.askIsOpen(key, path, "deb_packages") {
		t.Fatal("the kernel alone closed the ask")
	}
	w.clock.Advance(40 * time.Second) // within the source window of the first list: dropped, not taken
	w.post("/intake/osquery/log", peerA, logBody(key, images))
	if !w.askIsOpen(key, path, "deb_packages") {
		t.Fatal("a list the source window dropped closed the ask")
	}
	w.clock.Advance(5 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, images))
	if got := w.softwareRow("Linux", "Kernel"); got != "7.0.0-43.43" {
		t.Fatalf("after the list built with the new kernel: %s", got)
	}
	if w.askIsOpen(key, path, "deb_packages") {
		t.Fatal("the list taken after the kernel did not close the ask")
	}

	// Order 2: back on 30; the kernel comes first, then the list.
	w.clock.Advance(11 * time.Minute)
	if r := w.req("operator", "POST", path); r.code != 200 {
		t.Fatalf("second ask: %d %s", r.code, r.raw)
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, kernel("7.0.0-30-generic")))
	if !w.askIsOpen(key, path, "deb_packages") {
		t.Fatal("the kernel alone closed the second ask")
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, images))
	if got := w.softwareRow("Linux", "Kernel"); got != "7.0.0-30.30" || w.askIsOpen(key, path, "deb_packages") {
		t.Fatalf("kernel then list: row %s, ask still open %v", got, w.askIsOpen(key, path, "deb_packages"))
	}

	// Order 3: both in one request close it at once.
	w.clock.Advance(11 * time.Minute)
	if r := w.req("operator", "POST", path); r.code != 200 {
		t.Fatalf("third ask: %d %s", r.code, r.raw)
	}
	w.clock.Advance(5 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, kernel("7.0.0-43-generic"), images))
	if got := w.softwareRow("Linux", "Kernel"); got != "7.0.0-43.43" || w.askIsOpen(key, path, "deb_packages") {
		t.Fatalf("kernel and list together: row %s", got)
	}
}

// Review r1 M1 of #953: the same on Windows with os_revision (the update revision the Windows row of the programs list is built from).
func TestContract_INV23_WindowsAskWaitsForTheRevision(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("pc", 7)
	key := w.enroll(secret, "pc-01", peerA)
	osv := snap("os_version", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "major": "10", "minor": "0", "build": "22631", "platform": "windows", "arch": "64-bit"})
	progs := snap("programs", map[string]string{"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"})
	rev := func(r string) map[string]any {
		return snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": r, "arch": "64-bit"})
	}
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osv, rev("4460"), progs))
	if got := w.softwareRow("microsoft", "Windows"); got != "10.0.22631.4460" {
		t.Fatalf("UBR 4460: %s", got)
	}
	w.clock.Advance(61 * time.Minute)
	d, _ := w.device(peerA)
	path := "/inventory/agents/devices/" + d.ID + "/report"

	// Order 1: the programs first (the old revision), then the revision, then the next programs.
	if r := w.req("operator", "POST", path); r.code != 200 {
		t.Fatalf("ask: %d %s", r.code, r.raw)
	}
	w.clock.Advance(2 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, progs))
	if !w.askIsOpen(key, path, "programs") {
		t.Fatal("the programs alone, with the old revision, closed the ask")
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("4500")))
	if !w.askIsOpen(key, path, "programs") {
		t.Fatal("the revision alone closed the ask")
	}
	w.clock.Advance(5 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, progs))
	if got := w.softwareRow("microsoft", "Windows"); got != "10.0.22631.4500" || w.askIsOpen(key, path, "programs") {
		t.Fatalf("programs after the revision: row %s", got)
	}

	// Order 2: the revision first, then the programs.
	w.clock.Advance(11 * time.Minute)
	if r := w.req("operator", "POST", path); r.code != 200 {
		t.Fatalf("second ask: %d %s", r.code, r.raw)
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("4600")))
	if !w.askIsOpen(key, path, "programs") {
		t.Fatal("the revision alone closed the second ask")
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, progs))
	if got := w.softwareRow("microsoft", "Windows"); got != "10.0.22631.4600" || w.askIsOpen(key, path, "programs") {
		t.Fatalf("revision then programs: row %s", got)
	}
}

// Review r1 L1, L3, L4 of #953: the ask reaches only the asked device's node (another node stays hourly); GET says when the node last
// called and whether it is out of reach now (stale: more than 10 minutes), and from when a new ask is possible.
func TestContract_INV23_ScopeReachAndNextAsk(t *testing.T) {
	const peerB, macB = "192.0.2.11", "52:54:00:aa:bb:02"
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	keyA := w.enroll(secret, "srv-a", peerA)
	keyB := w.enroll(secret, "srv-b", peerB)
	w.post("/intake/osquery/log", peerA, fullLog(keyA))
	w.post("/intake/osquery/log", peerB, logBody(keyB, snap("interfaces", ifaceRow(macB, peerB)), snap("deb_packages", debRow("nginx", "1.24.0-2ubuntu7"))))
	w.refresh(keyA)
	w.clock.Advance(61 * time.Minute)
	d, _ := w.device(peerA)
	path := "/inventory/agents/devices/" + d.ID + "/report"

	// Silent for an hour: out of reach; a config fetch brings it back.
	if r := w.req("viewer", "GET", path); r.code != 200 || r.body["stale"] != true || r.body["last_seen"] == nil || r.body["ask_again_at"] != nil {
		t.Fatalf("silent node: %d %s", r.code, r.raw)
	}
	w.intervalsFrom(keyA, peerA)
	if r := w.req("viewer", "GET", path); r.body["stale"] != false {
		t.Fatalf("after a config fetch: %s", r.raw)
	}

	r := w.req("operator", "POST", path)
	if r.code != 200 || r.body["ask_again_at"] == nil {
		t.Fatalf("ask: %d %s", r.code, r.raw)
	}
	again, err := time.Parse(time.RFC3339Nano, r.body["ask_again_at"].(string))
	if err != nil || !again.Equal(w.clock.Now().Add(10*time.Minute)) {
		t.Fatalf("ask_again_at %v (%v), want ten minutes on", again, err)
	}
	if got := w.intervalsFrom(keyA, peerA)["deb_packages"]; got != 60 {
		t.Fatalf("the asked node: deb_packages every %v s", got)
	}
	wantIntervals(t, "the other node", w.intervalsFrom(keyB, peerB), hourly)
	w.clock.Advance(10 * time.Minute)
	if r := w.req("viewer", "GET", path); r.body["ask_again_at"] != nil {
		t.Fatalf("ten minutes on: %s", r.raw)
	}
}

package agentintake_test

import (
	"testing"
	"time"
)

// D-516, review round 2 of #732: osquery's kernel_info is its own one-row query, so it may arrive in another request than the
// package list. The node keeps the last kernel it reported; the package list then gives the Kernel row the running kernel's
// image (7.0.0-43 running with 7.0.0-30 installed → 43; after a "reboot" into 30 → 30). A node that never reported a kernel
// gets the lowest installed image.
func TestContract_D516_KernelOfAnotherRequest(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "byn", peerA)
	images := snap("deb_packages",
		map[string]string{"name": "linux-image-7.0.0-30-generic", "version": "7.0.0-30.30", "arch": "amd64", "source": "linux-signed"},
		map[string]string{"name": "linux-image-7.0.0-43-generic", "version": "7.0.0-43.43", "arch": "amd64", "source": "linux-signed"},
		map[string]string{"name": "linux-image-generic", "version": "7.0.0-43.43", "arch": "amd64", "source": "linux-meta"})
	kernelRow := func() string {
		t.Helper()
		d, ok := w.device(peerA)
		if !ok {
			t.Fatal("no device")
		}
		in, _, err := w.inv.MatchInput(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range in.Software {
			if s.Product == "Kernel" {
				return s.PkgVersion
			}
		}
		t.Fatalf("no Kernel row: %+v", in.Software)
		return ""
	}
	// no kernel reported yet: the lowest image
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), images))
	if got := kernelRow(); got != "7.0.0-30.30" {
		t.Fatalf("no running kernel known: %s, want the lowest", got)
	}
	// the kernel in one request, the package list in a later one
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("kernel_info", map[string]string{"version": "7.0.0-43-generic"})))
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, images))
	if got := kernelRow(); got != "7.0.0-43.43" {
		t.Fatalf("running 7.0.0-43: %s", got)
	}
	// both in one request: the running kernel of that request
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("kernel_info", map[string]string{"version": "7.0.0-30-generic"}), images))
	if got := kernelRow(); got != "7.0.0-30.30" {
		t.Fatalf("running 7.0.0-30: %s", got)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE kernel = '7.0.0-30-generic'`); n != 1 {
		t.Fatalf("the node's kernel is not stored: %d", n)
	}
	// a value that is not a kernel release is not taken: the stored one stays
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("kernel_info", map[string]string{"version": "7.0.0-43-generic; rm -rf /"}), images))
	if got := kernelRow(); got != "7.0.0-30.30" {
		t.Fatalf("a bad kernel value changed the row: %s", got)
	}
}

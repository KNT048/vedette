package agentintake_test

import (
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// D-524: Windows's update revision comes in its own query (os_revision), which may arrive in another request than os_version. The
// node keeps the last one and the device reads "Microsoft Windows 11 Pro 10.0.22631.4460". The revision is an answer of its own of
// the first report: asked every minute until a usable one came, even when os_version came first (review M3), and its own report
// shows the OS at once. A revision that is not a positive integer is not taken. No software row is made from it yet: KEV matching
// of the Windows release is the findings owner's follow-up.
func TestContract_D524_WindowsRevisionOfAnotherRequest(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("pc", 7)
	key := w.enroll(secret, "pc-01", peerA)
	osv := snap("os_version", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "major": "10", "minor": "0", "build": "22631", "platform": "windows", "arch": "64-bit"})
	progs := snap("programs", map[string]string{"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"})
	rev := func(r string) map[string]any {
		return snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": r, "arch": "64-bit"})
	}
	osText := func() string {
		t.Helper()
		d, ok := w.device(peerA)
		if !ok {
			t.Fatal("no device")
		}
		in, _, err := w.inv.MatchInput(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(in.Software, func(s inventory.MatchSoftware) bool {
			return s.Vendor == "microsoft"
		}) {
			t.Fatalf("a Windows software row was made: %+v", in.Software)
		}
		return in.OS
	}
	// os_version and the programs first: the OS with its build; os_revision is still asked every minute
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osv, progs))
	if os := osText(); os != "Microsoft Windows 11 Pro 10.0.22631 build 22631" {
		t.Fatalf("no revision: %q", os)
	}
	wantIntervals(t, "os_version before the revision", w.intervals(key), map[string]float64{"os_version": 3600, "programs": 3600, "os_revision": 60})
	// the revision alone, a minute later: the OS shows it at once and the query goes back to hourly
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("4460")))
	if os := osText(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("revision 4460: %q", os)
	}
	wantIntervals(t, "revision taken", w.intervals(key), map[string]float64{"os_revision": 3600})
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE win_version = '10.0.22631.4460' AND win_target = 'x64'`); n != 1 {
		t.Fatalf("the node's revision is not stored: %d", n)
	}
	// os_version in a later request keeps the stored revision on the OS
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, osv, progs))
	if os := osText(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("os_version after the revision: %q", os)
	}
	// a value that is not a revision is not taken: the stored one stays
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("0"), osv))
	if os := osText(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("a bad revision changed the OS: %q", os)
	}
	// a new monthly update: the next revision replaces it
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("5189"), osv))
	if os := osText(); os != "Microsoft Windows 11 Pro 10.0.22631.5189" {
		t.Fatalf("revision 5189: %q", os)
	}
}

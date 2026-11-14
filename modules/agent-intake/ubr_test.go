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
// shows the OS at once. A revision that is not a positive integer is not taken.
//
// D-546: every Windows package list then carries the operating system's row (Windows 11 23H2, 10.0.22631.<UBR>, CPE of the release
// with the target, key microsoft|windows), which findings matches by the update revision. A Windows list without it (the revision
// not reported yet) does not end the first report's package answer, so the row comes within minutes (review M3). A feature update
// (os_version of another build, no revision yet) clears the stored release: no stale row of the old release (review M2).
func TestContract_D524_WindowsRevisionOfAnotherRequest(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("pc", 7)
	key := w.enroll(secret, "pc-01", peerA)
	osvOf := func(build string) map[string]any {
		return snap("os_version", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0." + build, "major": "10", "minor": "0", "build": build, "platform": "windows", "arch": "64-bit"})
	}
	osv := osvOf("22631")
	progs := snap("programs", map[string]string{"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"})
	revOf := func(build, r string) map[string]any {
		return snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0." + build, "revision": r, "arch": "64-bit"})
	}
	rev := func(r string) map[string]any { return revOf("22631", r) }
	state := func() (string, []inventory.MatchSoftware) {
		t.Helper()
		d, ok := w.device(peerA)
		if !ok {
			t.Fatal("no device")
		}
		in, _, err := w.inv.MatchInput(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		var win []inventory.MatchSoftware
		for _, s := range in.Software {
			if s.Vendor == "microsoft" {
				win = append(win, s)
			}
		}
		return in.OS, win
	}
	wantRow := func(when, product, version, cpe string) {
		t.Helper()
		_, win := state()
		if len(win) != 1 || win[0].Product != product || win[0].Version != version || win[0].CPE != cpe || !slices.Equal(win[0].KevKeys, []string{"microsoft|windows"}) {
			t.Fatalf("%s: Windows rows %+v", when, win)
		}
	}
	// os_version and the programs first: the OS with its build, no Windows row yet; os_revision and the package list are still
	// asked every minute
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osv, progs))
	if os, win := state(); os != "Microsoft Windows 11 Pro 10.0.22631 build 22631" || len(win) != 0 {
		t.Fatalf("no revision: %q %+v", os, win)
	}
	wantIntervals(t, "os_version before the revision", w.intervals(key), map[string]float64{"os_version": 3600, "programs": 60, "os_revision": 60})
	// the revision alone, a minute later: the OS shows it at once and the query goes back to hourly
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("4460")))
	if os, _ := state(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("revision 4460: %q", os)
	}
	wantIntervals(t, "revision taken", w.intervals(key), map[string]float64{"os_revision": 3600, "programs": 60})
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE win_version = '10.0.22631.4460' AND win_target = 'x64'`); n != 1 {
		t.Fatalf("the node's revision is not stored: %d", n)
	}
	// os_version and the programs in a later request: the OS keeps the stored revision, and the list carries the Windows row
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, osv, progs))
	if os, _ := state(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("os_version after the revision: %q", os)
	}
	wantRow("first list with the row", "Windows 11 23H2", "10.0.22631.4460", "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:*:*:*:*:*:x64:*")
	wantIntervals(t, "first report complete", w.intervals(key), map[string]float64{"programs": 3600, "os_revision": 3600})
	// a value that is not a revision is not taken: the stored one stays
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("0"), osv))
	if os, _ := state(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("a bad revision changed the OS: %q", os)
	}
	// a new monthly update: the next revision replaces it, and the next list carries the new build
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, rev("5189"), osv))
	if os, _ := state(); os != "Microsoft Windows 11 Pro 10.0.22631.5189" {
		t.Fatalf("revision 5189: %q", os)
	}
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, progs))
	wantRow("after the monthly update", "Windows 11 23H2", "10.0.22631.5189", "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.5189:*:*:*:*:*:x64:*")
	// a feature update to 24H2, its revision not reported yet: the old release is cleared, the next list has no Windows row
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, osvOf("26100")))
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE win_version = ''`); n != 1 {
		t.Fatalf("the old release is still stored: %d", n)
	}
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, progs))
	if os, win := state(); os != "Microsoft Windows 11 Pro 10.0.26100 build 26100" || len(win) != 0 {
		t.Fatalf("after the feature update: %q %+v", os, win)
	}
	// its revision: the new release's row
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, revOf("26100", "7092"), progs))
	wantRow("24H2", "Windows 11 24H2", "10.0.26100.7092", "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.7092:*:*:*:*:*:x64:*")
}

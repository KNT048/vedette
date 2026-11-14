package agentintake_test

import (
	"slices"
	"testing"
	"time"
)

// D-524: Windows's update revision comes in its own query (os_revision), which may arrive in another request than os_version and the
// program list. The node keeps the last one; the device then reads "Microsoft Windows 11 Pro 10.0.22631.4460" and its software has the
// operating system's own row (Windows 11 23H2, the full version, the CISA key and NVD's CPE). A revision that is not a positive
// integer is not taken.
func TestContract_D524_WindowsRevisionOfAnotherRequest(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("pc", 7)
	key := w.enroll(secret, "pc-01", peerA)
	osv := snap("os_version", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "major": "10", "minor": "0", "build": "22631", "platform": "windows", "arch": "64-bit"})
	progs := snap("programs", map[string]string{"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"})
	osRow := func() (string, string, string) {
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
			if s.Vendor == "microsoft" && slices.Contains(s.KevKeys, "microsoft|windows") {
				return in.OS, s.Version, s.CPE
			}
		}
		return in.OS, "", ""
	}
	// no revision yet: the OS with its build, no operating-system row (as before D-524)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osv, progs))
	if os, ver, _ := osRow(); os != "Microsoft Windows 11 Pro 10.0.22631 build 22631" || ver != "" {
		t.Fatalf("no revision: %q %q", os, ver)
	}
	// the revision alone, then os_version and the programs in a later request
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "4460", "arch": "64-bit"})))
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, osv, progs))
	if os, ver, cpe := osRow(); os != "Microsoft Windows 11 Pro 10.0.22631.4460" || ver != "10.0.22631.4460" || cpe != "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:*:*:*:*:*:x64:*" {
		t.Fatalf("revision 4460: %q %q %q", os, ver, cpe)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE win_version = '10.0.22631.4460' AND win_target = 'x64'`); n != 1 {
		t.Fatalf("the node's revision is not stored: %d", n)
	}
	// a value that is not a revision is not taken: the stored one stays
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "0"}), osv, progs))
	if _, ver, _ := osRow(); ver != "10.0.22631.4460" {
		t.Fatalf("a bad revision changed the row: %q", ver)
	}
	// a new monthly update: the next revision replaces it
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("os_revision", map[string]string{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "5189", "arch": "64-bit"}), osv, progs))
	if os, ver, _ := osRow(); os != "Microsoft Windows 11 Pro 10.0.22631.5189" || ver != "10.0.22631.5189" {
		t.Fatalf("revision 5189: %q %q", os, ver)
	}
}

package agentintake_test

import (
	"testing"
)

// The package reporter (scripts/osquery.sh, for systems osquery cannot run on) posts to the osquery log endpoint with these lists.
// The rows below are the shape the script printed on Alpine 3.23 ("apk list -I", apk-tools 3) and Arch Linux ("pacman -Q"); the ingest must
// turn them into the device's software rows, with the full release kept for Alpine so that findings can compare it with Alpine's fixed releases.
func TestReporter_ApkAndPacmanListsBecomeSoftwareRows(t *testing.T) {
	apk := func(name, version, origin string) map[string]string {
		return map[string]string{"name": name, "version": version, "arch": "x86_64", "origin": origin}
	}
	cases := []struct {
		name  string
		os    map[string]string
		rows  []map[string]string
		query string
		want  map[string]string // product -> version
		pkg   map[string]string // product -> PkgVersion
	}{
		{"Alpine", map[string]string{"name": "Alpine Linux", "version": "3.23.2", "platform": "alpine", "arch": "x86_64"},
			[]map[string]string{apk("openssh-server", "10.2_p1-r1", "openssh"), apk("busybox", "1.37.0-r30", "busybox"), apk("ca-certificates-bundle", "20261020-r0", "ca-certificates"),
				apk("ncurses-libs", "6.5_p20250503-r0", "ncurses"), apk("OPENSSH", "10.2_p1-r1", "openssh"), apk("bad name", "1.0-r0", "x"), apk("musl", "1.2.5-bad", "musl")},
			"apk_packages", map[string]string{"OpenSSH": "10.2p1", "ncurses-libs": "6.5+20250503"}, map[string]string{"OpenSSH": "10.2_p1-r1"}}, // a date patch level is a build tail, never "6.5p20250503" (which an "up to 6.5" range would call not affected)
		{"Arch", map[string]string{"name": "Arch Linux", "version": "rolling", "platform": "arch", "arch": "x86_64"},
			[]map[string]string{{"name": "openssh", "version": "10.2p1-1"}, {"name": "git", "version": "1:2.43.0-1"}, {"name": "linux", "version": "6.12.1.arch1-1"}, {"name": "x", "version": "noRelease"}, {"name": "evil", "version": "1.0;x-1"}},
			"pacman_packages", map[string]string{"OpenSSH": "10.2p1", "Git": "2.43.0"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			_, secret := w.token("srv", 7)
			key := w.enroll(secret, "reporter-host", peerA)
			r := w.post("/intake/osquery/log", peerA, logBody(key, snap("os_version", c.os), snap("system_info", map[string]string{"hostname": "reporter-host"}),
				snap("interfaces", ifaceRow(macA, peerA)), snap(c.query, c.rows...)))
			if r.code != 200 || r.invalid() {
				t.Fatalf("the log was refused: %d %s", r.code, r.raw)
			}
			d, ok := w.device(peerA)
			if !ok {
				t.Fatal("no device")
			}
			if d.OS == nil || d.OS.Value != c.os["name"]+" "+c.os["version"] {
				t.Errorf("device OS %+v", d.OS)
			}
			in, _, err := w.inv.MatchInput(t.Context(), d.ID)
			if err != nil {
				t.Fatal(err)
			}
			got, pkg := map[string]string{}, map[string]string{}
			for _, s := range in.Software {
				got[s.Product], pkg[s.Product] = s.Version, s.PkgVersion
			}
			for p, v := range c.want {
				if got[p] != v {
					t.Errorf("%s: version %q, want %q (rows %v)", p, got[p], v, got)
				}
			}
			for p, v := range c.pkg {
				if pkg[p] != v {
					t.Errorf("%s: package release %q, want %q", p, pkg[p], v)
				}
			}
			for _, bad := range []string{"bad name", "musl", "x", "evil"} {
				if _, there := got[bad]; there {
					t.Errorf("a row that is not a package of this system was kept: %s", bad)
				}
			}
			if len(in.Software) < 3 {
				t.Errorf("only %d software rows: %v", len(in.Software), got)
			}
		})
	}
}

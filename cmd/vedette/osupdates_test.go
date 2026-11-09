package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Wiring of the OS endpoints (WP-07b part 2): an install without vedette-host answers every OS read with
// 409 not_appliance, whether no socket is configured or the configured socket file is absent. The behaviour of
// the endpoints against a host is tested in modules/core (os_test.go).
func TestWiringOSEndpointsWithoutAHostAreNotAppliance(t *testing.T) {
	t.Parallel()
	for name, tune := range map[string]func(*testing.T, *deps){
		"no socket configured": func(*testing.T, *deps) {},
		"socket file absent": func(t *testing.T, d *deps) {
			dir, err := os.MkdirTemp("", "vh") // short: a unix socket path may be at most about 100 bytes
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			d.HostSocket, d.DataDir, d.KeyPath = filepath.Join(dir, "absent.sock"), dir, filepath.Join(dir, "vedette.key")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStackWith(t, func(d *deps) { tune(t, d) })
			for _, path := range []string{"/core/updates/os", "/core/updates/os/run", "/core/network", "/core/network/span/status"} { // the Box network page is wired the same way (S-CORE-8)
				code, body := s.do("GET", path, "viewer", "")
				e, _ := body["error"].(map[string]any)
				if code != 409 || e["code"] != "not_appliance" {
					t.Errorf("GET %s = %d %v, want 409 not_appliance", path, code, body)
				}
			}
		})
	}
}

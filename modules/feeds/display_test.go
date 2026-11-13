package feeds

import "testing"

// W5-3: a product name that already starts with the vendor is not repeated (KEV pairs seen on a real box).
func TestDisplayOf_NoRepeatedVendor(t *testing.T) {
	for _, c := range []struct{ vendor, product, want string }{
		{"GNU", "GNU C Library", "GNU C Library"},
		{"OpenSSL", "OpenSSL", "OpenSSL"},
		{"Sudo", "Sudo", "sudo"},
		{"Drupal", "Drupal core", "Drupal core"},
		{"Android", "Android OS", "Android OS"},
		{"Daemon", "Daemon Tools Lite", "Daemon Tools Lite"},
		{"Ivanti", "Endpoint Manager", "Ivanti Endpoint Manager"},
		{"Git", "GitHub Enterprise", "Git GitHub Enterprise"}, // only a whole-word prefix counts
		{"Fortinet", "FortiOS", "FortiGate firewall (FortiOS)"},
	} {
		if got := DisplayOf(c.vendor, c.product); got != c.want {
			t.Errorf("DisplayOf(%q, %q) = %q, want %q", c.vendor, c.product, got, c.want)
		}
	}
}

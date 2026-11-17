package findings

import "testing"

// One reading of a release for the page and the matcher: a leading "v" before a digit is dropped, and a network OS orders it.
func TestOSVersionReadsALeadingV(t *testing.T) {
	for in, want := range map[string]string{"v7.2.13": "7.2.13", " V7.4.1 ": "7.4.1", "7.2.13": "7.2.13", "version 7": "version 7", "": ""} {
		if got := OSVersion(in); got != want {
			t.Errorf("OSVersion(%q) = %q, want %q", in, got, want)
		}
	}
	for _, r := range osRows {
		if r.Product == "FortiOS" && !r.reads("v7.2.13") {
			t.Error("FortiOS does not order v7.2.13")
		}
	}
}

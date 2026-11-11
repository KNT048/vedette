package release

import (
	"os"
	"testing"
)

// The linker's -X on MinSequenceText reaches the variable. deploy/containers builds this package's test binary with the -X flag it
// takes from `make host-deb` and runs only this test, with the wanted number in VEDETTE_WANT_MIN_SEQUENCE; in any other run it skips.
func TestMinSequenceTextIsWhatTheLinkerSet(t *testing.T) {
	want := os.Getenv("VEDETTE_WANT_MIN_SEQUENCE")
	if want == "" {
		t.Skip("only run by deploy/containers (TestMinSequenceFlag), which sets the linker flag")
	}
	if MinSequenceText != want {
		t.Fatalf("MinSequenceText = %q, the linker was asked for %q", MinSequenceText, want)
	}
	if n, err := parseMinSequence(MinSequenceText); err != nil || n == 0 {
		t.Fatalf("parseMinSequence(%q) = %d, %v", MinSequenceText, n, err)
	}
}

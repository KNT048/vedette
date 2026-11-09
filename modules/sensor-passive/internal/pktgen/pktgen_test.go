package pktgen_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

var update = flag.Bool("update", false, "rewrite the recordings in ../../testdata")

const dir = "../../testdata"

// TestWriteFixtures regenerates the recordings when run with -update; without it, it only checks them.
func TestWriteFixtures(t *testing.T) {
	for name, want := range pktgen.Fixtures() {
		path := filepath.Join(dir, name)
		if *update {
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path) //nolint:gosec // fixed fixture directory
		if err != nil {
			t.Fatalf("%v (run with -update to create it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is out of date: run `go test ./modules/sensor-passive/internal/pktgen -run TestWriteFixtures -update`", name)
		}
	}
}

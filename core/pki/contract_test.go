package pki_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-110 (1), core INV-24: the CA key is readable only through core/pki. Go's rules cannot stop another package from calling
// secrets.Store.Open with the purpose, so the purpose is restricted in core/secrets (pki.Open does it) and this scan fails when
// any other non-test source names the purpose or touches a restriction. Like the scan of core/conn (D-93), it walks the tree.
func TestOnlyPKINamesTheCAPurpose(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	allowed := func(rel string) bool {
		return rel == "core/pki/ca.go" || strings.HasPrefix(rel, "core/secrets/")
	}
	// core/conn's own restriction is a different purpose, so ".Restrict(" is allowed there; naming this purpose is not.
	needles := []string{`"core_sensor_ca"`, "core_sensor_ca"}
	scanned := 0
	for _, top := range []string{"core", "modules", "cmd", "host", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			scanned++
			if allowed(rel) {
				return nil
			}
			b, err := os.ReadFile(p) //nolint:gosec // walking our own source tree
			if err != nil {
				return err
			}
			for _, n := range needles {
				if strings.Contains(string(b), n) {
					t.Errorf("%s contains %s: only core/pki/ca.go may name the CA purpose", rel, n)
				}
			}
			if strings.Contains(string(b), ".Restrict(") && !strings.HasPrefix(rel, "core/conn/") && rel != "core/pki/authority.go" {
				t.Errorf("%s restricts a secret purpose: only core/conn and core/pki do", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("the scan saw %d files: the walk is broken", scanned)
	}
	// the scan would pass vacuously if pki stopped holding the purpose
	ca, err := os.ReadFile("ca.go")
	auth, err2 := os.ReadFile("authority.go")
	if err != nil || err2 != nil || !strings.Contains(string(ca), `"core_sensor_ca"`) || !strings.Contains(string(auth), ".Restrict(caPurpose)") {
		t.Fatalf("pki no longer restricts the CA purpose: %v %v", err, err2)
	}
}

// The CA key must not reach a log line or an error: nothing in this package formats a key.
func TestNothingFormatsAKey(t *testing.T) {
	t.Parallel()
	ents, _ := os.ReadDir(".")
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, _ := os.ReadFile(e.Name())
		for _, bad := range []string{"%x\", key", "%v\", key", "%s\", key", "Sprint(key", "Sprintf(\"%v\", a.ca", "slog.Any(\"key"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s: %s formats a key", e.Name(), bad)
			}
		}
	}
}

package pki_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

// D-110 (1), core INV-24: the CA key is readable only through core/pki (and the box CA's, D-351, only through cmd/vedette/boxca.go). Go's rules cannot stop another package from calling
// secrets.Store.Open with the purpose, so the purpose is reserved in core/secrets by an init function of this package (closed from
// the start of the process, TestACAPurposeIsClosedWithoutPKIOpen) and restricted by pki.Open; this scan fails when any other
// non-test source names the purpose, reserves or restricts it. Like the scan of core/conn (D-93) it walks every directory with
// Go files, not a list of top-level directories.
func TestOnlyPKINamesTheCAPurpose(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	scanned := 0
	tops := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		scanned++
		tops[strings.SplitN(rel, "/", 2)[0]] = true
		b, err := os.ReadFile(p) //nolint:gosec // walking our own source tree
		if err != nil {
			return err
		}
		src := string(b)
		if strings.HasPrefix(rel, "core/secrets/") {
			return nil // the mechanism itself
		}
		if rel != "core/pki/ca.go" && strings.Contains(src, "core_sensor_ca") {
			t.Errorf("%s contains core_sensor_ca: only core/pki/ca.go may name the CA purpose", rel)
		}
		// The box CA of the 8443 leaf (D-351) is the other CA with a restricted purpose: only cmd/vedette/boxca.go names it.
		if rel != "cmd/vedette/boxca.go" && strings.Contains(src, "core_box_ca") {
			t.Errorf("%s contains core_box_ca: only cmd/vedette/boxca.go may name the box CA purpose", rel)
		}
		if strings.Contains(src, "secrets.Reserve(") && rel != "core/pki/ca.go" && rel != "cmd/vedette/boxca.go" {
			t.Errorf("%s reserves a secret purpose: only core/pki/ca.go and cmd/vedette/boxca.go do", rel)
		}
		if strings.Contains(src, ".Restrict(") && !strings.HasPrefix(rel, "core/conn/internal/cred/") && rel != "core/pki/authority.go" && rel != "cmd/vedette/boxca.go" {
			t.Errorf("%s restricts a secret purpose: only core/conn/internal/cred, core/pki and cmd/vedette/boxca.go do", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("the scan saw %d files: the walk is broken", scanned)
	}
	for _, top := range []string{"core", "modules", "cmd", "host", "internal", "content"} {
		if !tops[top] {
			t.Fatalf("the scan saw no Go file under %s/: the walk is broken", top)
		}
	}
	// the scan would pass vacuously if pki stopped holding the purpose
	ca, err := os.ReadFile("ca.go")
	auth, err2 := os.ReadFile("authority.go")
	if err != nil || err2 != nil || !strings.Contains(string(ca), `"core_sensor_ca"`) || !strings.Contains(string(ca), "secrets.Reserve(caPurpose)") || !strings.Contains(string(auth), ".Restrict(caPurpose)") {
		t.Fatalf("pki no longer reserves and restricts the CA purpose: %v %v", err, err2)
	}
}

// L4: the purpose is closed in this process before any pki.Open: a store that was never given to pki refuses it, and so does the
// store pki.Open runs on (only its Opener reads).
func TestACAPurposeIsClosedWithoutPKIOpen(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s, err := secrets.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	e.open(t) // makes the CA row
	var id string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM core_secret WHERE purpose = 'core_sensor_ca'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(t.Context(), e.db.Reader(), id, "core_sensor_ca"); !errors.Is(err, secrets.ErrRestricted) {
		t.Errorf("Store.Open of the CA purpose before pki.Open on that store = %v, want ErrRestricted", err)
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

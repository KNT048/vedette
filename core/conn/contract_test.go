package conn_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-93 (1), core INV-23: only core/conn/internal/cred names the secret purpose of a connection credential and holds its opener.
// Go's internal rule alone stops nobody from calling secrets.Store.Open with the purpose, so the purpose is restricted in
// core/secrets (conn.New) and this scan fails when another non-test source names it or touches the restriction. Like the scan of
// the host contract (D-87), it walks the source tree: every directory with Go files (core, modules, cmd, host, internal,
// content, scripts, tools, whatever is added), not a list that a new top-level directory could be missing from.
//
// core/pki holds a restricted purpose of its own (core_sensor_ca, core INV-24), so its two files are exempt from the two needles
// about restriction and Opener use, and from nothing else: they may never name "core_connection".
func TestOnlyCredNamesTheCredentialPurpose(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	credOrSecrets := func(rel string) bool {
		return strings.HasPrefix(rel, "core/conn/internal/cred/") || strings.HasPrefix(rel, "core/secrets/")
	}
	pkiOwn := func(rel string) bool { return rel == "core/pki/ca.go" || rel == "core/pki/authority.go" }
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
		for _, n := range []string{`"core_connection"`, "secrets.Opener", ".Restrict("} {
			if !strings.Contains(string(b), n) || credOrSecrets(rel) {
				continue
			}
			if n != `"core_connection"` && pkiOwn(rel) {
				continue
			}
			t.Errorf("%s contains %s: only core/conn/internal/cred may name the credential purpose or hold its opener", rel, n)
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
	// The vault is what holds them: the scan above would pass vacuously if cred stopped doing so.
	b, err := os.ReadFile("internal/cred/cred.go")
	if err != nil || !strings.Contains(string(b), `"core_connection"`) || !strings.Contains(string(b), ".Restrict(") {
		t.Fatalf("internal/cred no longer restricts the purpose: %v", err)
	}
}

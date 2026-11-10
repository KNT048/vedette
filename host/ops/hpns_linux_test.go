//go:build linux

package ops

import (
	"os"
	"path/filepath"
	"testing"
)

// The real nsfs check, on files that change nothing: this process's own namespace link is on nsfs, a
// regular file is not. (Creating a namespace is not done in unit tests; see the lab checks.)
func TestIsNsfsOnRealFiles(t *testing.T) {
	t.Parallel()
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Skipf("no /proc/self/ns/net: %v", err)
	}
	defer func() { _ = ns.Close() }()
	if ok, err := isNsfs(ns); err != nil || !ok {
		t.Fatalf("/proc/self/ns/net: %v %v", ok, err)
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p) //nolint:gosec // a file the test just made
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if ok, err := isNsfs(f); err != nil || ok {
		t.Fatalf("a regular file: %v %v", ok, err)
	}
}

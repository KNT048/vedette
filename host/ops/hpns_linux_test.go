//go:build linux

package ops

import (
	"os"
	"path/filepath"
	"testing"
)

// The real namespace check, on files that change nothing: this process's own namespace link is on
// nsfs and is a network namespace, but it is the host's own and is refused; a regular file is not
// a namespace. (Creating a namespace is not done in unit tests; see the lab checks.)
func TestIsNetNSOnRealFiles(t *testing.T) {
	t.Parallel()
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Skipf("no /proc/self/ns/net: %v", err)
	}
	defer func() { _ = ns.Close() }()
	if ok, err := isNetNS(ns); err != nil || ok {
		t.Fatalf("/proc/self/ns/net must be refused as the process's own: %v %v", ok, err)
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
	if ok, err := isNetNS(f); err != nil || ok {
		t.Fatalf("a regular file: %v %v", ok, err)
	}
}

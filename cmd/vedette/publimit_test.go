package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/core/server"
)

// D-320: the per-address limit is on only where core sees each client's own address, an appliance with vedette-host's socket; a
// container-only install (no socket path, or no socket there) may see every client as the port proxy's address.
func TestPublicLimitOnlyOnAnAppliance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Skip("no unix socket here:", err)
	}
	defer func() { _ = l.Close() }()
	for path, want := range map[string]int{"": 0, filepath.Join(dir, "missing.sock"): 0, dir: 0, sock: server.PublicPerMinuteDefault} {
		if got := publicPerMinute(path); got != want {
			t.Errorf("publicPerMinute(%q) = %d, want %d", path, got, want)
		}
	}
}

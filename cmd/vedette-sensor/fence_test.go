package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The scan container starts without domain_ip when its fence key is missing or damaged (loadFence gives no
// fence, so the worker's heartbeat says domain_ip false and every domain_ip job is refused); a good key gives one.
func TestLoadFenceWithoutAUsableKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	if loadFence(filepath.Join(dir, "missing.key"), log) != nil {
		t.Fatal("a missing key gave a fence")
	}
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if loadFence(bad, log) != nil {
		t.Fatal("a damaged key gave a fence")
	}
	good := filepath.Join(dir, "fence.key")
	if err := os.WriteFile(good, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if loadFence(good, log) == nil {
		t.Fatal("a good key gave no fence")
	}
}

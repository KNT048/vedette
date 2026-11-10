package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSdNotifySendsReadyToTheSocketAndNothingWithoutOne(t *testing.T) {
	t.Parallel()
	if err := sdNotify(""); err != nil {
		t.Fatalf("no socket is not an error: %v", err)
	}
	dir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "notify")
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "unixgram", path)
	if err != nil {
		t.Skipf("no unixgram sockets here: %v", err)
	}
	defer func() { _ = pc.Close() }()
	if err := sdNotify(path); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("got %q %v", buf[:n], err)
	}
	// Anything that is neither a path nor an abstract name is refused, and a dead socket is an error.
	for _, bad := range []string{"relative/path", "tcp:1.2.3.4"} {
		if err := sdNotify(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := sdNotify(filepath.Join(dir, "nobody")); err == nil {
		t.Error("a socket nobody listens on was not an error")
	}
}

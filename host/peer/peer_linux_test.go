//go:build linux

package peer_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/host/peer"
)

// TestRealChecker runs the Linux checker on a real unix socket pair inside this process: the peer
// is this test process, so SO_PEERCRED must report our own uid and pid.
func TestRealChecker(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the checker refuses a root core uid by design; run as a normal user")
	}
	dir, err := os.MkdirTemp("", "vp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var d net.Dialer
	client, err := d.DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	// Layer 2 fails: a different uid is configured. The credentials read are still reported.
	other, err := peer.New(os.Getuid()+1, "vedette-core.service", "")
	if err != nil {
		t.Fatal(err)
	}
	info, err := other(server)
	if !errors.Is(err, peer.ErrNotAllowed) || info.UID != os.Getuid() || info.PID != os.Getpid() {
		t.Fatalf("wrong uid: info %+v err %v", info, err)
	}
	// Layer 3 fails: right uid, but this test process is not inside the core unit's cgroup.
	same, err := peer.New(os.Getuid(), "vedette-core.service", "")
	if err != nil {
		t.Fatal(err)
	}
	info, err = same(server)
	if !errors.Is(err, peer.ErrNotAllowed) || info.Unit != "" || info.PID != os.Getpid() {
		t.Fatalf("wrong cgroup: info %+v err %v", info, err)
	}
	// Not a unix socket at all.
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, err := same(a); !errors.Is(err, peer.ErrNotAllowed) {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := peer.New(1000, "vedette-core.service", "relative/cgroup"); err == nil {
		t.Fatal("bad anchor accepted")
	}
	// A misconfigured checker is refused at construction.
	if _, err := peer.New(0, "vedette-core.service", ""); err == nil {
		t.Fatal("uid 0 accepted")
	}
	if _, err := peer.New(1000, "not-a-unit", ""); err == nil {
		t.Fatal("bad unit accepted")
	}
}

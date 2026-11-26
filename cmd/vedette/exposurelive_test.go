package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/exposure"
)

// The liveness check of a scan connects to each port and closes the connection without sending a byte: a port that accepts is up, a
// closed one (refused) is not. It dials only the asked address and ports, and never a private address.
func TestExposureLivenessConnectsAndSendsNothing(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan int, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 16)
			n, _ := c.Read(buf) // the box closes at once: EOF, nothing read
			got <- n
			_ = c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	closed := func() int { // a port nothing listens on
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		return p
	}()
	var mu sync.Mutex
	var dialled []string
	box := netip.MustParseAddr("8.8.8.8") // stands for the box's own public IP; the dial goes to the local listener
	l := exposureLiveness{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, network+" "+address)
		mu.Unlock()
		_, port, _ := net.SplitHostPort(address)
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}}
	up, err := l.Alive(t.Context(), box, []int{open, closed})
	if err != nil || !up[open] || up[closed] {
		t.Fatalf("up = %v, err %v", up, err)
	}
	if n := <-got; n != 0 {
		t.Fatalf("the check sent %d bytes", n)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range dialled {
		if d != "tcp4 8.8.8.8:"+strconv.Itoa(open) && d != "tcp4 8.8.8.8:"+strconv.Itoa(closed) {
			t.Errorf("dialled %s", d)
		}
	}
	if _, err := l.Alive(t.Context(), netip.MustParseAddr("192.168.1.10"), []int{open}); err == nil {
		t.Fatal("a private address was checked")
	}
}

// The re-check before a scan's results are written tells a closed port (the connect is refused: a TCP reset) from a silent one (no
// answer at all: a firewall or WAF dropping the box's packets), and an open one; it sends nothing and dials only public addresses.
func TestExposureProbeTellsAClosedPortFromASilentOne(t *testing.T) {
	t.Parallel()
	box := netip.MustParseAddr("8.8.8.8")
	l := exposureLiveness{timeout: 20 * time.Millisecond, dial: func(ctx context.Context, _, address string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		switch port {
		case "22":
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		case "80":
			return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		}
		<-ctx.Done() // dropped: no answer until the connect times out
		return nil, ctx.Err()
	}}
	got, err := l.Probe(t.Context(), box, []int{22, 80, 443})
	if err != nil {
		t.Fatal(err)
	}
	if got[22] != exposure.PortOpen || got[80] != exposure.PortClosed || got[443] != exposure.PortSilent {
		t.Fatalf("answers %v, want 22 open, 80 closed, 443 silent", got)
	}
	if _, err := l.Probe(t.Context(), netip.MustParseAddr("10.0.0.1"), []int{22}); err == nil {
		t.Fatal("a private address was probed")
	}
}

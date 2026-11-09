package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// refuseLikeConn is the policy of core/conn for the tests of this package: loopback, link-local (the cloud metadata address), and
// the box addresses are refused.
func refuseLikeConn(box ...string) func(context.Context, netip.Addr) string {
	return func(_ context.Context, a netip.Addr) string {
		switch {
		case a.IsLoopback():
			return "a loopback address"
		case a.IsLinkLocalUnicast():
			return "a link-local address (the cloud metadata service lives there)"
		}
		for _, b := range box {
			if netip.MustParsePrefix(b).Contains(a) {
				return "the box itself"
			}
		}
		return ""
	}
}

func recorder() (*[]netip.AddrPort, func(context.Context, netip.AddrPort) (net.Conn, error)) {
	var got []netip.AddrPort
	return &got, func(_ context.Context, ap netip.AddrPort) (net.Conn, error) {
		got = append(got, ap)
		c, _ := net.Pipe()
		return c, nil
	}
}

// D-94 (1), INV-23: the address policy applies to the address that is dialled, not to the name that was typed.
func TestDialerRefusesWhatThePolicyRefuses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, host, why string }{
		{"loopback", "127.0.0.1:443", "loopback"},
		{"loopback v6", "[::1]:443", "loopback"},
		{"metadata", "169.254.169.254:80", "link-local"},
		{"box address", "192.168.10.250:443", "the box itself"},
		{"box subnet", "10.88.3.4:22", "the box itself"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, raw := recorder()
			d := &Dialer{Refuse: refuseLikeConn("192.168.10.250/32", "10.88.0.0/16"), raw: raw}
			_, err := d.DialContext(t.Context(), tc.host)
			var re *RefusedError
			if !errors.As(err, &re) || !strings.Contains(re.Why, tc.why) {
				t.Fatalf("err = %v, want a refusal for %q", err, tc.why)
			}
			if len(*got) != 0 {
				t.Fatalf("a socket was opened to %v", *got)
			}
		})
	}
}

// DNS rebinding: a name is resolved once, the address that was checked is the address that is dialled, and a name whose answer
// holds a refused address is refused whole.
func TestDialerResolvesOnceAndDialsTheCheckedAddress(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	got, raw := recorder()
	public := netip.MustParseAddr("203.0.113.7")
	d := &Dialer{
		Refuse: refuseLikeConn(),
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			if calls.Add(1) == 1 {
				return []netip.Addr{public}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil // what a rebinding server answers the second time
		},
		raw: raw,
	}
	c, err := d.DialContext(t.Context(), "rebind.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if calls.Load() != 1 {
		t.Fatalf("the name was resolved %d times, want once", calls.Load())
	}
	if len(*got) != 1 || (*got)[0] != netip.AddrPortFrom(public, 443) {
		t.Fatalf("dialled %v, want only %v", *got, public)
	}
}

func TestDialerRefusesALocalhostNameAtDialTime(t *testing.T) {
	t.Parallel()
	got, raw := recorder()
	d := &Dialer{
		Refuse: refuseLikeConn(),
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		raw: raw,
	}
	_, err := d.DialContext(t.Context(), "innocent.example:443") // a public-looking name that resolves to loopback now
	var re *RefusedError
	if !errors.As(err, &re) || len(*got) != 0 {
		t.Fatalf("err = %v, dials %v: want a refusal and no socket", err, *got)
	}
}

func TestDialerRefusesAMixedAnswerWhole(t *testing.T) {
	t.Parallel()
	got, raw := recorder()
	d := &Dialer{
		Refuse: refuseLikeConn(),
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("169.254.169.254")}, nil
		},
		raw: raw,
	}
	if _, err := d.DialContext(t.Context(), "mixed.example:443"); err == nil || len(*got) != 0 {
		t.Fatalf("err = %v, dials %v: a name that points at the metadata service must not be dialled at all", err, *got)
	}
}

// The real socket path: ControlContext refuses even if a caller got an address past the first check.
func TestDialerControlHookRefusesTheSocket(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	d := &Dialer{Refuse: refuseLikeConn()}
	_, err = d.dialOne(t.Context(), netip.MustParseAddrPort(ln.Addr().String()))
	var re *RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("dialOne to loopback = %v, want a RefusedError from the control hook", err)
	}
	// and the test hook opens that one socket only
	undo := AllowSocketForTest("", netip.MustParseAddrPort(ln.Addr().String()))
	defer undo()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()
	c, err := d.dialOne(t.Context(), netip.MustParseAddrPort(ln.Addr().String()))
	if err != nil {
		t.Fatalf("an allowed socket: %v", err)
	}
	_ = c.Close()
	other, _ := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	defer func() { _ = other.Close() }()
	if _, err := d.dialOne(t.Context(), netip.MustParseAddrPort(other.Addr().String())); err == nil {
		t.Fatal("a second loopback socket was reachable through the hook of the first")
	}
}

func TestCleanLine(t *testing.T) {
	t.Parallel()
	got := CleanLine("  Error:\x1b[31m token abcdefgh1234\r\n\tsecond line "+strings.Repeat("x", 400), "abcdefgh1234")
	if strings.Contains(got, "abcdefgh1234") || strings.ContainsAny(got, "\r\n\t\x1b") || len([]rune(got)) > MaxLine {
		t.Fatalf("CleanLine = %q", got)
	}
}

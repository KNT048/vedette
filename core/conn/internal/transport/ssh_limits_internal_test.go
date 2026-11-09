package transport

// Limits and resolver behaviour of the transport that need its unexported seams. The SSH servers below are in process on loopback,
// reached through AllowSocketForTest (the hook conntest uses; conntest itself cannot be imported here: it imports this package).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/knt048/vedette/core/secrets"
)

var fakeNames atomic.Int64

// fakeSSHServer starts an SSH server that accepts any password and hands each signed-in connection to serve. It returns the host:port
// of a connection target.
func fakeSSHServer(t *testing.T, serve func(sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request)) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ap := netip.MustParseAddrPort(ln.Addr().String())
	name := fmt.Sprintf("fake%d.device.test", fakeNames.Add(1))
	t.Cleanup(AllowSocketForTest(name, ap))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					_ = c.Close()
					return
				}
				serve(sc, chans, reqs)
			}()
		}
	}()
	return net.JoinHostPort(name, strconv.Itoa(int(ap.Port())))
}

func fakeSSHConfig() SSHConfig {
	return SSHConfig{
		Dialer: &Dialer{Refuse: func(_ context.Context, a netip.Addr) string {
			return map[bool]string{true: "a loopback address"}[a.IsLoopback()]
		}},
		Username: "vedette", Password: secrets.NewValue("pw-0123456789"), TOFU: true,
	}
}

// M3. After the sign-in a device may never answer the request to open a session, a terminal or a shell: that wait is bounded by
// SetupTimeout (10 seconds by default, inside the 20 seconds of a line), not by the caller's context.
func TestSSHSessionSetupIsBounded(t *testing.T) {
	t.Parallel()
	if SetupTimeout != 10*time.Second || SetupTimeout >= LineTimeout {
		t.Fatalf("SetupTimeout = %s: it is 10 seconds, within the line budget of %s", SetupTimeout, LineTimeout)
	}
	hold := make(chan struct{})
	addr := fakeSSHServer(t, func(sc *ssh.ServerConn, _ <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		go ssh.DiscardRequests(reqs)
		<-hold // never answers the request to open a session
		_ = sc.Close()
	})
	t.Cleanup(func() { close(hold) })
	cfg := fakeSSHConfig()
	cfg.SetupTimeout = 300 * time.Millisecond
	start := time.Now()
	s, err := DialSSH(context.Background(), addr, cfg) // the context has no deadline
	if err == nil {
		s.Close()
		t.Fatal("a session that never opened was reported as open")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("DialSSH waited %s for a session the server never opened (err %v)", took.Round(time.Millisecond), err)
	}
}

// M4. The reader goroutine caps its own buffer at MaxOutput: between two waits (after DialSSH returns, between two Run calls) a device
// that floods after its prompt must not grow it. Past the cap the reader stops, the session closes and the next step fails with a line.
func TestSSHOutputIsCappedWhileNobodyWaits(t *testing.T) {
	t.Parallel()
	addr := fakeSSHServer(t, func(sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		defer func() { _ = sc.Close() }()
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			ch, creqs, err := nc.Accept()
			if err != nil {
				return
			}
			go func() {
				for r := range creqs {
					_ = r.Reply(r.Type == "pty-req" || r.Type == "shell", nil)
					if r.Type == "shell" {
						go func() {
							_, _ = ch.Write([]byte("Fake switch\r\nSwitch> "))
							<-time.After(300 * time.Millisecond) // the prompt has settled: DialSSH has returned
							chunk := make([]byte, 32<<10)
							for i := range chunk {
								chunk[i] = 'A'
							}
							for sent := 0; sent < 64<<20; sent += len(chunk) {
								if _, err := ch.Write(chunk); err != nil {
									return
								}
							}
						}()
					}
				}
			}()
		}
	})
	s, err := DialSSH(context.Background(), addr, fakeSSHConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		held, total, over := len(s.buf), s.total, s.over
		s.mu.Unlock()
		if held > MaxOutput {
			t.Fatalf("the session holds %d MB of device output in memory (%d MB read); the cap is %d MB", held>>20, total>>20, MaxOutput>>20)
		}
		if over {
			if total > MaxOutput+64<<10 {
				t.Errorf("the reader went on to %d bytes after the cap", total)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the flood was never stopped")
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-t.Context().Done():
		}
	}
	_, err = s.Run(context.Background(), "show version")
	var de *DeviceError
	if !errors.As(err, &de) || !strings.Contains(de.Msg, "more than 1 MB") {
		t.Fatalf("the step after the flood = %v, want a DeviceError that names the cap", err)
	}
}

// L3. The pure-Go resolver (the one a CGO_ENABLED=0 build always uses, and Linux by default) answers a name from
// /etc/hosts with an IPv4-mapped address: on this machine (*net.Resolver).LookupNetIP with GODEBUG=netdns=go gives
// ::ffff:127.0.0.1 for "localhost". conn.RefusedAddr refuses every Is4In6 first (validate.go:339), so a LAN device named in
// /etc/hosts is refused as "an IPv6 address that carries an IPv4 address" although it is a plain IPv4 address. The answer of the
// resolver must be unmapped before the policy sees it (an address typed by the administrator is still checked as typed).
func TestDialerUnmapsTheResolversIPv4Answers(t *testing.T) {
	t.Parallel()
	got, raw := recorder()
	d := &Dialer{
		Refuse: func(_ context.Context, a netip.Addr) string {
			if a.Is4In6() { // as conn.RefusedAddr
				return "an IPv6 address that carries an IPv4 address"
			}
			return ""
		},
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("::ffff:192.168.10.5")}, nil // what LookupNetIP gives for "192.168.10.5 nas.lan" in /etc/hosts
		},
		raw: raw,
	}
	c, err := d.DialContext(context.Background(), "nas.lan:443")
	if err != nil {
		t.Fatalf("a name the hosts file maps to 192.168.10.5 was refused: %v", err)
	}
	_ = c.Close()
	if len(*got) != 1 || (*got)[0] != netip.MustParseAddrPort("192.168.10.5:443") {
		t.Fatalf("dialled %v, want 192.168.10.5:443", *got)
	}
}

// L5. Each resolved address gets its own share of the dial budget: one that does not answer (an AAAA record on a box whose IPv6 goes
// nowhere) must not use it all up before the next address is tried.
func TestDialerTriesTheNextAddressWhenOneHangs(t *testing.T) {
	t.Parallel()
	var tried []netip.AddrPort
	d := &Dialer{
		Timeout: 600 * time.Millisecond,
		Refuse:  func(context.Context, netip.Addr) string { return "" },
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("192.168.10.10")}, nil
		},
		raw: func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
			tried = append(tried, ap)
			if ap.Addr().Is6() {
				<-ctx.Done() // blackholed: no answer, no refusal
				return nil, ctx.Err()
			}
			c, _ := net.Pipe()
			return c, nil
		},
	}
	c, err := d.DialContext(context.Background(), "dual.lan:443")
	if err != nil {
		t.Fatalf("a name with a dead IPv6 address and a live IPv4 address did not connect (tried %v): %v", tried, err)
	}
	_ = c.Close()
	if len(tried) != 2 {
		t.Fatalf("tried %v", tried)
	}
}

// An RSA key signs with SHA-2 only: the library would otherwise fall back to ssh-rsa with SHA-1.
func TestSHA2OnlyRestrictsRSAKeys(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sha2Only(base)
	if err != nil {
		t.Fatal(err)
	}
	multi, ok := signer.(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatal("the restricted signer is not a MultiAlgorithmSigner")
	}
	if got := multi.Algorithms(); len(got) != 2 || got[0] != ssh.KeyAlgoRSASHA512 || got[1] != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("algorithms %v, want rsa-sha2-512 and rsa-sha2-256 only", got)
	}
	if _, err := multi.SignWithAlgorithm(rand.Reader, []byte("data"), ssh.KeyAlgoRSA); err == nil {
		t.Fatal("the restricted signer still signs with ssh-rsa (SHA-1)")
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	es, _ := ssh.NewSignerFromKey(ed)
	if got, err := sha2Only(es); err != nil || got != es {
		t.Fatalf("a key that is not RSA is left alone: %v", err)
	}
}

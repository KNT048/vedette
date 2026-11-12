package transport_test

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

func sshCfg() transport.SSHConfig {
	return transport.SSHConfig{Dialer: dialer(), Username: "vedette", Password: secrets.NewValue("pw-0123456789"), TOFU: true}
}

// D-94 (2): PTY session, one line at a time, the prompt waited for, a device error stops the chain and closes the session.
func TestSSHSessionOneLineAtATime(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		if line == "show version" {
			return "Fake IOS 15.2\n  uptime 3 days"
		}
		if strings.HasPrefix(line, "bad") {
			return "% Invalid input detected at '^' marker."
		}
		return ""
	}})
	s, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.HostKey != f.HostKeyPin() {
		t.Fatalf("host key %q, want %q", s.HostKey, f.HostKeyPin())
	}
	out, err := s.Run(context.Background(), "show version")
	if err != nil || out != "Fake IOS 15.2\n  uptime 3 days" {
		t.Fatalf("output %q, err %v", out, err)
	}
	for _, l := range []string{"configure terminal", "interface Gi1/0/5"} {
		if _, err := s.Run(context.Background(), l); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
	}
	var de *transport.DeviceError
	_, err = s.Run(context.Background(), "bad command")
	if !errors.As(err, &de) || !strings.Contains(de.Msg, "% Invalid input") {
		t.Fatalf("err = %v, want the device's error line", err)
	}
	if _, err := s.Run(context.Background(), "shutdown"); err == nil {
		t.Fatal("a line was accepted after the session closed on an error")
	}
	want := "show version,configure terminal,interface Gi1/0/5,bad command"
	if got := strings.Join(f.Lines(), ","); got != want {
		t.Fatalf("the device received %q, want %q (nothing after the error)", got, want)
	}
}

// D-358: Leave types its line only into a session that a refused line stopped, and closes the session in every case.
func TestSSHLeaveOnlyAfterARefusedLine(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	ctx := context.Background()
	s, err := transport.DialSSH(ctx, f.Addr, sshCfg())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(ctx, "configure terminal"); err != nil {
		t.Fatal(err)
	}
	s.Leave(ctx, "end", time.Second) // nothing was refused: nothing is typed
	if _, err := s.Run(ctx, "show version"); err == nil {
		t.Fatal("the session is open after Leave")
	}
	s, err = transport.DialSSH(ctx, f.Addr, sshCfg())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(ctx, "configure terminal"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(ctx, "bad line"); err == nil {
		t.Fatal("the refused line was accepted")
	}
	s.Leave(ctx, "end", time.Second)
	s.Leave(ctx, "end", time.Second) // closed: nothing more
	if got := strings.Join(f.Lines(), ","); got != "configure terminal,configure terminal,bad line,end" {
		t.Fatalf("the device received %q", got)
	}
}

// D-358: a line that did not come back in time closes the session; Leave, even with a live context, types nothing after it.
func TestSSHLeaveTypesNothingAfterATimeOut(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		if line == "shutdown" {
			<-release
		}
		return ""
	}})
	s, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background(), "configure terminal"); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := s.Run(short, "shutdown"); err == nil {
		t.Fatal("a line that never came back was accepted")
	}
	s.Leave(context.Background(), "end", time.Second)
	if got := strings.Join(f.Lines(), ","); got != "configure terminal,shutdown" {
		t.Fatalf("the device received %q", got)
	}
}

// FortiOS refusals are refusals: "command parse error", "value parse error", "Command fail. Return code".
func TestSSHRunSeesFortiOSRefusals(t *testing.T) {
	t.Parallel()
	for _, out := range []string{"command parse error before 'statuss'\nCommand fail. Return code -61", "value parse error before 'x'", "Command fail. Return code -3"} {
		f := conntest.NewSSH(t, conntest.SSHOpts{Prompt: "FGT", Respond: func(string) string { return out }})
		s, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
		if err != nil {
			t.Fatal(err)
		}
		var de *transport.DeviceError
		if _, err := s.Run(context.Background(), "set statuss disable"); !errors.As(err, &de) || !strings.Contains(de.Msg, strings.Split(out, "\n")[0]) {
			t.Errorf("%q: err = %v, want the refusal", out, err)
		}
		s.Close()
	}
}

func TestSSHKeyAuth(t *testing.T) {
	t.Parallel()
	signer, priv := conntest.NewSSHKey(t)
	pem, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	f := conntest.NewSSH(t, conntest.SSHOpts{AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()}})
	cfg := transport.SSHConfig{Dialer: dialer(), Username: "vedette", Key: secrets.NewValue(string(encode(pem))), TOFU: true}
	s, err := transport.DialSSH(context.Background(), f.Addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if f.Logins() != 1 {
		t.Fatalf("logins = %d", f.Logins())
	}
}

// D-94 (2): a host key that is not the pinned one is refused before any credential is sent.
func TestSSHChangedHostKeySendsNoCredential(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	cfg := sshCfg()
	first, err := transport.DialSSH(context.Background(), f.Addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.HostKey, cfg.TOFU = first.HostKey, false
	first.Close()

	before := f.AuthCalls()
	f.RotateHostKey(t)
	if _, err := transport.DialSSH(context.Background(), f.Addr, cfg); !errors.Is(err, transport.ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
	if f.AuthCalls() != before {
		t.Fatalf("the server was asked to check %d credentials after the key changed", f.AuthCalls()-before)
	}
}

func TestSSHUnpinnedWithoutTOFUSendsNoCredential(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	cfg := sshCfg()
	cfg.TOFU = false
	if _, err := transport.DialSSH(context.Background(), f.Addr, cfg); !errors.Is(err, transport.ErrUnverified) || f.AuthCalls() != 0 {
		t.Fatalf("err = %v, auth calls %d", err, f.AuthCalls())
	}
}

func TestSSHWrongPassword(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	cfg := sshCfg()
	cfg.Password = secrets.NewValue("not-the-password-1")
	var de *transport.DeviceError
	_, err := transport.DialSSH(context.Background(), f.Addr, cfg)
	if !errors.As(err, &de) || strings.Contains(err.Error(), "not-the-password-1") {
		t.Fatalf("err = %v, want a DeviceError without the password", err)
	}
}

// D-94 (2): only secure algorithms: a server that offers only CBC, SHA-1 key exchange or SHA-1 MACs is not talked to.
func TestSSHRefusesWeakAlgorithms(t *testing.T) {
	t.Parallel()
	for name, o := range map[string]conntest.SSHOpts{
		"cbc cipher":       {Ciphers: []string{ssh.InsecureCipherAES128CBC}},
		"3des cipher":      {Ciphers: []string{ssh.InsecureCipherTripleDESCBC}},
		"dh group1":        {KeyExchanges: []string{ssh.InsecureKeyExchangeDH1SHA1}},
		"dh group14 sha1":  {KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1}},
		"hmac-sha1-96 mac": {Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.InsecureHMACSHA196}}, // AEAD ciphers need no MAC, so CTR forces one
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := conntest.NewSSH(t, o)
			_, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
			if err == nil {
				t.Fatal("connected with a weak algorithm")
			}
			if f.AuthCalls() != 0 {
				t.Fatalf("credentials were sent after a weak negotiation (%d calls)", f.AuthCalls())
			}
		})
	}
	// control: the secure defaults of both sides talk to each other
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	s, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	s.Close()
}

func TestSSHCapsTheOutput(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(string) string { return strings.Repeat("0123456789abcdef\n", 2<<16) }})
	s, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var de *transport.DeviceError
	if _, err := s.Run(context.Background(), "show tech-support"); !errors.As(err, &de) {
		t.Fatalf("err = %v, want a DeviceError for output over the cap", err)
	}
}

// encode is the PEM text of a block returned by ssh.MarshalPrivateKey.
func encode(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// M1. Run must refuse every control character, not only \r and \n: the line goes to a PTY whose line editor acts on other control
// characters: Ctrl-Z applies the line and ends config mode on IOS, Ctrl-O is accept-line in bash/readline, Ctrl-V quotes the next key
// (a literal newline), Ctrl-U kills what the template put before a parameter, Ctrl-C/ESC/DEL/TAB edit or abort. A parameter that
// carries one of them turns "one approved line" into another command, or two. INV-23 (3): "một dòng một lần".
func TestSSHRunRefusesControlCharacters(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{})
	for name, line := range map[string]string{
		"ctrl-z": "show clock\x1aconfigure terminal",
		"ctrl-o": "true\x0fid",
		"ctrl-v": "echo a\x16b",
		"ctrl-u": "show interface \x15reload",
		"ctrl-c": "show run\x03",
		"escape": "show \x1b[A",
		"del":    "show x\x7f",
		"tab":    "sh\tver",
		"nul":    "show\x00 run",
		"c1 csi": "show \u009b2J",
		"nel c1": "show\u0085reload",
		"ctrl-d": "show\x04",
	} {
		t.Run(name, func(t *testing.T) {
			s, err := transport.DialSSH(context.Background(), f.Addr, sshCfg())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.Run(context.Background(), line); err == nil {
				t.Errorf("Run sent a line with a control character: %q", line)
			}
		})
	}
	for _, l := range f.Lines() {
		if strings.ContainsFunc(l, unicode.IsControl) {
			t.Errorf("the device received a control character in %q", l)
		}
	}
}

// M5 (review of 13b-6): a write that waits for window the device never grants blocks inside the library, where no deadline reaches it. The end
// of the context closes the socket under it, so the line returns within the step's time instead of waiting for ever.
func TestSSHWriteThatNeverGetsWindowEndsWithTheContext(t *testing.T) {
	t.Parallel()
	f := conntest.NewSSH(t, conntest.SSHOpts{StallInput: true})
	ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
	defer cancel()
	s, err := transport.DialSSH(ctx, f.Addr, sshCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	start := time.Now()
	done := make(chan error, 1)
	go func() { _, err := s.Run(ctx, strings.Repeat("a", 6<<20)); done <- err }() // more than the 2 MB window
	select {
	case err := <-done:
		if err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("the stuck write returned %v after %v", err, time.Since(start))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a write that never gets window did not end with the context")
	}
}

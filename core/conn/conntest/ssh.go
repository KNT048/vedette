package conntest

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// SSHOpts configures the SSH fake. The zero value is a switch with the user "vedette" and the password "pw-0123456789".
type SSHOpts struct {
	User, Password string
	AuthorizedKeys []ssh.PublicKey
	HostKey        ssh.Signer // nil: a new Ed25519 key

	// Ciphers, KeyExchanges and MACs narrow what the server offers; nil keeps the library's secure list. A test of weak
	// algorithms sets one to something only an old device speaks.
	Ciphers, KeyExchanges, MACs []string

	// Prompt is the device's name; the prompt is "<name>>" and, after "enable", "<name>#".
	Prompt string
	// Respond is the output of one command line, without the echo and the prompt; nil answers like an IOS switch: "% Invalid
	// input detected" for a line that starts with "bad", nothing for the rest.
	Respond func(line string) string
}

// SSH is an SSH server on loopback that records what it is sent.
type SSH struct {
	Host string // the name that reaches it
	Addr string // Host:port, the target of a connection

	opts    SSHOpts
	mu      sync.Mutex
	hostKey ssh.Signer
	lines   []string
	pwCalls int
	kiCalls int
	keyCall int
	logins  int
}

// NewSSHKey makes an Ed25519 key pair; the private key is also given as PEM through ssh.MarshalPrivateKey by the caller if needed.
func NewSSHKey(t testing.TB) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

// NewSSH starts the fake.
func NewSSH(t testing.TB, o SSHOpts) *SSH {
	t.Helper()
	if o.User == "" {
		o.User = "vedette"
	}
	if o.Password == "" {
		o.Password = "pw-0123456789"
	}
	if o.Prompt == "" {
		o.Prompt = "Switch"
	}
	s := &SSH{opts: o, hostKey: o.HostKey}
	if s.hostKey == nil {
		s.hostKey, _ = NewSSHKey(t)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Host = AllowLoopback(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.Addr = s.Host + ":" + port
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

// HostKeyPin is the host key as a pin: "<type> SHA256:<fingerprint>".
func (s *SSH) HostKeyPin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostKey.PublicKey().Type() + " " + ssh.FingerprintSHA256(s.hostKey.PublicKey())
}

// RotateHostKey gives the server another host key: the pin of the old one no longer matches.
func (s *SSH) RotateHostKey(t testing.TB) {
	t.Helper()
	k, _ := NewSSHKey(t)
	s.mu.Lock()
	s.hostKey = k
	s.mu.Unlock()
}

// Lines are the command lines received, in order.
func (s *SSH) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

// AuthCalls counts how many times the server was asked to check a password, a keyboard-interactive answer or a public key: zero
// means that no credential was sent.
func (s *SSH) AuthCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pwCalls + s.kiCalls + s.keyCall
}

// Logins counts the sign-ins that succeeded.
func (s *SSH) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

func (s *SSH) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	s.mu.Lock()
	hk := s.hostKey
	s.mu.Unlock()
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{Ciphers: s.opts.Ciphers, KeyExchanges: s.opts.KeyExchanges, MACs: s.opts.MACs},
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.pwCalls++
			if m.User() == s.opts.User && string(pw) == s.opts.Password {
				return nil, nil
			}
			return nil, errBadLogin
		},
		KeyboardInteractiveCallback: func(m ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			s.mu.Lock()
			s.kiCalls++
			s.mu.Unlock()
			ans, err := ch(m.User(), "", []string{"Password: "}, []bool{false})
			if err != nil || len(ans) != 1 || m.User() != s.opts.User || ans[0] != s.opts.Password {
				return nil, errBadLogin
			}
			return nil, nil
		},
		PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) { //nolint:gosec // a test fake: it counts the calls and checks the key itself
			s.mu.Lock()
			defer s.mu.Unlock()
			s.keyCall++
			for _, a := range s.opts.AuthorizedKeys {
				if m.User() == s.opts.User && string(a.Marshal()) == string(k.Marshal()) {
					return nil, nil
				}
			}
			return nil, errBadLogin
		},
	}
	cfg.AddHostKey(hk)
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go s.session(ch, creqs)
	}
}

type loginError string

func (e loginError) Error() string { return string(e) }

const errBadLogin = loginError("bad login")

func (s *SSH) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	pty := false
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			pty = true
			_ = r.Reply(true, nil)
		case "shell":
			_ = r.Reply(pty, nil)
			if pty {
				s.shell(ch)
			}
			return
		default:
			_ = r.Reply(false, nil)
		}
	}
}

func (s *SSH) shell(ch ssh.Channel) {
	suffix := ">"
	prompt := func() { _, _ = ch.Write([]byte(s.opts.Prompt + suffix + " ")) }
	_, _ = ch.Write([]byte("Fake switch, ready.\r\n"))
	prompt()
	rd := bufio.NewReader(ch)
	for {
		line, err := rd.ReadString('\r')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		s.mu.Lock()
		s.lines = append(s.lines, line)
		s.mu.Unlock()
		_, _ = ch.Write([]byte(line + "\r\n")) // the terminal's echo
		switch line {
		case "exit", "logout":
			return
		case "enable", "end":
			suffix = "#"
		case "configure terminal":
			suffix = "(config)#"
		}
		out := ""
		if s.opts.Respond != nil {
			out = s.opts.Respond(line)
		} else if strings.HasPrefix(line, "bad") {
			out = "% Invalid input detected at '^' marker."
		}
		if out != "" {
			_, _ = ch.Write([]byte(strings.ReplaceAll(out, "\n", "\r\n") + "\r\n"))
		}
		prompt()
	}
}

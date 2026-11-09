package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/knt048/vedette/core/secrets"
)

// SSHConfig configures one SSH session (D-94 (2)).
type SSHConfig struct {
	Dialer   *Dialer
	Username string
	// Key is a private key in PEM without a passphrase; Password is the password. One of them is set.
	Key      secrets.Value
	Password secrets.Value
	// HostKey is the pinned host key, "<type> SHA256:<fingerprint>"; "" means none is pinned.
	HostKey string
	// TOFU accepts the host key of a server with no pin and reports it in SSH.HostKey (trust on first use, like OpenSSH's
	// StrictHostKeyChecking accept-new). Without a pin and without TOFU nothing is accepted.
	TOFU bool
	// SetupTimeout bounds opening the session, the terminal and the shell once the sign-in is done; 0 is 10 seconds.
	SetupTimeout time.Duration
}

// SetupTimeout is the default of SSHConfig.SetupTimeout: the whole session budget is 60 seconds and one line gets 20.
const SetupTimeout = 10 * time.Second

// The algorithms are the library's list of those without a known weakness: no ssh-rsa with SHA-1, no CBC or RC4 ciphers, no
// Diffie-Hellman group 1 or SHA-1 key exchange. The library's default list is wider, because it still has to talk to old gear.
func algorithms() ssh.Algorithms {
	a := ssh.SupportedAlgorithms()
	hk := make([]string, 0, len(a.HostKeys))
	for _, h := range a.HostKeys {
		if !strings.Contains(h, "-cert-") { // the pin is the host key itself, not a certificate that vouches for one
			hk = append(hk, h)
		}
	}
	a.HostKeys = hk
	return a
}

// SSH is an interactive session on a device: a pseudo-terminal with the login shell, one line sent at a time, the prompt waited
// for after each, and the output read into memory only (D-94 (5)).
type SSH struct {
	// HostKey is what the server presented: "<type> SHA256:<fingerprint>".
	HostKey string

	raw      net.Conn // the socket under the SSH connection: closing it ends a read or a write that is stuck
	stopCtx  func() bool
	client   *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	deadline time.Time

	wmu    sync.Mutex // serialises writes to the session with its close (the library does not)
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	total  int
	rdErr  error
	closed bool
	over   bool     // the device sent more than MaxOutput: the reader stopped and the session was closed
	redact []string // the credentials, removed from any line of device text that is kept
}

// promptRE is what a device prints when it waits for a command: a short last line that ends in #, >, $ or % (Cisco-like "Switch#",
// "Switch(config)#", Fortinet "FGT $", Unix "user@host:~$"). It is the last, unfinished line of the output, so a line of output
// that merely ends in one of them does not count.
var promptRE = regexp.MustCompile(`^\S.{0,78}[#>$%] ?$`)

var ansiRE = regexp.MustCompile(`\x1b(\[[0-9;?]*[ -/]*[@-~]|[()][0-9A-B]|[=>])`)

// DialSSH connects, checks the host key before any credential is sent, signs in, starts the shell and reads the first prompt.
func DialSSH(ctx context.Context, hostport string, cfg SSHConfig) (*SSH, error) {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "22")
	}
	raw, err := cfg.Dialer.DialContext(ctx, hostport)
	if err != nil {
		return nil, err
	}
	s := &SSH{raw: raw, deadline: time.Now().Add(SessionTimeout), redact: []string{cfg.Password.Reveal(), cfg.Username}}
	s.cond = sync.NewCond(&s.mu)
	fail := func(err error) (*SSH, error) {
		_ = raw.Close()
		return nil, err
	}

	var auth []ssh.AuthMethod
	switch {
	case cfg.Key.IsSet():
		signer, err := ssh.ParsePrivateKey([]byte(cfg.Key.Reveal()))
		if err != nil {
			return fail(deviceErr("the saved SSH key could not be read"))
		}
		signer, err = sha2Only(signer)
		if err != nil {
			return fail(deviceErr("the saved SSH key could not be used"))
		}
		auth = append(auth, ssh.PublicKeys(signer))
	case cfg.Password.IsSet():
		pw := cfg.Password.Reveal()
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			out := make([]string, len(qs))
			for i := range out {
				out[i] = pw
			}
			return out, nil
		}))
	default:
		return fail(deviceErr("no sign-in is set for the SSH connection"))
	}
	alg := algorithms()
	var pinErr error
	conf := &ssh.ClientConfig{
		User: cfg.Username, Auth: auth,
		Config:            ssh.Config{KeyExchanges: alg.KeyExchanges, Ciphers: alg.Ciphers, MACs: alg.MACs},
		HostKeyAlgorithms: alg.HostKeys,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			s.HostKey = key.Type() + " " + ssh.FingerprintSHA256(key)
			switch {
			case cfg.HostKey != "" && cfg.HostKey != s.HostKey:
				pinErr = ErrPinMismatch // returned before the library asks for a password or signs anything
				return pinErr
			case cfg.HostKey == "" && !cfg.TOFU:
				pinErr = ErrUnverified
				return pinErr
			}
			return nil
		},
		ClientVersion: "SSH-2.0-Vedette",
	}
	// The handshake is bounded by the connect and call timeouts: a server that stops answering must not hold the Test.
	_ = raw.SetDeadline(time.Now().Add(ConnectTimeout + CallTimeout))
	stopDial := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopDial()
	cc, chans, reqs, err := ssh.NewClientConn(raw, hostport, conf)
	if err != nil {
		_ = raw.Close()
		if pinErr != nil {
			return nil, pinErr
		}
		return nil, sshError(err, cfg)
	}
	_ = raw.SetDeadline(time.Time{})
	// The sign-in is done, but a device may still never answer the request to open a session, a terminal or a shell: that wait is
	// bounded too, by closing the connection under it.
	setup := cfg.SetupTimeout
	if setup <= 0 {
		setup = SetupTimeout
	}
	setupTimer := time.AfterFunc(setup, func() { _ = raw.Close() })
	defer setupTimer.Stop()
	s.client = ssh.NewClient(cc, chans, reqs)
	closeOnErr := func(err error) (*SSH, error) {
		s.Close()
		return nil, err
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return closeOnErr(deviceErr("the server did not open a session"))
	}
	s.session = sess
	if err := sess.RequestPty("xterm", 24, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return closeOnErr(deviceErr("the server did not give a terminal"))
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		return closeOnErr(errors.New("the session could not be read"))
	}
	if s.stdin, err = sess.StdinPipe(); err != nil {
		return closeOnErr(errors.New("the session could not be written"))
	}
	if err := sess.Shell(); err != nil {
		return closeOnErr(deviceErr("the server did not start a shell"))
	}
	if !setupTimer.Stop() { // it fired: the connection is already closed
		return closeOnErr(errors.New("timed out"))
	}
	// For the rest of the session the end of ctx closes the socket: a write that waits for window the device never grants (the channel
	// blocks inside the library, where no deadline reaches it) must not outlive the step.
	s.stopCtx = context.AfterFunc(ctx, func() { _ = raw.Close() })
	go s.read(out)
	if _, err := s.waitPrompt(ctx, LineTimeout); err != nil {
		return closeOnErr(err)
	}
	return s, nil
}

// sshError turns the library's errors into words without the sign-in: a refused sign-in is the device's answer, the rest is a
// connection that did not work.
func sshError(err error, cfg SSHConfig) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods remain"):
		return deviceErr("the device refused the sign-in")
	case strings.Contains(msg, "no common algorithm"):
		return deviceErr("the device offers only SSH algorithms that Vedette does not use (%s)", CleanLine(msg, cfg.Password.Reveal(), cfg.Username))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timed out")
	}
	return errors.New(CleanLine(msg, cfg.Password.Reveal(), cfg.Username))
}

func (s *SSH) read(r io.Reader) {
	b := make([]byte, 4096)
	for {
		n, err := r.Read(b)
		s.mu.Lock()
		if n > 0 {
			s.total += n
			if s.total > MaxOutput {
				// Past the cap nothing more is kept or read: a device that floods while nobody waits must not grow the buffer.
				s.over, s.buf = true, s.buf[:0]
			} else {
				s.buf = append(s.buf, b[:n]...)
			}
		}
		if err != nil {
			s.rdErr = err
		}
		over := s.over
		s.mu.Unlock()
		s.cond.Broadcast()
		if over {
			s.Close()
			return
		}
		if err != nil {
			return
		}
	}
}

// waitPrompt waits until the output ends in a prompt and stays still for a moment, and returns the output read before it. It
// gives up after limit, at the end of the session, or when ctx ends.
func (s *SSH) waitPrompt(ctx context.Context, limit time.Duration) (string, error) {
	end := time.Now().Add(limit)
	if end.After(s.deadline) {
		end = s.deadline
	}
	if time.Until(end) <= 0 {
		return "", errors.New("timed out")
	}
	wake := time.AfterFunc(time.Until(end), func() { s.cond.Broadcast() })
	defer wake.Stop()
	stop := context.AfterFunc(ctx, func() { s.cond.Broadcast() })
	defer stop()

	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.over {
			return "", deviceErr("the device sent more than %d MB", MaxOutput>>20)
		}
		if isPrompt(s.buf) {
			// A prompt that is only the end of what has come so far is not enough: a device writes in pieces. It counts once nothing
			// follows for a moment.
			n := len(s.buf)
			s.mu.Unlock()
			settle := time.NewTimer(40 * time.Millisecond)
			select {
			case <-settle.C:
			case <-ctx.Done():
				settle.Stop()
			}
			s.mu.Lock()
			if len(s.buf) == n {
				out := string(s.buf)
				s.buf = s.buf[:0]
				return out, nil
			}
			continue
		}
		if s.rdErr != nil {
			return "", deviceErr("the device closed the session")
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if !time.Now().Before(end) {
			return "", errors.New("timed out")
		}
		s.cond.Wait()
	}
}

func isPrompt(b []byte) bool {
	clean := ansiRE.ReplaceAll(b, nil)
	i := bytes.LastIndexAny(clean, "\r\n")
	return promptRE.Match(clean[i+1:])
}

// errorMarkers are the starts of a line by which devices say that a command failed (spec action-templates 9.3): Cisco-like "%",
// "Invalid input", "Error", and "Unknown command".
var errorMarkers = []string{"%", "Error", "Invalid", "Unknown command"}

// Run sends one line, waits for the next prompt and returns the output without the echo of the line and without the prompt. A
// line of the output that begins like an error ends the session: the error is a DeviceError with that one line, cleaned, and the
// session is closed.
func (s *SSH) Run(ctx context.Context, line string) (string, error) {
	// A terminal acts on more than the line break: Ctrl-Z ends configuration mode, Ctrl-U kills what the template put before a
	// parameter, Ctrl-V quotes the next key, ESC and the C1 controls start escape sequences. One approved line stays one line.
	if strings.ContainsFunc(line, unicode.IsControl) {
		return "", errors.New("a command is one line of printable characters")
	}
	s.mu.Lock()
	over, closed := s.over, s.closed
	s.buf = s.buf[:0]
	s.mu.Unlock()
	if over {
		return "", deviceErr("the device sent more than %d MB", MaxOutput>>20)
	}
	if closed {
		return "", deviceErr("the device closed the session")
	}
	// A line has LineTimeout to be written, whatever the window of the channel says: the timer closes the socket under the write.
	limit := LineTimeout
	if left := time.Until(s.deadline); left < limit {
		limit = left
	}
	stuck := time.AfterFunc(limit, func() { _ = s.raw.Close() })
	s.wmu.Lock()
	_, err := io.WriteString(s.stdin, line+"\r")
	s.wmu.Unlock()
	stuck.Stop()
	if err != nil {
		s.Close()
		return "", deviceErr("the device closed the session")
	}
	raw, err := s.waitPrompt(ctx, LineTimeout)
	if err != nil {
		s.Close()
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(ansiRE.ReplaceAll([]byte(raw), nil)), "\r", ""), "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == strings.TrimSpace(line) {
		lines = lines[1:] // the echo
	}
	if len(lines) > 0 { // the prompt
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		for _, m := range errorMarkers { // at the start of the line: command output is indented, a device's own message is not
			if strings.HasPrefix(l, m) {
				s.Close()
				return "", deviceErr("the device refused a command: %s", CleanLine(l, s.redact...))
			}
		}
	}
	return strings.Join(lines, "\n"), nil
}

// Close ends the session and the connection.
func (s *SSH) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	if s.stopCtx != nil {
		s.stopCtx()
	}
	if s.raw != nil {
		_ = s.raw.Close() // first: it frees a write that is stuck, which holds wmu
	}
	if s.stdin != nil {
		s.wmu.Lock()
		_ = s.stdin.Close()
		s.wmu.Unlock()
	}
	if s.session != nil {
		_ = s.session.Close()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
}

// sha2Only restricts an RSA key to the SHA-2 signatures: a library signer would otherwise fall back to ssh-rsa with SHA-1.
func sha2Only(sg ssh.Signer) (ssh.Signer, error) {
	if sg.PublicKey().Type() != ssh.KeyAlgoRSA {
		return sg, nil
	}
	as, ok := sg.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("the key cannot sign with SHA-2")
	}
	return ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
}

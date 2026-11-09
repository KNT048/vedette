package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/secrets"
)

// ErrPinMismatch is a server whose certificate or host key is not the one pinned at the first Test: nothing was sent to it.
var ErrPinMismatch = errors.New("the identity of the server is not the one pinned at the first test")

// ErrUnverified is a server that no public authority vouches for and that has no pin yet (it is only accepted by a first Test).
var ErrUnverified = errors.New("the certificate of the server is not trusted and nothing is pinned for it")

// DeviceError is a failure of the device or service itself, in words that are safe to show: the connection was made. Anything
// else that Do returns (a dial that failed, a timeout, a handshake that failed) means the address could not be reached.
type DeviceError struct{ Msg string }

func (e *DeviceError) Error() string { return e.Msg }

func deviceErr(format string, args ...any) *DeviceError {
	return &DeviceError{Msg: CleanLine(fmt.Sprintf(format, args...))}
}

// deviceErrAuth is deviceErr for a message that holds the device's own words: the credentials are removed before the line is cut to
// its length, or the first characters of a credential cut in half would survive.
func deviceErrAuth(a Auth, format string, args ...any) *DeviceError {
	return &DeviceError{Msg: CleanLine(fmt.Sprintf(format, args...), a.redactions()...)}
}

// redactions are the strings of this credential that must not appear in any text: the secret, the user name, and the Basic form
// (base64 of user:secret). CleanLine adds the base64 of each of them alone.
func (a Auth) redactions() []string {
	r := []string{a.Secret.Reveal(), a.Username}
	if a.Type == "basic" {
		r = append(r, base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Secret.Reveal())))
	}
	return r
}

// Auth is how the box signs in to an HTTP server (D-94 (1)). The secret is read from the vault by the caller.
type Auth struct {
	Type     string // none, token or basic
	Username string
	Secret   secrets.Value
}

// HTTPSConfig configures a Client.
type HTTPSConfig struct {
	Dialer *Dialer
	// Pin is the hex SHA-256 of the SubjectPublicKeyInfo of the pinned leaf certificate. With a pin, the key must be that one and
	// nothing else counts, public authorities included.
	Pin string
	// TOFU lets a certificate that no public authority vouches for through when there is no pin, and reports it in Seen: the
	// first Test pins it (trust on first use). Without it, such a certificate is refused: ErrUnverified.
	TOFU bool
	// Roots are the authorities that vouch for a server; nil is the system's. Tests set it; the product does not.
	Roots *x509.CertPool
}

// Seen is what the last handshake showed.
type Seen struct {
	SPKISHA256    string // hex SHA-256 of the leaf's public key, "" until a handshake completed
	SystemTrusted bool   // a public authority vouches for the certificate and the name
}

// Client sends requests over HTTPS with the rules of D-94: TLS 1.2 or later, the pin or the roots decide, no redirect, no proxy,
// no retry, capped request, response and time.
type Client struct {
	cfg  HTTPSConfig
	http *http.Client
	mu   sync.Mutex
	seen Seen
}

// NewHTTPS returns a Client.
func NewHTTPS(cfg HTTPSConfig) *Client {
	c := &Client{cfg: cfg}
	tr := &http.Transport{
		Proxy:                  nil, // never the environment's proxy: it would carry a request past the address policy
		DialTLSContext:         c.dialTLS,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    ConnectTimeout,
		ResponseHeaderTimeout:  CallTimeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	c.http = &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // a redirect is an answer, not an instruction
	}
	return c
}

// Seen reports what the last handshake showed.
func (c *Client) Seen() Seen {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen
}

func (c *Client) dialTLS(ctx context.Context, _, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	raw, err := c.cfg.Dialer.DialContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	conf := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		// The standard verification is replaced by verify below, which does the same check against the roots and adds the pin; a
		// certificate is never accepted without one of the two. gosec cannot see through the callback.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection verifies: pin, or roots, or (first Test only) trust on first use
		VerifyConnection:   func(cs tls.ConnectionState) error { return c.verify(host, cs) },
	}
	tc := tls.Client(raw, conf)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

func (c *Client) verify(host string, cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("the server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	// The pin is the hash of the public key (SubjectPublicKeyInfo), like an SSH host key pin: a certificate re-issued for the
	// same key keeps it.
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	hash := hex.EncodeToString(sum[:])
	trusted := false
	inter := x509.NewCertPool()
	for _, ic := range cs.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: c.cfg.Roots, Intermediates: inter}); err == nil {
		trusted = true
	}
	switch {
	case c.cfg.Pin != "":
		if !strings.EqualFold(hash, c.cfg.Pin) {
			return ErrPinMismatch
		}
	case trusted, c.cfg.TOFU:
	default:
		return ErrUnverified
	}
	// One client is one trust decision (one Test): every handshake after the first must show the same key, or the credential would
	// go to whoever answers the second request.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen.SPKISHA256 != "" && c.seen.SPKISHA256 != hash {
		return ErrPinMismatch
	}
	c.seen = Seen{SPKISHA256: hash, SystemTrusted: trusted}
	return nil
}

// ForbiddenHeader reports whether a template may not set a header (D-94 (1)): the sign-in is the connection's, the route is the
// box's, and hop-by-hop headers belong to the transport.
func ForbiddenHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "authorization", "cookie", "set-cookie", "host", "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
		"proxy-connection", "forwarded", "content-length":
		return true
	}
	return strings.HasPrefix(n, "proxy-") || strings.HasPrefix(n, "x-forwarded-")
}

// Request is one HTTPS request. The URL is complete (the caller checked it is under the target and the allow-list).
type Request struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

// Response is what came back, capped at MaxResponse.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Stream is a response whose body is read by the caller, up to MaxResponse bytes, within CallTimeout of Open. Close it.
type Stream struct {
	Status int
	Header http.Header
	Body   io.Reader
	close  func()
}

// Close ends the call and frees the connection.
func (s *Stream) Close() { s.close() }

// Open sends the request and returns as soon as the headers are in.
func (c *Client) Open(ctx context.Context, a Auth, r Request) (*Stream, error) {
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("the address is not an https address")
	}
	if len(r.Body) > MaxRequest {
		return nil, deviceErr("the request is larger than %d KB", MaxRequest>>10)
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, deviceErr("the method %s is not allowed", method)
	}
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	req, err := http.NewRequestWithContext(ctx, method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		cancel()
		return nil, errors.New("the request could not be built")
	}
	for k, vs := range r.Header {
		if ForbiddenHeader(k) {
			cancel()
			return nil, deviceErr("the header %s may not be set", k)
		}
		for _, v := range vs {
			if strings.ContainsAny(k+v, "\r\n") {
				cancel()
				return nil, deviceErr("a header holds a line break")
			}
			req.Header.Add(k, v)
		}
	}
	switch a.Type {
	case "token":
		req.Header.Set("Authorization", "Bearer "+a.Secret.Reveal())
	case "basic":
		req.SetBasicAuth(a.Username, a.Secret.Reveal())
	}
	resp, err := c.http.Do(req) //nolint:bodyclose // closed by Stream.Close, which every caller defers
	if err != nil {
		cancel()
		return nil, cleanTransportError(err, a)
	}
	return &Stream{
		Status: resp.StatusCode, Header: resp.Header, Body: io.LimitReader(resp.Body, MaxResponse+1),
		close: func() { _ = resp.Body.Close(); cancel() },
	}, nil
}

// Do sends the request and reads the whole answer. An answer of more than MaxResponse bytes is a DeviceError.
func (c *Client) Do(ctx context.Context, a Auth, r Request) (*Response, error) {
	s, err := c.Open(ctx, a, r)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	body, err := io.ReadAll(s.Body)
	if err != nil {
		return nil, cleanTransportError(err, a)
	}
	if len(body) > MaxResponse {
		return nil, deviceErr("the answer is larger than %d MB", MaxResponse>>20)
	}
	return &Response{Status: s.Status, Header: s.Header, Body: body}, nil
}

// cleanTransportError keeps what matters to the administrator (a pin, a refusal, a timeout) and drops the rest: the standard
// library puts the URL in its errors, which can carry a name the administrator typed but never a header or a body.
func cleanTransportError(err error, a Auth) error {
	var re *RefusedError
	switch {
	case errors.Is(err, ErrPinMismatch), errors.Is(err, ErrUnverified), errors.As(err, &re):
		return err
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("timed out")
	}
	var de *DeviceError
	if errors.As(err, &de) {
		return err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timed out")
	}
	return errors.New(CleanLine(unwrapURL(err), a.redactions()...))
}

func unwrapURL(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

package conn

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"

	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

// The HTTPS facade (D-305): a module that talks to one server of its own, outside the saved connections of this package (agent-intake's
// Wazuh pull, D-169 (12)), gets the same client the connections use instead of a second TLS and address-policy implementation: TLS 1.2
// or later, the pin or the public roots decide, trust on first use only when asked, no redirect, no proxy, no retry, a request of at most
// 64 KiB, an answer of at most 1 MiB, 15 seconds a call, and every address checked against the policy of D-94 (RefusedAddr with the
// box's addresses) when it is dialled. Errors carry one cleaned line and never the credential.

// Errors of an HTTPSClient call, to tell the administrator what happened. Anything else is "could not be reached".
var (
	// ErrPinMismatch: the server's key is not the pinned one (or changed between two requests of one client). Nothing was sent.
	ErrPinMismatch = transport.ErrPinMismatch
	// ErrUnverified: no public authority vouches for the certificate and nothing is pinned. Nothing was sent.
	ErrUnverified = transport.ErrUnverified
)

// RefusedError is a dial the address policy stopped (loopback, link-local, the box itself...): no socket was opened.
type RefusedError = transport.RefusedError

// DeviceError is the server's own failure in words that are safe to show (an answer over the cap, a header that may not be set).
type DeviceError = transport.DeviceError

// HTTPSOptions is the trust decision of one HTTPSClient.
type HTTPSOptions struct {
	// Pin is the hex SHA-256 of the SubjectPublicKeyInfo of the server's leaf certificate. Set, it is the only thing that counts.
	Pin string
	// TOFU lets a certificate that no public authority vouches for through when Pin is empty, and Seen reports its key: the caller
	// pins it (trust on first use). Without it such a certificate is ErrUnverified.
	TOFU bool
	// Roots replaces the system's public authorities. Tests set it; the product does not.
	Roots *x509.CertPool
}

// HTTPSRequest is one request. URL is complete and https; the caller checked it is one it may call.
type HTTPSRequest struct {
	Method string // "" is GET
	URL    string
	Header http.Header // Authorization, Cookie, Host and the hop-by-hop headers may not be set (ForbiddenHeader)
	Body   []byte
	// Exactly one way of signing in, or none: Basic with BasicUser and Secret, or Bearer with Secret alone.
	BasicUser string
	Bearer    bool
	Secret    secrets.Value
}

// HTTPSResponse is the whole answer, at most 1 MiB.
type HTTPSResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// HTTPSClient is one trust decision: every handshake it makes must show the same key as its first one. Make a new one per pull or test.
type HTTPSClient struct{ c *transport.Client }

// NewHTTPS returns a client whose every dial is checked against the address policy of this service (RefusedAddr with BoxAddrs, asked
// at the moment of the dial).
func (s *Service) NewHTTPS(o HTTPSOptions) *HTTPSClient {
	return &HTTPSClient{c: transport.NewHTTPS(transport.HTTPSConfig{Dialer: s.dialer(), Pin: o.Pin, TOFU: o.TOFU, Roots: o.Roots})}
}

// Do sends the request and reads the whole answer. The errors are ErrPinMismatch, ErrUnverified, a *RefusedError, a *DeviceError or
// a plain error meaning the server could not be reached in time; none holds the secret.
func (h *HTTPSClient) Do(ctx context.Context, r HTTPSRequest) (*HTTPSResponse, error) {
	a := transport.Auth{Type: "none"}
	switch {
	case r.BasicUser != "" && r.Bearer:
		return nil, errors.New("conn: a request signs in one way only")
	case r.BasicUser != "":
		a = transport.Auth{Type: "basic", Username: r.BasicUser, Secret: r.Secret}
	case r.Bearer:
		a = transport.Auth{Type: "token", Secret: r.Secret}
	}
	resp, err := h.c.Do(ctx, a, transport.Request{Method: r.Method, URL: r.URL, Header: r.Header, Body: r.Body})
	if err != nil {
		return nil, err
	}
	return &HTTPSResponse{Status: resp.Status, Header: resp.Header, Body: resp.Body}, nil
}

// Seen is what the last handshake showed: the hex SHA-256 of the leaf's public key ("" before any), and whether a public authority
// vouched for the certificate and the name.
func (h *HTTPSClient) Seen() (spki string, systemTrusted bool) {
	s := h.c.Seen()
	return s.SPKISHA256, s.SystemTrusted
}

// HTTPSTargetProblem checks an address an administrator typed for a server of their own: https, a host, no user name or password, no
// query or fragment, and a host the address policy allows (as typed; the dial checks the resolved address again). It returns the
// sentence to show, or "" when the address may be used. A path is the caller's to refuse or keep.
func (s *Service) HTTPSTargetProblem(ctx context.Context, target string) string {
	var box []netip.Prefix
	if s.cfg.BoxAddrs != nil {
		box = s.cfg.BoxAddrs(ctx)
	}
	if e := checkTarget(target, false, box); e != nil {
		return e.Message
	}
	return ""
}

// CleanLine makes text from a server fit in a message: one line, no control or invisible characters, at most 200 characters, every
// string in redact replaced first.
func CleanLine(s string, redact ...string) string { return transport.CleanLine(s, redact...) }

package authoidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Limits on the identity provider (INV-11, SYS-6): every answer is untrusted.
const (
	idpTimeout   = 10 * time.Second
	maxIDPBody   = 1 << 20 // discovery, keys and token answers are a few KiB
	discoveryTTL = time.Hour
)

// allowedAlgs are the ID-token signature algorithms Vedette accepts (D-194 (3)): asymmetric only. none and HS* never: a symmetric
// key would be the client secret, and "none" is no signature.
var allowedAlgs = []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.PS256, oidc.PS384, oidc.PS512, oidc.ES256, oidc.ES384, oidc.ES512}

// errTooLarge: an answer of the identity provider went past maxIDPBody.
var errTooLarge = errors.New("authoidc: the identity provider's answer is larger than 1 MiB")

// newClient is the HTTP client of every call to the identity provider: https only, no redirects (SYS-7), 10 s, 1 MiB answers.
// base is the transport (tests pass the httptest TLS one); nil = a clone of the default transport.
func newClient(base http.RoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	return &http.Client{
		Timeout:       idpTimeout,
		Transport:     capped{base},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type capped struct{ rt http.RoundTripper }

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("authoidc: %s is not an https address", r.URL.Redacted())
	}
	resp, err := c.rt.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &limited{rc: resp.Body, left: maxIDPBody}
	return resp, nil
}

// limited fails a read past its limit instead of cutting the body short (a cut JSON could still parse).
type limited struct {
	rc   io.ReadCloser
	left int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.left <= 0 {
		var one [1]byte
		if n, _ := l.rc.Read(one[:]); n > 0 {
			return 0, errTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.rc.Read(p)
	l.left -= int64(n)
	return n, err
}

func (l *limited) Close() error { return l.rc.Close() }

// idp is the discovered identity provider of one issuer.
type idp struct {
	issuer    string
	caPEM     string       // the saved CA this was discovered with (D-378)
	client    *http.Client // clientFor(caPEM): discovery, keys (the provider keeps it) and the token exchange
	provider  *oidc.Provider
	jwksURL   string
	algs      []string // allowedAlgs that the provider says it signs ID tokens with
	authStyle oauth2.AuthStyle
	fetchedAt time.Time
}

// discover reads <issuer>/.well-known/openid-configuration through the capped client, or returns the cached result for that issuer
// (1 hour; Store and Test drop it), through clientFor(the saved CA). go-oidc checks that the document's issuer is the configured one. Every endpoint must be https.
func (s *Service) discover(ctx context.Context, c Config, fresh bool) (*idp, error) {
	issuer := c.Issuer
	s.mu.Lock()
	cached := s.cache
	s.mu.Unlock()
	if !fresh && cached != nil && cached.issuer == issuer && cached.caPEM == c.CAPEM && s.now().Sub(cached.fetchedAt) < discoveryTTL {
		return cached, nil
	}
	// The provider keeps this context for its key set, so it must not end with this request: WithoutCancel. Only the client in it
	// is used; its timeout bounds every call.
	client := s.clientFor(c.CAPEM)
	pctx := oidc.ClientContext(context.WithoutCancel(ctx), client)
	done := make(chan struct{})
	var p *oidc.Provider
	var err error
	go func() { defer close(done); p, err = oidc.NewProvider(pctx, issuer) }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}
	if err != nil {
		return nil, err
	}
	var meta struct {
		JWKS  string   `json:"jwks_uri"`
		Algs  []string `json:"id_token_signing_alg_values_supported"`
		Auths []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, fmt.Errorf("authoidc: discovery document: %w", err)
	}
	ep := p.Endpoint()
	for name, u := range map[string]string{"authorization": ep.AuthURL, "token": ep.TokenURL, "jwks": meta.JWKS} {
		if !strings.HasPrefix(u, "https://") {
			return nil, fmt.Errorf("authoidc: the %s endpoint %q is not an https address", name, u)
		}
	}
	if len(meta.Algs) == 0 {
		meta.Algs = []string{oidc.RS256} // OpenID Connect Discovery: RS256 when the provider says nothing
	}
	var algs []string
	for _, a := range allowedAlgs {
		if slices.Contains(meta.Algs, a) {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return nil, fmt.Errorf("authoidc: the identity provider signs ID tokens only with %v; Vedette accepts %v", meta.Algs, allowedAlgs)
	}
	// client_secret_basic is the default of the specification (absent list); client_secret_post only when the provider lists it
	// without basic. Other methods (private_key_jwt) are not supported.
	style := oauth2.AuthStyleInHeader
	if len(meta.Auths) > 0 && !slices.Contains(meta.Auths, "client_secret_basic") {
		if !slices.Contains(meta.Auths, "client_secret_post") {
			return nil, fmt.Errorf("authoidc: the token endpoint accepts only %v; Vedette sends client_secret_basic or client_secret_post", meta.Auths)
		}
		style = oauth2.AuthStyleInParams
	}
	d := &idp{issuer: issuer, caPEM: c.CAPEM, client: client, provider: p, jwksURL: meta.JWKS, algs: algs, authStyle: style, fetchedAt: s.now()}
	s.mu.Lock()
	s.cache = d
	s.mu.Unlock()
	return d, nil
}

// forget drops the discovery cache (the configuration changed, or Test asked for a fresh read).
func (s *Service) forget() {
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()
}

package authoidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/store"
	authoidc "github.com/knt048/vedette/modules/auth-oidc"
)

// fakeIDP is an OpenID Connect provider on an httptest TLS server: discovery, keys and a token endpoint that checks the client
// secret and the PKCE verifier and answers with an ID token the test shapes (claims, alg, key). There is no authorization page:
// the test reads state, nonce and the code challenge from the authorize URL and "comes back" with a code of its own.
type fakeIDP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	secret string

	mu        sync.Mutex
	challenge string              // code_challenge of the last authorize URL
	nonce     string              // nonce of the last authorize URL
	claims    map[string]any      // claims of the next ID token (nonce filled in unless the test set one)
	sign      func(string) string // nil: RS256 with key; else returns the whole token from the claims JSON
	tokenErr  int                 // non-zero: the token endpoint answers this status with error=invalid_grant
	gotVerify string              // code_verifier the box sent
	gotAuth   bool                // the client secret was right
	discovery map[string]any      // overrides of the discovery document
	big       bool                // discovery answers more than 1 MiB
	redirect  bool                // discovery answers a redirect to another host
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: k, kid: "k1", secret: "client-secret-123"}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) issuer() string { return f.srv.URL }

func (f *fakeIDP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	if strings.HasSuffix(path, "/.well-known/openid-configuration") {
		path = "/.well-known/openid-configuration"
	}
	switch path {
	case "/.well-known/openid-configuration":
		iss := f.srv.URL + strings.TrimSuffix(r.URL.Path, "/.well-known/openid-configuration") // an issuer with a path (a realm)
		if f.redirect {
			http.Redirect(w, r, "https://elsewhere.example/.well-known/openid-configuration", http.StatusFound)
			return
		}
		doc := map[string]any{
			"issuer": iss, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		}
		for k, v := range f.discovery {
			doc[k] = v
		}
		if f.big {
			doc["padding"] = strings.Repeat("x", 2<<20)
		}
		_ = json.NewEncoder(w).Encode(doc)
	case "/jwks":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}}})
	case "/token":
		_ = r.ParseForm()
		user, pass, ok := r.BasicAuth()
		if !ok {
			user, pass = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		f.gotAuth = user == "vedette" && pass == f.secret
		f.gotVerify = r.PostForm.Get("code_verifier")
		sum := sha256.Sum256([]byte(f.gotVerify))
		pkceOK := base64.RawURLEncoding.EncodeToString(sum[:]) == f.challenge
		if f.tokenErr != 0 || !f.gotAuth || !pkceOK || r.PostForm.Get("code") != "the-code" {
			status := f.tokenErr
			if status == 0 {
				status = http.StatusBadRequest
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		claims := map[string]any{"nonce": f.nonce}
		for k, v := range f.claims {
			claims[k] = v
		}
		body, _ := json.Marshal(claims)
		var tok string
		if f.sign != nil {
			tok = f.sign(string(body))
		} else {
			tok = f.signWith(jose.RS256, f.key, f.kid, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": tok})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIDP) signWith(alg jose.SignatureAlgorithm, key any, kid string, payload []byte) string {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		panic(err)
	}
	jws, err := s.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return out
}

// pubDER is the public key as bytes: the "secret" of the HS256 key-confusion attack.
func (f *fakeIDP) pubDER() []byte {
	b, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *fakeIDP) set(fn func(*fakeIDP)) { f.mu.Lock(); fn(f); f.mu.Unlock() }

// world is a box with core migrated, auth-oidc on top, and a fake IdP configured.
type world struct {
	t    *testing.T
	env  *authtest.Env
	svc  *authoidc.Service
	idp  *fakeIDP
	addr netip.Addr
}

const origin = "https://vedette.test"

func newWorld(t *testing.T) *world {
	t.Helper()
	env := authtest.New(t)
	if err := store.Migrate(t.Context(), env.DB, "auth-oidc", authoidc.Migrations); err != nil {
		t.Fatal(err)
	}
	idp := newFakeIDP(t)
	svc, err := authoidc.New(authoidc.Deps{DB: env.DB, Secrets: env.Secrets, Auth: env.Svc, Audit: env.Audit, Log: discard(), Clock: env.Clock.Now, IDPBase: idp.srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, env: env, svc: svc, idp: idp, addr: netip.MustParseAddr("192.0.2.10")}
	w.configure(authoidc.Save{Scopes: "openid email profile", GroupsClaim: "groups", RoleMap: []authoidc.RoleRow{{Group: "vedette-operators", Role: routes.Operator}, {Group: "vedette-admins", Role: routes.Admin}, {Group: "staff", Role: routes.Viewer}}})
	idp.set(func(f *fakeIDP) {
		f.claims = map[string]any{"iss": idp.issuer(), "sub": "user-1", "aud": "vedette", "exp": w.env.Clock.Now().Add(5 * time.Minute).Unix(), "iat": w.env.Clock.Now().Unix(),
			"email": "Ana@Acme.Example", "email_verified": true, "name": "Ana", "groups": []string{"staff", "vedette-operators"}}
	})
	return w
}

// configure saves the configuration with the fake IdP's issuer and secret; zero fields of s take the world's defaults.
func (w *world) configure(s authoidc.Save) {
	w.t.Helper()
	if s.Issuer == "" {
		s.Issuer = w.idp.issuer() + "/"
	}
	if s.ClientID == "" {
		s.ClientID = "vedette"
	}
	if s.ClientSecret == "" {
		s.ClientSecret = w.idp.secret
	}
	if s.Scopes == "" {
		s.Scopes = "openid email"
	}
	if s.GroupsClaim == "" {
		s.GroupsClaim = "groups"
	}
	if _, err := w.svc.Store(w.t.Context(), "admin@acme.example", origin, s); err != nil {
		w.t.Fatalf("Store: %v", err)
	}
}

// start begins a sign-in and plays the identity provider's page: it records nonce and challenge for the token endpoint and returns
// the state and binding the browser would come back with.
func (w *world) start() (state, binding string) {
	w.t.Helper()
	st, err := w.svc.Start(w.t.Context(), origin, w.addr)
	if err != nil {
		w.t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(st.AuthorizeURL)
	if err != nil {
		w.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("redirect_uri") != origin+"/sso/callback" || q.Get("client_id") != "vedette" {
		w.t.Fatalf("authorize URL = %s", st.AuthorizeURL)
	}
	w.idp.set(func(f *fakeIDP) { f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce") })
	return q.Get("state"), st.Binding
}

func (w *world) callback(state, binding string) (auth.Issued, error) {
	return w.svc.Callback(w.t.Context(), authoidc.CallbackRequest{Code: "the-code", State: state, Binding: binding, IP: w.addr, UserAgent: "test"})
}

// signIn is a whole round trip.
func (w *world) signIn() (auth.Issued, error) {
	w.t.Helper()
	s, b := w.start()
	return w.callback(s, b)
}

func (w *world) claim(k string, v any) { w.idp.set(func(f *fakeIDP) { f.claims[k] = v }) }

func (w *world) auditHas(action, detail string) bool {
	w.t.Helper()
	return w.env.Count(w.t, `SELECT count(*) FROM core_audit WHERE action = ? AND detail = ?`, action, detail) > 0
}

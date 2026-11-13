package channel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// fakeTokenService is a token endpoint (Microsoft or Google): check inspects each request and returns the status and body to send.
type fakeTokenService struct {
	srv   *httptest.Server
	calls atomic.Int32
}

func startTokenService(t *testing.T, check func(path string, form url.Values) (int, string)) *fakeTokenService {
	t.Helper()
	f := &fakeTokenService{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		code, body := check(r.URL.Path, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

const testTenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
const testClient = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"

func microsoftCfg(f *fakeSMTP, tokens *fakeTokenService, t *testing.T) EmailConfig {
	cfg := oauthAt(f, emailCfg(f, SecurityStartTLS), "smtp.office365.com")
	cfg.Provider, cfg.TenantID, cfg.ClientID = "microsoft365", testTenant, testClient
	cfg.Password = secrets.NewValue("Abc8Q~client.secret_value-123")
	cfg.HTTPClient = clientTo(t, tokens.srv.URL)
	return cfg
}

// oauthAt names the provider's own SMTP host (the only one an OAuth2 preset accepts) and connects to the fake instead.
func oauthAt(f *fakeSMTP, cfg EmailConfig, host string) EmailConfig {
	cfg.Host, cfg.dialAddr = host, f.ln.Addr().String()
	return cfg
}

// msTokens answers a correct client-credentials request with token tok, valid an hour.
func msTokens(t *testing.T, tok string) *fakeTokenService {
	return startTokenService(t, func(path string, form url.Values) (int, string) {
		if path != "/"+testTenant+"/oauth2/v2.0/token" || form.Get("grant_type") != "client_credentials" || form.Get("client_id") != testClient ||
			form.Get("client_secret") != "Abc8Q~client.secret_value-123" || form.Get("scope") != "https://outlook.office365.com/.default" {
			return 400, `{"error":"invalid_request","error_description":"AADSTS900144 the request is wrong"}`
		}
		return 200, `{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"` + tok + `"}`
	})
}

func TestSMTPPasswordSignInPicksPlainThenLogin(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		offered []string
		want    string
	}{
		"plain first":     {[]string{"LOGIN", "PLAIN"}, "PLAIN"},
		"login when only": {[]string{"LOGIN", "XOAUTH2"}, "LOGIN"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: c.offered})
			s, err := NewEmail(emailCfg(f, SecurityStartTLS))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Send(context.Background(), sample); err != nil {
				t.Fatal(err)
			}
			if got := f.usedMech(); got != c.want {
				t.Errorf("mechanism %s, want %s", got, c.want)
			}
		})
	}
	t.Run("nothing usable", func(t *testing.T) {
		t.Parallel()
		f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"CRAM-MD5"}})
		s, _ := NewEmail(emailCfg(f, SecurityStartTLS))
		_, err := s.Send(context.Background(), sample)
		var si *SignInError
		if !errors.As(err, &si) || !strings.Contains(si.Msg, "PLAIN or LOGIN") {
			t.Fatalf("err = %v", err)
		}
		if authPlain, authTLS, from, _, _ := f.snapshot(); authPlain || authTLS || from != "" {
			t.Errorf("session went on: %v %v %q", authPlain, authTLS, from)
		}
	})
	t.Run("a refused login is our sentence over the SMTP code", func(t *testing.T) {
		t.Parallel()
		f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"LOGIN"}})
		cfg := emailCfg(f, SecurityStartTLS)
		cfg.Password = secrets.NewValue("wrong-Password-1")
		s, _ := NewEmail(cfg)
		_, err := s.Send(context.Background(), sample)
		var si *SignInError
		var se *StatusError
		if !errors.As(err, &si) || !errors.As(err, &se) || se.Code != 535 || !strings.Contains(si.Msg, "SMTP code 535") {
			t.Fatalf("err = %v", err)
		}
		mustNot(t, err.Error()+se.Reason, "wrong-Password-1")
	})
}

func TestSMTPPostmarkTokenIsUsernameAndPassword(t *testing.T) {
	t.Parallel()
	tok := "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
	f := startFakeSMTP(t, &fakeSMTP{starttls: true, user: tok, pass: tok})
	cfg := emailCfg(f, SecurityStartTLS)
	cfg.Provider, cfg.Username = "postmark", "ignored@acme.example"
	s, err := NewEmail(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
}

// The token is cached until shortly before it expires, then fetched again (Now moves; no real clock).
func TestSMTPMicrosoftOAuthTokenIsCachedUntilItExpires(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"LOGIN", "XOAUTH2"}, user: "alerts@acme.example", token: "eyJ0eXAi.ms-token.1"}) //nolint:gosec // a fake token
	tokens := msTokens(t, "eyJ0eXAi.ms-token.1")
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	cfg := microsoftCfg(f, tokens, t)
	cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	cache := NewTokenCache()
	cfg.Tokens = cache
	s, err := NewEmail(cfg)
	if err != nil {
		t.Fatal(err)
	}
	send := func() {
		t.Helper()
		if _, err := s.Send(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
	}
	send()
	if f.usedMech() != "XOAUTH2" {
		t.Errorf("mechanism %s", f.usedMech())
	}
	// another sender of the same channel (a two-step code to one person) uses the same cached token
	cfg2 := cfg
	cfg2.To = []string{"one@acme.example"}
	s2, _ := NewEmail(cfg2)
	if _, err := s2.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(54 * time.Minute) // still more than 5 minutes left
	mu.Unlock()
	send()
	if n := tokens.calls.Load(); n != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", n)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute) // 56 minutes: less than 5 minutes left of 3599 s
	mu.Unlock()
	send()
	if n := tokens.calls.Load(); n != 2 {
		t.Fatalf("token requests = %d, want 2 (expired token fetched again)", n)
	}
}

func TestSMTPOAuthBearerWhenOnlyThatIsOffered(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{implicit: true, mechs: []string{"OAUTHBEARER"}, user: "alerts@acme.example", token: "tok-ob"})
	cfg := microsoftCfg(f, msTokens(t, "tok-ob"), t)
	cfg.Security = SecuritySSL
	s, err := NewEmail(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if f.usedMech() != "OAUTHBEARER" {
		t.Errorf("mechanism %s", f.usedMech())
	}
}

// The server refuses the token: our sentence, no server text (it echoes the token), and the token is not used again.
func TestSMTPRefusedTokenIsDroppedAndNeverShown(t *testing.T) {
	t.Parallel()
	for _, mech := range []string{"XOAUTH2", "OAUTHBEARER"} {
		t.Run(mech, func(t *testing.T) {
			t.Parallel()
			f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{mech}, user: "alerts@acme.example", token: "the-right-one"})
			tokens := msTokens(t, "stale-token-value")
			s, _ := NewEmail(microsoftCfg(f, tokens, t))
			for range 2 {
				_, err := s.Send(context.Background(), sample)
				var si *SignInError
				var se *StatusError
				if !errors.As(err, &si) || !errors.As(err, &se) || se.Code != 535 || se.Reason != "" || !strings.Contains(si.Msg, "Microsoft 365 refused the sign-in") {
					t.Fatalf("err = %v", err)
				}
				mustNot(t, err.Error(), "stale-token-value", "client.secret")
			}
			if n := tokens.calls.Load(); n != 2 {
				t.Errorf("token requests = %d, want 2: a refused token is dropped", n)
			}
		})
	}
}

// Credentials and tokens never go out before TLS: not with OAuth either, and not even if net/smtp were asked to.
func TestSMTPOAuthNeverSignsInWithoutTLS(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{starttls: false, mechs: []string{"XOAUTH2"}, user: "alerts@acme.example", token: "tok"})
	s, _ := NewEmail(microsoftCfg(f, msTokens(t, "tok"), t))
	_, err := s.Send(context.Background(), sample)
	var si *SignInError
	if !errors.As(err, &si) || !strings.Contains(si.Msg, "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if authPlain, authTLS, from, _, _ := f.snapshot(); authPlain || authTLS || from != "" {
		t.Errorf("session went on: %v %v %q", authPlain, authTLS, from)
	}
	for _, m := range []string{"PLAIN", "LOGIN", "XOAUTH2", "OAUTHBEARER"} {
		a := &saslAuth{mechs: []string{m}, user: "u", pass: "p", token: "t"}
		if _, resp, err := a.Start(&smtp.ServerInfo{Name: "mail", TLS: false, Auth: []string{m}}); !errors.Is(err, errUnencryptedAuth) || resp != nil {
			t.Errorf("%s started without TLS: %q %v", m, resp, err)
		}
	}
	cfg := microsoftCfg(f, msTokens(t, "tok"), t)
	cfg.Security, cfg.Port = SecurityNone, 25
	if _, err := NewEmail(cfg); !isCode(err, "bad_security") {
		t.Errorf("OAuth without encryption: %v", err)
	}
}

func TestSMTPTokenServiceRefusals(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		code       int
		body, want string
		google     bool
	}{
		"ms bad secret":     {401, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. Abc8Q~client"}`, "client ID or the client secret", false},
		"ms unknown client": {400, `{"error":"unauthorized_client","error_description":"AADSTS700016"}`, "does not know this client ID", false},
		"ms odd":            {500, `<html>oops Abc8Q~client</html>`, "HTTP 500", false},
		"google no dwd":     {401, `{"error":"unauthorized_client","error_description":"Client is unauthorized"}`, "Domain-wide delegation", true},
		"google grant":      {400, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`, "key or the mailbox", true},
		"bad code shape":    {400, `{"error":"Has Spaces\r\nX: y"}`, "(HTTP 400)", false},
		"unreadable 200":    {200, `{"access_token":"two words","expires_in":3600}`, "cannot read", false},
		"crlf token":        {200, `{"access_token":"a\r\nRCPT TO:<x@y.zz>","expires_in":3600}`, "cannot read", false},
		"not bearer":        {200, `{"access_token":"abc","token_type":"mac","expires_in":3600}`, "cannot read", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"XOAUTH2"}})
			tokens := startTokenService(t, func(string, url.Values) (int, string) { return c.code, c.body })
			cfg := microsoftCfg(f, tokens, t)
			if c.google {
				cfg.Provider, cfg.TenantID, cfg.ClientID, cfg.Password, cfg.Host = "google-workspace", "", "", secrets.NewValue(googleKeyFile(t)), "smtp.gmail.com"
			}
			s, err := NewEmail(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Send(context.Background(), sample)
			var si *SignInError
			if !errors.As(err, &si) || !strings.Contains(si.Msg, c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			mustNot(t, si.Msg, "AADSTS", "Abc8Q", "Invalid JWT", "\r", "\n")
			f.mu.Lock()
			sessions := f.sessions
			f.mu.Unlock()
			if sessions != 0 {
				t.Errorf("an SMTP session was opened without a token")
			}
		})
	}
}

var (
	testRSAOnce sync.Once
	testRSAKey  *rsa.PrivateKey
)

func googleRSA() *rsa.PrivateKey {
	testRSAOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testRSAKey = k
	})
	return testRSAKey
}

func keyFile(t *testing.T, mod func(map[string]string)) string {
	der, err := x509.MarshalPKCS8PrivateKey(googleRSA())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{ //nolint:gosec // a key made by the test
		"type": "service_account", "project_id": "acme-alerts", "private_key_id": "0123456789abcdef0123456789abcdef01234567",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "vedette@acme-alerts.iam.gserviceaccount.com", "client_id": "112233445566778899001",
		"token_uri": "https://evil.example/token", // never used: the endpoint is fixed
	}
	if mod != nil {
		mod(m)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b)
}

func googleKeyFile(t *testing.T) string { return keyFile(t, nil) }

func TestSMTPGoogleServiceAccountJWT(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"LOGIN", "PLAIN", "XOAUTH2", "OAUTHBEARER"}, user: "alerts@acme.example", token: "ya29.google-token"}) //nolint:gosec // a fake token
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	tokens := startTokenService(t, func(path string, form url.Values) (int, string) {
		if path != "/token" || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			return 400, `{"error":"invalid_request"}`
		}
		parts := strings.Split(form.Get("assertion"), ".")
		if len(parts) != 3 {
			return 400, `{"error":"invalid_grant"}`
		}
		var head map[string]string
		var claims map[string]any
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		_ = json.Unmarshal(hb, &head)
		_ = json.Unmarshal(cb, &claims)
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&googleRSA().PublicKey, crypto.SHA256, sum[:], sig) != nil || head["alg"] != "RS256" || head["kid"] != "0123456789abcdef0123456789abcdef01234567" {
			return 400, `{"error":"invalid_grant"}`
		}
		if claims["iss"] != "vedette@acme-alerts.iam.gserviceaccount.com" || claims["sub"] != "alerts@acme.example" || claims["scope"] != "https://mail.google.com/" ||
			claims["aud"] != "https://oauth2.googleapis.com/token" || claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(time.Hour).Unix()) {
			return 400, `{"error":"invalid_grant"}`
		}
		return 200, `{"access_token":"ya29.google-token","expires_in":3599,"token_type":"Bearer"}`
	})
	cfg := oauthAt(f, emailCfg(f, SecurityStartTLS), "smtp.gmail.com")
	cfg.Provider, cfg.Password, cfg.HTTPClient, cfg.Now = "google-workspace", secrets.NewValue(googleKeyFile(t)), clientTo(t, tokens.srv.URL), func() time.Time { return now }
	s, err := NewEmail(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if f.usedMech() != "XOAUTH2" || tokens.calls.Load() != 1 {
		t.Errorf("mechanism %s, token requests %d", f.usedMech(), tokens.calls.Load())
	}
}

func isCode(err error, code string) bool {
	var ce *ConfigError
	return errors.As(err, &ce) && ce.Code == code
}

func TestSMTPProviderConfigRefusals(t *testing.T) {
	t.Parallel()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	small, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the key the box must refuse
	smallDER, _ := x509.MarshalPKCS8PrivateKey(small)
	bigDER, err := x509.MarshalPKCS8PrivateKey(bigRSA(t))
	if err != nil {
		t.Fatal(err)
	}
	base := EmailConfig{Host: "smtp.office365.com", Port: 587, Security: SecurityStartTLS, Provider: "microsoft365", Username: "alerts@acme.example",
		TenantID: testTenant, ClientID: testClient, Password: secrets.NewValue("Abc8Q~client.secret_value-123"), From: "alerts@acme.example", To: []string{"it@acme.example"}}
	if _, err := NewEmail(base); err != nil {
		t.Fatal(err)
	}
	google := base
	google.Provider, google.Host, google.TenantID, google.ClientID, google.Password = "google-workspace", "smtp.gmail.com", "", "", secrets.NewValue(googleKeyFile(t))
	if _, err := NewEmail(google); err != nil {
		t.Fatal(err)
	}
	gkey := func(mod func(map[string]string)) func(*EmailConfig) {
		return func(c *EmailConfig) { *c = google; c.Password = secrets.NewValue(keyFile(t, mod)) }
	}
	for name, c := range map[string]struct {
		mod  func(*EmailConfig)
		code string
	}{
		"unknown provider":     {func(c *EmailConfig) { c.Provider = "hotmail" }, "bad_provider"},
		"tenant with a path":   {func(c *EmailConfig) { c.TenantID = "acme.onmicrosoft.com/../x" }, "bad_tenant_id"},
		"tenant empty":         {func(c *EmailConfig) { c.TenantID = "" }, "bad_tenant_id"},
		"client not a guid":    {func(c *EmailConfig) { c.ClientID = "my-app" }, "bad_client_id"},
		"mailbox not an email": {func(c *EmailConfig) { c.Username = "alerts" }, "bad_username"},
		"no client secret":     {func(c *EmailConfig) { c.Password = secrets.Value{} }, "secret_required"},
		"secret with a CRLF":   {func(c *EmailConfig) { c.Password = secrets.NewValue("abc\r\ndef") }, "bad_secret"},
		"key not json":         {func(c *EmailConfig) { *c = google; c.Password = secrets.NewValue("-----BEGIN PRIVATE KEY-----") }, "bad_secret"},
		"key wrong type":       {gkey(func(m map[string]string) { m["type"] = "authorized_user" }), "bad_secret"},
		"key no email":         {gkey(func(m map[string]string) { delete(m, "client_email") }), "bad_secret"},
		"key garbled pem":      {gkey(func(m map[string]string) { m["private_key"] = strings.Replace(m["private_key"], "M", "%", 3) }), "bad_secret"},
		"key ec": {gkey(func(m map[string]string) {
			m["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))
		}), "bad_secret"},
		"key rsa 1024": {gkey(func(m map[string]string) {
			m["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: smallDER}))
		}), "bad_secret"},
		"key odd kid": {gkey(func(m map[string]string) { m["private_key_id"] = "\"}\r\n" }), "bad_secret"},
		"key too big": {gkey(func(m map[string]string) { m["padding"] = strings.Repeat("x", maxKeyFile) }), "bad_secret"},
		"no key":      {func(c *EmailConfig) { *c = google; c.Password = secrets.Value{} }, "secret_required"},
		"key rsa over 4096": {gkey(func(m map[string]string) {
			m["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bigDER}))
		}), "bad_secret"},
		"ms token elsewhere": {func(c *EmailConfig) { c.Host = "smtp.acme.example" }, "bad_host"},
		"google elsewhere":   {func(c *EmailConfig) { *c = google; c.Host = "smtp.googlemail.evil.example" }, "bad_host"},
		"password with a NUL": {func(c *EmailConfig) {
			c.Provider, c.Host, c.Password = "custom", "smtp.acme.example", secrets.NewValue("pass\x00word")
		}, "bad_secret"},
		"password with a LF": {func(c *EmailConfig) {
			c.Provider, c.Host, c.Password = "gmail", "smtp.gmail.com", secrets.NewValue("abcd\nefgh")
		}, "bad_secret"},
		"username with a NUL": {func(c *EmailConfig) {
			c.Provider, c.Host, c.Username = "custom", "smtp.acme.example", "alerts\x00@acme.example"
		}, "bad_username"},
	} {
		cfg := base
		c.mod(&cfg)
		_, err := NewEmail(cfg)
		if !isCode(err, c.code) {
			t.Errorf("%s: err = %v, want %s", name, err, c.code)
		}
		mustNot(t, errString(err), "Abc8Q", "PRIVATE KEY")
	}
}

// bigRSA is a valid 4112-bit RSA key built from two fixed primes: generating one takes seconds, and a PEM private key does not belong
// in the repository even for a test.
func bigRSA(t *testing.T) *rsa.PrivateKey {
	p, _ := new(big.Int).SetString("c6997eee05fbd604ae274f1ec53ef1a4a6aba9e90a514cf43b6aa4e142b88e76a6cb9b4d42dcf6a649af6b64b316162ac3bd98c453cb7266316a0a2da6fd16508a1e9dd6860c6bbfc2046d8825b105f6ed9ee92d42ec837cd54ed9bf7fe3ee6c8a737a59e3de477f22d7fbacdb56bd7c8d14ad0962bebdaf118fa675084136f0d039af3610bc15f899b2dc71f21ec6570aaabcefeeceaa9525fb26c38a71d1c9ef26fc0f4c406585ec16df4996b8c2efb5a0f1c4e64093fd233ca560cb2ad7ddbbcc27fbafd455056f2ba88ddf97c1da1e090c5c4795bcfb3ddc53a0beb146737cf35aab6cc5f7f227e94150dc26c8e53d4bce7810118aa31d0874139c01922ef7", 16)
	q, _ := new(big.Int).SetString("c7514e69db962e555d1a769f075e74d8e261fb433f8e9ec286898f922d0c461e3b7ae8d87fc6d9f24886b25f289e3e2f1e1ae036dde2deea4c18a6c57df5f7985d4c9a39291a304fa8c5746a253b8f4c7fd30d55e1b0aa8496f63629ce1be1ad8a77e3fcca7c9e6d03b269659fbb5bf1568bae67a659f4814e252f424dd2dd99a34b8947f2241df2063ab1ac770c616f3742ba25ff9b4587e763b7ae46150e8492097154a40854b06d9312eb0bcb2908d8f4e6cd8e3eab64222908f015132c5583b473ca21a58d01263ebe5e0cf9a9cd89aabbf38154ab6d26ab846b9064e194fa07f9a8b31162e29668e4987edf8eddd7245d5b9025ed088cdbb4abd60c4b6fb1", 16)
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537}, D: new(big.Int).ModInverse(big.NewInt(65537), phi), Primes: []*big.Int{p, q}}
	k.Precompute()
	if err := k.Validate(); err != nil || k.N.BitLen() <= 4096 {
		t.Fatalf("test key: %v, %d bits", err, k.N.BitLen())
	}
	return k
}

// A server that keeps challenging after the OAuth error challenge gets no third answer: the client gives up, nothing is sent.
func TestSMTPOAuthEndlessChallengesStop(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"XOAUTH2"}, user: "alerts@acme.example", token: "the-right-one", endless: true})
	s, _ := NewEmail(microsoftCfg(f, msTokens(t, "another-token"), t))
	_, err := s.Send(context.Background(), sample)
	if err == nil {
		t.Fatal("sent after an endless challenge")
	}
	mustNot(t, err.Error(), "another-token")
	if _, _, from, _, _ := f.snapshot(); from != "" {
		t.Errorf("MAIL FROM after a failed sign-in: %q", from)
	}
}

// Many senders at once ask for one token: one request, every sender gets it; Clear and a refused token's drop run alongside
// (the daily -race run checks the locking).
func TestSMTPTokenCacheIsSharedAndSingleFlight(t *testing.T) {
	t.Parallel()
	tokens := msTokens(t, "shared-token")
	f := startFakeSMTP(t, &fakeSMTP{starttls: true})
	cache := NewTokenCache()
	cfg := microsoftCfg(f, tokens, t)
	cfg.Tokens = cache
	snd, err := NewEmail(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := snd.(*emailSender)
	var wg sync.WaitGroup
	got := make([]string, 16)
	for i := range got {
		wg.Go(func() {
			tok, _, err := e.token(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			got[i] = tok.Reveal()
		})
	}
	wg.Wait()
	for _, g := range got {
		if g != "shared-token" {
			t.Fatalf("tokens %v", got)
		}
	}
	if n := tokens.calls.Load(); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
	for range 8 {
		wg.Go(func() { _, _, _ = e.token(context.Background()) })
		wg.Go(cache.Clear)
		wg.Go(func() { cache.drop(e.tokenKey()) })
	}
	wg.Wait()
}

// A fetch that started before Clear (the channel was saved meanwhile) does not cache the token it gets.
func TestTokenCacheClearDuringAFetch(t *testing.T) {
	t.Parallel()
	c := NewTokenCache()
	var k [32]byte
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	fetches := 0
	fetch := func(clear bool) func() (secrets.Value, time.Duration, error) {
		return func() (secrets.Value, time.Duration, error) {
			fetches++
			if clear {
				c.Clear()
			}
			return secrets.NewValue("tok"), time.Hour, nil
		}
	}
	for _, clear := range []bool{true, false, false} {
		if _, err := c.once(context.Background(), k, now, fetch(clear)); err != nil {
			t.Fatal(err)
		}
	}
	if fetches != 2 {
		t.Fatalf("fetches = %d, want 2: the token fetched across a Clear is not kept, the next one is", fetches)
	}
}

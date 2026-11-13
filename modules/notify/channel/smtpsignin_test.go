package channel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// idToken is an unsigned id_token with the given claims (the box reads it straight from the token endpoint).
func idToken(claims map[string]string) string {
	b, _ := json.Marshal(claims)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestMicrosoftDeviceCodeStates(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	answers := []struct {
		code int
		body string
	}{
		{400, `{"error":"authorization_pending"}`},
		{400, `{"error":"slow_down"}`},
		{400, `{"error":"authorization_declined"}`},
		{400, `{"error":"expired_token"}`},
		{400, `{"error":"invalid_client","error_description":"AADSTS7000218: client_assertion or client_secret required"}`},
		{200, `{"token_type":"Bearer","expires_in":3599,"access_token":"at-1","refresh_token":"rt-1","id_token":"` + idToken(map[string]string{"preferred_username": "Alerts@Acme.example"}) + `"}`},
		{200, `{"access_token":"at-1","expires_in":3599,"id_token":"x.y.z"}`}, // no refresh token
	}
	svc := startTokenService(t, func(path string, form url.Values) (int, string) {
		switch path {
		case "/organizations/oauth2/v2.0/devicecode":
			if form.Get("client_id") != testClient || form.Get("scope") != "https://outlook.office.com/SMTP.Send offline_access openid profile email" {
				return 400, `{"error":"invalid_scope"}`
			}
			return 200, `{"device_code":"dc-123","user_code":"ABCD-EFGH","verification_uri":"https://evil.example/devicelogin","expires_in":900,"interval":5,"message":"go"}`
		case "/organizations/oauth2/v2.0/token":
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || form.Get("device_code") != "dc-123" || form.Get("client_id") != testClient {
				return 400, `{"error":"invalid_request"}`
			}
			mu.Lock()
			defer mu.Unlock()
			a := answers[0]
			answers = answers[1:]
			return a.code, a.body
		}
		return 404, `{}`
	})
	hc := clientTo(t, svc.srv.URL)
	if _, err := StartMicrosoftDevice(context.Background(), hc, "../x", testClient); !isCode(err, "bad_tenant_id") {
		t.Fatalf("tenant: %v", err)
	}
	if _, err := StartMicrosoftDevice(context.Background(), hc, "organizations", "app"); !isCode(err, "bad_client_id") {
		t.Fatalf("client: %v", err)
	}
	d, err := StartMicrosoftDevice(context.Background(), hc, "organizations", testClient)
	if err != nil {
		t.Fatal(err)
	}
	if d.UserCode != "ABCD-EFGH" || d.VerificationURI != "https://microsoft.com/devicelogin" || d.Interval != 5*time.Second || d.ExpiresIn != 15*time.Minute {
		t.Fatalf("device %+v", d) // a verification page on another host is replaced by Microsoft's own
	}
	poll := func() (string, UserSignIn, error) { return d.Poll(context.Background(), hc) }
	for _, want := range []string{SigninWaiting, SigninWaiting, SigninDeclined, SigninExpired} {
		if st, _, err := poll(); st != want || err != nil {
			t.Fatalf("state %q %v, want %s", st, err, want)
		}
	}
	if d.Interval != 10*time.Second {
		t.Errorf("slow_down: interval %v, want 10s", d.Interval)
	}
	_, _, err = poll()
	var si *SignInError
	if !errors.As(err, &si) || !strings.Contains(si.Msg, "Allow public client flows") || strings.Contains(si.Msg, "AADSTS") {
		t.Fatalf("invalid_client: %v", err)
	}
	st, in, err := poll()
	if g, ok := parseGrant(in.Secret.Reveal(), false); err != nil || st != SigninSignedIn || in.Mailbox != "alerts@acme.example" || !ok || g.RefreshToken != "rt-1" {
		t.Fatalf("signed in: %q %+v %v", st, in, err)
	}
	if _, _, err := poll(); !errors.As(err, &si) || !strings.Contains(si.Msg, "no refresh token") {
		t.Fatalf("no refresh token: %v", err)
	}
}

// A refresh that returns a new refresh token keeps it: in memory for the next refresh and through SaveSecret for the channel.
func TestMicrosoftUserRefreshTokenRotates(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := []string{}
	svc := startTokenService(t, func(path string, form url.Values) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		if path != "/organizations/oauth2/v2.0/token" || form.Get("grant_type") != "refresh_token" || form.Get("scope") != microsoftUserScope {
			return 400, `{"error":"invalid_request"}`
		}
		rt := form.Get("refresh_token")
		seen = append(seen, rt)
		switch rt {
		case "rt-1":
			return 200, `{"access_token":"at-1","expires_in":3599,"refresh_token":"rt-2"}`
		case "rt-2":
			return 200, `{"access_token":"at-2","expires_in":3599,"refresh_token":"rt-3"}`
		}
		return 400, `{"error":"invalid_grant","error_description":"AADSTS70008 expired"}`
	})
	f := startFakeSMTP(t, &fakeSMTP{starttls: true, mechs: []string{"XOAUTH2"}, user: "alerts@acme.example", token: "at-1"})
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	var saved []string
	cfg := oauthAt(f, emailCfg(f, SecurityStartTLS), "smtp.office365.com")
	cfg.Provider, cfg.TenantID, cfg.ClientID, cfg.Password, cfg.HTTPClient = "microsoft365-user", "organizations", testClient, secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"rt-1"}`), clientTo(t, svc.srv.URL)
	cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	cfg.SaveSecret = func(_ context.Context, old, next secrets.Value) error {
		saved = append(saved, old.Reveal()+" -> "+next.Reveal())
		return nil
	}
	s, err := NewEmail(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(time.Hour) // the access token expired: the next send refreshes with the rotated token
	mu.Unlock()
	f.mu.Lock()
	f.token = "at-2"
	f.mu.Unlock()
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "rt-1,rt-2" || len(saved) != 2 || saved[0] != `{"id":"0123456789abcdef0123456789abcdef","refresh_token":"rt-1"} -> {"id":"0123456789abcdef0123456789abcdef","refresh_token":"rt-2"}` {
		t.Fatalf("refreshes %v, saved %v", seen, saved)
	}
	// A refresh token Microsoft no longer takes: our sentence, nothing of Microsoft's text, no SMTP session.
	cfg.Password, cfg.Tokens = secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"rt-old"}`), NewTokenCache()
	s2, _ := NewEmail(cfg)
	_, err = s2.Send(context.Background(), sample)
	var si *SignInError
	if !errors.As(err, &si) || !strings.Contains(si.Msg, "sign in with Microsoft again") || strings.Contains(si.Msg, "AADSTS") {
		t.Fatalf("invalid_grant: %v", err)
	}
}

const testGoogleClient = "123456789012-abcdefghijklmnop0123456789abcdef.apps.googleusercontent.com"

func TestGoogleConsentPasteBack(t *testing.T) {
	t.Parallel()
	if _, err := StartGoogleConsent("not-a-client", "GOCSPX-secret"); !isCode(err, "bad_client_id") {
		t.Fatalf("client: %v", err)
	}
	if _, err := StartGoogleConsent(testGoogleClient, ""); !isCode(err, "bad_secret") {
		t.Fatalf("secret: %v", err)
	}
	g, err := StartGoogleConsent(testGoogleClient, "GOCSPX-secret_1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(g.URL)
	q := u.Query()
	if u.Host != "accounts.google.com" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != g.redirect || !strings.HasPrefix(g.redirect, "http://127.0.0.1:") ||
		q.Get("state") != g.state || q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || q.Get("scope") != "https://mail.google.com/ openid email" {
		t.Fatalf("consent URL %s", g.URL)
	}
	sum := sha256.Sum256([]byte(g.verifier.Reveal()))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("code_challenge is not S256 of the verifier")
	}
	ok := g.redirect + "/?state=" + g.state + "&code=4/0AeanS0Zabc&scope=https://mail.google.com/"
	port := strings.TrimPrefix(g.redirect, "http://127.0.0.1:")
	for name, c := range map[string]struct{ pasted, code string }{
		"not loopback":     {strings.Replace(ok, "127.0.0.1", "evil.example", 1), "bad_url"},
		"https":            {strings.Replace(ok, "http://", "https://", 1), "bad_url"},
		"another port":     {strings.Replace(ok, ":"+port, ":1", 1), "bad_url"},
		"userinfo":         {strings.Replace(ok, "http://", "http://a@", 1), "bad_url"},
		"a path":           {strings.Replace(ok, "/?", "/x?", 1), "bad_url"},
		"not a URL":        {"4/0AeanS0Zabc", "bad_url"},
		"too long":         {ok + strings.Repeat("a", maxPasted), "bad_url"},
		"state mismatch":   {strings.Replace(ok, g.state, strings.Repeat("A", 43), 1), "bad_state"},
		"no state":         {g.redirect + "/?code=4/0AeanS0Zabc", "bad_state"},
		"missing code":     {g.redirect + "/?state=" + g.state, "bad_url"},
		"code with spaces": {g.redirect + "/?state=" + g.state + "&code=a%20b", "bad_url"},
		"declined":         {g.redirect + "/?state=" + g.state + "&error=access_denied", "declined"},
	} {
		if _, err := g.pastedCode(c.pasted); !isCode(err, c.code) {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	if code, err := g.pastedCode("  " + strings.Replace(ok, "127.0.0.1", "localhost", 1) + "\n"); err != nil || code != "4/0AeanS0Zabc" {
		t.Errorf("localhost: %q %v", code, err)
	}

	svc := startTokenService(t, func(path string, form url.Values) (int, string) {
		if path != "/token" || form.Get("grant_type") != "authorization_code" || form.Get("code") != "4/0AeanS0Zabc" || form.Get("redirect_uri") != g.redirect ||
			form.Get("client_id") != testGoogleClient || form.Get("client_secret") != "GOCSPX-secret_1" || form.Get("code_verifier") != g.verifier.Reveal() {
			return 400, `{"error":"invalid_grant"}`
		}
		return 200, `{"access_token":"ya29.a","expires_in":3599,"refresh_token":"1//0g-refresh","id_token":"` + idToken(map[string]string{"email": "me@gmail.com"}) + `"}`
	})
	in, err := g.Finish(context.Background(), clientTo(t, svc.srv.URL), ok)
	if g, ok := parseGrant(in.Secret.Reveal(), true); err != nil || in.Mailbox != "me@gmail.com" || !ok || g.RefreshToken != "1//0g-refresh" || g.ClientSecret != "GOCSPX-secret_1" {
		t.Fatalf("finish: %+v %v", in, err)
	}
	// the code was used: Google refuses it again, with our sentence
	bad := strings.Replace(ok, "4/0AeanS0Zabc", "4/used", 1)
	var si *SignInError
	if _, err := g.Finish(context.Background(), clientTo(t, svc.srv.URL), bad); !errors.As(err, &si) || !strings.Contains(si.Msg, "used already") {
		t.Fatalf("used code: %v", err)
	}
}

func TestUserGrantConfig(t *testing.T) {
	t.Parallel()
	base := EmailConfig{Host: "smtp.gmail.com", Port: 587, Security: SecurityStartTLS, Provider: "gmail-oauth", Username: "me@gmail.com", ClientID: testGoogleClient,
		Password: secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"1//0g","client_secret":"GOCSPX-x"}`), From: "me@gmail.com", To: []string{"it@acme.example"}}
	if _, err := NewEmail(base); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		mod  func(*EmailConfig)
		code string
	}{
		"elsewhere":     {func(c *EmailConfig) { c.Host = "smtp.acme.example" }, "bad_host"},
		"not signed in": {func(c *EmailConfig) { c.Password = secrets.Value{} }, "secret_required"},
		"no mailbox":    {func(c *EmailConfig) { c.Username = "" }, "bad_username"},
		"grant without secret": {func(c *EmailConfig) {
			c.Password = secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"1//0g"}`)
		}, "bad_secret"},
		"grant without id": {func(c *EmailConfig) {
			c.Password = secrets.NewValue(`{"refresh_token":"1//0g","client_secret":"GOCSPX-x"}`)
		}, "bad_secret"},
		"grant crlf": {func(c *EmailConfig) {
			c.Password = secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"a\r\nb","client_secret":"x"}`)
		}, "bad_secret"},
		"client id": {func(c *EmailConfig) { c.ClientID = "x.apps.googleusercontent.com" }, "bad_client_id"},
		"outlook elsewhere": {func(c *EmailConfig) {
			c.Provider, c.Host, c.TenantID, c.ClientID, c.Password = "outlook", "smtp.office365.com", "consumers", testClient, secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"m"}`)
		}, "bad_host"},
	} {
		cfg := base
		c.mod(&cfg)
		if _, err := NewEmail(cfg); !isCode(err, c.code) {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	ol := base
	ol.Provider, ol.Host, ol.TenantID, ol.ClientID, ol.Password = "outlook", "smtp-mail.outlook.com", "consumers", testClient, secrets.NewValue(`{"id":"0123456789abcdef0123456789abcdef","refresh_token":"m"}`)
	if _, err := NewEmail(ol); err != nil {
		t.Fatalf("outlook: %v", err)
	}
}

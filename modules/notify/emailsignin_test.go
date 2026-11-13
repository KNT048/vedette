package notify_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// roundTrip answers the token services in place of Microsoft and Google.
type roundTrip func(*http.Request, url.Values) (int, string)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(b))
	code, body := f(r, form)
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": {"application/json"}}, Request: r}, nil
}

func unsignedIDToken(claims map[string]string) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

const msClient = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"

// D-480: a device sign-in is polled at Microsoft's interval only, belongs to the admin who started it, and SaveChannel takes its
// refresh token as the secret and its mailbox as the username, once. A rotated refresh token is saved back.
func TestEmailDeviceSigninThenSaveThenRotate(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	rt := roundTrip(func(r *http.Request, form url.Values) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/organizations/oauth2/v2.0/devicecode":
			return 200, `{"device_code":"dc-1","user_code":"QWER-TYUI","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`
		case form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code":
			if polls++; polls == 1 {
				return 400, `{"error":"authorization_pending"}`
			}
			return 200, `{"access_token":"at-0","expires_in":3599,"refresh_token":"rt-1","id_token":"` + unsignedIDToken(map[string]string{"preferred_username": "alerts@acme.example"}) + `"}`
		}
		return 400, `{"error":"invalid_request"}`
	})
	e := newEnv(t, func(c *notify.Config) { c.HTTPClient = &http.Client{Transport: rt} })
	const admin = "admin@acme.example"
	s, err := e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient})
	if err != nil {
		t.Fatal(err)
	}
	if s.Flow != "device" || s.UserCode != "QWER-TYUI" || s.Status != "waiting" || s.Interval != 5 {
		t.Fatalf("start %+v", s)
	}
	check := func(who string) (notify.EmailSignin, error) { return e.svc.CheckEmailSignin(e.ctx(), who, s.ID, "") }
	if _, err := check("other@acme.example"); err == nil {
		t.Fatal("another admin read the sign-in")
	}
	if v, _ := check(admin); v.Status != "waiting" || polls != 0 {
		t.Fatalf("polled before the interval: %+v, %d", v, polls)
	}
	e.clock.Add(5 * time.Second)
	if v, _ := check(admin); v.Status != "waiting" || polls != 1 {
		t.Fatalf("pending: %+v", v)
	}
	e.clock.Add(5 * time.Second)
	v, err := check(admin)
	if err != nil || v.Status != "signed_in" || v.Mailbox != "alerts@acme.example" {
		t.Fatalf("signed in: %+v %v", v, err)
	}
	f := map[string]string{"provider": "microsoft365-user", "host": "smtp.office365.com", "port": "587", "security": "starttls", "tenant_id": "organizations",
		"client_id": msClient, "username": "someone@else.example", "from": "alerts@acme.example", "to": "it@acme.example"}
	in := notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Fields: f, Signin: s.ID}
	if _, err := e.svc.SaveChannel(e.ctx(), "other@acme.example", channel.Email, in); err == nil {
		t.Fatal("another admin saved the sign-in")
	}
	c, err := e.svc.SaveChannel(e.ctx(), admin, channel.Email, in)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fields["username"] != "alerts@acme.example" {
		t.Fatalf("the mailbox is the account that signed in: %v", c.Fields)
	}
	_, err = e.svc.SaveChannel(e.ctx(), admin, channel.Email, in) // used once
	wantCode(t, err, 400, "secret_required")

	// A refresh token Microsoft rotated is saved back, unless the channel was saved again since (the newer save wins). The sending
	// side (channel.EmailConfig.SaveSecret) is TestMicrosoftUserRefreshTokenRotates.
	rt1, rt2 := `{"refresh_token":"rt-1"}`, `{"refresh_token":"rt-2"}`
	if got := e.svc.EmailSecretForTest(e.ctx()); got != rt1 {
		t.Fatalf("saved secret %q", got)
	}
	e.svc.RotateEmailSecretForTest(rt1, rt2)
	if got := e.svc.EmailSecretForTest(e.ctx()); got != rt2 {
		t.Fatalf("after rotation %q", got)
	}
	e.svc.RotateEmailSecretForTest(rt1, `{"refresh_token":"rt-stale"}`)
	if got := e.svc.EmailSecretForTest(e.ctx()); got != rt2 {
		t.Fatalf("a rotation from an older secret overwrote %q", got)
	}
}

func TestEmailGoogleSigninRefusesAStrangePaste(t *testing.T) {
	e := newEnv(t)
	const admin = "admin@acme.example"
	s, err := e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "gmail-oauth",
		ClientID: "123456789012-abcdefghijklmnop0123456789abcdef.apps.googleusercontent.com", ClientSecret: "GOCSPX-1"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(s.ConsentURL)
	if s.Flow != "paste" || u.Host != "accounts.google.com" {
		t.Fatalf("start %+v", s)
	}
	_, err = e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, "https://evil.example/?code=x&state="+u.Query().Get("state"))
	wantCode(t, err, 400, "bad_url")
	_, err = e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, u.Query().Get("redirect_uri")+"/?code=x&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	wantCode(t, err, 400, "bad_state")
	v, err := e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, u.Query().Get("redirect_uri")+"/?error=access_denied&state="+u.Query().Get("state"))
	if err != nil || v.Status != "declined" {
		t.Fatalf("declined: %+v %v", v, err)
	}
	_, err = e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "gmail", ClientID: "x"})
	wantCode(t, err, 400, "bad_provider")
}

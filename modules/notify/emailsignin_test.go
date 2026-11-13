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

	// The saved grant is the sign-in's refresh token with the sign-in's id; a rotation of that sign-in is saved back (the sending side
	// is TestMicrosoftUserRefreshTokenRotates; the order of rotations, TestEmailRotationFollowsTheSignInNotTheToken).
	var g struct {
		ID           string `json:"id"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(e.svc.EmailSecretForTest(e.ctx())), &g); err != nil || len(g.ID) != 32 || g.RefreshToken != "rt-1" {
		t.Fatalf("saved grant %+v %v", g, err)
	}
	e.svc.RotateEmailSecretForTest(grantJSON(g.ID, "rt-1"), grantJSON(g.ID, "rt-2"))
	if got := e.svc.EmailSecretForTest(e.ctx()); got != grantJSON(g.ID, "rt-2") {
		t.Fatalf("after rotation %q", got)
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

func grantJSON(id, rt string) string { return `{"id":"` + id + `","refresh_token":"` + rt + `"}` }

// Round-2 review: a per-address sender (two-step code, approval) rotates the token between two rotations of the cached sender.
// The saved grant follows the newest rotation of the same sign-in (same grant id) whichever token each sender held; a grant of
// another sign-in is left alone and the cached sender is dropped so the next send loads the saved one.
func TestEmailRotationFollowsTheSignInNotTheToken(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.HTTPClient = &http.Client{Transport: roundTrip(func(*http.Request, url.Values) (int, string) { return 500, `{}` })}
	})
	const g1, g2 = "11111111111111111111111111111111", "22222222222222222222222222222222"
	f := map[string]string{"provider": "microsoft365-user", "host": "smtp.office365.com", "port": "587", "security": "starttls", "tenant_id": "organizations",
		"client_id": msClient, "username": "alerts@acme.example", "from": "alerts@acme.example", "to": "it@acme.example"}
	save := func(secret string) {
		t.Helper()
		if _, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Fields: f, Secret: secret}); err != nil {
			t.Fatal(err)
		}
	}
	save(grantJSON(g1, "rt-2"))
	e.svc.RotateEmailSecretForTest(grantJSON(g1, "rt-2"), grantJSON(g1, "rt-3")) // a code send rotates rt-2 → rt-3
	e.svc.RotateEmailSecretForTest(grantJSON(g1, "rt-2"), grantJSON(g1, "rt-4")) // the cached sender, still on rt-2, rotates → rt-4
	if got := e.svc.EmailSecretForTest(e.ctx()); got != grantJSON(g1, "rt-4") {
		t.Fatalf("the newest rotation of the sign-in was not saved: %q", got)
	}
	// Signed in again (another grant): an older sender's rotation does not overwrite it, and the cached sender is dropped.
	save(grantJSON(g2, "rt-9"))
	if err := e.svc.CacheEmailSenderForTest(e.ctx()); err != nil || !e.svc.EmailSenderCachedForTest() {
		t.Fatalf("cache: %v", err)
	}
	e.svc.RotateEmailSecretForTest(grantJSON(g1, "rt-4"), grantJSON(g1, "rt-5"))
	if got := e.svc.EmailSecretForTest(e.ctx()); got != grantJSON(g2, "rt-9") {
		t.Fatalf("another sign-in's rotation overwrote the saved one: %q", got)
	}
	if e.svc.EmailSenderCachedForTest() {
		t.Fatal("the cached sender stayed after its sign-in was replaced")
	}
}

// A device sign-in that signed in, ready to save: the start, two checks past the interval.
func signedInDevice(t *testing.T, e *env, admin string) notify.EmailSignin {
	t.Helper()
	s, err := e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Add(5 * time.Second)
	v, err := e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, "")
	if err != nil || v.Status != "signed_in" {
		t.Fatalf("sign-in: %+v %v", v, err)
	}
	return v
}

func deviceThatSignsIn(fail func() bool) roundTrip {
	return func(r *http.Request, form url.Values) (int, string) {
		if r.URL.Path == "/organizations/oauth2/v2.0/devicecode" {
			return 200, `{"device_code":"dc-1","user_code":"QWER-TYUI","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`
		}
		if fail != nil && fail() {
			return 500, `{"error":"temporarily_unavailable"}`
		}
		return 200, `{"access_token":"at-0","expires_in":3599,"refresh_token":"rt-1","id_token":"` + unsignedIDToken(map[string]string{"preferred_username": "alerts@acme.example"}) + `"}`
	}
}

// Round-2 review: a sign-in is taken by one save only, even when two saves run at the same moment; a failed save gives it back.
func TestEmailSigninIsTakenByOneSaveOnly(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.HTTPClient = &http.Client{Transport: deviceThatSignsIn(nil)} })
	const admin = "admin@acme.example"
	v := signedInDevice(t, e, admin)
	f := map[string]string{"provider": "microsoft365-user", "host": "smtp.office365.com", "port": "587", "security": "starttls", "tenant_id": "organizations",
		"client_id": msClient, "from": "alerts@acme.example", "to": "it@acme.example"}
	in := notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Signin: v.ID}
	// a save that fails after taking the sign-in (a bad recipient) gives it back
	bad := map[string]string{}
	for k, x := range f {
		bad[k] = x
	}
	bad["to"] = "nope"
	in.Fields = bad
	_, err := e.svc.SaveChannel(e.ctx(), admin, channel.Email, in)
	wantCode(t, err, 400, "bad_to")
	in.Fields = f
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() {
			ff := map[string]string{}
			for k, x := range f {
				ff[k] = x
			}
			c := in
			c.Fields = ff
			_, errs[i] = e.svc.SaveChannel(e.ctx(), admin, channel.Email, c)
		})
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two saves of one sign-in: %v, %v", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil {
			wantCode(t, err, 400, "secret_required")
		}
	}
}

// Round-2 review: a check that fails still waits the interval before asking Microsoft again; starts are limited per admin; a
// sign-in that ended is dropped (and its refresh token with it).
func TestEmailSigninPacingAndExpiry(t *testing.T) {
	var mu sync.Mutex
	failing, polls := true, 0
	e := newEnv(t, func(c *notify.Config) {
		c.HTTPClient = &http.Client{Transport: deviceThatSignsIn(func() bool { mu.Lock(); defer mu.Unlock(); polls++; return failing })}
	})
	const admin = "admin@acme.example"
	s, err := e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient})
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Add(5 * time.Second)
	_, err = e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, "")
	wantCode(t, err, 400, "signin_refused")
	if _, err := e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, ""); err != nil || polls != 1 {
		t.Fatalf("asked Microsoft again before the interval after a failure: %d polls, %v", polls, err)
	}
	mu.Lock()
	failing = false
	mu.Unlock()
	e.clock.Add(5 * time.Second)
	if v, err := e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, ""); err != nil || v.Status != "signed_in" {
		t.Fatalf("after the interval: %+v %v", v, err)
	}
	// ended sign-ins go, refresh token and all
	e.clock.Add(16*time.Minute + time.Minute)
	_, err = e.svc.CheckEmailSignin(e.ctx(), admin, s.ID, "")
	wantCode(t, err, 404, "not_found")
	// five starts per admin in ten minutes (the first start is older than that by now), then 429; another admin is not held back
	for range 5 {
		if _, err := e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient})
	wantCode(t, err, 429, "rate_limited")
	if _, err := e.svc.StartEmailSignin(e.ctx(), "other@acme.example", notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient}); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(10 * time.Minute)
	if _, err := e.svc.StartEmailSignin(e.ctx(), admin, notify.EmailSigninStart{Provider: "microsoft365-user", TenantID: "organizations", ClientID: msClient}); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

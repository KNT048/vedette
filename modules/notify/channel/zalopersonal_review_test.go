package channel

// Regression tests for the findings of the independent security review of the
// Zalo personal adapter (service host, sign-in storms, duplicate sends, scrubbing).

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// clockSender gives the sender a clock the test moves by hand.
type zpClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *zpClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *zpClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClockedSender(t *testing.T, f *zaloFake) (*zaloPersonalSender, *zpClock) {
	t.Helper()
	s := newZPSender(t, f, nil)
	c := &zpClock{t: time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)}
	s.now = c.now
	return s, c
}

// M1: a service address that is not a name below chat.zalo.me never gets cookies.
func TestContract_D46_ZaloPersonalServiceHostIsStrict(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://[::1%25.zalo.me]", "https://[::ffff:c0a8:101%2525.zalo.me]", "https://[::ffff:7f00:1%25.zalo.me]",
		"https://[::ffff:c0a8:101%25.zalo.me]:443", "https://[fe80::1%25.zalo.me]/", "https://x.chat.zalo.me.",
		"https://zalo.me.evil.com", "https://evilzalo.me", "https://evil.com%2F.chat.zalo.me", "https://evil.com%2e.chat.zalo.me",
		"https://evil.com\\.chat.zalo.me", "https://a%40evil.com.chat.zalo.me", "https://ẹvil.chat.zalo.me", "https://evil．chat.zalo.me",
		"https://zalo.me", "https://id.zalo.me", "https://a.zalo.me", "https://chat.zalo.me", "https://a.chat.zalo.me:", "https://a.chat.zalo.me:0443",
		"https://a.chat.zalo.me%3A8443", "https://a.chat.zalo.me?", "https://a.chat.zalo.me#", "https://127.0.0.1", "https://1.2.3.4",
		"https://[::1]", "https://a.chat.zalo.me:8443", "https://a.b.chat.zalo.me@evil.example", "http://a.chat.zalo.me",
	} {
		if base, err := zaloServiceBase(raw); err == nil {
			t.Errorf("%q was accepted as %q", raw, base)
		}
	}
	for raw, want := range map[string]string{
		"https://tt-chat1-wpa.chat.zalo.me":  "https://tt-chat1-wpa.chat.zalo.me",
		"https://TT-Chat1-WPA.Chat.Zalo.ME/": "https://tt-chat1-wpa.chat.zalo.me",
		"https://a.b.chat.zalo.me:443":       "https://a.b.chat.zalo.me",
		"https://wpa.chat.zalo.me":           "https://wpa.chat.zalo.me",
	} {
		if base, err := zaloServiceBase(raw); err != nil || base != want {
			t.Errorf("%q -> %q, %v; want %q", raw, base, err, want)
		}
	}
}

func TestContract_D46_ZaloPersonalCallChecksTheHostBeforeCookies(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var dialed []string
	tr := &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return nil, errors.New("no network in tests")
	}}
	s, err := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	z := s.(*zaloPersonalSender)
	for _, raw := range []string{
		"https://[::ffff:7f00:1%2525.zalo.me]/api", "https://[::ffff:7f00:1%25.zalo.me]/api", "https://zalo.me/api", "https://id.zalo.me/api",
		"http://wpa.chat.zalo.me/api", "https://wpa.chat.zalo.me.evil.example/api", "https://127.0.0.1/api", "https://user@wpa.chat.zalo.me/api",
	} {
		if _, err := z.call(context.Background(), http.MethodPost, raw, strings.NewReader("x")); err == nil {
			t.Errorf("%q: no error", raw)
		}
	}
	mu.Lock()
	n := len(dialed)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("dialed %v for refused addresses", dialed)
	}
	_, _ = z.call(context.Background(), http.MethodGet, "https://wpa.chat.zalo.me/api", nil)
	if mu.Lock(); len(dialed) != 1 || dialed[0] != "wpa.chat.zalo.me:443" {
		t.Errorf("an allowed host was not dialled: %v", dialed)
	}
	mu.Unlock()
}

// M2: a refused sign-in is not repeated for every alert (D-46: the account can be locked).
func TestContract_D46_ZaloPersonalSignInsAreRationed(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	f.loginErr = -1357
	s, clock := newClockedSender(t, f)
	send := func() error { _, err := s.Send(context.Background(), sample); return err }

	var be *BackoffError
	if err := send(); err == nil || errors.As(err, &be) {
		t.Fatalf("first send: %v", err)
	}
	for i := 0; i < 20; i++ {
		if err := send(); !errors.As(err, &be) || be.Channel != ZaloPersonal || !be.Until.After(clock.now()) {
			t.Fatalf("send %d during the pause: %v", i, err)
		}
	}
	if f.logins != 1 || f.sends != 0 {
		t.Fatalf("20 sends: %d sign-ins, %d posts", f.logins, f.sends)
	}
	// The pause doubles from 1 minute to the 1 hour cap, and ends exactly on time.
	want := []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour, time.Hour}
	logins := f.logins
	for i, w := range want {
		if err := send(); !errors.As(err, &be) { // the BackoffError of the running pause
			t.Fatalf("pause %d: %v", i, err)
		}
		until := be.Until
		clock.add(until.Sub(clock.now()) - time.Second)
		if err := send(); !errors.As(err, &be) || f.logins != logins {
			t.Fatalf("pause %d ended early: %v, %d sign-ins", i, err, f.logins)
		}
		clock.add(time.Second)
		if err := send(); errors.As(err, &be) || err == nil || f.logins != logins+1 {
			t.Fatalf("pause %d did not end: %v, %d sign-ins", i, err, f.logins)
		}
		logins++
		if err := send(); !errors.As(err, &be) {
			t.Fatalf("pause %d: no pause after the failure: %v", i, err)
		}
		if got := be.Until.Sub(clock.now()); got != w {
			t.Fatalf("after failure %d the pause is %v, want %v", i+2, got, w)
		}
	}
	// A success ends the doubling.
	f.mu.Lock()
	f.loginErr = 0
	f.mu.Unlock()
	clock.add(time.Hour)
	if err := send(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.loginErr = -1357
	f.mu.Unlock()
	clock.add(zaloLoginTTL + time.Minute)
	_ = send()
	if err := send(); !errors.As(err, &be) {
		t.Fatalf("after a success and a failure: %v", err)
	}
	if got := be.Until.Sub(clock.now()); got != time.Minute {
		t.Errorf("after a success the pause is %v, want 1m0s", got)
	}
}

func TestZaloPersonalMessageRefusalDoesNotSignInAgain(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s, _ := newClockedSender(t, f)
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	f.innerCode = 221 // Zalo refuses the message itself (a bad recipient, say), not the session
	for i := 0; i < 10; i++ {
		_, err := s.Send(context.Background(), sample)
		var pe *ProviderError
		if !errors.As(err, &pe) || pe.Code != 221 {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if f.logins != 1 || f.sends != 11 {
		t.Errorf("sign-ins %d, posts %d", f.logins, f.sends)
	}
}

func TestZaloPersonalRefusedSessionIsRetriedOnceThenPaused(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s, _ := newClockedSender(t, f)
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	f.sendErr = func(int) int { return 221 } // the request as a whole is refused, every time
	for i := 0; i < 10; i++ {
		_, _ = s.Send(context.Background(), sample)
	}
	if f.logins != 2 || f.sends != 3 {
		t.Errorf("10 refused sends: %d sign-ins (want 2), %d posts (want 3)", f.logins, f.sends)
	}
}

// L6: HTTP 401/403 on a reused session drops it, and the next sign-in waits.
func TestZaloPersonalForbiddenSessionIsDroppedAndPaused(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s, clock := newClockedSender(t, f)
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	f.sendStatus = http.StatusForbidden
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 || f.logins != 1 || f.sends != 2 {
		t.Fatalf("403: %v, %d sign-ins, %d posts", err, f.logins, f.sends)
	}
	var be *BackoffError
	if _, err := s.Send(context.Background(), sample); !errors.As(err, &be) || f.logins != 1 || f.sends != 2 {
		t.Fatalf("after the 403: %v, %d sign-ins, %d posts", err, f.logins, f.sends)
	}
	f.sendStatus = 0
	clock.add(time.Minute + time.Second)
	if _, err := s.Send(context.Background(), sample); err != nil || f.logins != 2 {
		t.Errorf("after the pause: %v, %d sign-ins", err, f.logins)
	}
}

// M3: an answer that cannot be read may hide a delivered message: never post again.
func TestContract_D46_ZaloPersonalNeverPostsTwiceOnAnUnreadableAnswer(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s, _ := newClockedSender(t, f)
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	before := f.sends
	f.garbage = true
	_, err := s.Send(context.Background(), sample)
	var pe *ProviderError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if f.sends-before != 1 || f.logins != 1 {
		t.Fatalf("one alert -> %d posts, %d sign-ins", f.sends-before, f.logins)
	}
	// Also with a message that Zalo accepted but whose answer lacks the id.
	f.garbage = false
	f.innerCode = 0
	for name, key := range map[string]string{"empty": `""`, "false": `false`, "object": `{}`, "zero": `0`, "zero string": `"000"`, "float": `1.5`, "negative": `-4`, "exponent": `1e3`, "word": `"abc"`} {
		if confirmZaloSend(inner(t, `{"error_code":0,"data":{"msgId":`+key+`}}`), []byte(zpKey)) == nil {
			t.Errorf("msgId %s (%s) was taken as a delivery", key, name)
		}
	}
}

func inner(t *testing.T, plain string) []byte {
	t.Helper()
	enc, err := zaloEncrypt([]byte(zpKey), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"error_code":0,"error_message":"","data":"` + enc + `"}`)
}

// L2: ids and envelope keys are read the way upstream reads them.
func TestZaloPersonalReadsAnswersStrictly(t *testing.T) {
	t.Parallel()
	key := []byte(zpKey)
	for _, ok := range []string{`7000000000000000123`, `"123456"`, `5`} {
		if err := confirmZaloSend(inner(t, `{"error_code":0,"data":{"msgId":`+ok+`}}`), key); err != nil {
			t.Errorf("msgId %s: %v", ok, err)
		}
	}
	for name, body := range map[string]string{
		"MSGID upper":        `{"error_code":0,"data":{"MSGID":5}}`,
		"Msgid mixed":        `{"error_code":0,"data":{"msgid":5}}`,
		"inner ERROR_CODE":   `{"ERROR_CODE":0,"data":{"msgId":5}}`,
		"inner both":         `{"error_code":5,"ERROR_CODE":0,"data":{"msgId":5}}`,
		"inner Data":         `{"error_code":0,"Data":{"msgId":5}}`,
		"inner data array":   `{"error_code":0,"data":[{"msgId":5}]}`,
		"inner data missing": `{"error_code":0}`,
	} {
		if err := confirmZaloSend(inner(t, body), key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	enc, _ := zaloEncrypt(key, []byte(`{"error_code":0,"data":{"msgId":1}}`))
	var pe *ProviderError
	if err := confirmZaloSend([]byte(`{"error_code":5,"ERROR_CODE":0,"data":"`+enc+`"}`), key); !errors.As(err, &pe) || pe.Code != 5 {
		t.Errorf("outer {error_code:5, ERROR_CODE:0}: %v", err)
	}
	if err := confirmZaloSend([]byte(`{"ERROR_CODE":0,"data":"`+enc+`"}`), key); err == nil {
		t.Error("outer with only ERROR_CODE accepted")
	}
	if err := confirmZaloSend([]byte(`{"error_code":0,"Data":"`+enc+`"}`), key); err == nil {
		t.Error("outer with only Data accepted")
	}
}

// L1: a cookie Zalo rotates in an error answer is scrubbed from that answer's text.
func TestContract_FORBID2_ZaloPersonalScrubsACookieRotatedInTheErrorAnswer(t *testing.T) {
	t.Parallel()
	const fresh = "FRESHLYrotatedSECRET999"
	for _, status := range []int{http.StatusForbidden, http.StatusBadGateway} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "zpw_sek", Value: fresh, Domain: "chat.zalo.me", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			w.WriteHeader(status)
			_, _ = w.Write([]byte("denied " + fresh))
		}))
		t.Cleanup(srv.Close)
		s, _ := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: clientTo(t, srv.URL)})
		_, err := s.Send(context.Background(), sample)
		var se *StatusError
		if !errors.As(err, &se) || se.Code != status {
			t.Fatalf("err = %v", err)
		}
		mustNot(t, err.Error(), fresh)
		if !strings.Contains(err.Error(), redacted) {
			t.Errorf("no redaction in %q", err)
		}
	}
}

// L5: waiting for an earlier send ends with the context.
func TestZaloPersonalWaitingForTheTurnHonoursTheContext(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	s, _ := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: clientTo(t, srv.URL)})
	done := make(chan struct{})
	go func() { defer close(done); _, _ = s.Send(context.Background(), sample) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := s.Send(ctx, sample)
	if err == nil || !strings.Contains(err.Error(), "waiting") || time.Since(start) > 5*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
	mustNot(t, errString(err), zpIMEI, zpSID)
	_ = done
}

// 8 goroutines at once: one sign-in, every message posted once, no data race.
func TestZaloPersonalConcurrentSends(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Send(context.Background(), sample)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logins != 1 || f.sends != 8 {
		t.Errorf("8 concurrent sends: %d sign-ins, %d posts", f.logins, f.sends)
	}
}

// L7: scoping and deletion of cookies.
func TestZaloPersonalCookiesAreScopedAndCanBeDeleted(t *testing.T) {
	t.Parallel()
	const noDomain = `{"imei":"` + zpIMEI + `","userAgent":"ua","cookie":[{"name":"zpsid","value":"NODOMAINcookie1"}]}`
	s, err := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(noDomain)})
	if err != nil {
		t.Fatal(err)
	}
	z := s.(*zaloPersonalSender)
	for _, h := range []string{"wpa.chat.zalo.me", "tt-chat1-wpa.chat.zalo.me", "chat.zalo.me"} {
		if !strings.Contains(z.cookieHeader(h), "zpsid=NODOMAINcookie1") {
			t.Errorf("a cookie without a domain does not go to %s", h)
		}
	}
	for _, h := range []string{"zalo.me", "id.zalo.me", "evil.example", "chat.zalo.me.evil.example", "xchat.zalo.me"} {
		if z.cookieHeader(h) != "" {
			t.Errorf("a cookie without a domain goes to %s", h)
		}
	}
	// Set-Cookie without Domain is host-only.
	now := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	resp := http.Response{Header: http.Header{"Set-Cookie": {"zpw_host=HOSTONLYvalue1; Path=/", "zpw_dom=DOMAINvalue123; Domain=.chat.zalo.me"}}}
	z.absorb("wpa.chat.zalo.me", resp.Cookies(), now)
	if h := z.cookieHeader("wpa.chat.zalo.me"); !strings.Contains(h, "zpw_host=HOSTONLYvalue1") || !strings.Contains(h, "zpw_dom=DOMAINvalue123") {
		t.Errorf("same host: %q", h)
	}
	if h := z.cookieHeader("tt-chat1-wpa.chat.zalo.me"); strings.Contains(h, "zpw_host") || !strings.Contains(h, "zpw_dom") {
		t.Errorf("sibling host: %q", h)
	}
	if h := z.cookieHeader("x.wpa.chat.zalo.me"); strings.Contains(h, "zpw_host") {
		t.Errorf("a host-only cookie went to a child host: %q", h)
	}
	// Deletion: Max-Age of 0 or less, or an Expires in the past (when there is no Max-Age).
	del := http.Response{Header: http.Header{"Set-Cookie": {
		"zpw_host=; Max-Age=0", "zpw_dom=x; Domain=.chat.zalo.me; Expires=Thu, 01 Jan 1970 00:00:00 GMT", "zpsid=; Domain=chat.zalo.me; Max-Age=-1",
	}}}
	z.absorb("wpa.chat.zalo.me", del.Cookies(), now)
	if h := z.cookieHeader("wpa.chat.zalo.me"); strings.Contains(h, "zpw_host") || strings.Contains(h, "zpw_dom") || strings.Contains(h, "zpsid") {
		t.Errorf("deleted cookies are still sent: %q", h)
	}
	// A future Expires keeps it; Max-Age wins over a past Expires.
	keep := http.Response{Header: http.Header{"Set-Cookie": {
		"zpw_a=FUTUREvalue123; Domain=chat.zalo.me; Expires=Wed, 09 Nov 2033 08:00:00 GMT", "zpw_b=MAXAGEvalue1234; Domain=chat.zalo.me; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
	}}}
	z.absorb("wpa.chat.zalo.me", keep.Cookies(), now)
	if h := z.cookieHeader("wpa.chat.zalo.me"); !strings.Contains(h, "zpw_a=") || !strings.Contains(h, "zpw_b=") {
		t.Errorf("cookies were dropped: %q", h)
	}
	// A cookie for another site never gets in, and a short value is ignored.
	other := http.Response{Header: http.Header{"Set-Cookie": {"x=EVILvalue12345; Domain=evil.example", "y=short; Domain=chat.zalo.me"}}}
	z.absorb("wpa.chat.zalo.me", other.Cookies(), now)
	if h := z.cookieHeader("wpa.chat.zalo.me"); strings.Contains(h, "EVIL") || strings.Contains(h, "y=") {
		t.Errorf("%q", h)
	}
}

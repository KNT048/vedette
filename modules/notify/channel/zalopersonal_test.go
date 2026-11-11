package channel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/secrets"
)

// Fixed test values. The cookie values, device id and session key are made up.
const (
	zpIMEI   = "0b8e3a52-7d41-4c6e-9a10-5f2d8c3e1b77-2df2c35b2edfffe69f903518ff8ab3f1"
	zpSID    = "SAVEDzpsidCOOKIEvalue123"
	zpSEK    = "OLDsekCOOKIEvalue456"
	zpOther  = "NOTforZALOhosts789"
	zpRotate = "ROTATEDsekCOOKIEvalue000"
	zpKey    = "0123456789abcdef0123456789ABCDEF" // the session key the fake hands out (32 bytes)
	zpUser   = "123456789"
)

var zpSession = `{"imei":"` + zpIMEI + `","userAgent":"Mozilla/5.0 (X11; Linux x86_64) TestAgent","cookie":[` +
	`{"name":"zpsid","value":"` + zpSID + `","domain":".zalo.me"},` +
	`{"name":"zpw_sek","value":"` + zpSEK + `","domain":".chat.zalo.me"},` +
	`{"name":"other","value":"` + zpOther + `","domain":".example.com"}]}`

// TestZaloPersonalVectors checks the primitives against values produced by
// running the algorithms of zca-js v2.2.0 (MIT) on crypto-js 4.2.0 (the library
// zca-js uses) with fixed inputs. zca-js ships no test vectors of its own.
func TestZaloPersonalVectors(t *testing.T) {
	t.Parallel()
	const (
		first    = 1700000000000
		ext      = "a1b2c3d4"
		zcid     = "A391EB8F18A8C479ACD60512473FFC188E1103006B4B3E7780CD12CB13DCD6FA167780AC299EADDF1895C8078729B96DF3D4736A2B0AC7C1B16D916E681DB426920CD9877F4330E4E1197828DDEBBF70573053C06D7F55F177E570881C74845E"
		key      = "2C431646A9E81AC7AD01E44C805715FD"
		loginEnc = "mUtVcOpZWFUtqC8U8N0FTXFxllwgLLTt2dNvaS27dv0Bb0T2hcAeWSvttQHGCtw6BlaMKI7VdWHaF6aNvNXxwBs7w5gt7yd7evWumHyN75XzpOzhbqoUCFeo60psAhKpNTjO/9mG9bF3VPx+AqjavGzTrEHk+EjxOw7/vyeCLCP3rr0x0/KGVHG3+MB3ytDB"
		signLog  = "8495b7aa409e35bd13848541c3325d1f"
		signSrv  = "ca88ca0243b62757024dfb654f47cdd4"
		secret   = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlBQkNERUY=" //nolint:gosec // fake test key
		sendEnc  = "RZQt/F/ggnhKJieO682+cndbVtMlYMzCy8qj3ljbIOVwUC4wHcv8lKo2B2BvSJIYMjhWnW9oVU+jBNiAfef3Yx8CPmveGWA4QAa509DKUVUBJaNeA+ml+XRSwiPr3X88/XmPY1wELbXcWwFOReULkzkfdOG/ciqDI3UBWw3CjQNda8cajVfnleRq/8tJB5257dvG205hdcJ6Uqz96k/0yw=="
	)
	if got, err := zaloEncryptHex([]byte(zaloLoginKey), fmt.Sprintf("30,%s,%d", zpIMEI, first)); err != nil || got != zcid {
		t.Errorf("zcid = %q, %v", got, err)
	}
	if got := zaloLoginKeyFor(zcid, ext); got != key {
		t.Errorf("login key = %q", got)
	}
	plain := `{"computer_name":"Web","imei":"` + zpIMEI + `","language":"vi","ts":1700000001234}`
	if got, err := zaloEncrypt([]byte(key), []byte(plain)); err != nil || got != loginEnc {
		t.Errorf("login params = %q, %v", got, err)
	}
	if back, err := zaloDecrypt([]byte(key), loginEnc); err != nil || string(back) != plain {
		t.Errorf("login params round trip = %q, %v", back, err)
	}
	signed := map[string]string{"zcid": zcid, "zcid_ext": ext, "enc_ver": "v2", "params": loginEnc, "type": "30", "client_version": "685"}
	if got := zaloSignKey("getlogininfo", signed); got != signLog {
		t.Errorf("getlogininfo signkey = %q", got)
	}
	info := map[string]string{"imei": zpIMEI, "type": "30", "client_version": "685", "computer_name": "Web"}
	if got := zaloSignKey("getserverinfo", info); got != signSrv {
		t.Errorf("getserverinfo signkey = %q", got)
	}
	k, _ := base64.StdEncoding.DecodeString(secret)
	body := `{"message":"hello","clientId":1700000002000,"imei":"` + zpIMEI + `","ttl":0,"toid":"123456789"}`
	if got, err := zaloEncrypt(k, []byte(body)); err != nil || got != sendEnc {
		t.Errorf("send params = %q, %v", got, err)
	}
	// What the server sends back is URI-escaped base64: decrypt accepts it.
	if back, err := zaloDecrypt(k, url.QueryEscape(sendEnc)); err != nil || string(back) != body {
		t.Errorf("escaped round trip = %q, %v", back, err)
	}
}

func TestZaloPersonalConfig(t *testing.T) {
	t.Parallel()
	mk := func(mod func(*ZaloPersonalConfig)) error {
		c := ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession)}
		mod(&c)
		_, err := NewZaloPersonal(c)
		return err
	}
	if err := mk(func(*ZaloPersonalConfig) {}); err != nil {
		t.Fatal(err)
	}
	sess := func(cookie, ua string) secrets.Value {
		return secrets.NewValue(`{"imei":"` + zpIMEI + `","userAgent":"` + ua + `","cookie":` + cookie + `}`)
	}
	for name, c := range map[string]struct {
		mod  func(*ZaloPersonalConfig)
		code string
	}{
		"no user":       {func(c *ZaloPersonalConfig) { c.UserID = "" }, "bad_user_id"},
		"letters":       {func(c *ZaloPersonalConfig) { c.UserID = "abc" }, "bad_user_id"},
		"no session":    {func(c *ZaloPersonalConfig) { c.Session = secrets.Value{} }, "secret_required"},
		"not json":      {func(c *ZaloPersonalConfig) { c.Session = secrets.NewValue("zl-session-secret-value") }, "bad_session"},
		"no imei":       {func(c *ZaloPersonalConfig) { c.Session = secrets.NewValue(`{"userAgent":"ua","cookie":"a=b"}`) }, "bad_session"},
		"no cookie":     {func(c *ZaloPersonalConfig) { c.Session = sess("null", "ua") }, "bad_session"},
		"empty cookie":  {func(c *ZaloPersonalConfig) { c.Session = sess(`[]`, "ua") }, "bad_session"},
		"cookie header": {func(c *ZaloPersonalConfig) { c.Session = sess(`[{"name":"a","value":"x\r\nHost: evil"}]`, "ua") }, "bad_session"},
		"cookie name":   {func(c *ZaloPersonalConfig) { c.Session = sess(`[{"name":"a b","value":"x"}]`, "ua") }, "bad_session"},
		"cookie short":  {func(c *ZaloPersonalConfig) { c.Session = sess(`[{"name":"zpsid","value":"Q7z"}]`, "ua") }, "bad_session"},
		"cookie 7":      {func(c *ZaloPersonalConfig) { c.Session = sess(`"zpsid=1234567"`, "ua") }, "bad_session"},
		"cookie semi":   {func(c *ZaloPersonalConfig) { c.Session = sess(`[{"name":"a","value":"x;y=z"}]`, "ua") }, "bad_session"},
		"agent control": {func(c *ZaloPersonalConfig) { c.Session = sess(`"a=b"`, `ua\nX: y`) }, "bad_session"},
		"no agent":      {func(c *ZaloPersonalConfig) { c.Session = sess(`"a=b"`, ``) }, "bad_session"},
		"huge":          {func(c *ZaloPersonalConfig) { c.Session = sess(`"a=`+strings.Repeat("x", zaloMaxSession)+`"`, "ua") }, "bad_session"},
	} {
		err := mk(c.mod)
		var ce *ConfigError
		if !errors.Is(err, ErrInvalidConfig) || !errors.As(err, &ce) || ce.Code != c.code {
			t.Errorf("%s: err = %v", name, err)
		}
		mustNot(t, errString(err), "zl-session-secret-value", zpIMEI)
	}
	// The accepted shapes of "cookie".
	for name, cookie := range map[string]string{
		"array":          `[{"name":"zpsid","value":"abcdefgh1","domain":".zalo.me","extra":1}]`,
		"wrapped":        `{"url":"https://chat.zalo.me","cookies":[{"name":"zpsid","value":"abcdefgh1"}]}`,
		"header":         `"zpsid=abcdefgh1; zpw_sek=defdefdef2"`,
		"array as text":  `"[{\"name\":\"zpsid\",\"value\":\"abcdefgh1\"}]"`,
		"wrapped as txt": `"{\"cookies\":[{\"name\":\"zpsid\",\"value\":\"abcdefgh1\"}]}"`,
	} {
		if err := mk(func(c *ZaloPersonalConfig) { c.Session = sess(cookie, "ua") }); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// zaloFake plays the Zalo servers: sign-in, server info and the two send
// endpoints, with the encryption and the signature checked on the way in.
type zaloFake struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	logins      int
	infos       int
	sends       int
	other       int
	hosts       []string // Host header of each send
	paths       []string
	cookies     []string // Cookie header of each send
	sent        []map[string]any
	loginErr    int                                          // outer error_code of the sign-in answer
	loginSvc    string                                       // overrides the service map: the chat and group address
	noChat      bool                                         // the service map names no chat service
	sendErr     func(n int) int                              // outer error_code of the nth send (0 = success)
	echo        string                                       // appended to every error message
	loginCookie bool                                         // set the rotated cookie at sign-in
	sendStatus  int                                          // HTTP status of every send (0 = 200)
	garbage     bool                                         // answer every send with an unreadable 2xx, after recording the post
	innerCode   int                                          // error_code inside the encrypted answer of every send (0 = success)
	info        any                                          // data of the server info answer (nil = empty settings)
	wsHosts     []string                                     // Host of each message connection request
	ws          func(w http.ResponseWriter, r *http.Request) // serves the message connection (zalopersonal_listen_test.go)
}

func newZaloFake(t *testing.T) *zaloFake {
	t.Helper()
	f := &zaloFake{t: t, loginCookie: true}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *zaloFake) envelope(code int, msg string, data any) []byte {
	b, _ := json.Marshal(map[string]any{"error_code": code, "error_message": msg, "data": data})
	return b
}

func (f *zaloFake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if ws := f.ws; ws != nil && strings.HasSuffix(r.Host, "-msg.chat.zalo.me") { // long-lived: served without the lock
		f.wsHosts = append(f.wsHosts, r.Host)
		f.mu.Unlock()
		ws(w, r)
		return
	}
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/login/getServerInfo":
		f.infos++
		info := f.info
		if info == nil {
			info = map[string]any{"settings": map[string]any{}}
		}
		_, _ = w.Write(f.envelope(0, "Success", info))
	case "/api/login/getLoginInfo":
		f.logins++
		f.login(w, r)
	case "/api/message/sms", "/api/group/sendmsg":
		f.sends++
		f.send(w, r)
	case "/redirect":
		f.other++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	default:
		f.other++
		http.NotFound(w, r)
	}
}

func (f *zaloFake) login(w http.ResponseWriter, r *http.Request) {
	t := f.t
	t.Helper()
	q := r.URL.Query()
	p := map[string]string{}
	for _, k := range []string{"zcid", "zcid_ext", "enc_ver", "params", "type", "client_version"} {
		p[k] = q.Get(k)
	}
	if zaloSignKey("getlogininfo", p) != q.Get("signkey") || q.Get("zpw_ver") != "685" || q.Get("zpw_type") != "30" || q.Get("nretry") != "0" || p["enc_ver"] != "v2" {
		t.Errorf("sign-in query not as the web client sends it: %v", q)
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	if len(p["zcid_ext"]) < 6 || len(p["zcid_ext"]) > 12 {
		t.Errorf("zcid_ext length %d", len(p["zcid_ext"]))
	}
	enk := zaloLoginKeyFor(p["zcid"], p["zcid_ext"])
	plain, err := zaloDecrypt([]byte(enk), p["params"])
	if err != nil {
		t.Errorf("sign-in params do not decrypt: %v", err)
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	var in struct {
		ComputerName string `json:"computer_name"`
		IMEI         string `json:"imei"`
		Language     string `json:"language"`
		TS           int64  `json:"ts"`
	}
	_ = json.Unmarshal(plain, &in)
	raw, _ := hex.DecodeString(p["zcid"])
	zc, err := zaloDecrypt([]byte(zaloLoginKey), base64.StdEncoding.EncodeToString(raw))
	if err != nil || string(zc) != fmt.Sprintf("30,%s,%d", zpIMEI, in.TS) || in.IMEI != zpIMEI || in.Language != "vi" || in.ComputerName != "Web" {
		t.Errorf("sign-in params %+v zcid %q %v", in, zc, err)
	}
	if c := r.Header.Get("Cookie"); !strings.Contains(c, "zpsid="+zpSID) || !strings.Contains(c, "zpw_sek=") || strings.Contains(c, zpOther) {
		t.Errorf("sign-in cookies %q", c)
	}
	if r.Host != "wpa.chat.zalo.me" || r.Header.Get("Origin") != "https://chat.zalo.me" || r.Header.Get("User-Agent") != "Mozilla/5.0 (X11; Linux x86_64) TestAgent" {
		t.Errorf("sign-in headers: host %q origin %q ua %q", r.Host, r.Header.Get("Origin"), r.Header.Get("User-Agent"))
	}
	if f.loginErr != 0 {
		_, _ = w.Write(f.envelope(f.loginErr, "login refused"+f.echo, nil))
		return
	}
	chat, group := "https://tt-chat1-wpa.chat.zalo.me", "https://tt-group-wpa.chat.zalo.me"
	if f.loginSvc != "" {
		chat, group = f.loginSvc, f.loginSvc
	}
	chats := []string{chat}
	if f.noChat {
		chats = nil
	}
	inner := f.envelope(0, "Success", map[string]any{
		"uid": "42", "zpw_enk": base64.StdEncoding.EncodeToString([]byte(zpKey)),
		"zpw_service_map_v3": map[string]any{"chat": chats, "group": []string{group}},
		"zpw_ws":             []string{"wss://ws1-msg.chat.zalo.me"},
	})
	enc, _ := zaloEncrypt([]byte(enk), inner)
	if f.loginCookie {
		http.SetCookie(w, &http.Cookie{Name: "zpw_sek", Value: zpRotate, Domain: "chat.zalo.me", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	_, _ = w.Write(f.envelope(0, "Success", enc))
}

func (f *zaloFake) send(w http.ResponseWriter, r *http.Request) {
	t := f.t
	t.Helper()
	q := r.URL.Query()
	_ = r.ParseForm()
	plain, err := zaloDecrypt([]byte(zpKey), r.PostForm.Get("params"))
	if err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || q.Get("zpw_ver") != "685" || q.Get("zpw_type") != "30" {
		t.Errorf("send request: %v method %s query %v", err, r.Method, q)
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	var p map[string]any
	_ = json.Unmarshal(plain, &p)
	f.sent = append(f.sent, p)
	f.hosts = append(f.hosts, r.Host)
	f.paths = append(f.paths, r.URL.Path)
	f.cookies = append(f.cookies, r.Header.Get("Cookie"))
	if f.sendStatus != 0 {
		w.WriteHeader(f.sendStatus)
		_, _ = w.Write([]byte("denied" + f.echo))
		return
	}
	if f.garbage {
		_, _ = w.Write([]byte("<html>queued</html>"))
		return
	}
	if f.innerCode != 0 {
		enc, _ := zaloEncrypt([]byte(zpKey), f.envelope(f.innerCode, "message refused"+f.echo, nil))
		_, _ = w.Write(f.envelope(0, "Success", enc))
		return
	}
	if f.sendErr != nil {
		if code := f.sendErr(f.sends); code != 0 {
			_, _ = w.Write(f.envelope(code, "refused"+f.echo, nil))
			return
		}
	}
	inner := f.envelope(0, "Success", map[string]any{"msgId": 7000000000000000123})
	enc, _ := zaloEncrypt([]byte(zpKey), inner)
	_, _ = w.Write(f.envelope(0, "Success", enc))
}

func newZPSender(t *testing.T, f *zaloFake, mod func(*ZaloPersonalConfig)) *zaloPersonalSender {
	t.Helper()
	cfg := ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: clientTo(t, f.srv.URL)}
	if mod != nil {
		mod(&cfg)
	}
	s, err := NewZaloPersonal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*zaloPersonalSender)
}

func TestContract_D46_ZaloPersonalSendsToTheUser(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, nil)
	m := sample
	m.Title = "@everyone http://evil.example/x"
	rec, err := s.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != "Zalo "+zpUser || s.Type() != ZaloPersonal || s.Dest() != "Zalo "+zpUser {
		t.Errorf("rec %+v dest %q", rec, s.Dest())
	}
	if f.logins != 1 || f.infos != 1 || f.sends != 1 || f.other != 0 {
		t.Fatalf("calls: login %d info %d send %d other %d", f.logins, f.infos, f.sends, f.other)
	}
	p := f.sent[0]
	text, _ := p["message"].(string)
	if p["toid"] != zpUser || p["imei"] != zpIMEI || p["ttl"] != float64(0) || p["grid"] != nil || f.paths[0] != "/api/message/sms" || f.hosts[0] != "tt-chat1-wpa.chat.zalo.me" {
		t.Errorf("params %v path %s host %s", p, f.paths[0], f.hosts[0])
	}
	if c, ok := p["clientId"].(float64); !ok || c < 1e12 {
		t.Errorf("clientId %v", p["clientId"])
	}
	body, details, _ := strings.Cut(text, "\nDetails: ")
	if !strings.HasPrefix(text, "Critical: ") || details != m.Link || strings.Contains(body, "://") || strings.Contains(body, "@e") && !strings.Contains(body, "@"+zwj+"e") {
		t.Errorf("text %q", text)
	}
	// The cookies for chat.zalo.me are sent, the cookie Zalo rotated replaced the saved one, the foreign cookie never goes.
	c := f.cookies[0]
	if !strings.Contains(c, "zpsid="+zpSID) || !strings.Contains(c, "zpw_sek="+zpRotate) || strings.Contains(c, zpSEK) || strings.Contains(c, zpOther) {
		t.Errorf("send cookies %q", c)
	}
	// A second send reuses the session: no new sign-in.
	if _, err := s.Send(context.Background(), sample); err != nil || f.logins != 1 || f.sends != 2 {
		t.Errorf("second send: err %v logins %d sends %d", err, f.logins, f.sends)
	}
}

func TestZaloPersonalGroupAndClock(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, func(c *ZaloPersonalConfig) { c.Group = true })
	clock := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	p := f.sent[0]
	if p["grid"] != zpUser || p["visibility"] != float64(0) || p["toid"] != nil || p["imei"] != nil || f.paths[0] != "/api/group/sendmsg" || f.hosts[0] != "tt-group-wpa.chat.zalo.me" {
		t.Errorf("group params %v path %s host %s", p, f.paths[0], f.hosts[0])
	}
	if p["clientId"] != float64(clock.UnixMilli()) {
		t.Errorf("clientId %v", p["clientId"])
	}
	clock = clock.Add(zaloLoginTTL + time.Minute)
	if _, err := s.Send(context.Background(), sample); err != nil || f.logins != 2 {
		t.Errorf("after the lifetime: err %v logins %d", err, f.logins)
	}
}

func TestZaloPersonalSignsInAgainOnceWhenAReusedSessionIsRefused(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, nil)
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	f.sendErr = func(n int) int {
		if n == 2 {
			return 114
		}
		return 0
	}
	if _, err := s.Send(context.Background(), sample); err != nil || f.logins != 2 || f.sends != 3 {
		t.Errorf("refused once: err %v logins %d sends %d", err, f.logins, f.sends)
	}
	// A refusal on a fresh session is final: one sign-in, one try.
	g := newZaloFake(t)
	g.sendErr = func(int) int { return 114 }
	s2 := newZPSender(t, g, nil)
	_, err := s2.Send(context.Background(), sample)
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Code != 114 || pe.Channel != ZaloPersonal || g.logins != 1 || g.sends != 1 {
		t.Errorf("fresh refusal: err %v logins %d sends %d", err, g.logins, g.sends)
	}
	// A refused sign-in is a provider error too, and nothing is sent.
	h := newZaloFake(t)
	h.loginErr = 2
	_, err = newZPSender(t, h, nil).Send(context.Background(), sample)
	if !errors.As(err, &pe) || pe.Code != 2 || h.sends != 0 {
		t.Errorf("refused sign-in: err %v sends %d", err, h.sends)
	}
}

func TestContract_FORBID2_ZaloPersonalErrorsNeverContainSecrets(t *testing.T) {
	t.Parallel()
	secretsSeen := []string{zpSID, zpSEK, zpRotate, zpIMEI, base64.StdEncoding.EncodeToString([]byte(zpKey)), zpSession}
	echo := " " + strings.Join(secretsSeen, " ")
	// The server echoes every secret in its error text, at sign-in and at send.
	f := newZaloFake(t)
	f.echo = echo
	f.sendErr = func(int) int { return 7 }
	_, err := newZPSender(t, f, nil).Send(context.Background(), sample)
	if err == nil {
		t.Fatal("want an error")
	}
	mustNot(t, err.Error(), secretsSeen...)
	if !strings.Contains(err.Error(), redacted) {
		t.Errorf("no redaction in %q", err)
	}
	g := newZaloFake(t)
	g.echo = " " + strings.Join([]string{zpSID, zpSEK, zpIMEI, zpSession}, " ") // the sign-in refusal comes before Zalo hands out a key or a cookie

	g.loginErr = 5
	_, err = newZPSender(t, g, nil).Send(context.Background(), sample)
	mustNot(t, errString(err), secretsSeen...)
	// HTTP errors with an echoing body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway " + zpSID + " " + zpSEK + " " + zpIMEI + " " + zpSession))
	}))
	t.Cleanup(srv.Close)
	s, _ := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: clientTo(t, srv.URL)})
	_, err = s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 502 {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), secretsSeen...)
	// A transport failure names neither the URL nor a secret.
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	s, _ = NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: clientTo(t, url)})
	_, err = s.Send(context.Background(), sample)
	mustNot(t, errString(err), secretsSeen...)
	mustNot(t, errString(err), "wpa.chat.zalo.me", "getLoginInfo", "signkey", "zcid")
}

func TestZaloPersonalRefusesServiceAddressesOutsideZalo(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{
		"https://evil.example", "http://tt-chat1-wpa.chat.zalo.me", "https://chat.zalo.me.evil.example",
		"https://user:pw@tt-chat1-wpa.chat.zalo.me", "https://tt-chat1-wpa.chat.zalo.me:8443", "https://tt-chat1-wpa.chat.zalo.me/api",
		"https://tt-chat1-wpa.chat.zalo.me?x=1", "https://notzalo.me", "//tt-chat1-wpa.chat.zalo.me", "https://", "ftp://x.zalo.me",
	} {
		f := newZaloFake(t)
		f.loginSvc = addr
		_, err := newZPSender(t, f, nil).Send(context.Background(), sample)
		var pe *ProviderError
		if !errors.As(err, &pe) || f.sends != 0 {
			t.Errorf("%q: err %v sends %d", addr, err, f.sends)
		}
	}
	if base, err := zaloServiceBase("https://tt-chat1-wpa.chat.zalo.me:443/"); err != nil || base != "https://tt-chat1-wpa.chat.zalo.me" {
		t.Errorf("good address: %q %v", base, err)
	}
}

func TestZaloPersonalFailsClosedOnBadAnswers(t *testing.T) {
	t.Parallel()
	key := []byte(zpKey)
	good, _ := zaloEncrypt(key, []byte(`{"error_code":0,"error_message":"","data":{"msgId":1}}`))
	bad, _ := zaloEncrypt(key, []byte(`{"error_code":0,"data":{}}`))
	noCode, _ := zaloEncrypt(key, []byte(`{"data":{"msgId":1}}`))
	innerErr, _ := zaloEncrypt(key, []byte(`{"error_code":-5,"error_message":"nope","data":null}`))
	other, _ := zaloEncrypt([]byte("ffffffffffffffffffffffffffffffff"), []byte(`{"error_code":0,"data":{"msgId":1}}`))
	short := strings.TrimRight(good, "=")[:20]
	outer := func(data any) []byte {
		b, _ := json.Marshal(map[string]any{"error_code": 0, "error_message": "", "data": data})
		return b
	}
	for name, c := range map[string]struct {
		body []byte
		ok   bool
		code int
	}{
		"good":               {outer(good), true, 0},
		"good, unpadded":     {outer(strings.TrimRight(good, "=")), true, 0},
		"good, escaped":      {outer(url.QueryEscape(good)), true, 0},
		"not json":           {[]byte("<html>"), false, 0},
		"empty":              {nil, false, 0},
		"no outer code":      {[]byte(`{"data":"` + good + `"}`), false, 0},
		"outer error":        {[]byte(`{"error_code":114,"error_message":"expired"}`), false, 114},
		"data not a string":  {outer(map[string]any{"msgId": 1}), false, 0},
		"data null":          {outer(nil), false, 0},
		"not base64":         {outer("!!!"), false, 0},
		"truncated":          {outer(short), false, 0},
		"wrong key":          {outer(other), false, 0},
		"no msgId":           {outer(bad), false, 0},
		"no inner code":      {outer(noCode), false, 0},
		"inner error":        {outer(innerErr), false, -5},
		"escape garbage":     {outer("%zz"), false, 0},
		"huge":               {outer(strings.Repeat("A", zaloMaxCipher+1)), false, 0},
		"numeric error_code": {[]byte(`{"error_code":"0","data":"` + good + `"}`), false, 0},
		"fractional code":    {[]byte(`{"error_code":0.5,"data":"` + good + `"}`), false, 0},
		"nested depth bomb":  {[]byte(strings.Repeat(`{"data":`, 5000)), false, 0},
	} {
		err := confirmZaloSend(c.body, key)
		var pe *ProviderError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", name, err)
		case !c.ok && !errors.As(err, &pe):
			t.Errorf("%s: want a ProviderError, got %v", name, err)
		case !c.ok && pe.Code != c.code:
			t.Errorf("%s: code %d", name, pe.Code)
		}
	}
}

func TestZaloPersonalDoesNotFollowRedirectsAndCapsAnswers(t *testing.T) {
	t.Parallel()
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		if r.URL.Path == "/elsewhere" {
			t.Error("the redirect was followed")
		}
		if strings.Contains(r.URL.Path, "getLoginInfo") && strings.Contains(r.URL.RawQuery, "zcid") {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := clientTo(t, srv.URL)
	c.CheckRedirect = nil // a client that follows redirects: the adapter must still refuse them
	s, _ := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: c})
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusFound || hits != 1 {
		t.Errorf("err %v hits %d", err, hits)
	}
	// An answer far over the cap is cut and then refused, never buffered whole.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error_code":0,"data":"` + strings.Repeat("A", 5<<20)))
	}))
	t.Cleanup(big.Close)
	s, _ = NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: clientTo(t, big.URL)})
	if _, err := s.Send(context.Background(), sample); err == nil {
		t.Error("an oversized answer was accepted")
	}
}

func TestZaloPersonalHonoursTheContextDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); srv.Close() })
	c := clientTo(t, srv.URL) // no client timeout: the deadline must come from the context or the adapter
	s, _ := NewZaloPersonal(ZaloPersonalConfig{UserID: zpUser, Session: secrets.NewValue(zpSession), Client: c})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := s.Send(ctx, sample)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v", err)
	}
}

func TestZaloPersonalRejectsBadMessages(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, nil)
	bad := sample
	bad.Severity = "nope"
	if _, err := s.Send(context.Background(), bad); !errors.Is(err, ErrInvalidMessage) || f.logins != 0 {
		t.Errorf("err %v logins %d", err, f.logins)
	}
}

// ---- fuzz: every decode, decrypt and parse path of untrusted input ----

func FuzzZaloOpenAnswer(f *testing.F) {
	key := []byte(zpKey)
	good, _ := zaloEncrypt(key, []byte(`{"error_code":0,"error_message":"","data":{"msgId":1}}`))
	f.Add([]byte(`{"error_code":0,"error_message":"","data":"`+good+`"}`), key)
	f.Add([]byte(`{"error_code":114,"error_message":"expired"}`), key)
	f.Add([]byte(`{"error_code":0,"data":"%zz"}`), key)
	f.Add([]byte(`<html>`), []byte("short"))
	f.Fuzz(func(t *testing.T, body, k []byte) {
		data, err := openZaloAnswer(body, k)
		if err == nil {
			if !json.Valid(data) && len(data) != 0 {
				t.Fatalf("success with invalid JSON %q", data)
			}
			return
		}
		var pe *ProviderError
		if !errors.As(err, &pe) || !utf8.ValidString(err.Error()) || len(err.Error()) > 400 || strings.ContainsAny(err.Error(), "\r\n\x00") {
			t.Fatalf("bad error %q", err)
		}
	})
}

func FuzzZaloDecrypt(f *testing.F) {
	k := []byte(zpKey)
	enc, _ := zaloEncrypt(k, []byte("hello"))
	f.Add(k, enc)
	f.Add(k, url.QueryEscape(enc))
	f.Add(k, "AAAAAAAAAAAAAAAAAAAAAA==")
	f.Add([]byte("0123456789abcdef"), "")
	f.Fuzz(func(t *testing.T, key []byte, s string) {
		out, err := zaloDecrypt(key, s)
		if err != nil {
			return
		}
		if len(out) > len(s) {
			t.Fatalf("plaintext %d longer than the text %d", len(out), len(s))
		}
		// What decrypted must encrypt back to a text that decrypts to the same bytes.
		again, err := zaloEncrypt(key, out)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := zaloDecrypt(key, again); err != nil || string(back) != string(out) {
			t.Fatalf("round trip %q %v", back, err)
		}
	})
}

func FuzzZaloParseSession(f *testing.F) {
	f.Add(zpSession)
	f.Add(`{"imei":"` + zpIMEI + `","userAgent":"ua","cookie":"a=b; c=d"}`)
	f.Add(`{"imei":"` + zpIMEI + `","userAgent":"ua","cookie":{"cookies":[{"name":"a","value":"b"}]}}`)
	f.Add(`{"imei":"` + zpIMEI + `","userAgent":"ua","cookie":"[{\"name\":\"a\",\"value\":\"b\"}]"}`)
	f.Add(`{"cookie":` + strings.Repeat("[", 3000))
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := parseZaloSession(raw)
		if err != nil {
			return
		}
		if !zaloIMEIRE.MatchString(s.imei) || !zaloLangRE.MatchString(s.language) || s.userAgent == "" || len(s.cookies) == 0 || len(s.cookies) > zaloMaxCookies {
			t.Fatalf("accepted a bad session %+v", s)
		}
		for _, c := range s.cookies {
			if !zaloCookieNameRE.MatchString(c.name) || !zaloCookieValueOK(c.value) || strings.ContainsAny(c.domain, " \r\n;,/") {
				t.Fatalf("accepted a bad cookie %+v", c)
			}
		}
	})
}

func FuzzZaloLoginInfo(f *testing.F) {
	f.Add([]byte(`{"zpw_enk":"`+base64.StdEncoding.EncodeToString([]byte(zpKey))+`","zpw_service_map_v3":{"chat":["https://tt-chat1-wpa.chat.zalo.me"],"group":["https://g.chat.zalo.me"]}}`), false)
	f.Add([]byte(`{"zpw_enk":"AAAA","zpw_service_map_v3":{"chat":[]}}`), true)
	f.Add([]byte(`[]`), false)
	f.Fuzz(func(t *testing.T, data []byte, group bool) {
		key, base, err := parseZaloLoginInfo(data, group)
		if err != nil {
			return
		}
		u, perr := url.Parse(base)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 || perr != nil || u.Scheme != "https" || !zaloServiceHostRE.MatchString(u.Hostname()) || u.Path != "" || u.User != nil {
			t.Fatalf("accepted key %d bytes, base %q", len(key), base)
		}
	})
}

func FuzzZaloServiceBase(f *testing.F) {
	for _, s := range []string{"https://tt-chat1-wpa.chat.zalo.me", "https://evil.example", "https://a.zalo.me:443/", "https://a.zalo.me@evil.example", "https://evil.example\\@a.zalo.me", "https://a.zalo.me#@evil.example", "https://[::ffff:c0a8:101%2525.zalo.me]", "https://[::1%25.zalo.me]", "https://x.chat.zalo.me.", "https://X.CHAT.ZALO.ME", "https://a%40evil.com.chat.zalo.me", "https://evil.com%2e.chat.zalo.me", "https://1.2.3.4", "https://[fe80::1%25chat.zalo.me]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		base, err := zaloServiceBase(raw)
		if err != nil {
			return
		}
		u, perr := url.Parse(base)
		if perr != nil || u.Scheme != "https" || u.Hostname() != strings.TrimPrefix(base, "https://") || !zaloServiceHostRE.MatchString(u.Hostname()) || u.User != nil || strings.ContainsAny(base, "@\\ #?[]%") {
			t.Fatalf("accepted %q as %q", raw, base)
		}
		if u2, err := url.Parse(raw); err != nil || !strings.EqualFold(u2.Hostname(), u.Hostname()) {
			t.Fatalf("%q was taken for host %q", raw, u.Hostname())
		}
	})
}

func FuzzZaloSetCookie(f *testing.F) {
	f.Add("zpw_sek=abc; Domain=.zalo.me; Path=/")
	f.Add("a=b; Domain=evil.example")
	f.Add("a=b; Max-Age=-1")
	f.Add("a=b\r\nX: y; Domain=zalo.me")
	f.Fuzz(func(t *testing.T, header string) {
		sess, err := parseZaloSession(zpSession)
		if err != nil {
			t.Fatal(err)
		}
		z := &zaloPersonalSender{sess: sess, jar: append([]zaloCookie(nil), sess.cookies...)}
		resp := http.Response{Header: http.Header{"Set-Cookie": {header}}}
		const host = "tt-chat1-wpa.chat.zalo.me"
		z.absorb(host, resp.Cookies(), time.Now())
		if len(z.jar) > zaloMaxCookies {
			t.Fatalf("jar has %d cookies", len(z.jar))
		}
		for _, c := range z.jar {
			if c.domain != "" && !zaloHostOK(c.domain) && c.domain != "example.com" {
				t.Fatalf("kept a cookie for %q", c.domain)
			}
		}
		if h := z.cookieHeader(host); strings.ContainsAny(h, "\r\n") {
			t.Fatalf("header injection in %q", h)
		}
	})
}

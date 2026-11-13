package channel

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the device id format
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

// qrPNG draws a 21x21 pattern at 4 pixels a cell inside a white margin: the top-left finder, one lone cell at (10, 10) and one at (20, 20).
func qrPNG(t *testing.T) []byte {
	t.Helper()
	return qrPNGBytes()
}

func qrPNGBytes() []byte {
	img := image.NewGray(image.Rect(0, 0, 21*4+16, 21*4+16))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	cell := func(cx, cy int) {
		for y := range 4 {
			for x := range 4 {
				img.SetGray(8+cx*4+x, 8+cy*4+y, color.Gray{})
			}
		}
	}
	for i := range 7 {
		cell(i, 0)
		cell(i, 6)
		cell(0, i)
		cell(6, i)
	}
	for i := range 9 {
		cell(2+i%3, 2+i/3)
	}
	cell(10, 10)
	cell(20, 20) // the far corner, so the dark box is 21 cells a side
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func zenv(code int, msg string, data any) []byte {
	b, _ := json.Marshal(map[string]any{"error_code": code, "error_message": msg, "data": data})
	return b
}

// qrFake plays id.zalo.me, chat.zalo.me, jr.chat.zalo.me and the chat services of a signed-in session, by host and path.
type qrFake struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	scanWaits  int    // waiting-scan answers 8 this many times first
	confirm    int    // error_code of waiting-confirm
	redirectTo string // where checksession sends the browser
	findCode   int    // outer error_code of findUser (0 = found)
	seen       []string
	loginCk    string // Cookie header of getLoginInfo
}

func newQRFake(t *testing.T) *qrFake {
	t.Helper()
	f := &qrFake{t: t, redirectTo: "https://chat.zalo.me/index.html"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *qrFake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Host+r.URL.Path)
	_ = r.ParseForm()
	switch r.Host + r.URL.Path {
	case "id.zalo.me/account":
		http.SetCookie(w, &http.Cookie{Name: "zpdid", Value: "DEVICEcookie0001", Domain: "id.zalo.me", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		_, _ = w.Write([]byte(`<html><script src="https://stc-zlogin.zdn.vn/main-2.44.13.js"></script></html>`))
	case "id.zalo.me/account/logininfo", "id.zalo.me/account/verify-client":
		if r.PostForm.Get("v") != "2.44.13" || r.Header.Get("User-Agent") != ZaloQRUserAgent {
			f.t.Errorf("%s: v %q ua %q", r.URL.Path, r.PostForm.Get("v"), r.Header.Get("User-Agent"))
		}
		_, _ = w.Write(zenv(0, "", nil))
	case "id.zalo.me/account/authen/qr/generate":
		if !strings.Contains(r.Header.Get("Cookie"), "zpdid=DEVICEcookie0001") {
			f.t.Errorf("generate without the login page's cookie: %q", r.Header.Get("Cookie"))
		}
		_, _ = w.Write(zenv(0, "", map[string]any{"code": "qr-code-123", "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG(f.t)), "token": "x"}))
	case "id.zalo.me/account/authen/qr/waiting-scan":
		if r.PostForm.Get("code") != "qr-code-123" {
			f.t.Errorf("waiting-scan code %q", r.PostForm.Get("code"))
		}
		if f.scanWaits > 0 {
			f.scanWaits--
			_, _ = w.Write(zenv(8, "waiting", nil))
			return
		}
		_, _ = w.Write(zenv(0, "", map[string]any{"display_name": "Vedette Alerts\u202e", "avatar": "https://s120.example/a.jpg"}))
	case "id.zalo.me/account/authen/qr/waiting-confirm":
		if r.PostForm.Get("gAction") != "CONFIRM_QR" {
			f.t.Errorf("waiting-confirm form %v", r.PostForm)
		}
		_, _ = w.Write(zenv(f.confirm, "", nil))
	case "id.zalo.me/account/checksession":
		http.SetCookie(w, &http.Cookie{Name: "zpsid", Value: "SESSIONzpsid00001", Domain: ".zalo.me", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "zpw_sek", Value: "SEKcookie0000001", Domain: "chat.zalo.me", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}) // set from id.zalo.me, as zca-js keeps it
		http.SetCookie(w, &http.Cookie{Name: "evil", Value: "NOTzaloCOOKIE0001", Domain: "example.com", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, f.redirectTo, http.StatusFound)
	case "chat.zalo.me/index.html":
		_, _ = w.Write([]byte("<html></html>"))
	case "jr.chat.zalo.me/jr/userinfo":
		_, _ = w.Write(zenv(0, "", map[string]any{"logged": true, "session_chat_valid": true, "info": map[string]any{"name": "Vedette Box", "avatar": "x"}}))
	case "wpa.chat.zalo.me/api/login/getLoginInfo":
		f.loginCk = r.Header.Get("Cookie")
		q := r.URL.Query()
		enk := zaloLoginKeyFor(q.Get("zcid"), q.Get("zcid_ext"))
		inner := zenv(0, "", map[string]any{"uid": "42", "zpw_enk": base64.StdEncoding.EncodeToString([]byte(zpKey)),
			"zpw_service_map_v3": map[string]any{"chat": []string{"https://tt-chat1-wpa.chat.zalo.me"}, "group": []string{"https://tt-group-wpa.chat.zalo.me"},
				"profile": []string{"https://tt-profile-wpa.chat.zalo.me"}, "group_poll": []string{"https://tt-group-cm.chat.zalo.me"},
				"friend": []string{"https://tt-friend-wpa.chat.zalo.me"}}})
		enc, _ := zaloEncrypt([]byte(enk), inner)
		_, _ = w.Write(zenv(0, "", enc))
	case "tt-profile-wpa.chat.zalo.me/api/social/friend/getfriends":
		f.answer(w, []map[string]any{{"userId": "7000000002", "displayName": "binh"}, {"userId": "7000000001", "displayName": "", "zaloName": "An Nguyen"},
			{"userId": "../etc", "displayName": "bad id"}})
	case "tt-group-cm.chat.zalo.me/api/group/getlg/v4":
		f.answer(w, map[string]any{"version": "1", "gridVerMap": map[string]string{"8000000002": "1", "8000000001": "1", "nope": "1"}})
	case "tt-group-wpa.chat.zalo.me/api/group/getmg-v2":
		f.answer(w, map[string]any{"gridInfoMap": map[string]any{"8000000001": map[string]any{"name": "IT team", "totalMember": 5}, "8000000002": map[string]any{"name": "Alerts", "totalMember": 3}}})
	case "tt-group-wpa.chat.zalo.me/api/group/link/ginfo":
		p := f.params(r.URL.Query().Get("params"))
		if p["link"] != "https://zalo.me/g/rowukgvsyq24kacrh4ii" {
			f.t.Errorf("group link sent as %v", p["link"])
		}
		f.answer(w, map[string]any{"groupId": "8000000009", "name": "Night shift", "totalMember": 12})
	case "tt-friend-wpa.chat.zalo.me/api/friend/profile/get":
		p := f.params(r.URL.Query().Get("params"))
		if p["phone"] != "84912345678" {
			f.t.Errorf("phone sent as %v", p["phone"])
		}
		if f.findCode != 0 {
			_, _ = w.Write(zenv(f.findCode, "not found", nil))
			return
		}
		f.answer(w, map[string]any{"uid": "7000000005", "zalo_name": "Chi", "display_name": "Chi Tran"})
	default:
		http.NotFound(w, r)
	}
}

func (f *qrFake) answer(w http.ResponseWriter, data any) {
	enc, _ := zaloEncrypt([]byte(zpKey), zenv(0, "", data))
	_, _ = w.Write(zenv(0, "", enc))
}

func (f *qrFake) params(enc string) map[string]any {
	plain, err := zaloDecrypt([]byte(zpKey), enc)
	if err != nil {
		f.t.Errorf("params do not decrypt: %v", err)
	}
	var p map[string]any
	_ = json.Unmarshal(plain, &p)
	return p
}

func startQR(t *testing.T, f *qrFake) *ZaloQR {
	t.Helper()
	q, err := StartZaloQR(context.Background(), clientTo(t, f.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	q.pollGap = 0
	return q
}

func TestContract_D447_ZaloQRSignInEndToEnd(t *testing.T) {
	t.Parallel()
	f := newQRFake(t)
	f.scanWaits = 2
	q := startQR(t, f)
	if q.QR().Size != 21+8 || !strings.HasPrefix(q.QR().Path, "M4 4h7v1h-7z") || !strings.Contains(q.QR().Path, "M14 14h1v1h-1z") {
		t.Errorf("QR redrawn as %+v", q.QR())
	}
	name, err := q.WaitScan(context.Background())
	if err != nil || name != "Vedette Alerts" { // the bidi control is cleaned off
		t.Fatalf("scan: %q, %v", name, err)
	}
	if err := q.WaitConfirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	signed, err := q.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if signed.Name != "Vedette Box" || signed.Account == nil {
		t.Errorf("signed in as %q", signed.Name)
	}
	sess, err := parseZaloSession(signed.Session.Reveal())
	uaSum := md5.Sum([]byte(ZaloQRUserAgent)) //nolint:gosec // the device id format of the web client, not a security control
	if err != nil || sess.userAgent != ZaloQRUserAgent || !strings.HasSuffix(sess.imei, "-"+hex.EncodeToString(uaSum[:])) || len(sess.imei) != 36+1+32 {
		t.Fatalf("session %+v, %v", sess, err)
	}
	names := map[string]bool{}
	for _, c := range sess.cookies {
		names[c.name] = true
	}
	if !names["zpsid"] || !names["zpw_sek"] || names["evil"] {
		t.Errorf("saved cookies %v", names)
	}
	if !strings.Contains(f.loginCk, "zpsid=SESSIONzpsid00001") || !strings.Contains(f.loginCk, "zpw_sek=SEKcookie0000001") || strings.Contains(f.loginCk, "NOTzalo") {
		t.Errorf("first sign-in cookies %q", f.loginCk)
	}
}

func TestZaloQRDeclinedAndExpired(t *testing.T) {
	t.Parallel()
	f := newQRFake(t)
	f.confirm = -13
	q := startQR(t, f)
	if _, err := q.WaitScan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := q.WaitConfirm(context.Background()); !errors.Is(err, ErrZaloQRDeclined) {
		t.Errorf("declined: %v", err)
	}
	f2 := newQRFake(t)
	f2.scanWaits = 1 << 30
	q2 := startQR(t, f2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the code's deadline has passed
	if _, err := q2.WaitScan(ctx); !errors.Is(err, ErrZaloQRExpired) {
		t.Errorf("expired: %v", err)
	}
}

func TestZaloQRRedirectStaysOnZalo(t *testing.T) {
	t.Parallel()
	f := newQRFake(t)
	f.redirectTo = "https://evil.example/steal"
	q := startQR(t, f)
	if _, err := q.WaitScan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := q.WaitConfirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := q.Finish(context.Background())
	if err == nil || strings.Contains(err.Error(), "evil") {
		t.Fatalf("redirect off Zalo: %v", err)
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "evil.example") {
			t.Errorf("followed a redirect to %s", s)
		}
	}
}

func TestZaloQRPathRefusesWhatIsNotAQRImage(t *testing.T) {
	t.Parallel()
	big := image.NewGray(image.Rect(0, 0, 2000, 30))
	var b bytes.Buffer
	_ = png.Encode(&b, big)
	white := image.NewGray(image.Rect(0, 0, 50, 50))
	for i := range white.Pix {
		white.Pix[i] = 0xff
	}
	var w bytes.Buffer
	_ = png.Encode(&w, white)
	for name, raw := range map[string][]byte{"not png": []byte("<svg/>"), "too large": b.Bytes(), "blank": w.Bytes()} {
		if _, err := zaloQRPath(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestZaloInviteLinkAndPhone(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"https://zalo.me/g/rowukgvsyq24kacrh4ii": "https://zalo.me/g/rowukgvsyq24kacrh4ii", " zalo.me/g/abcDEF123/ ": "https://zalo.me/g/abcDEF123",
		"https://evil.me/g/abcdef1": "", "https://zalo.me/g/ab": "", "https://zalo.me/g/abcdef1?x=1": "", "javascript:zalo.me/g/abcdef1": ""} {
		if got, _ := ZaloInviteLink(in); got != want {
			t.Errorf("ZaloInviteLink(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"0912345678": "84912345678", "+84 912 345 678": "84912345678", "84912.345.678": "84912345678", "12345": "", "2938475610293847561": ""} {
		if got, _ := ZaloPhone(in); got != want {
			t.Errorf("ZaloPhone(%q) = %q", in, got)
		}
	}
}

func TestZaloContactsAndLookups(t *testing.T) {
	t.Parallel()
	f := newQRFake(t)
	acct, err := NewZaloAccount(secrets.NewValue(zpSession), clientTo(t, f.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acct.Send(context.Background(), sample); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("an account without a recipient sent: %v", err)
	}
	friends, groups, err := ZaloContacts(context.Background(), acct)
	if err != nil {
		t.Fatal(err)
	}
	if len(friends) != 2 || friends[0] != (ZaloContact{ID: "7000000001", Name: "An Nguyen"}) || friends[1].Name != "binh" {
		t.Errorf("friends %+v", friends)
	}
	if len(groups) != 2 || groups[0] != (ZaloContact{ID: "8000000002", Name: "Alerts", Group: true, Members: 3}) || groups[1].Name != "IT team" {
		t.Errorf("groups %+v", groups)
	}
	g, member, err := ZaloGroupByLink(context.Background(), acct, "zalo.me/g/rowukgvsyq24kacrh4ii")
	if err != nil || g.ID != "8000000009" || g.Name != "Night shift" || !g.Group || member {
		t.Errorf("group by link %+v member %v, %v", g, member, err)
	}
	p, err := ZaloFindPhone(context.Background(), acct, "0912 345 678")
	if err != nil || p.ID != "7000000005" || p.Name != "Chi Tran" {
		t.Errorf("phone %+v, %v", p, err)
	}
	f.mu.Lock()
	f.findCode = 216
	f.mu.Unlock()
	if _, err := ZaloFindPhone(context.Background(), acct, "0912345678"); !errors.Is(err, ErrZaloNotFound) {
		t.Errorf("not found: %v", err)
	}
	if z := acct.(*zaloPersonalSender); z.failures != 0 || !z.notBefore.IsZero() {
		t.Errorf("a phone number nobody has paused sign-ins: %d %v", z.failures, z.notBefore)
	}
	if _, err := ZaloFindPhone(context.Background(), acct, "not a phone"); err == nil {
		t.Error("a bad phone number was looked up")
	}
	for _, s := range f.seen {
		if strings.Contains(s, "evil") {
			t.Errorf("request to %s", s)
		}
	}
}

package channel

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

var zpConnKey = []byte("fedcba9876543210fedcba9876543210") // the key of the fake connection (32 bytes)

func zlibOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// zaloEvent builds the body of an event frame the way the server sends it.
func zaloEvent(t testing.TB, enc int, plain []byte) []byte {
	t.Helper()
	var data string
	switch enc {
	case 0:
		data = string(plain)
	case 1:
		data = base64.StdEncoding.EncodeToString(zlibOf(t, plain))
	default:
		if enc == 2 {
			plain = zlibOf(t, plain)
		}
		blk, _ := aes.NewCipher(zpConnKey)
		gcm, _ := cipher.NewGCMWithNonceSize(blk, 16)
		iv, aad := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{9}, 16)
		data = url.QueryEscape(base64.StdEncoding.EncodeToString(append(append(append([]byte{}, iv...), aad...), gcm.Seal(nil, iv, plain, aad)...)))
	}
	b, _ := json.Marshal(map[string]any{"data": data, "encrypt": enc})
	return b
}

func userMsgs(msgs ...string) []byte {
	return []byte(`{"data":{"msgs":[` + strings.Join(msgs, ",") + `]}}`)
}

// listen opens the connection to the fake and runs it, collecting what take gets, until Run returns.
type listenRun struct {
	mu   sync.Mutex
	got  []ZaloText
	done chan error
}

func (l *listenRun) texts() []ZaloText {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ZaloText(nil), l.got...)
}

func startListen(ctx context.Context, t *testing.T, z *zaloPersonalSender) *listenRun {
	t.Helper()
	c, err := ZaloListen(ctx, z)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	l := &listenRun{done: make(chan error, 1)}
	go func() {
		l.done <- c.Run(ctx, func(m ZaloText) { l.mu.Lock(); l.got = append(l.got, m); l.mu.Unlock() })
	}()
	return l
}

func waitRun(t *testing.T, l *listenRun) error {
	t.Helper()
	select {
	case err := <-l.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// The message connection goes to the checked zpw_ws address with the session as the web client sends it, reads the key, and hands
// over only direct text messages from other accounts, whatever the encoding; Zalo handing the account to another client ends it.
func TestContract_PRE8_ZaloListenReadsDirectTexts(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	var mu sync.Mutex
	var hdr http.Header
	var query url.Values
	f.ws = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hdr, query = r.Header.Clone(), r.URL.Query()
		mu.Unlock()
		c, err := websocket.Accept(w, r, zaloAccept)
		if err != nil {
			return
		}
		ctx := r.Context()
		send := func(cmd uint16, sub byte, body []byte) {
			_ = c.Write(ctx, websocket.MessageBinary, zaloFrame(1, cmd, sub, body))
		}
		send(1, 1, []byte(`{"key":"`+base64.StdEncoding.EncodeToString(zpConnKey)+`"}`))
		_ = c.Write(ctx, websocket.MessageText, []byte(`{"not":"binary"}`))
		send(501, 0, []byte(`not json`))
		send(501, 0, zaloEvent(t, 2, userMsgs(
			`{"msgId":"1","uidFrom":"2938475610293847561","idTo":"0","dName":"Lan`+"\u202e"+`","content":" a-7kq2mx "}`,
			`{"msgId":"2","uidFrom":"0","idTo":"2938475610293847561","content":"from the box itself"}`,
			`{"msgId":"3","uidFrom":"42","content":"self by id"}`,
			`{"msgId":"4","uidFrom":"2938475610293847561","content":{"title":"a picture"}}`,
			`{"msgId":"5","uidFrom":"2938475610293847561","content":{"deleteMsg":{}}}`,
			`{"msgId":"6","uidFrom":"evil","content":"bad sender"}`,
			`{"msgId":"7","uidFrom":9007199254740993123,"content":"big number id"}`)))
		send(521, 0, zaloEvent(t, 0, []byte(`{"data":{"groupMsgs":[{"uidFrom":"5555555","content":"group text"}]}}`)))
		send(501, 0, zaloEvent(t, 0, userMsgs(`{"uidFrom":"1111111","content":"plain"}`)))
		send(501, 0, zaloEvent(t, 1, userMsgs(`{"uidFrom":"2222222","content":"zlib"}`)))
		send(501, 0, zaloEvent(t, 3, userMsgs(`{"uidFrom":"3333333","content":"gcm"}`)))
		send(501, 0, zaloEvent(t, 4, userMsgs(`{"uidFrom":"4444444","content":"unknown encoding"}`)))
		send(3000, 0, []byte(`{}`))
		<-c.CloseRead(ctx).Done() // answers the client's close at once
	}
	z := newZPSender(t, f, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := startListen(ctx, t, z)
	if err := waitRun(t, l); !errors.Is(err, ErrZaloReplaced) {
		t.Fatalf("Run = %v, want ErrZaloReplaced", err)
	}
	want := []ZaloText{{ID: "1", From: "2938475610293847561", Name: "Lan", Text: " a-7kq2mx "}, {ID: "7", From: "9007199254740993123", Text: "big number id"},
		{From: "1111111", Text: "plain"}, {From: "2222222", Text: "zlib"}, {From: "3333333", Text: "gcm"}}
	if got := l.texts(); len(got) != len(want) {
		t.Fatalf("texts = %+v", got)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("text %d = %+v, want %+v", i, got[i], want[i])
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wsHosts[0] != "ws1-msg.chat.zalo.me" || hdr.Get("Origin") != "https://chat.zalo.me" || hdr.Get("User-Agent") != "Mozilla/5.0 (X11; Linux x86_64) TestAgent" {
		t.Errorf("handshake host %v headers %v", f.wsHosts, hdr)
	}
	if c := hdr.Get("Cookie"); !strings.Contains(c, "zpsid="+zpSID) || !strings.Contains(c, "zpw_sek="+zpRotate) || strings.Contains(c, zpOther) {
		t.Errorf("handshake cookies %q", c)
	}
	if query.Get("zpw_ver") != "685" || query.Get("zpw_type") != "30" || query.Get("t") == "" {
		t.Errorf("handshake query %v", query)
	}
	if f.logins != 1 {
		t.Errorf("sign-ins = %d", f.logins)
	}
}

// The key frame starts the ping of the web client, at the interval the server info asked for.
func TestZaloListenPings(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	pinged := make(chan []byte, 1)
	f.ws = func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, zaloAccept)
		if err != nil {
			return
		}
		_ = c.Write(r.Context(), websocket.MessageBinary, zaloFrame(1, 1, 1, []byte(`{"key":"`+base64.StdEncoding.EncodeToString(zpConnKey)+`"}`)))
		_, b, err := c.Read(r.Context())
		if err == nil {
			pinged <- b
		}
		<-c.CloseRead(r.Context()).Done()
	}
	z := newZPSender(t, f, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := ZaloListen(ctx, z)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ping != zaloPingDefault {
		t.Errorf("ping = %v, want the default when the server info names none", c.ping)
	}
	c.ping = 20 * time.Millisecond
	go func() { _ = c.Run(ctx, func(ZaloText) {}) }()
	select {
	case b := <-pinged:
		if len(b) < 4 || b[0] != 1 || b[1] != 2 || b[2] != 0 || b[3] != 1 || !strings.HasPrefix(string(b[4:]), `{"eventId":`) {
			t.Errorf("ping frame %q", b)
		}
	case <-ctx.Done():
		t.Fatal("no ping")
	}
}

// A refused handshake is the listener's own failure: it neither forgets the session nor pauses the channel's sign-ins, so alerts keep
// going; a kick (close 3003) is a takeover.
func TestZaloListenRefusedAndKicked(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	var refuse atomic.Bool
	refuse.Store(true)
	f.ws = func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		c, err := websocket.Accept(w, r, zaloAccept)
		if err != nil {
			return
		}
		_ = c.Close(zaloCloseKick, "kicked")
	}
	z := newZPSender(t, f, nil)
	ctx := context.Background()
	_, err := ZaloListen(ctx, z)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusForbidden {
		t.Fatalf("refused handshake = %v", err)
	}
	if z.li == nil || !z.notBefore.IsZero() || z.failures != 0 {
		t.Fatalf("a refused handshake touched the shared session: li %v pause %v failures %d", z.li != nil, z.notBefore, z.failures)
	}
	if _, err := z.Send(ctx, sample); err != nil || f.logins != 1 {
		t.Fatalf("alert after a refused handshake = %v, sign-ins %d", err, f.logins)
	}
	refuse.Store(false)
	c, err := ZaloListen(ctx, z)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Run(ctx, func(ZaloText) {}); !errors.Is(err, ErrZaloReplaced) {
		t.Errorf("kicked = %v", err)
	}
}

// No message connection without a checked address: the sign-in answer's zpw_ws must be wss under chat.zalo.me.
func TestZaloSocketAddresses(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"wss://ws1-msg.chat.zalo.me":           "wss://ws1-msg.chat.zalo.me/",
		"wss://WS2-MSG.chat.zalo.me:443/":      "wss://ws2-msg.chat.zalo.me/",
		"wss://ws1-msg.chat.zalo.me/ws/v2":     "wss://ws1-msg.chat.zalo.me/ws/v2",
		"ws://ws1-msg.chat.zalo.me":            "",
		"https://ws1-msg.chat.zalo.me":         "",
		"wss://chat.zalo.me":                   "",
		"wss://ws1-msg.chat.zalo.me.evil.test": "",
		"wss://evil.test/ws1-msg.chat.zalo.me": "",
		"wss://u:p@ws1-msg.chat.zalo.me":       "",
		"wss://ws1-msg.chat.zalo.me:8443":      "",
		"wss://ws1-msg.chat.zalo.me/?a=b":      "",
		"wss://ws1-msg.chat.zalo.me/#f":        "",
		"wss://ws1-msg.chat.zalo.me/%2e%2e":    "",
		"wss://ws1-msg.chat.zalo.me/../x":      "",
		"wss://ws1-msg.chat.zalo.me.":          "",
		"wss://[::1]":                          "",
		"wss://1.2.3.4":                        "",
		"":                                     "",
	} {
		got, ok := zaloSocketBase(in)
		if got != want || ok != (want != "") {
			t.Errorf("zaloSocketBase(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	self, ws := parseZaloListenInfo(json.RawMessage(`{"uid":"42","zpw_ws":["wss://evil.test","wss://ws1-msg.chat.zalo.me","wss://ws2-msg.chat.zalo.me"]}`))
	if self != "42" || len(ws) != 2 || ws[0] != "wss://ws1-msg.chat.zalo.me/" {
		t.Errorf("listen info %q %v", self, ws)
	}
	if self, ws := parseZaloListenInfo(json.RawMessage(`{"uid":"0","zpw_ws":"wss://ws1-msg.chat.zalo.me"}`)); self != "" || ws != nil {
		t.Errorf("bad listen info %q %v", self, ws)
	}
}

func TestZaloPingInterval(t *testing.T) {
	t.Parallel()
	env := func(data string) []byte { return []byte(`{"error_code":0,"data":` + data + `}`) }
	for in, want := range map[string]time.Duration{
		`{"setttings":{"features":{"socket":{"ping_interval":20000}}}}`:  20 * time.Second,
		`{"settings":{"features":{"socket":{"ping_interval":30000}}}}`:   30 * time.Second,
		`{"settings":{"features":{"socket":{"ping_interval":5}}}}`:       zaloPingFloor,
		`{"settings":{"features":{"socket":{"ping_interval":3000000}}}}`: zaloPingCeiling,
		`{"settings":{"features":{"socket":{"ping_interval":-1}}}}`:      0,
		`{"settings":{"features":{"socket":{"ping_interval":"x"}}}}`:     0,
		`{"settings":{}}`: 0,
		`null`:            0,
	} {
		if got := parseZaloPing(env(in)); got != want {
			t.Errorf("parseZaloPing(%s) = %v, want %v", in, got, want)
		}
	}
	if got := parseZaloPing([]byte(`{"error_code":1,"data":{"settings":{"features":{"socket":{"ping_interval":20000}}}}}`)); got != 0 {
		t.Errorf("refused answer = %v", got)
	}
}

// An event that inflates past the cap is refused, not cut.
func TestZaloEventIsCapped(t *testing.T) {
	t.Parallel()
	big := userMsgs(`{"uidFrom":"1111111","content":"` + strings.Repeat("x", zaloMaxEvent) + `"}`)
	if _, err := parseZaloUserMessages(zaloEvent(t, 1, big), nil, ""); err == nil {
		t.Error("an event over the cap was read")
	}
	if _, err := parseZaloUserMessages(zaloEvent(t, 2, userMsgs()), nil, ""); err == nil {
		t.Error("an encrypted event was read without a key")
	}
	long := userMsgs(`{"uidFrom":"1111111","content":"` + strings.Repeat("y", zaloMaxText+50) + `"}`)
	if got, err := parseZaloUserMessages(zaloEvent(t, 0, long), nil, ""); err != nil || len(got) != 1 || len(got[0].Text) != zaloMaxText {
		t.Errorf("long text: %d, %v", len(got), err)
	}
}

// The answer to a reply is the title alone, only through the direct sender of the person who replied.
func TestZaloReplyAnswerIsPlainAndDirectOnly(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	z := newZPSender(t, f, nil)
	m := Message{Kind: KindReply, Severity: "info", Title: "Approved. " + strings.Repeat("z", 400), Link: "https://192.0.2.1/x"}
	if _, err := z.Send(context.Background(), m); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("channel send of an answer = %v", err)
	}
	d, err := ZaloPersonalTo(z, "2938475610293847561")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	msg, _ := f.sent[0]["message"].(string)
	if !strings.HasPrefix(msg, "Approved. zzz") || len([]rune(msg)) != zaloReplyMax || strings.Contains(msg, "192.0.2.1") || strings.Contains(msg, "Info:") || f.sent[0]["toid"] != "2938475610293847561" {
		t.Errorf("answer %q to %v", msg, f.sent[0]["toid"])
	}
}

func FuzzZaloUserMessages(f *testing.F) {
	f.Add(zaloEvent(f, 0, userMsgs(`{"uidFrom":"1111111","content":"A-7KQ2MX","dName":"x"}`)), []byte(nil))
	f.Add(zaloEvent(f, 1, userMsgs(`{"uidFrom":2222222,"content":"x"}`)), []byte(nil))
	f.Add(zaloEvent(f, 2, userMsgs(`{"uidFrom":"3333333","content":"x"}`)), zpConnKey)
	f.Add(zaloEvent(f, 3, userMsgs(`{"uidFrom":"3333333","content":{"a":1}}`)), zpConnKey)
	f.Add([]byte(`{"data":"%zz","encrypt":2}`), zpConnKey)
	f.Fuzz(func(t *testing.T, body, key []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			key = nil
		}
		got, err := parseZaloUserMessages(body, key, "42")
		if err != nil && got != nil {
			t.Fatal("messages with an error")
		}
		if len(got) > zaloMaxMsgs {
			t.Fatalf("%d messages", len(got))
		}
		for _, m := range got {
			if !zaloUIDRE.MatchString(m.From) || m.From == "42" || strings.Trim(m.From, "0") == "" || len(m.Text) > zaloMaxText || len([]rune(m.Name)) > 64 {
				t.Fatalf("message %+v", m)
			}
		}
	})
}

func FuzzZaloSocketBase(f *testing.F) {
	for _, s := range []string{"wss://ws1-msg.chat.zalo.me", "wss://a.chat.zalo.me:443/x/y", "wss://chat.zalo.me.evil", "wss://x.chat.zalo.me/../a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, ok := zaloSocketBase(raw)
		if !ok {
			return
		}
		u, err := url.Parse(got)
		if err != nil || u.Scheme != "wss" || !zaloServiceHostOK(u.Host) || u.RawQuery != "" || strings.Contains(u.Path, "..") {
			t.Fatalf("zaloSocketBase(%q) = %q", raw, got)
		}
	})
}

// zaloAccept takes the Origin the web client sends (the library refuses a cross-origin handshake by default).
var zaloAccept = &websocket.AcceptOptions{OriginPatterns: []string{"chat.zalo.me"}}

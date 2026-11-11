package channel

// The reply listener of the Zalo personal channel (slice 4b, D-243): the message connection of the Zalo web client, read from zca-js
// v2.2.0 `listen.ts` (MIT) and re-implemented here. EXPERIMENTAL: nothing in it is documented by Zalo and it has not been checked
// against a real account yet (lab line in .ai/deferred/feat-notify-listeners.md). Everything that comes in is untrusted: frames are
// capped, decoding fails closed, a frame that cannot be read is skipped, and only direct text messages from another account leave
// this file.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// KindReply is the Kind of a private answer to an approver's reply: only the sender of ZaloPersonalTo takes it, and it sends the
// Title alone (at most zaloReplyMax characters).
const KindReply = "reply"

const (
	zaloReplyMax     = 300
	zaloMaxFrame     = 512 << 10 // one frame off the connection
	zaloMaxEvent     = 1 << 20   // one event once decrypted and inflated
	zaloMaxMsgs      = 200       // messages taken from one event
	zaloMaxText      = 2000      // bytes of one message kept (a code is 8)
	zaloDialWait     = 15 * time.Second
	zaloPingDefault  = time.Minute
	zaloPingMin      = 10 * time.Second
	zaloPingMax      = 10 * time.Minute
	zaloCloseReplace = 3000 // DuplicateConnection: the server, or the client after cmd 3000
	zaloCloseKick    = 3003 // KickConnection
)

// ErrZaloReplaced means Zalo ended the connection because another client of the same account opened one (Zalo Web, another
// listener): one account holds one connection. Reconnecting at once would take it back and the two would kick each other.
var ErrZaloReplaced = errors.New("notify: zalo-personal: another Zalo client of this account took over the message connection")

// ZaloText is a direct text message to the box's account from another account: From is the sender's Zalo user ID (digits), Name the
// display name the sender chose (untrusted, cleaned, at most 64 characters), Text the content (at most zaloMaxText bytes, uncleaned:
// only a reply code is ever acted on).
type ZaloText struct {
	From, Name, Text string
}

// ZaloConn is one open message connection.
type ZaloConn struct {
	c    *websocket.Conn
	self string
	ping time.Duration
}

// ZaloListen opens the message connection of the Zalo personal channel whose sender is snd, over its session: same sign-in, same
// sign-in pause, so a sign-in the listener needs is rationed with the sends (D-46). The address comes from the sign-in answer
// (zpw_ws), checked like every Zalo address before any cookie goes to it.
func ZaloListen(ctx context.Context, snd Sender) (*ZaloConn, error) {
	z, ok := snd.(*zaloPersonalSender)
	if !ok {
		return nil, errors.New("notify: zalo-personal: listening needs the Zalo personal channel")
	}
	t, err := z.socketTarget(ctx)
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, zaloDialWait)
	defer cancel()
	c, resp, err := websocket.Dial(dctx, t.url, &websocket.DialOptions{HTTPClient: z.client, HTTPHeader: t.header})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.Is(err, context.DeadlineExceeded):
			return nil, &ProviderError{Channel: ZaloPersonal, Reason: "timed out connecting to Zalo"}
		case resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden):
			z.refused() // the session is refused: the next sign-in waits, like a refused send
			return nil, &StatusError{Channel: ZaloPersonal, Code: resp.StatusCode}
		}
		return nil, &ProviderError{Channel: ZaloPersonal, Reason: "could not connect to Zalo"} // never the text of err: it holds the address
	}
	c.SetReadLimit(zaloMaxFrame)
	z.connected()
	return &ZaloConn{c: c, self: t.self, ping: t.ping}, nil
}

// zaloSocket is what one dial needs, taken under the sender's lock.
type zaloSocket struct {
	url    string
	header http.Header
	self   string
	ping   time.Duration
}

// socketTarget signs in when the sender has no fresh session (honouring the sign-in pause) and returns the address and headers of
// the message connection: the cookies of chat.zalo.me, the saved user agent, Origin chat.zalo.me, as the web client sends them.
func (z *zaloPersonalSender) socketTarget(ctx context.Context) (zaloSocket, error) {
	select {
	case z.sem <- struct{}{}:
	case <-ctx.Done():
		return zaloSocket{}, ctx.Err()
	}
	defer func() { <-z.sem }()
	if z.li == nil || z.now().Sub(z.li.at) > zaloLoginTTL {
		if now := z.now(); now.Before(z.notBefore) {
			return zaloSocket{}, &BackoffError{Channel: ZaloPersonal, Until: z.notBefore}
		}
		if err := z.signIn(ctx); err != nil {
			z.fail()
			return zaloSocket{}, err
		}
	}
	if len(z.li.ws) == 0 {
		return zaloSocket{}, badAnswer("the sign-in answer named no address for the message connection")
	}
	u := z.li.ws[0] + "?" + url.Values{"zpw_ver": {strconv.Itoa(zaloAPIVersion)}, "zpw_type": {strconv.Itoa(zaloAPIType)}, "t": {strconv.FormatInt(z.now().UnixMilli(), 10)}}.Encode()
	h := http.Header{}
	h.Set("Origin", "https://chat.zalo.me")
	h.Set("User-Agent", z.sess.userAgent)
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Cache-Control", "no-cache")
	if c := z.cookieHeader("chat.zalo.me"); c != "" {
		h.Set("Cookie", c)
	}
	ping := z.li.ping
	if ping == 0 {
		ping = zaloPingDefault
	}
	return zaloSocket{url: u, header: h, self: z.li.self, ping: ping}, nil
}

// connected clears the failure count once Zalo took the session for the message connection (a sign-in alone does not: a session
// Zalo then refuses would sign in again every minute).
func (z *zaloPersonalSender) connected() {
	z.sem <- struct{}{}
	defer func() { <-z.sem }()
	z.failures = 0
}

// refused forgets the session after Zalo refused it and arms the sign-in pause.
func (z *zaloPersonalSender) refused() {
	z.sem <- struct{}{}
	defer func() { <-z.sem }()
	z.li = nil
	z.fail()
}

// Close ends the connection.
func (c *ZaloConn) Close() { _ = c.c.Close(websocket.StatusNormalClosure, "") }

// Run reads the connection until ctx ends (it returns ctx.Err()), Zalo hands the account to another client (ErrZaloReplaced) or the
// connection fails. take is called on the read loop, once per direct text message from another account, in order: it must not block.
// Once Zalo has sent the key of the connection, a ping goes out every interval the server info asked for (1 minute when it named
// none, kept within 10 seconds and 10 minutes).
func (c *ZaloConn) Run(ctx context.Context, take func(ZaloText)) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	var key []byte
	for {
		typ, b, err := c.c.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if s := websocket.CloseStatus(err); s == zaloCloseReplace || s == zaloCloseKick {
				return ErrZaloReplaced
			}
			return &ProviderError{Channel: ZaloPersonal, Reason: "the connection to Zalo ended"}
		}
		if typ != websocket.MessageBinary || len(b) <= 4 {
			continue
		}
		version, cmd, sub, body := b[0], binary.LittleEndian.Uint16(b[1:3]), b[3], b[4:]
		if version != 1 {
			continue
		}
		switch {
		case cmd == 1 && sub == 1:
			k, ok := parseZaloConnKey(body)
			if !ok {
				continue
			}
			if key == nil {
				wg.Go(func() { c.pinger(ctx) })
			}
			key = k
		case cmd == 3000 && sub == 0:
			_ = c.c.Close(zaloCloseReplace, "")
			return ErrZaloReplaced
		case cmd == 501 && sub == 0:
			msgs, err := parseZaloUserMessages(body, key, c.self)
			if err != nil {
				continue // an event that cannot be read is skipped: it was never ours to trust
			}
			for _, m := range msgs {
				take(m)
			}
		}
	}
}

// pinger sends the keep-alive frame of the web client until ctx ends or a write fails (then the read loop sees the end too).
func (c *ZaloConn) pinger(ctx context.Context) {
	t := time.NewTicker(c.ping)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if c.c.Write(ctx, websocket.MessageBinary, zaloFrame(1, 2, 1, []byte(`{"eventId":`+strconv.FormatInt(time.Now().UnixMilli(), 10)+`}`))) != nil {
			return
		}
	}
}

// zaloFrame is the frame layout of both directions: version, cmd (uint16 little-endian), subCmd, then the JSON.
func zaloFrame(version byte, cmd uint16, sub byte, body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	out[0], out[3] = version, sub
	binary.LittleEndian.PutUint16(out[1:3], cmd)
	return append(out, body...)
}

// ---- the sign-in and server info answers ----

var zaloSocketPathRE = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)*/?$`)

// zaloSocketBase checks one address of the message connection before any cookie goes to it: wss, a host under chat.zalo.me
// (zaloServiceHostRE, lower-cased), no credentials, port 443 or none, a plain path, no query or fragment. Anything bracketed,
// percent-encoded or with a backslash is refused outright. The address is rebuilt from the checked parts.
func zaloSocketBase(raw string) (string, bool) {
	if strings.ContainsAny(raw, `[]%\?#`) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" || u.User != nil || u.Opaque != "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" ||
		(u.Port() == "" && strings.Contains(u.Host, ":")) || (u.Port() != "" && u.Port() != "443") || !zaloSocketPathRE.MatchString(u.Path) {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if !zaloServiceHostOK(host) {
		return "", false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return "wss://" + host + path, true
}

var zaloUIDRE = regexp.MustCompile(`^[0-9]{1,25}$`)

// parseZaloListenInfo takes what the listener needs from the sign-in answer: the user ID of the box's own account ("" when it is not
// one) and the addresses of the message connection that pass zaloSocketBase, at most 8.
func parseZaloListenInfo(data json.RawMessage) (self string, ws []string) {
	var info struct {
		UID json.RawMessage `json:"uid"`
		WS  []string        `json:"zpw_ws"`
	}
	if json.Unmarshal(data, &info) != nil {
		return "", nil
	}
	if id := strings.Trim(string(info.UID), `"`); zaloUIDRE.MatchString(id) && strings.Trim(id, "0") != "" {
		self = id
	}
	for _, w := range info.WS {
		if b, ok := zaloSocketBase(w); ok && len(ws) < 8 {
			ws = append(ws, b)
		}
	}
	return self, ws
}

// parseZaloPing reads settings.features.socket.ping_interval (milliseconds) from the server info answer, which is plain JSON
// {error_code, data: {settings | setttings}} (Zalo spells it "setttings" today). 0 = not given; otherwise kept within
// zaloPingMin..zaloPingMax.
func parseZaloPing(body []byte) time.Duration {
	env, ok := parseZaloEnvelope(body)
	if !ok || env.check(true, nil) != nil {
		return 0
	}
	type socket struct {
		Features struct {
			Socket struct {
				Ping *float64 `json:"ping_interval"`
			} `json:"socket"`
		} `json:"features"`
	}
	var d struct {
		Settings  *socket `json:"settings"`
		Setttings *socket `json:"setttings"`
	}
	if json.Unmarshal(env.Data, &d) != nil {
		return 0
	}
	s := d.Setttings
	if s == nil {
		s = d.Settings
	}
	if s == nil || s.Features.Socket.Ping == nil || *s.Features.Socket.Ping <= 0 || *s.Features.Socket.Ping > float64(time.Hour/time.Millisecond) {
		return 0
	}
	return min(max(time.Duration(*s.Features.Socket.Ping)*time.Millisecond, zaloPingMin), zaloPingMax)
}

// ---- events ----

// parseZaloConnKey reads the first frame of a connection, {"key": "<base64>"}: the AES-GCM key of its events (16, 24 or 32 bytes).
func parseZaloConnKey(body []byte) ([]byte, bool) {
	m, ok := jsonObject(body)
	if !ok {
		return nil, false
	}
	var k string
	if json.Unmarshal(m["key"], &k) != nil {
		return nil, false
	}
	key, err := base64.StdEncoding.DecodeString(k)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		return nil, false
	}
	return key, true
}

var errZaloEvent = errors.New("the event could not be read")

// decodeZaloEvent opens the body of an event frame, {"data": "<text>", "encrypt": 0..3}: 0 = data is the JSON; 1 = base64 of a
// zlib stream; 2 = URI-escaped base64 of iv(16) | aad(16) | ciphertext+tag, AES-GCM with the key of the connection, then zlib; 3 =
// as 2 without zlib. A gzip stream is taken where zlib is (pako, which zca-js uses, reads both). The result is capped at zaloMaxEvent.
func decodeZaloEvent(body, key []byte) ([]byte, error) {
	m, ok := jsonObject(body)
	if !ok {
		return nil, errZaloEvent
	}
	var data string
	var enc int
	if json.Unmarshal(m["data"], &data) != nil || json.Unmarshal(m["encrypt"], &enc) != nil || enc < 0 || enc > 3 {
		return nil, errZaloEvent
	}
	if enc == 0 {
		return []byte(data), nil
	}
	if enc != 1 {
		t, err := url.PathUnescape(data)
		if err != nil {
			return nil, errZaloEvent
		}
		data = t
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(data); err != nil {
			return nil, errZaloEvent
		}
	}
	if enc != 1 {
		if len(raw) < 48 || key == nil {
			return nil, errZaloEvent
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, errZaloEvent
		}
		gcm, err := cipher.NewGCMWithNonceSize(blk, 16)
		if err != nil {
			return nil, errZaloEvent
		}
		if raw, err = gcm.Open(nil, raw[:16], raw[32:], raw[16:32]); err != nil {
			return nil, errZaloEvent
		}
		if enc == 3 {
			if len(raw) > zaloMaxEvent {
				return nil, errZaloEvent
			}
			return raw, nil
		}
	}
	return inflateZalo(raw)
}

// inflateZalo inflates a zlib (or gzip) stream into at most zaloMaxEvent bytes; more is an error, not a cut.
func inflateZalo(raw []byte) ([]byte, error) {
	var r io.ReadCloser
	var err error
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		r, err = gzip.NewReader(bytes.NewReader(raw))
	} else {
		r, err = zlib.NewReader(bytes.NewReader(raw))
	}
	if err != nil {
		return nil, errZaloEvent
	}
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, zaloMaxEvent+1))
	if err != nil || len(out) > zaloMaxEvent {
		return nil, errZaloEvent
	}
	return out, nil
}

// parseZaloUserMessages reads an event of cmd 501 ({"data": {"msgs": [...]}}) and returns the direct text messages from other
// accounts: content is a JSON string (an object is a file, a picture, a card or a recall), uidFrom is a user ID that is neither
// "0" nor self (both mean the box's own account). Ids may exceed 2^53, so they are read as text.
func parseZaloUserMessages(body, key []byte, self string) ([]ZaloText, error) {
	plain, err := decodeZaloEvent(body, key)
	if err != nil {
		return nil, err
	}
	var ev struct {
		Data struct {
			Msgs []json.RawMessage `json:"msgs"`
		} `json:"data"`
	}
	if json.Unmarshal(plain, &ev) != nil {
		return nil, errZaloEvent
	}
	var out []ZaloText
	for i, raw := range ev.Data.Msgs {
		if i == zaloMaxMsgs {
			break
		}
		m, ok := jsonObject(raw)
		if !ok {
			continue
		}
		from := strings.Trim(string(m["uidFrom"]), `"`)
		if !zaloUIDRE.MatchString(from) || strings.Trim(from, "0") == "" || from == self {
			continue
		}
		var text string
		if c := bytes.TrimSpace(m["content"]); len(c) == 0 || c[0] != '"' || json.Unmarshal(c, &text) != nil {
			continue
		}
		if len(text) > zaloMaxText {
			text = text[:zaloMaxText]
		}
		var name string
		_ = json.Unmarshal(m["dName"], &name) // absent or not a string: no name
		out = append(out, ZaloText{From: from, Name: Line(name, 64), Text: text})
	}
	return out, nil
}

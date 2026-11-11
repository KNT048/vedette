package notify_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Slack tokens are built at run time: GitHub push protection blocks fake secrets of these shapes in source.
var (
	slackBotTok = strings.Join([]string{"xoxb", "1111111111", "fakefakefake"}, "-")
	slackAppTok = strings.Join([]string{"xapp", "1", "A0FAKEAPP1", "2222222222", "fakefakefake"}, "-")
)

const (
	slChannel = "C04ABCDEF12"
	slTeam    = "T0EXAMPLE1"
	slUser    = "U04ABCD1234"
	slTS      = "1731326400.000100"
)

// fakeSlack is Slack as one TLS server: the Web API (slack.com), Socket Mode (wss-primary.slack.com) and response URLs (hooks.slack.com).
// Hosts in URLs stay real; the transport sends every dial to this server, so the allowlists are exercised and nothing dials out.
type fakeSlack struct {
	srv       *httptest.Server
	mu        sync.Mutex
	posts     []map[string]any // chat.postMessage bodies
	replies   []map[string]any // bodies posted to response URLs
	hosts     []string         // every Host the server saw
	reqs      []string         // every Host+path the server saw
	auths     []string         // Authorization headers of the Web API
	socketURL string           // what apps.connections.open answers; "" = a good one
	conns     chan *slackConn
	acks      chan string
	postTS    string
	team      string
	authTests int
}

type slackConn struct{ out chan []byte }

func newFakeSlack(t *testing.T) *fakeSlack {
	t.Helper()
	f := &fakeSlack{conns: make(chan *slackConn, 16), acks: make(chan string, 64), postTS: slTS, team: slTeam}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) client() *http.Client {
	addr := f.srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a test server with its own certificate; every host name stays the real one
	}}
}

func (f *fakeSlack) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hosts = append(f.hosts, r.Host)
	f.reqs = append(f.reqs, r.Host+r.URL.Path)
	f.mu.Unlock()
	switch {
	case r.Host == "slack.com" && r.URL.Path == "/api/auth.test":
		f.mu.Lock()
		f.authTests++
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		team := f.team
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true,"team_id":"`+team+`"}`)
	case r.Host == "slack.com" && r.URL.Path == "/api/apps.connections.open":
		f.mu.Lock()
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		u := f.socketURL
		f.mu.Unlock()
		if u == "" {
			u = "wss://wss-primary.slack.com/link/?ticket=SECRETTICKET&app_id=A0FAKEAPP1"
		}
		_, _ = io.WriteString(w, `{"ok":true,"url":`+jsonStr(u)+`}`)
	case r.Host == "slack.com" && r.URL.Path == "/api/chat.postMessage":
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.mu.Lock()
		f.posts = append(f.posts, m)
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		ts := f.postTS
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true,"channel":"`+slChannel+`","ts":"`+ts+`"}`)
	case r.Host == "wss-primary.slack.com" && strings.HasPrefix(r.URL.Path, "/link"):
		f.socket(w, r)
	case r.Host == "hooks.slack.com" && strings.HasPrefix(r.URL.Path, "/actions/"):
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.mu.Lock()
		f.replies = append(f.replies, m)
		f.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	default:
		http.NotFound(w, r)
	}
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func (f *fakeSlack) socket(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	sc := &slackConn{out: make(chan []byte, 16)}
	f.conns <- sc
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		defer cancel()
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			var a struct {
				EnvelopeID string `json:"envelope_id"`
			}
			_ = json.Unmarshal(b, &a)
			f.acks <- a.EnvelopeID
		}
	}()
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"hello","num_connections":1}`))
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-sc.out:
			if b == nil {
				_ = c.Close(websocket.StatusNormalClosure, "")
				return
			}
			if c.Write(ctx, websocket.MessageText, b) != nil {
				return
			}
		}
	}
}

func (f *fakeSlack) conn(t *testing.T) *slackConn {
	t.Helper()
	select {
	case c := <-f.conns:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never connected")
		return nil
	}
}

func (f *fakeSlack) ack(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-f.acks:
		if got != want {
			t.Fatalf("acknowledged %q, want %q", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("envelope %q was not acknowledged", want)
	}
}

func (f *fakeSlack) reply(t *testing.T) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.replies) > 0 {
			r := f.replies[0]
			f.replies = f.replies[1:]
			f.mu.Unlock()
			return r
		}
		f.mu.Unlock()
		time.Sleep(10 * time.Millisecond) //nolint:forbidigo // test polling of a fake
	}
	t.Fatal("no private reply was sent")
	return nil
}

func (f *fakeSlack) noReply(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.replies) != 0 {
		t.Fatalf("unexpected reply: %v", f.replies)
	}
}

func (f *fakeSlack) sawHost(h string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.hosts {
		if x == h {
			return true
		}
	}
	return false
}

type slPress struct {
	env, team, user, channel, ts, action, value, respURL string
}

func (p slPress) json() []byte {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&p.env, "env-1")
	def(&p.team, slTeam)
	def(&p.user, slUser)
	def(&p.channel, slChannel)
	def(&p.ts, slTS)
	def(&p.action, "vedette_a")
	def(&p.value, "a:act-1")
	def(&p.respURL, "https://hooks.slack.com/actions/T0EXAMPLE1/123456/abcDEF")
	payload := `{"type":"block_actions","team":{"id":"` + p.team + `"},"user":{"id":"` + p.user + `"},"channel":{"id":"` + p.channel +
		`"},"container":{"type":"message","message_ts":"` + p.ts + `","channel_id":"` + p.channel + `"},"response_url":` + jsonStr(p.respURL) +
		`,"actions":[{"action_id":"` + p.action + `","value":"` + p.value + `"}]}`
	return []byte(`{"type":"interactive","envelope_id":"` + p.env + `","payload":` + payload + `}`)
}

type slEnv struct {
	*env
	sl      *fakeSlack
	dec     *recDecisions
	decided chan map[string]string
}

func newSLEnv(t *testing.T, opts ...func(*notify.Config)) *slEnv {
	t.Helper()
	sl, dec := newFakeSlack(t), &recDecisions{res: notify.DecisionResult{Status: "approved", Message: "Approved. Block 203.0.113.9 is being run."}}
	opts = append([]func(*notify.Config){func(c *notify.Config) { c.HTTPClient = sl.client(); c.Decisions = dec }}, opts...)
	se := &slEnv{env: newEnv(t, opts...), sl: sl, dec: dec, decided: make(chan map[string]string, 16)}
	se.bus.Subscribe("notify.approval.decided", func(_ context.Context, ev events.Event) error {
		m, _ := ev.Data.(map[string]string)
		se.decided <- m
		return nil
	})
	se.saveSlack(true)
	return se
}

func (se *slEnv) saveSlack(approvals bool) {
	se.save(channel.Slack, notify.ChannelInput{Enabled: true, Fields: map[string]string{"label": "#it-alerts", "channel_id": slChannel}, Secret: slackURL,
		AppToken: slackAppTok, BotToken: slackBotTok, MinSeverity: notify.Low, Approvals: approvals,
		Approvers: []notify.Approver{{UserID: "u-admin", Address: slUser}}})
}

func (se *slEnv) job() jobs.Job {
	se.t.Helper()
	for _, j := range se.svc.Jobs() {
		if j.Name == "slack-listen" {
			return j
		}
	}
	se.t.Fatal("no slack-listen job")
	return jobs.Job{}
}

// listen starts the job and returns the first connection and a stop that fails the test when the job does not stop on ctx.
func (se *slEnv) listen() (*slackConn, func() error) {
	se.t.Helper()
	ctx, cancel := context.WithCancel(se.ctx())
	done := make(chan error, 1)
	j := se.job()
	go func() { done <- j.Run(ctx) }()
	var once sync.Once
	var err error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				se.t.Error("the listener did not stop when ctx ended")
			}
		})
		return err
	}
	se.t.Cleanup(func() { _ = stop() })
	return se.sl.conn(se.t), stop
}

func (se *slEnv) request() {
	se.t.Helper()
	if _, err := se.svc.SendApprovalRequest(se.ctx(), se.approvalReq("act-1", channel.Slack)); err != nil {
		se.t.Fatal(err)
	}
}

func (se *slEnv) noDecision(t *testing.T) {
	t.Helper()
	if got := se.dec.got(); len(got) != 0 {
		t.Fatalf("Decide called: %+v", got)
	}
	select {
	case m := <-se.decided:
		t.Fatalf("notify.approval.decided published: %v", m)
	default:
	}
}

func TestContract_PRE8_SlackApprovalIsPostedWithButtonsAndKeptByTS(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	if len(se.sl.posts) != 1 {
		t.Fatalf("posts = %d", len(se.sl.posts))
	}
	p := se.sl.posts[0]
	if p["channel"] != slChannel {
		t.Fatalf("posted to %v", p["channel"])
	}
	raw, _ := json.Marshal(p["blocks"])
	for _, want := range []string{`"action_id":"vedette_a"`, `"value":"a:act-1"`, `"action_id":"vedette_r"`, `"value":"r:act-1"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("blocks lack %s: %s", want, raw)
		}
	}
	if se.sl.auths[0] != "Bearer "+slackBotTok || se.sawHostWebhook() {
		t.Fatalf("authorization %q, webhook used = %v", se.sl.auths[0], se.sawHostWebhook())
	}
	if se.count(`SELECT COUNT(*) FROM notify_slack_button WHERE request_id = 'act-1' AND channel_id = ? AND ts = ?`, slChannel, slTS) != 1 {
		t.Fatal("the posted message is not kept")
	}
	for _, tok := range []string{slackBotTok, slackAppTok} {
		if se.count(`SELECT COUNT(*) FROM notify_send WHERE message LIKE '%'||?||'%' OR error LIKE '%'||?||'%'`, tok, tok) != 0 {
			t.Fatal("a token is in the send history")
		}
	}
}

func (se *slEnv) sawHostWebhook() bool { return se.sl.sawHost("hooks.slack.com") }

func TestContract_PRE8_SlackRequestWithoutChatButtonsUsesTheWebhookOnly(t *testing.T) {
	se := newSLEnv(t)
	for _, mod := range []func(*notify.ApprovalRequest){func(r *notify.ApprovalRequest) { r.NoChatButtons = true }, func(r *notify.ApprovalRequest) { r.InAppOnly = true }} {
		req := se.approvalReq("act-1", channel.Slack)
		mod(&req)
		if _, err := se.svc.SendApprovalRequest(se.ctx(), req); err != nil {
			t.Fatal(err)
		}
		if len(se.sl.posts) != 0 || !se.sawHostWebhook() || se.count(`SELECT COUNT(*) FROM notify_slack_button`) != 0 {
			t.Fatal("no buttons wanted: the message must go through the webhook and keep nothing")
		}
	}
}

func TestContract_POST8_SlackPressIsDecidedAndAnsweredPrivately(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	c, _ := se.listen()
	c.out <- slPress{}.json()
	se.sl.ack(t, "env-1")
	r := se.sl.reply(t)
	if r["response_type"] != "ephemeral" || r["replace_original"] != false || r["text"] != "Approved. Block 203.0.113.9 is being run." {
		t.Fatalf("reply %v", r)
	}
	got := se.dec.got()
	if len(got) != 1 || got[0] != (notify.Decision{Channel: channel.Slack, ExternalID: slUser, RequestID: "act-1", Approve: true}) {
		t.Fatalf("Decide = %+v", got)
	}
	if m := <-se.decided; m["request_id"] != "act-1" || m["decision"] != "approved" || m["approver"] != slUser || m["channel"] != "slack" {
		t.Fatalf("event %v", m)
	}
	c.out <- slPress{env: "env-2", action: "vedette_r", value: "r:act-1"}.json()
	se.sl.ack(t, "env-2")
	se.sl.reply(t)
	if got := se.dec.got(); len(got) != 2 || got[1].Approve {
		t.Fatalf("reject not passed: %+v", got)
	}
	se.sl.mu.Lock()
	defer se.sl.mu.Unlock()
	for _, a := range se.sl.auths {
		if strings.Contains(a, slackBotTok) == false && strings.Contains(a, slackAppTok) == false {
			t.Fatalf("an API call without a token: %q", a)
		}
	}
}

func TestContract_PRE8_SlackPressNotOursIsNeverDecided(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	c, _ := se.listen()
	// Other workspace and other channel: acknowledged, ignored, no reply.
	c.out <- slPress{env: "e1", team: "T0OTHER001"}.json()
	se.sl.ack(t, "e1")
	c.out <- slPress{env: "e2", channel: "C0OTHER0001"}.json()
	se.sl.ack(t, "e2")
	// A valid press right after them: its reply is the first reply, so the two above sent none, and Decide has run once (theirs never did).
	c.out <- slPress{env: "e-ok"}.json()
	se.sl.ack(t, "e-ok")
	if r := se.sl.reply(t); r["text"] != "Approved. Block 203.0.113.9 is being run." {
		t.Fatalf("first reply %v", r)
	}
	// Another message (ts), a request that was never posted, a press from an out-of-form action: answered "not valid".
	for i, p := range []slPress{
		{env: "e3", ts: "1731326999.000200"},
		{env: "e4", value: "a:other", action: "vedette_a"},
		{env: "e5", action: "vedette_a", value: "r:act-1"},
		{env: "e6", action: "other_action"},
		{env: "e7", user: "evil"},
	} {
		c.out <- p.json()
		se.sl.ack(t, p.env)
		if r := se.sl.reply(t); r["text"] != "This button is not valid. Open Vedette to decide." {
			t.Fatalf("press %d: reply %v", i, r)
		}
	}
	se.sl.noReply(t)
	if got := se.dec.got(); len(got) != 1 || got[0].ExternalID != slUser {
		t.Fatalf("Decide = %+v, want only the valid press", got)
	}
}

func TestContract_PRE8_SlackPressAfterTheRequestEndedIsNotDecided(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	c, _ := se.listen()
	se.clock.Add(16 * time.Minute)
	c.out <- slPress{}.json()
	se.sl.ack(t, "env-1")
	if r := se.sl.reply(t); r["text"] != "This button is not valid. Open Vedette to decide." {
		t.Fatalf("reply %v", r)
	}
	se.noDecision(t)
}

func TestContract_SYS2_SlackReplyAddressIsHooksSlackComOnly(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	c, _ := se.listen()
	for i, u := range []string{
		"https://hooks.slack.com.evil.example/actions/T0/1/a", "http://hooks.slack.com/actions/T0/1/a", "https://hooks.slack.com:8443/actions/T0/1/a",
		"https://user@hooks.slack.com/actions/T0/1/a", "https://hooks.slack.com/actions/T0/1/a?x=1", "https://hooks.slack.com/actions/../services/a",
		"https://hooks.slack.com/services/T0/B0/a", "https://evilhooks.slack.com/actions/T0/1/a",
	} {
		id := "bad-" + string(rune('a'+i))
		c.out <- slPress{env: id, respURL: u}.json()
		se.sl.ack(t, id)
	}
	c.out <- slPress{env: "good"}.json() // the one that ends the wait: every earlier press was fully handled before it
	se.sl.ack(t, "good")
	se.sl.reply(t)
	se.sl.noReply(t)
	se.sl.mu.Lock()
	for _, r := range se.sl.reqs {
		if strings.HasPrefix(r, "hooks.slack.com") && r != "hooks.slack.com/actions/T0EXAMPLE1/123456/abcDEF" {
			t.Errorf("a reply went to %s", r)
		}
	}
	for _, h := range se.sl.hosts {
		if h != "slack.com" && h != "hooks.slack.com" && h != "wss-primary.slack.com" {
			t.Errorf("a request went to host %s", h)
		}
	}
	se.sl.mu.Unlock()
	if n := len(se.dec.got()); n != 9 {
		t.Fatalf("Decide called %d times, want 9 (the press itself is valid, only the reply address is not)", n)
	}
}

func TestContract_SYS2_SlackSocketAddressMustBeSlacks(t *testing.T) {
	for _, bad := range []string{
		"wss://wss-primary.slack.com.evil.example/link/?ticket=x", "ws://wss-primary.slack.com/link/?ticket=x", "wss://evil.example/link/?ticket=x",
		"wss://wss-primary.slack.com:8443/link/?ticket=x", "wss://u@wss-primary.slack.com/link/?ticket=x", "wss://wss-primary.slack.com/other",
		"wss://wss-primary.slack.com./link/", "wss://slack.com/link/", "https://wss-primary.slack.com/link/",
	} {
		se := newSLEnv(t)
		se.sl.socketURL = bad
		err := se.job().Run(se.ctx())
		if err == nil {
			t.Fatalf("%q: the listener accepted it", bad)
		}
		if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "ticket") || strings.Contains(err.Error(), slackAppTok) {
			t.Fatalf("%q: error carries the address or a token: %v", bad, err)
		}
		se.sl.mu.Lock()
		for _, h := range se.sl.hosts {
			if h != "slack.com" {
				t.Errorf("%q: a request went to %s", bad, h)
			}
		}
		se.sl.mu.Unlock()
	}
}

func TestContract_SLACK_DisconnectReconnectsAtOnceAndStopsOnCtx(t *testing.T) {
	se := newSLEnv(t)
	c, stop := se.listen()
	c.out <- []byte(`{"type":"disconnect","reason":"refresh_requested"}`)
	c2 := se.sl.conn(t)
	if c2 == c {
		t.Fatal("the same connection")
	}
	if err := stop(); err != nil {
		t.Fatalf("stopping on ctx returned %v", err)
	}
}

func TestContract_SLACK_ListenerIsIdleUntilTheChannelTakesApprovals(t *testing.T) {
	se := newSLEnv(t)
	se.saveSlack(false)
	if err := se.job().Run(se.ctx()); err != nil || se.sl.sawHost("slack.com") {
		t.Fatalf("approvals off: err = %v, dialled = %v", err, se.sl.sawHost("slack.com"))
	}
	se2 := newSLEnv(t, func(c *notify.Config) { c.Decisions = nil })
	if err := se2.job().Run(se2.ctx()); err != nil || se2.sl.sawHost("slack.com") {
		t.Fatal("no Decisions port: the listener must not run")
	}
}

func TestContract_SLACK_TeamIsLearnedOncePerRevision(t *testing.T) {
	se := newSLEnv(t)
	_, stop := se.listen()
	_ = stop()
	_, stop = se.listen()
	_ = stop()
	if se.sl.authTests != 1 {
		t.Fatalf("auth.test called %d times for one channel revision", se.sl.authTests)
	}
	se.saveSlack(true) // a change bumps the revision: the workspace is learned again
	_, stop = se.listen()
	_ = stop()
	if se.sl.authTests != 2 {
		t.Fatalf("auth.test called %d times after a change, want 2", se.sl.authTests)
	}
}

func TestContract_SLACK_DecideErrorAnswersAFixedText(t *testing.T) {
	se := newSLEnv(t)
	se.dec.set(notify.DecisionResult{}, context.DeadlineExceeded)
	se.request()
	c, _ := se.listen()
	c.out <- slPress{}.json()
	se.sl.ack(t, "env-1")
	if r := se.sl.reply(t); r["text"] != "Vedette could not record your decision. Try again, or open Vedette to decide." {
		t.Fatalf("reply %v", r)
	}
	se.noDecisionEvent(t)
}

func (se *slEnv) noDecisionEvent(t *testing.T) {
	t.Helper()
	select {
	case m := <-se.decided:
		t.Fatalf("event %v", m)
	default:
	}
}

func TestContract_SLACK_ARepeatedEnvelopeIsDecidedOnce(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	c, _ := se.listen()
	c.out <- slPress{}.json()
	c.out <- slPress{}.json() // Slack sends the same envelope again when its ack came late
	c.out <- slPress{env: "env-2"}.json()
	se.sl.ack(t, "env-1")
	se.sl.ack(t, "env-1")
	se.sl.ack(t, "env-2")
	se.sl.reply(t)
	se.sl.reply(t)
	if got := se.dec.got(); len(got) != 2 {
		t.Fatalf("Decide called %d times, want 2", len(got))
	}
}

func TestContract_SLACK_PressAfterTheChannelWasTurnedOffIsNotDecided(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	c, _ := se.listen()
	se.saveSlack(false) // approvals off: the open connection must not decide any more, even before the watcher closes it
	c.out <- slPress{}.json()
	se.sl.ack(t, "env-1")
	c.out <- slPress{env: "env-2", team: "T0OTHER001"}.json() // a later envelope, ignored too: ack proves the first was handled
	se.sl.ack(t, "env-2")
	se.sl.noReply(t)
	se.noDecision(t)
}

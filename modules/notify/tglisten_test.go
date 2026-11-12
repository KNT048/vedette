package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// fakeTelegram is the Telegram Bot API as an http.Handler, served in process through the adapters' client (nothing dials out).
// getUpdates long-polls: it answers at once when updates are queued and otherwise waits for one or for the request to end.
type fakeTelegram struct {
	mu      sync.Mutex
	queue   []string // raw updates, each with its update_id
	ids     []int64
	nextID  int64
	polls   int
	sends   []map[string]any
	answers chan map[string]any
	wake    chan struct{}
	waiting chan struct{} // signalled each time a getUpdates call starts to wait (the listener is in a long poll)
	status  int           // non-zero: every call answers this HTTP status
	// hangAnswers is how many answerCallbackQuery calls get no answer at all (they end with the caller's deadline).
	hangAnswers int
	edits       []map[string]any // editMessageReplyMarkup bodies
	sendChat    string           // the chat id sendMessage answers with (a JSON number); "" = tgChat
	editStatus  int              // non-zero: editMessageReplyMarkup answers this HTTP status
}

func newFakeTelegram() *fakeTelegram {
	return &fakeTelegram{answers: make(chan map[string]any, 64), wake: make(chan struct{}, 1), waiting: make(chan struct{}, 1), nextID: 100}
}

// inPoll waits until the listener is inside a long poll.
func (f *fakeTelegram) inPoll(t *testing.T) {
	t.Helper()
	select {
	case <-f.waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never polled")
	}
}

func (f *fakeTelegram) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = r
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	return resp, nil
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	if !strings.HasPrefix(r.URL.Path, "/bot"+tgToken+"/") || r.URL.Host != "api.telegram.org" {
		http.Error(w, `{"ok":false,"description":"Not Found"}`, http.StatusNotFound)
		return
	}
	f.mu.Lock()
	status := f.status
	f.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"ok":false,"description":"Unauthorized"}`)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/bot"+tgToken+"/") {
	case "sendMessage":
		f.mu.Lock()
		f.sends = append(f.sends, body)
		f.mu.Unlock()
		f.mu.Lock()
		chat := f.sendChat
		f.mu.Unlock()
		if chat == "" {
			chat = tgChat
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":7,"chat":{"id":`+chat+`,"type":"supergroup"}}}`) // Telegram names the chat as a number
	case "editMessageReplyMarkup":
		f.mu.Lock()
		f.edits = append(f.edits, body)
		code := f.editStatus
		f.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"ok":false,"description":"edit refused"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
	case "answerCallbackQuery":
		f.mu.Lock()
		hang := f.hangAnswers > 0
		if hang {
			f.hangAnswers--
		}
		f.mu.Unlock()
		if hang { // Telegram does not answer this call: it ends with the caller's deadline
			<-r.Context().Done()
			return
		}
		f.answers <- body
		_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
	case "getUpdates":
		offset, _ := body["offset"].(float64)
		timeout, _ := body["timeout"].(float64)
		for {
			f.mu.Lock()
			f.polls++
			var out []string
			for i, u := range f.queue {
				if f.ids[i] >= int64(offset) {
					out = append(out, u)
				}
			}
			f.mu.Unlock()
			if len(out) > 0 || timeout == 0 { // timeout 0 is a short poll: what is waiting now, maybe nothing
				_, _ = io.WriteString(w, `{"ok":true,"result":[`+strings.Join(out, ",")+`]}`)
				return
			}
			select {
			case f.waiting <- struct{}{}:
			default:
			}
			select {
			case <-f.wake:
			case <-r.Context().Done():
				return
			}
		}
	default:
		http.Error(w, `{"ok":false}`, http.StatusNotFound)
	}
}

// press queues one button press as Telegram would deliver it.
func (f *fakeTelegram) press(from, chat, data string) {
	f.mu.Lock()
	f.nextID++
	id := f.nextID
	u := `{"update_id":` + strconv.FormatInt(id, 10) + `,"callback_query":{"id":"cq` + strconv.FormatInt(id, 10) + `","from":{"id":` + from +
		`,"is_bot":false,"first_name":"Lan"},"message":{"message_id":7,"chat":{"id":` + chat + `,"type":"supergroup"}},"data":` + strconv.Quote(data) + `}}`
	f.queue, f.ids = append(f.queue, u), append(f.ids, id)
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fakeTelegram) answer(t *testing.T) map[string]any {
	t.Helper()
	select {
	case a := <-f.answers:
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("the button press was not answered")
		return nil
	}
}

func (f *fakeTelegram) buttons(t *testing.T) (approve, reject string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sends) == 0 {
		t.Fatal("no message was sent")
	}
	var kb struct {
		InlineKeyboard [][]struct {
			Text string `json:"text"`
			Data string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	raw, _ := json.Marshal(f.sends[len(f.sends)-1]["reply_markup"])
	if err := json.Unmarshal(raw, &kb); err != nil || len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 2 {
		t.Fatalf("no Approve/Reject keyboard: %s", raw)
	}
	return kb.InlineKeyboard[0][0].Data, kb.InlineKeyboard[0][1].Data
}

// recDecisions is the Decisions port of the response module: it records every call and answers what the test set.
type recDecisions struct {
	mu    sync.Mutex
	links []notify.Decision
	link  notify.DecisionResult
	calls []notify.Decision
	res   notify.DecisionResult
	err   error
	each  chan struct{} // when set, gets one value per Decide (buffered by the test): lets a test wait for each decision
}

func (d *recDecisions) Decide(_ context.Context, c notify.Decision) (notify.DecisionResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, c)
	if d.each != nil {
		d.each <- struct{}{}
	}
	return d.res, d.err
}

// LinkChat records the call like Decide (Code is the link code) and answers with link, or "linked".
func (d *recDecisions) LinkChat(_ context.Context, c notify.Decision) (notify.DecisionResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.links = append(d.links, c)
	if d.link.Status == "" {
		return notify.DecisionResult{Status: "linked", Message: "Linked."}, nil
	}
	return d.link, nil
}

func (d *recDecisions) got() []notify.Decision {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]notify.Decision(nil), d.calls...)
}

func (d *recDecisions) set(r notify.DecisionResult, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.res, d.err = r, err
}

type tgEnv struct {
	*env
	tg      *fakeTelegram
	dec     *recDecisions
	decided chan map[string]string
}

const tgChat = "-1002145678901"

func newTGEnv(t *testing.T, opts ...func(*notify.Config)) *tgEnv {
	t.Helper()
	tg, dec := newFakeTelegram(), &recDecisions{res: notify.DecisionResult{Status: "approved", Message: "Approved. Block 203.0.113.9 is being run."}}
	opts = append([]func(*notify.Config){func(c *notify.Config) { c.HTTPClient = &http.Client{Transport: tg}; c.Decisions = dec }}, opts...)
	te := &tgEnv{env: newEnv(t, opts...), tg: tg, dec: dec, decided: make(chan map[string]string, 16)}
	te.bus.Subscribe("notify.approval.decided", func(_ context.Context, ev events.Event) error {
		m, _ := ev.Data.(map[string]string)
		te.decided <- m
		return nil
	})
	te.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": tgChat}, Secret: tgToken, MinSeverity: notify.Low,
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-admin", Address: "123456789"}}})
	return te
}

func (te *tgEnv) job() jobs.Job {
	te.t.Helper()
	for _, j := range te.svc.Jobs() {
		if j.Name == "telegram-listen" {
			return j
		}
	}
	te.t.Fatal("no telegram-listen job")
	return jobs.Job{}
}

// listen runs the listener job until the test ends (or stop is called) and fails the test when it does not stop on ctx. It returns once
// the listener is in a long poll, so the presses a test makes after it are new (presses waiting from before are dropped, review L3).
func (te *tgEnv) listen() (stop func() error) {
	te.t.Helper()
	stop = te.start()
	te.tg.inPoll(te.t)
	return stop
}

// start runs the listener job without waiting for its first long poll.
func (te *tgEnv) start() (stop func() error) {
	te.t.Helper()
	ctx, cancel := context.WithCancel(te.ctx())
	done := make(chan error, 1)
	j := te.job()
	go func() { done <- j.Run(ctx) }()
	var once sync.Once
	var err error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				te.t.Error("the listener did not stop when ctx ended")
			}
		})
		return err
	}
	te.t.Cleanup(func() { _ = stop() })
	return stop
}

func (te *tgEnv) request(id string) {
	te.t.Helper()
	if _, err := te.svc.SendApprovalRequest(te.ctx(), te.approvalReq(id, channel.Telegram)); err != nil {
		te.t.Fatal(err)
	}
}

func (te *tgEnv) noEvent() {
	te.t.Helper()
	select {
	case m := <-te.decided:
		te.t.Fatalf("notify.approval.decided published: %v", m)
	default:
	}
}

// ---- PRE-8 / POST-8: Telegram buttons and the long-polling listener (13b-8, spec approval-tokens.md 6) ----

func TestContract_PRE8_TelegramButtonsCarryAStoredNonce(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	a, r := te.tg.buttons(t)
	if !strings.HasPrefix(a, "a:act-1:") || !strings.HasPrefix(r, "r:act-1:") || len(a) > 64 || a[len("a:act-1:"):] != r[len("r:act-1:"):] {
		t.Fatalf("callback data %q %q", a, r)
	}
	nonce := a[len("a:act-1:"):]
	if len(nonce) != 11 {
		t.Fatalf("nonce %q is not 8 random bytes in base64url", nonce)
	}
	if te.count(`SELECT COUNT(*) FROM notify_tg_button WHERE request_id = 'act-1'`) != 1 || te.count(`SELECT COUNT(*) FROM notify_tg_button WHERE nonce_hash LIKE '%'||?||'%'`, nonce) != 0 {
		t.Fatal("the nonce is not kept, or kept in plain text")
	}
	if te.count(`SELECT COUNT(*) FROM notify_send WHERE message LIKE '%'||?||'%'`, nonce) != 0 {
		t.Fatal("the button data is in the history")
	}
	// A second request gets another nonce.
	te.request("act-2")
	a2, _ := te.tg.buttons(t)
	if a2[len("a:act-2:"):] == nonce {
		t.Fatal("the nonce is not random")
	}
}

func TestContract_PRE8_TelegramNoButtonsWithoutDecisionsOrWhenInAppOnly(t *testing.T) {
	te := newTGEnv(t, func(c *notify.Config) { c.Decisions = nil })
	te.request("act-1")
	te.tg.mu.Lock()
	_, has := te.tg.sends[0]["reply_markup"]
	te.tg.mu.Unlock()
	if has || te.count(`SELECT COUNT(*) FROM notify_tg_button`) != 0 {
		t.Fatal("buttons were sent while no one can take the decision")
	}
	te2 := newTGEnv(t)
	req := te2.approvalReq("act-ai", channel.Telegram)
	req.InAppOnly = true
	if _, err := te2.svc.SendApprovalRequest(te2.ctx(), req); err != nil {
		t.Fatal(err)
	}
	te2.tg.mu.Lock()
	_, has = te2.tg.sends[0]["reply_markup"]
	te2.tg.mu.Unlock()
	if has || te2.count(`SELECT COUNT(*) FROM notify_tg_button`) != 0 {
		t.Fatal("an in-app-only request got buttons")
	}
	// A request id too long for the 64 bytes of callback_data: the message goes out without buttons (open Vedette).
	long := "act-" + strings.Repeat("x", 60)
	te2.request(long)
	te2.tg.mu.Lock()
	_, has = te2.tg.sends[1]["reply_markup"]
	te2.tg.mu.Unlock()
	if has {
		t.Fatal("a button with more than 64 bytes of data was sent")
	}
}

func TestContract_PRE8_TelegramPressReachesDecide(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	a, r := te.tg.buttons(t)
	te.listen()
	te.tg.press("123456789", tgChat, a)
	ans := te.tg.answer(t)
	if ans["callback_query_id"] == "" || ans["text"] != "Approved. Block 203.0.113.9 is being run." || ans["show_alert"] != true {
		t.Fatalf("answer = %v", ans)
	}
	want := notify.Decision{Channel: channel.Telegram, ExternalID: "123456789", RequestID: "act-1", Approve: true}
	if got := te.dec.got(); len(got) != 1 || got[0] != want {
		t.Fatalf("decisions = %+v, want %+v", got, want)
	}
	select {
	case m := <-te.decided:
		if m["request_id"] != "act-1" || m["decision"] != "approved" || m["approver"] != "123456789" || m["channel"] != "telegram" {
			t.Fatalf("event = %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notify.approval.decided")
	}
	// Reject carries Approve=false.
	te.dec.set(notify.DecisionResult{Status: "rejected", Message: "Rejected."}, nil)
	te.tg.press("123456789", tgChat, r)
	if ans := te.tg.answer(t); ans["text"] != "Rejected." {
		t.Fatalf("answer = %v", ans)
	}
	if got := te.dec.got(); len(got) != 2 || got[1].Approve {
		t.Fatalf("decisions = %+v", got)
	}
}

func TestContract_PRE8_TelegramPressFromAnotherChatIsNotDecided(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	a, _ := te.tg.buttons(t)
	te.listen()
	te.tg.press("123456789", "-1009999999999", a) // the bot was added to another group and the message forwarded there
	if ans := te.tg.answer(t); ans["text"] != "" && ans["text"] != nil {
		t.Fatalf("a press in another chat got an answer that says something: %v", ans)
	}
	if got := te.dec.got(); len(got) != 0 {
		t.Fatalf("Decide was called: %+v", got)
	}
	te.noEvent()
}

func TestContract_PRE8_TelegramForgedButtonIsNotDecided(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	a, _ := te.tg.buttons(t)
	te.listen()
	for _, data := range []string{
		"a:act-1:" + strings.Repeat("A", 11),   // the nonce guessed
		"a:act-9:" + a[len("a:act-1:"):],       // the nonce of act-1 on another request
		"x:act-1:" + a[len("a:act-1:"):],       // not approve or reject
		"a:act-1",                              // no nonce
		"a:act-1:" + a[len("a:act-1:"):] + "=", // nonce one character longer
		"a::" + a[len("a:act-1:"):],            // empty request id
	} {
		te.tg.press("123456789", tgChat, data)
		if ans := te.tg.answer(t); ans["text"] != "This button is not valid. Open Vedette to decide." {
			t.Errorf("%q: answer = %v", data, ans)
		}
	}
	if got := te.dec.got(); len(got) != 0 {
		t.Fatalf("Decide was called: %+v", got)
	}
	te.noEvent()
}

func TestContract_POST8_TelegramRefusalIsRelayedWithoutEvent(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	a, _ := te.tg.buttons(t)
	te.listen()
	te.dec.set(notify.DecisionResult{Status: "approver_not_listed", Message: "You are not an approver on this channel."}, nil)
	te.tg.press("555555555", tgChat, a)
	if ans := te.tg.answer(t); ans["text"] != "You are not an approver on this channel." {
		t.Fatalf("answer = %v", ans)
	}
	te.noEvent()
	// pending is a recorded decision: the event goes out.
	te.dec.set(notify.DecisionResult{Status: "pending", Message: "Approved. One more person must approve."}, nil)
	te.tg.press("123456789", tgChat, a)
	te.tg.answer(t)
	select {
	case m := <-te.decided:
		if m["decision"] != "pending" {
			t.Fatalf("event = %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event for pending")
	}
	// An infrastructure error: a fixed reply (never the error text), no event.
	te.dec.set(notify.DecisionResult{}, errors.New("database is locked at /var/lib/vedette"))
	te.tg.press("123456789", tgChat, a)
	if ans := te.tg.answer(t); ans["text"] != "Vedette could not record your decision. Try again, or open Vedette to decide." {
		t.Fatalf("answer = %v", ans)
	}
	te.noEvent()
}

func TestContract_PRE8_TelegramListenerOnlyWhileReady(t *testing.T) {
	// No Decisions port: the job returns at once and never polls.
	te := newTGEnv(t, func(c *notify.Config) { c.Decisions = nil })
	if err := te.job().Run(te.ctx()); err != nil {
		t.Fatal(err)
	}
	// Approvals turned off on the channel: no polling (PRIVACY flow 5: "turn off approvals to stop Telegram polling").
	te2 := newTGEnv(t)
	te2.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": tgChat}, MinSeverity: notify.Low})
	if err := te2.job().Run(te2.ctx()); err != nil {
		t.Fatal(err)
	}
	te.tg.mu.Lock()
	te2.tg.mu.Lock()
	polls := te.tg.polls + te2.tg.polls
	te2.tg.mu.Unlock()
	te.tg.mu.Unlock()
	if polls != 0 {
		t.Fatalf("%d getUpdates calls while the listener is not ready", polls)
	}
	// Approvals turned off while it runs: it stops by itself at the next poll.
	te3 := newTGEnv(t)
	stop := te3.listen()
	// listen returned in a long poll: approvals are turned off while it runs (before it, the listener would correctly stop without polling).
	te3.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": tgChat}, MinSeverity: notify.Low})
	te3.tg.press("1", tgChat, "a:x:y") // ends the current long poll
	te3.tg.answer(t)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestTelegramListenerErrorHidesTheToken(t *testing.T) {
	te := newTGEnv(t)
	te.tg.mu.Lock()
	te.tg.status = http.StatusUnauthorized
	te.tg.mu.Unlock()
	err := te.job().Run(te.ctx())
	if err == nil || strings.Contains(err.Error(), tgSecret) || strings.Contains(err.Error(), "api.telegram.org") {
		t.Fatalf("err = %v", err)
	}
}

func TestTelegramButtonNoncesArePrunedAWeekAfterTheRequestEnds(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	te.clock.Add(15*time.Minute + 6*24*time.Hour) // six days after the request ended
	te.flush()
	if n := te.count(`SELECT COUNT(*) FROM notify_tg_button`); n != 1 {
		t.Fatalf("%d nonce rows six days after the request ended, want 1", n)
	}
	te.clock.Add(25 * time.Hour)
	te.flush()
	if n := te.count(`SELECT COUNT(*) FROM notify_tg_button`); n != 0 {
		t.Fatalf("%d nonce rows a week after the request ended, want 0", n)
	}
}

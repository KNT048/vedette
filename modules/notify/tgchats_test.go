package notify_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// tgUpdatesNet answers getUpdates with one fixed status and body and keeps what it was asked.
type tgUpdatesNet struct {
	mu     sync.Mutex
	code   int
	body   string
	paths  []string
	bodies []string
}

func (n *tgUpdatesNet) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	n.mu.Lock()
	n.paths = append(n.paths, r.URL.Path)
	n.bodies = append(n.bodies, string(raw))
	code, body := n.code, n.body
	n.mu.Unlock()
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

const tgChatsAnswer = `{"ok":true,"result":[
 {"update_id":10,"message":{"message_id":1,"chat":{"id":5550001,"type":"private","first_name":"Lan","last_name":"Tran","username":"lan_t"},"text":"hi"}},
 {"update_id":11,"my_chat_member":{"chat":{"id":-1002145678901,"type":"supergroup","title":"IT Ops"}}},
 {"update_id":12,"message":{"message_id":2,"chat":{"id":5550001,"type":"private","first_name":"Lan"},"text":"again"}}]}`

func tgChatsEnv(t *testing.T, n *tgUpdatesNet) *env {
	return newEnv(t, func(c *notify.Config) { c.HTTPClient = &http.Client{Transport: n} })
}

// D-491: Find my chat lists the chats the bot saw, newest first, one row per chat, and asks Telegram so that nothing is confirmed
// (no offset) and without waiting; the token in the form is used, never logged into the answer.
func TestTelegramChatsListsChatsAndConfirmsNothing(t *testing.T) {
	n := &tgUpdatesNet{code: 200, body: tgChatsAnswer}
	e := tgChatsEnv(t, n)
	got, _, err := e.svc.TelegramChats(e.ctx(), tgToken)
	if err != nil || len(got) != 2 {
		t.Fatalf("chats = %+v, %v", got, err)
	}
	if got[0].ID != "5550001" || got[0].Kind != "private" || got[0].Name != "Lan" || got[1].ID != "-1002145678901" || got[1].Name != "IT Ops" || got[1].Kind != "supergroup" {
		t.Errorf("order or fields wrong: %+v", got)
	}
	if len(n.paths) != 1 || n.paths[0] != "/bot"+tgToken+"/getUpdates" {
		t.Fatalf("calls = %v", n.paths)
	}
	if b := n.bodies[0]; strings.Contains(b, "offset") || !strings.Contains(b, `"limit":100`) || !strings.Contains(b, `"timeout":0`) {
		t.Errorf("getUpdates body must have no offset, limit 100, timeout 0: %s", b)
	}
	for _, kind := range []string{"message", "my_chat_member", "callback_query"} { // callback_query: a later approval poller relies on the stored list
		if !strings.Contains(n.bodies[0], `"`+kind+`"`) {
			t.Errorf("allowed_updates lacks %s: %s", kind, n.bodies[0])
		}
	}
}

// With no token in the form (an edit) the saved one is used; it never appears in the answer.
func TestTelegramChatsUsesTheSavedTokenWhenTheFormHasNone(t *testing.T) {
	n := &tgUpdatesNet{code: 200, body: tgChatsAnswer}
	e := tgChatsEnv(t, n)
	e.telegram(notify.Low)
	got, _, err := e.svc.TelegramChats(e.ctx(), "")
	if err != nil || len(got) != 2 || len(n.paths) != 1 || !strings.Contains(n.paths[0], tgToken) {
		t.Fatalf("chats = %+v, %v, calls %v", got, err, n.paths)
	}
}

func TestTelegramChatsErrorsSayWhatToDo(t *testing.T) {
	cases := []struct {
		name, token string
		code        int
		body        string
		status      int
		want        string
	}{
		{"bad token form", "not a token", 200, `{}`, 400, "bad_token"},
		{"telegram refuses the token", tgToken, 401, `{"ok":false,"description":"Unauthorized"}`, 400, "bad_token"},
		{"webhook or another reader", tgToken, 409, `{"ok":false,"description":"Conflict: terminated by other getUpdates request"}`, 409, "telegram_busy"},
		{"telegram down", tgToken, 500, `oops`, 502, "telegram_failed"},
		{"garbage", tgToken, 200, `<html>not json</html>`, 502, "telegram_failed"},
		{"too big", tgToken, 200, `{"ok":true,"result":[],"pad":"` + strings.Repeat("x", 1<<20+10) + `"}`, 502, "telegram_failed"},
		{"not ok", tgToken, 200, `{"ok":false,"description":"no"}`, 502, "telegram_failed"},
		{"asked to wait", tgToken, 429, `{"ok":false,"description":"Too Many Requests: retry after 5","parameters":{"retry_after":5}}`, 502, "telegram_failed"},
	}
	for _, c := range cases {
		e := tgChatsEnv(t, &tgUpdatesNet{code: c.code, body: c.body})
		_, _, err := e.svc.TelegramChats(e.ctx(), c.token)
		if st, code := apiCode(err); st != c.status || code != c.want {
			t.Errorf("%s: %d %s, want %d %s", c.name, st, code, c.status, c.want)
		}
		if err != nil && strings.Contains(err.Error(), tgToken) {
			t.Errorf("%s: the token is in the error: %v", c.name, err)
		}
	}
}

func TestTelegramChatsEmptyIsAnEmptyListAndNoTokenIsAskedFor(t *testing.T) {
	e := tgChatsEnv(t, &tgUpdatesNet{code: 200, body: `{"ok":true,"result":[]}`})
	got, _, err := e.svc.TelegramChats(e.ctx(), tgToken)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty = %+v, %v", got, err)
	}
	if _, _, err := e.svc.TelegramChats(e.ctx(), "  "); err == nil {
		t.Fatal("no token and no saved channel must be refused")
	} else if st, code := apiCode(err); st != 400 || code != "secret_required" {
		t.Errorf("%d %s", st, code)
	}
}

// While the box long-polls the bot for approval buttons it is the one reader: Find my chat for that bot says so and does not call Telegram.
func TestTelegramChatsIsRefusedWhileTheApprovalPollerReadsTheBot(t *testing.T) {
	n := &tgUpdatesNet{code: 200, body: tgChatsAnswer}
	e := newEnv(t, func(c *notify.Config) { c.HTTPClient, c.Decisions = &http.Client{Transport: n}, fakeDecisions{} }) // the poller runs only with Decisions
	e.save("telegram", notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.Low,
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-op", Address: "5550001"}}})
	_, _, err := e.svc.TelegramChats(e.ctx(), "")
	if st, code := apiCode(err); st != 409 || code != "telegram_busy" || len(n.paths) != 0 {
		t.Fatalf("%d %s, %d calls", st, code, len(n.paths))
	}
}

// Without Decisions the box runs no poller, so approvals on do not make Find my chat busy.
func TestTelegramChatsIsNotBusyWhenNoPollerRuns(t *testing.T) {
	n := &tgUpdatesNet{code: 200, body: tgChatsAnswer}
	e := tgChatsEnv(t, n)
	e.save("telegram", notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.Low,
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-op", Address: "5550001"}}})
	if got, _, err := e.svc.TelegramChats(e.ctx(), ""); err != nil || len(got) != 2 {
		t.Fatalf("%+v, %v", got, err)
	}
}

// The first empty answer for a bot says its update filter was just reset (an earlier message may not have been kept); later ones do not.
func TestTelegramChatsFirstEmptyAnswerIsFresh(t *testing.T) {
	e := tgChatsEnv(t, &tgUpdatesNet{code: 200, body: `{"ok":true,"result":[]}`})
	for i, want := range []bool{true, false} {
		if _, fresh, err := e.svc.TelegramChats(e.ctx(), tgToken); err != nil || fresh != want {
			t.Fatalf("call %d: fresh = %v, %v", i, fresh, err)
		}
	}
}

// A transport error carries the request URL, which holds the token: neither the error nor its words may.
func TestTelegramChatsTransportErrorNeverCarriesTheToken(t *testing.T) {
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errors.New("connection refused")}
	}))
	_, _, err := e.svc.TelegramChats(e.ctx(), tgToken)
	if st, code := apiCode(err); st != 502 || code != "telegram_failed" || strings.Contains(err.Error(), tgToken) || strings.Contains(err.Error(), "bot"+tgToken[:4]) {
		t.Fatalf("%d %s %v", st, code, err)
	}
}

// A channel that was deleted leaves no saved token: the form must bring one.
func TestTelegramChatsAfterTheChannelIsDeletedAsksForTheToken(t *testing.T) {
	e := tgChatsEnv(t, &tgUpdatesNet{code: 200, body: tgChatsAnswer})
	e.telegram(notify.Low)
	if err := e.svc.DeleteChannel(e.ctx(), "admin@acme.example", channel.Telegram); err != nil {
		t.Fatal(err)
	}
	_, _, err := e.svc.TelegramChats(e.ctx(), "")
	if st, code := apiCode(err); st != 400 || code != "secret_required" {
		t.Fatalf("%d %s", st, code)
	}
}

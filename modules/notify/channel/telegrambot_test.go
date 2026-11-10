package channel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// bidiNul is a right-to-left override and a NUL, built from code points so the source holds no bidi character.
var bidiNul = string(rune(0x202e)) + string(rune(0))

func newTelegramBotAt(t *testing.T, base string, c *http.Client) *TelegramBot {
	t.Helper()
	b, err := NewTelegramBot(secrets.NewValue(tgToken), c)
	if err != nil {
		t.Fatal(err)
	}
	b.base = strings.TrimRight(base, "/")
	return b
}

// update is one callback_query update as Telegram sends it (only the fields the parser reads, plus noise it must ignore).
func update(id int64, query, from, chat, data string) string {
	return `{"update_id":` + strconv.FormatInt(id, 10) + `,"callback_query":{"id":"` + query + `","from":{"id":` + from + `,"is_bot":false,"first_name":"Lan"},` +
		`"message":{"message_id":7,"chat":{"id":` + chat + `,"type":"supergroup","title":"IT"},"date":1,"text":"Block 203.0.113.9"},"chat_instance":"-1","data":"` + data + `"}}`
}

func TestParseTelegramUpdatesReadsCallbacks(t *testing.T) {
	t.Parallel()
	body := `{"ok":true,"result":[` + update(10, "q1", "123456789", "-1002145678901", "a:act-1:AAAAAAAAAAA") + `,` +
		`{"update_id":11,"message":{"message_id":8,"chat":{"id":1},"text":"hi"}}` + `]}`
	cbs, next, err := ParseTelegramUpdates([]byte(body), 0)
	if err != nil {
		t.Fatal(err)
	}
	if next != 12 {
		t.Errorf("next offset = %d, want 12 (every update is confirmed, also the ones that are not callbacks)", next)
	}
	want := Callback{UpdateID: 10, QueryID: "q1", FromID: "123456789", ChatID: "-1002145678901", Data: "a:act-1:AAAAAAAAAAA"}
	if len(cbs) != 1 || cbs[0] != want {
		t.Fatalf("callbacks = %+v, want [%+v]", cbs, want)
	}
}

func TestParseTelegramUpdatesFailsClosed(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"not json":      `<html>`,
		"ok false":      `{"ok":false,"description":"Conflict"}`,
		"no result":     `{"ok":true}`,
		"result object": `{"ok":true,"result":{}}`,
		"too big":       `{"ok":true,"result":[` + strings.Repeat(" ", maxUpdatesBody) + `]}`,
		"trailing data": `{"ok":true,"result":[]} {"ok":true,"result":[]}`,
	} {
		if cbs, _, err := ParseTelegramUpdates([]byte(body), 5); err == nil || len(cbs) != 0 {
			t.Errorf("%s: callbacks %+v, err %v", name, cbs, err)
		}
	}
	// A malformed press comes out as Invalid with only its query id (it must still be answered, Telegram shows a progress
	// indicator until then; no decision can come from it), and its update is confirmed, so it is never read again.
	for name, u := range map[string]string{
		"from is a string":  update(20, "q", `"123456789"`, "-100", "a:x:AAAAAAAAAAA"),
		"from negative":     update(20, "q", "-5", "-100", "a:x:AAAAAAAAAAA"),
		"from too long":     update(20, "q", "1234567890123456", "-100", "a:x:AAAAAAAAAAA"),
		"from fraction":     update(20, "q", "1.5", "-100", "a:x:AAAAAAAAAAA"),
		"chat is a string":  update(20, "q", "123456789", `"-100"`, "a:x:AAAAAAAAAAA"),
		"data too long":     update(20, "q", "123456789", "-100", strings.Repeat("a", 65)),
		"data control char": update(20, "q", "123456789", "-100", `a:x\u0000:AAAAAAAAAAA`),
		"data with =":       update(20, "q", "123456789", "-100", "a:x:AAAAAAAAAAA="),
		"empty data":        update(20, "q", "123456789", "-100", ""),
		"inline message (no chat)": `{"update_id":20,"callback_query":{"id":"q","from":{"id":123456789},"inline_message_id":"x",` +
			`"data":"a:x:AAAAAAAAAAA"}}`,
		"pressed by a bot": `{"update_id":20,"callback_query":{"id":"q","from":{"id":123456789,"is_bot":true},"message":{"chat":{"id":-100}},` +
			`"data":"a:x:AAAAAAAAAAA"}}`,
	} {
		cbs, next, err := ParseTelegramUpdates([]byte(`{"ok":true,"result":[`+u+`]}`), 0)
		want := Callback{UpdateID: 20, QueryID: "q", Invalid: true}
		if err != nil || len(cbs) != 1 || cbs[0] != want || next != 21 {
			t.Errorf("%s: callbacks %+v, next %d, err %v", name, cbs, next, err)
		}
	}
	// A press whose query id cannot be used cannot be answered: dropped, still confirmed.
	for name, u := range map[string]string{
		"query id too long":   update(20, strings.Repeat("q", 65), "123456789", "-100", "a:x:AAAAAAAAAAA"),
		"query id with space": update(20, "q q", "123456789", "-100", "a:x:AAAAAAAAAAA"),
		"callback not object": `{"update_id":20,"callback_query":"x"}`,
	} {
		cbs, next, err := ParseTelegramUpdates([]byte(`{"ok":true,"result":[`+u+`]}`), 0)
		if err != nil || len(cbs) != 0 || next != 21 {
			t.Errorf("%s: callbacks %+v, next %d, err %v", name, cbs, next, err)
		}
	}
	// An offset never goes back: an old update id cannot move the listener to read updates again.
	_, next, err := ParseTelegramUpdates([]byte(`{"ok":true,"result":[{"update_id":3}]}`), 9)
	if err != nil || next != 9 {
		t.Errorf("next = %d, %v", next, err)
	}
}

func TestTelegramBotUpdatesAndAnswer(t *testing.T) {
	t.Parallel()
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		bodies = append(bodies, m)
		if strings.HasSuffix(r.URL.Path, "/getUpdates") {
			_, _ = io.WriteString(w, `{"ok":true,"result":[`+update(41, "q9", "123456789", "-1002145678901", "r:act-2:BBBBBBBBBBB")+`]}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
	}))
	t.Cleanup(srv.Close)
	b := newTelegramBotAt(t, srv.URL, srv.Client())
	cbs, next, err := b.Updates(t.Context(), 40, 25*time.Second)
	if err != nil || len(cbs) != 1 || next != 42 || cbs[0].QueryID != "q9" {
		t.Fatalf("updates = %+v, %d, %v", cbs, next, err)
	}
	if calls[0] != "/bot"+tgToken+"/getUpdates" || bodies[0]["offset"] != float64(40) || bodies[0]["timeout"] != float64(25) {
		t.Errorf("getUpdates call %s %v", calls[0], bodies[0])
	}
	if au, _ := json.Marshal(bodies[0]["allowed_updates"]); string(au) != `["callback_query"]` {
		t.Errorf("allowed_updates = %s, want only callback_query", au)
	}
	long := strings.Repeat("é", 300) + bidiNul
	if err := b.Answer(t.Context(), "q9", long); err != nil {
		t.Fatal(err)
	}
	ans := bodies[1]
	text, _ := ans["text"].(string)
	if calls[1] != "/bot"+tgToken+"/answerCallbackQuery" || ans["callback_query_id"] != "q9" || ans["show_alert"] != true {
		t.Errorf("answer call %s %v", calls[1], ans)
	}
	if n := len([]rune(text)); n > 200 || strings.ContainsAny(text, bidiNul) {
		t.Errorf("answer text is %d runes or keeps control characters: %q", n, text)
	}
	if err := b.Answer(t.Context(), "q9", ""); err != nil || bodies[2]["show_alert"] != false {
		t.Errorf("empty answer: %v %v", err, bodies[2])
	}
}

func TestTelegramBotErrorsHideTheToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"description":"Unauthorized `+tgToken+`"}`)
	}))
	t.Cleanup(srv.Close)
	b := newTelegramBotAt(t, srv.URL, srv.Client())
	_, _, err := b.Updates(t.Context(), 0, time.Second)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, errString(err), "AAHexample", srv.URL)
	if err := b.Answer(t.Context(), "q", "x"); err == nil {
		t.Fatal("a refused answer is not an error")
	}
	if _, err := NewTelegramBot(secrets.NewValue("nope"), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("a malformed token is accepted: %v", err)
	}
	mustNot(t, (&TelegramBot{token: secrets.NewValue(tgToken)}).String(), "AAHexample")
}

func TestTelegramBotUpdatesStopsOnContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(srv.Close)
	b := newTelegramBotAt(t, srv.URL, srv.Client())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, _, err := b.Updates(ctx, 0, 25*time.Second); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled poll returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the poll did not stop when ctx ended")
	}
}

func TestTelegramSendButtons(t *testing.T) {
	t.Parallel()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":5}}`)
	}))
	t.Cleanup(srv.Close)
	s, err := newTelegramAt(srv.URL, TelegramConfig{Token: secrets.NewValue(tgToken), ChatID: "-1002145678901", Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Buttons = []Button{{Text: "Approve", Data: "a:act-1:AAAAAAAAAAA"}, {Text: "Reject", Data: "r:act-1:AAAAAAAAAAA"}}
	if _, err := s.Send(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	kb, _ := json.Marshal(body["reply_markup"])
	if string(kb) != `{"inline_keyboard":[[{"callback_data":"a:act-1:AAAAAAAAAAA","text":"Approve"},{"callback_data":"r:act-1:AAAAAAAAAAA","text":"Reject"}]]}` {
		t.Errorf("reply_markup = %s", kb)
	}
	// Buttons are never part of the stored message (JSON), so a resend has none.
	if raw, _ := json.Marshal(m); strings.Contains(string(raw), "act-1:AAAA") {
		t.Errorf("buttons are in the JSON form: %s", raw)
	}
	for name, bad := range map[string][]Button{
		"data too long": {{Text: "Approve", Data: strings.Repeat("a", 65)}},
		"empty text":    {{Text: " ", Data: "a:x:y"}},
		"bad data char": {{Text: "Approve", Data: "a:x y"}},
		"too many":      {{"1", "a"}, {"2", "b"}, {"3", "c"}, {"4", "d"}, {"5", "e"}},
	} {
		m.Buttons = bad
		if _, err := s.Send(t.Context(), m); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func FuzzParseTelegramUpdates(f *testing.F) {
	f.Add([]byte(`{"ok":true,"result":[`+update(1, "q", "123456789", "-100", "a:act-1:AAAAAAAAAAA")+`]}`), int64(0))
	f.Add([]byte(`{"ok":true,"result":[{"update_id":9223372036854775807}]}`), int64(1))
	f.Add([]byte(`{"ok":true,"result":[{"update_id":-1,"callback_query":null}]}`), int64(0))
	f.Fuzz(func(t *testing.T, body []byte, offset int64) {
		cbs, next, err := ParseTelegramUpdates(body, offset)
		if err != nil {
			if len(cbs) != 0 {
				t.Fatal("callbacks with an error")
			}
			return
		}
		if next < offset {
			t.Fatalf("offset went back: %d -> %d", offset, next)
		}
		for _, c := range cbs {
			if !telegramQueryRE.MatchString(c.QueryID) {
				t.Fatalf("a press without a usable query id came out: %+v", c)
			}
			if c.Invalid {
				if c.FromID != "" || c.ChatID != "" || c.ChatUsername != "" || c.Data != "" {
					t.Fatalf("an invalid press carries data: %+v", c)
				}
				continue
			}
			if !telegramFromRE.MatchString(c.FromID) || c.QueryID == "" || len(c.Data) == 0 || len(c.Data) > 64 || (c.ChatID == "" && c.ChatUsername == "") {
				t.Fatalf("an unchecked callback came out: %+v", c)
			}
		}
	})
}

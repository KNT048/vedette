package channel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

// Slice 2: the id Telegram gives a sent message is kept (the buttons are removed from that message later); an answer Telegram
// sends is untrusted, so an id out of form is "unknown" (0) and the send still counts as delivered.
func TestTelegramSendReturnsTheMessageID(t *testing.T) {
	t.Parallel()
	answer := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, answer) }))
	t.Cleanup(srv.Close)
	s, err := newTelegramAt(srv.URL, TelegramConfig{Token: secrets.NewValue(tgToken), ChatID: "-1002145678901", Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for body, want := range map[string]int64{
		`{"ok":true,"result":{"message_id":5,"chat":{"id":-1002145678901}}}`: 5,
		`{"ok":true,"result":{"message_id":"5"}}`:                            0,
		`{"ok":true,"result":{"message_id":-5}}`:                             0,
		`{"ok":true,"result":{"message_id":9007199254740993}}`:               0, // above 2^53
		`{"ok":true,"result":{"message_id":1.5}}`:                            0,
		`{"ok":true,"result":{}}`:                                            0,
		`{"ok":true,"result":true}`:                                          0,
	} {
		answer = body
		r, err := s.Send(t.Context(), sample)
		if err != nil || r.MessageID != want {
			t.Errorf("%s: message id %d, err %v", body, r.MessageID, err)
		}
	}
}

func TestTelegramBotRemoveButtons(t *testing.T) {
	t.Parallel()
	var path string
	var body map[string]any
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		body = nil
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = io.WriteString(w, `{"ok":false,"description":"Bad Request: message is not modified `+tgToken+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
	}))
	t.Cleanup(srv.Close)
	b := newTelegramBotAt(t, srv.URL, srv.Client())
	if err := b.RemoveButtons(t.Context(), "-1002145678901", 7); err != nil {
		t.Fatal(err)
	}
	kb, _ := json.Marshal(body["reply_markup"])
	if path != "/bot"+tgToken+"/editMessageReplyMarkup" || body["chat_id"] != "-1002145678901" || body["message_id"] != float64(7) || string(kb) != `{"inline_keyboard":[]}` {
		t.Fatalf("call %s %v", path, body)
	}
	status = http.StatusBadRequest
	err := b.RemoveButtons(t.Context(), "-1002145678901", 7)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadRequest {
		t.Fatalf("a refused edit: %v", err)
	}
	mustNot(t, errString(err), "AAHexample", srv.URL)
	if err := b.RemoveButtons(t.Context(), "-1002145678901", 0); err == nil {
		t.Fatal("message id 0 was sent")
	}
}

func FuzzTelegramSentMessageID(f *testing.F) {
	f.Add([]byte(`{"ok":true,"result":{"message_id":5}}`))
	f.Add([]byte(`{"ok":true,"result":{"message_id":9007199254740992}}`))
	f.Add([]byte(`{"ok":true,"result":{"message_id":"5"}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		id := sentMessageID(body)
		if id < 0 || id > maxMessageID {
			t.Fatalf("message id %d out of range from %q", id, body)
		}
	})
}

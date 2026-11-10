package channel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// Review of #172, L2: an answer whose updates cannot be confirmed (no usable update_id) and that moves the offset nowhere is an error,
// so the listener stops and the scheduler waits before it asks again (no hot loop on the same answer).
func TestParseTelegramUpdatesUnconfirmableIsAnError(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"no update_id":       `{"ok":true,"result":[{"callback_query":{"id":"q"}}]}`,
		"negative update_id": `{"ok":true,"result":[{"update_id":-4}]}`,
		"string update_id":   `{"ok":true,"result":["x"]}`,
		"huge update_id":     `{"ok":true,"result":[{"update_id":9223372036854775807}]}`,
	} {
		if cbs, next, err := ParseTelegramUpdates([]byte(body), 7); err == nil || len(cbs) != 0 || next != 7 {
			t.Errorf("%s: callbacks %+v, next %d, err %v", name, cbs, next, err)
		}
	}
	// Mixed with an update that does move the offset: fine, the next call no longer returns the old ones.
	if _, next, err := ParseTelegramUpdates([]byte(`{"ok":true,"result":[{"update_id":-4},{"update_id":9}]}`), 7); err != nil || next != 10 {
		t.Errorf("mixed: next %d, err %v", next, err)
	}
	// An empty answer is a quiet poll, not an error.
	if _, next, err := ParseTelegramUpdates([]byte(`{"ok":true,"result":[]}`), 7); err != nil || next != 7 {
		t.Errorf("empty: next %d, err %v", next, err)
	}
}

// L1: approval messages cannot be forwarded or saved out of the chat (protect_content); other messages are unchanged.
func TestTelegramApprovalMessagesAreProtected(t *testing.T) {
	t.Parallel()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = nil
		_ = json.Unmarshal(b, &body)
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":5}}`)
	}))
	t.Cleanup(srv.Close)
	s, err := newTelegramAt(srv.URL, TelegramConfig{Token: secrets.NewValue(tgToken), ChatID: "-1002145678901", Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Kind = "approval"
	if _, err := s.Send(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if body["protect_content"] != true {
		t.Errorf("approval message: protect_content = %v", body["protect_content"])
	}
	if _, err := s.Send(t.Context(), sample); err != nil {
		t.Fatal(err)
	}
	if _, has := body["protect_content"]; has {
		t.Errorf("incident message: protect_content = %v", body["protect_content"])
	}
}

// L5: a caller's client with a total Timeout shorter than a long poll would cut every poll; the bot clears it on its copy (each call
// has its own deadline) and leaves the caller's client as it was.
func TestTelegramBotClearsTheTotalTimeoutOfItsClient(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // a long poll that waited a little
		case <-time.After(200 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
	}))
	t.Cleanup(srv.Close)
	c := srv.Client()
	c.Timeout = 50 * time.Millisecond
	b := newTelegramBotAt(t, srv.URL, c)
	if _, _, err := b.Updates(t.Context(), 0, time.Second); err != nil {
		t.Fatalf("a poll longer than the caller's client Timeout failed: %v", err)
	}
	if c.Timeout != 50*time.Millisecond {
		t.Error("the caller's client was changed")
	}
}

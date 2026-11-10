package notify_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

// Slice 2 (13b-8, spec approval-tokens.md 6 "sửa tin để bỏ nút", CONTRACT Events "response.decision.made"): once a request is finally
// decided or has ended, the Approve/Reject buttons are removed from the Telegram message that carried them, so nobody presses a dead
// button. The removal is made by the deliver job (event handlers only write the database).

// decision publishes response.decision.made for act-1, the request every test here sends.
func (te *tgEnv) decision(final bool) {
	te.t.Helper()
	if err := te.bus.Publish(te.ctx(), events.Event{Name: "response.decision.made", Data: map[string]any{"request_id": "act-1", "decision": "approved", "by": "admin@acme.example", "final": final}}); err != nil {
		te.t.Fatal(err)
	}
}

func (te *tgEnv) edits() []map[string]any {
	te.tg.mu.Lock()
	defer te.tg.mu.Unlock()
	return append([]map[string]any(nil), te.tg.edits...)
}

func TestContract_POST8_TelegramButtonsRemovedWhenFinallyDecided(t *testing.T) {
	te := newTGEnv(t)
	te.svc.Subscribe(te.bus)
	te.request("act-1")
	te.flush()
	if n := len(te.edits()); n != 0 {
		t.Fatalf("%d edits before any decision", n)
	}
	te.decision(false) // the first of two approvals: the second person still needs the buttons
	te.flush()
	if n := len(te.edits()); n != 0 {
		t.Fatalf("%d edits after the first of two approvals", n)
	}
	te.decision(true)
	te.flush()
	ed := te.edits()
	if len(ed) != 1 {
		t.Fatalf("%d edits after the final decision, want 1", len(ed))
	}
	kb, _ := json.Marshal(ed[0]["reply_markup"])
	if ed[0]["chat_id"] != tgChat || ed[0]["message_id"] != float64(7) || string(kb) != `{"inline_keyboard":[]}` {
		t.Fatalf("edit = %v", ed[0])
	}
	te.flush()
	te.decision(true) // a repeated event
	te.flush()
	if n := len(te.edits()); n != 1 {
		t.Fatalf("%d edits, want the one", n)
	}
	// Events about requests notify never sent buttons for, or not of the documented form, change nothing.
	for _, data := range []any{map[string]any{"request_id": "act-9", "final": true}, map[string]any{"request_id": "act 1", "final": true}, "garbage", map[string]any{"final": "yes"}} {
		_ = te.bus.Publish(te.ctx(), events.Event{Name: "response.decision.made", Data: data})
	}
	te.flush()
	if n := len(te.edits()); n != 1 {
		t.Fatalf("%d edits after unrelated events", n)
	}
}

// Events are best effort (D-144): a request whose decision event was lost still loses its buttons once it has ended.
func TestTelegramButtonsRemovedWhenTheRequestEnds(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	te.clock.Add(14 * time.Minute)
	te.flush()
	if n := len(te.edits()); n != 0 {
		t.Fatalf("%d edits before the request ended", n)
	}
	te.clock.Add(2 * time.Minute)
	te.flush()
	if n := len(te.edits()); n != 1 {
		t.Fatalf("%d edits after the request ended, want 1", n)
	}
}

// A refused edit (400: already edited, the message was deleted) is final; other failures are tried at most 5 times in all.
func TestTelegramButtonRemovalRetriesAFewTimes(t *testing.T) {
	te := newTGEnv(t)
	te.svc.Subscribe(te.bus)
	te.tg.mu.Lock()
	te.tg.editStatus = http.StatusInternalServerError
	te.tg.mu.Unlock()
	te.request("act-1")
	te.decision(true)
	for range 7 {
		te.flush()
	}
	if n := len(te.edits()); n != 5 {
		t.Fatalf("%d edit attempts, want 5", n)
	}
	te2 := newTGEnv(t)
	te2.svc.Subscribe(te2.bus)
	te2.tg.mu.Lock()
	te2.tg.editStatus = http.StatusBadRequest
	te2.tg.mu.Unlock()
	te2.request("act-1")
	te2.decision(true)
	te2.flush()
	te2.flush()
	if n := len(te2.edits()); n != 1 {
		t.Fatalf("%d edit attempts after a 400, want 1", n)
	}
}

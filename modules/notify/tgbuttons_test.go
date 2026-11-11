package notify_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Review of #198, M1: the chat kept for the removal is the one Telegram names in its answer (a checked number), never the configured
// text. A configured chat_id can be any form the adapter accepts (for example with leading zeros), and editMessageReplyMarkup only
// takes Telegram's own id: with the configured text the removal was refused before any call, 5 times, and the buttons stayed.
func TestTelegramButtonsAreRemovedInTheChatTelegramNamed(t *testing.T) {
	te := newTGEnv(t)
	te.svc.Subscribe(te.bus)
	te.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "0012345"}, MinSeverity: notify.Low,
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-admin", Address: "123456789"}}})
	te.tg.mu.Lock()
	te.tg.sendChat = "-1009876543210"
	te.tg.mu.Unlock()
	te.request("act-1")
	te.decision(true)
	te.flush()
	ed := te.edits()
	if len(ed) != 1 || ed[0]["chat_id"] != "-1009876543210" || ed[0]["message_id"] != float64(7) {
		t.Fatalf("edits = %v, want one in the chat Telegram named", ed)
	}
}

// M1 as first reported (a long public @name chat breaking the chat_id CHECK and rolling back the send records) cannot happen: a
// @name chat never gets buttons (approvals need a numeric chat, #178 L1), so nothing about the message is kept. This pins it: a
// 25-character @name with approvals forced on (a channel saved before that rule) records its send, gets no buttons and no row.
func TestTelegramApprovalToALongPublicNameRecordsTheSend(t *testing.T) {
	te := newTGEnv(t)
	name := "@" + strings.Repeat("v", 24)
	te.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": name}, MinSeverity: notify.Low})
	te.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(te.ctx(), `UPDATE notify_channel SET approvals = 1 WHERE type = 'telegram'`)
		return err
	})
	te.request("act-1")
	if n := te.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'approval' AND ok = 1`); n != 1 {
		t.Fatalf("%d approval sends recorded, want 1", n)
	}
	if n := te.count(`SELECT COUNT(*) FROM notify_tg_button`); n != 0 {
		t.Fatalf("%d button rows for a @name chat", n)
	}
}

// Review of #198, L2: a button of a request that is over (marked for removal, removed, or past its end) is refused before Decide.
func TestTelegramPressOnARequestThatIsOverIsNotDecided(t *testing.T) {
	te := newTGEnv(t)
	te.svc.Subscribe(te.bus)
	te.request("act-1")
	a, _ := te.tg.buttons(t)
	te.request("act-2")
	a2, _ := te.tg.buttons(t)
	te.listen()
	te.decision(true) // act-1 is finally decided: its buttons are marked for removal
	te.tg.press("123456789", tgChat, a)
	if ans := te.tg.answer(t); ans["text"] != "This button is not valid. Open Vedette to decide." {
		t.Fatalf("a press on a decided request: answer = %v", ans)
	}
	te.tg.inPoll(t)                // the listener is in its next long poll: moving the clock now is not a gap without polling (L3)
	te.clock.Add(16 * time.Minute) // act-2 has ended
	te.tg.press("123456789", tgChat, a2)
	if ans := te.tg.answer(t); ans["text"] != "This button is not valid. Open Vedette to decide." {
		t.Fatalf("a press on an ended request: answer = %v", ans)
	}
	if got := te.dec.got(); len(got) != 0 {
		t.Fatalf("Decide was called: %+v", got)
	}
}

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

// L1 (#198 review): button removal runs inside the deliver job, so a Telegram that fails or does not answer must cost one edit per run,
// not one per marked message (20 × 15 s held alert delivery for about 5 minutes). The rest wait for the next run, as on Slack.
func TestTelegramButtonRemovalStopsAtTheFirstFailure(t *testing.T) {
	te := newTGEnv(t)
	te.svc.Subscribe(te.bus)
	for _, id := range []string{"act-1", "act-2", "act-3"} {
		te.request(id)
		if err := te.bus.Publish(te.ctx(), events.Event{Name: "response.decision.made", Data: map[string]any{"request_id": id, "decision": "approved", "by": "admin@acme.example", "final": true}}); err != nil {
			t.Fatal(err)
		}
	}
	te.tg.mu.Lock()
	te.tg.editStatus = http.StatusInternalServerError
	te.tg.mu.Unlock()
	te.flush()
	if n := len(te.edits()); n != 1 {
		t.Fatalf("%d edit attempts in one run against a failing Telegram, want 1", n)
	}
	te.tg.mu.Lock()
	te.tg.editStatus = 0
	te.tg.mu.Unlock()
	te.flush()
	if n := len(te.edits()); n != 4 {
		t.Fatalf("%d edit attempts after Telegram came back, want 1 + 3", n)
	}
}

// L3 (#198 review): sending the same request again must not orphan the keyboard of the message already shown. The re-send carries no
// buttons; the first message keeps them, stays tracked and is the one cleared. A first send that never reached Telegram left no message,
// so a re-send then carries buttons.
func TestTelegramResendKeepsTheShownKeyboard(t *testing.T) {
	te := newTGEnv(t)
	te.svc.Subscribe(te.bus)
	te.request("act-1")
	te.request("act-1")
	te.tg.mu.Lock()
	sends := append([]map[string]any(nil), te.tg.sends...)
	te.tg.mu.Unlock()
	if len(sends) != 2 || sends[0]["reply_markup"] == nil || sends[1]["reply_markup"] != nil {
		t.Fatalf("sends = %v", sends)
	}
	te.decision(true)
	te.flush()
	if n := len(te.edits()); n != 1 {
		t.Fatalf("%d edits, want the first message cleared once", n)
	}

	te2 := newTGEnv(t)
	te2.tg.mu.Lock()
	te2.tg.status = http.StatusInternalServerError
	te2.tg.mu.Unlock()
	_, _ = te2.svc.SendApprovalRequest(te2.ctx(), te2.approvalReq("act-2", channel.Telegram))
	te2.tg.mu.Lock()
	te2.tg.status = 0
	te2.tg.mu.Unlock()
	te2.request("act-2")
	te2.tg.mu.Lock()
	last := te2.tg.sends[len(te2.tg.sends)-1]
	te2.tg.mu.Unlock()
	if last["reply_markup"] == nil {
		t.Fatalf("a re-send after a failed first send has no buttons: %v", last)
	}
}

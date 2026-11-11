package notify_test

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Slice 3b (D-241, spec approval-tokens.md 5 "chat.update để bỏ nút"): once a request is finally decided or has ended, the Slack
// message that carried its Approve/Reject buttons is rewritten without them (chat.update with the bot token), keeping its text and
// adding one line that says how it ended. The deliver job does the network; the event handler only writes the database.

func (se *slEnv) decision(id, decision string, final bool) {
	se.t.Helper()
	if err := se.bus.Publish(se.ctx(), events.Event{Name: "response.decision.made",
		Data: map[string]any{"request_id": id, "decision": decision, "by": "admin@acme.example", "final": final}}); err != nil {
		se.t.Fatal(err)
	}
}

func (se *slEnv) updates() []map[string]any {
	se.sl.mu.Lock()
	defer se.sl.mu.Unlock()
	return append([]map[string]any(nil), se.sl.updates...)
}

func (se *slEnv) setUpd(mode string) {
	se.sl.mu.Lock()
	se.sl.updMode = mode
	se.sl.mu.Unlock()
}

func (se *slEnv) updTries() int {
	se.sl.mu.Lock()
	defer se.sl.mu.Unlock()
	return se.sl.updTries
}

// checkUpdate asserts one chat.update: the kept message, the bot token, no actions block, the original text and the end line.
func checkUpdate(t *testing.T, u map[string]any, end string) {
	t.Helper()
	raw, _ := json.Marshal(u["blocks"])
	if u["channel"] != slChannel || u["ts"] != slTS {
		t.Fatalf("updated %v %v, want %s %s", u["channel"], u["ts"], slChannel, slTS)
	}
	if strings.Contains(string(raw), `"actions"`) || strings.Contains(string(raw), "vedette_a") {
		t.Fatalf("the buttons are still there: %s", raw)
	}
	if !strings.Contains(string(raw), "Block 203.0.113.9") || !strings.Contains(string(raw), end) {
		t.Fatalf("blocks lack the original text or %q: %s", end, raw)
	}
	if txt, _ := u["text"].(string); !strings.Contains(txt, "Block 203.0.113.9") || !strings.Contains(txt, end) {
		t.Fatalf("text = %q", u["text"])
	}
}

func TestContract_POST8_SlackButtonsRemovedWhenFinallyDecided(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	se.flush()
	if n := len(se.updates()); n != 0 {
		t.Fatalf("%d updates before any decision", n)
	}
	se.decision("act-1", "approved", false) // the first of two approvals: the second person still needs the buttons
	se.flush()
	if n := len(se.updates()); n != 0 {
		t.Fatalf("%d updates after the first of two approvals", n)
	}
	se.decision("act-1", "approved", true)
	se.flush()
	u := se.updates()
	if len(u) != 1 {
		t.Fatalf("%d updates after the final decision, want 1", len(u))
	}
	checkUpdate(t, u[0], "Approved.")
	se.sl.mu.Lock()
	auth := se.sl.auths[len(se.sl.auths)-1]
	se.sl.mu.Unlock()
	if auth != "Bearer "+slackBotTok {
		t.Fatalf("chat.update authorization %q", auth)
	}
	se.flush()
	se.decision("act-1", "approved", true) // a repeated event
	se.flush()
	if n := len(se.updates()); n != 1 {
		t.Fatalf("%d updates, want the one", n)
	}
	// Events about requests without a Slack message, or not of the documented form, change nothing.
	for _, data := range []any{map[string]any{"request_id": "act-9", "final": true}, map[string]any{"request_id": "act 1", "final": true}, "garbage", map[string]any{"final": "yes"}} {
		_ = se.bus.Publish(se.ctx(), events.Event{Name: "response.decision.made", Data: data})
	}
	se.flush()
	if n := len(se.updates()); n != 1 {
		t.Fatalf("%d updates after unrelated events", n)
	}
}

// Each outcome has its own line; an outcome not of the documented set reads as "ended" (no untrusted text reaches Slack).
func TestSlackEndLineFollowsTheDecision(t *testing.T) {
	for _, c := range []struct{ decision, end string }{
		{"rejected", "Rejected."}, {"expired", "Expired. Nothing was changed."}, {"cancelled", "Cancelled."},
		{"<!channel> *pwned*", "This request has ended. Open Vedette to see the outcome."},
	} {
		se := newSLEnv(t)
		se.svc.Subscribe(se.bus)
		se.request()
		se.decision("act-1", c.decision, true)
		se.flush()
		u := se.updates()
		if len(u) != 1 {
			t.Fatalf("%s: %d updates", c.decision, len(u))
		}
		checkUpdate(t, u[0], c.end)
		if raw, _ := json.Marshal(u[0]); strings.Contains(string(raw), "pwned") {
			t.Fatalf("event text reached Slack: %s", raw)
		}
	}
}

// Events are best effort (D-144): a request whose decision event was lost still loses its buttons once it has ended.
func TestSlackButtonsRemovedWhenTheRequestEnds(t *testing.T) {
	se := newSLEnv(t)
	se.request()
	se.clock.Add(14 * time.Minute)
	se.flush()
	if n := len(se.updates()); n != 0 {
		t.Fatalf("%d updates before the request ended", n)
	}
	se.clock.Add(2 * time.Minute)
	se.flush()
	u := se.updates()
	if len(u) != 1 {
		t.Fatalf("%d updates after the request ended, want 1", len(u))
	}
	checkUpdate(t, u[0], "This request has ended. Open Vedette to see the outcome.")
}

// The final decision can arrive before the send of the Slack message is recorded (another channel's approver pressed first while
// the messages were still going out). The message recorded afterwards is marked for removal at once.
func TestSlackDecisionBeforeTheSendRecordStillRemovesTheButtons(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.decision("act-1", "rejected", true)
	se.request()
	se.flush()
	u := se.updates()
	if len(u) != 1 {
		t.Fatalf("%d updates, want 1", len(u))
	}
	checkUpdate(t, u[0], "Rejected.")
}

// A press on a request that is finally decided is refused before Decide, like one on an ended request.
func TestSlackPressAfterTheFinalDecisionIsNotDecided(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	c, _ := se.listen()
	se.decision("act-1", "approved", true)
	c.out <- slPress{}.json()
	se.sl.ack(t, "env-1")
	if r := se.sl.reply(t); r["text"] != "This button is not valid. Open Vedette to decide." {
		t.Fatalf("reply %v", r)
	}
	se.noDecision(t)
}

// Slack refusing the edit for good (ok:false, e.g. message_not_found) ends the work at once; a 5xx is tried again at the next runs,
// at most 5 times in all.
func TestSlackButtonRemovalGivesUp(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	se.decision("act-1", "approved", true)
	se.setUpd("gone")
	se.flush()
	se.flush()
	if n := se.updTries(); n != 1 {
		t.Fatalf("%d tries after message_not_found, want 1", n)
	}

	se2 := newSLEnv(t)
	se2.svc.Subscribe(se2.bus)
	se2.request()
	se2.decision("act-1", "approved", true)
	se2.setUpd("500")
	for range 7 {
		se2.flush()
	}
	if n := se2.updTries(); n != 5 {
		t.Fatalf("%d tries with a 5xx, want 5", n)
	}
}

// L1 of #198 for Slack: a Slack that does not answer stops the removals of this run at the first failure, so the deliver job is held
// for at most one request timeout, not one per message; the rest are done at the next run.
func TestSlackButtonRemovalStopsAtTheFirstTransportError(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	se.sl.mu.Lock()
	se.sl.postTS = "1731326400.000200"
	se.sl.mu.Unlock()
	if _, err := se.svc.SendApprovalRequest(se.ctx(), se.approvalReq("act-2", channel.Slack)); err != nil {
		t.Fatal(err)
	}
	se.decision("act-1", "approved", true)
	se.decision("act-2", "rejected", true)
	se.setUpd("drop")
	se.flush()
	if n := se.updTries(); n != 1 {
		t.Fatalf("%d tries in a run where Slack does not answer, want 1", n)
	}
	se.setUpd("")
	se.flush()
	if n := len(se.updates()); n != 2 {
		t.Fatalf("%d updates at the next run, want 2", n)
	}
}

// Without the bot token (channel changed to the webhook only) nothing is sent, and the flush does not fail.
func TestSlackButtonRemovalWithoutABotTokenSendsNothing(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	se.decision("act-1", "approved", true)
	se.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(se.ctx(), `UPDATE notify_channel SET bot_token_secret_id = NULL, bot_token_last4 = NULL WHERE type = 'slack'`)
		return err
	})
	se.flush()
	if n := se.updTries(); n != 0 {
		t.Fatalf("%d chat.update calls without a bot token", n)
	}
}

// Review of 3b: which failures are final for one message and which stop the run (count a try, the rest wait).
func TestSlackButtonRemovalFailureKinds(t *testing.T) {
	for _, c := range []struct {
		mode      string
		triesRun1 int  // chat.update calls in the first run, with two messages to rewrite
		final     bool // the first message is given up after its first try
	}{
		{"gone", 2, true}, {"404", 2, true}, // Slack refuses this edit: final, the run goes on
		{"429", 1, false}, {"500", 1, false}, {"garbage", 1, false}, {"auth", 1, false}, {"drop", 1, false}, // stop the run
	} {
		se := newSLEnv(t)
		se.svc.Subscribe(se.bus)
		se.request()
		se.sl.mu.Lock()
		se.sl.postTS = "1731326400.000200"
		se.sl.mu.Unlock()
		if _, err := se.svc.SendApprovalRequest(se.ctx(), se.approvalReq("act-2", channel.Slack)); err != nil {
			t.Fatal(err)
		}
		se.decision("act-1", "approved", true)
		se.decision("act-2", "approved", true)
		se.setUpd(c.mode)
		se.flush()
		if n := se.updTries(); n != c.triesRun1 {
			t.Fatalf("%s: %d calls in the first run, want %d", c.mode, n, c.triesRun1)
		}
		left := se.count(`SELECT COUNT(*) FROM notify_slack_button WHERE state = 'remove'`)
		if want := map[bool]int{true: 0, false: 2}[c.final]; left != want {
			t.Fatalf("%s: %d messages still to rewrite, want %d", c.mode, left, want)
		}
	}
}

// Review of 3b: the expiry sweep marks a message "ended" at the end time; response's "expired" event, which comes after, still
// gives it the real line when it has not been rewritten yet.
func TestSlackExpiredEventAfterTheSweepKeepsTheRealLine(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	se.clock.Add(16 * time.Minute)
	se.setUpd("drop") // the sweep marks it; Slack does not answer, so it is not rewritten yet
	se.flush()
	se.setUpd("")
	se.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(se.ctx(), `UPDATE notify_slack_button SET tries = 0`)
		return err
	})
	se.decision("act-1", "expired", true)
	se.flush()
	u := se.updates()
	if len(u) != 1 {
		t.Fatalf("%d updates", len(u))
	}
	checkUpdate(t, u[0], "Expired. Nothing was changed.")
}

// Without the history copy (history cleared) the message is still rewritten, with the end line only.
func TestSlackButtonRemovalWithoutHistoryWritesTheEndLine(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.request()
	se.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(se.ctx(), `DELETE FROM notify_send`)
		return err
	})
	se.decision("act-1", "rejected", true)
	se.flush()
	u := se.updates()
	if len(u) != 1 {
		t.Fatalf("%d updates", len(u))
	}
	raw, _ := json.Marshal(u[0]["blocks"])
	if u[0]["text"] != "Rejected." || strings.Contains(string(raw), "actions") {
		t.Fatalf("update %v", u[0])
	}
}

// A request id longer than a Telegram button can carry (51 to 128 characters) still has its Slack buttons removed.
func TestSlackButtonRemovalForALongRequestID(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	id := "act-" + strings.Repeat("x", 100)
	if _, err := se.svc.SendApprovalRequest(se.ctx(), se.approvalReq(id, channel.Slack)); err != nil {
		t.Fatal(err)
	}
	if n := se.count(`SELECT COUNT(*) FROM notify_slack_button`); n != 1 {
		t.Fatalf("%d rows, posts %d", n, len(se.sl.posts))
	}
	se.decision(id, "approved", true)
	se.flush()
	if n := len(se.updates()); n != 1 {
		t.Fatalf("%d updates for a %d-character request id", n, len(id))
	}
}

// Final decisions are forgotten a week after they arrived (the hourly prune).
func TestSlackFinalDecisionsArePruned(t *testing.T) {
	se := newSLEnv(t)
	se.svc.Subscribe(se.bus)
	se.decision("act-9", "approved", true)
	if n := se.count(`SELECT COUNT(*) FROM notify_slack_final`); n != 1 {
		t.Fatalf("%d final rows", n)
	}
	se.clock.Add(8 * 24 * time.Hour)
	se.flush()
	if n := se.count(`SELECT COUNT(*) FROM notify_slack_final`); n != 0 {
		t.Fatalf("%d final rows after a week", n)
	}
}

// Review of 3b (slice 3 gap): an approval whose rendered text does not fit one Block Kit section (3000 characters, after escaping)
// would be refused by chat.postMessage; it goes through the webhook without buttons instead.
func TestSlackApprovalTooLongForASectionUsesTheWebhook(t *testing.T) {
	se := newSLEnv(t)
	req := se.approvalReq("act-1", channel.Slack)
	req.What = strings.Repeat("a&b ", 700) // 2800 characters, each & escaped to &amp;
	if _, err := se.svc.SendApprovalRequest(se.ctx(), req); err != nil {
		t.Fatal(err)
	}
	if len(se.sl.posts) != 0 || !se.sawHostWebhook() || se.count(`SELECT COUNT(*) FROM notify_slack_button`) != 0 {
		t.Fatalf("posts %d, webhook %v: a message too long for a section must go through the webhook", len(se.sl.posts), se.sawHostWebhook())
	}
}

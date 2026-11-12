package notify_test

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Follow-ups of the security review of #172.

const answerStale = "This button was pressed while Vedette was not listening. Press it again."

// L1: a public @name chat can be joined by anyone, and a released name can be taken by someone else, who would then receive the approval
// messages. Approvals need the numeric chat id; a @name stays fine for alerts only.
func TestContract_PRE8_TelegramApprovalsNeedANumericChat(t *testing.T) {
	te := newTGEnv(t)
	_, err := te.svc.SaveChannel(te.ctx(), "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "@vedette_alerts"},
		MinSeverity: notify.Low, Approvals: true, Approvers: []notify.Approver{{UserID: "u-admin", Address: "123456789"}}})
	if s, c := apiCode(err); s != http.StatusBadRequest || c != "bad_chat_id" {
		t.Fatalf("approvals with a @name chat: %v", err)
	}
	if n := te.count(`SELECT COUNT(*) FROM notify_channel WHERE type = 'telegram' AND fields LIKE '%vedette_alerts%'`); n != 0 {
		t.Fatal("the @name was saved")
	}
	te.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "@vedette_alerts"}, MinSeverity: notify.Low})
	// A channel saved before this rule, with approvals on and a @name: no buttons and no polling.
	te.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(te.ctx(), `UPDATE notify_channel SET approvals = 1 WHERE type = 'telegram'`)
		return err
	})
	te.request("act-1")
	te.tg.mu.Lock()
	_, has := te.tg.sends[len(te.tg.sends)-1]["reply_markup"]
	polls := te.tg.polls
	te.tg.mu.Unlock()
	if has || te.count(`SELECT COUNT(*) FROM notify_tg_button`) != 0 {
		t.Fatal("a @name chat got approval buttons")
	}
	if err := te.job().Run(te.ctx()); err != nil {
		t.Fatal(err)
	}
	te.tg.mu.Lock()
	defer te.tg.mu.Unlock()
	if te.tg.polls != polls {
		t.Fatal("the listener polled for a @name chat")
	}
}

// L3: a press that waited at Telegram while the box was not listening (down, restarting, or the listener stopped for more than a
// minute) is answered and dropped, never decided: the person may have given up on it long ago. message.date cannot tell this (it is
// when the approval message was sent), so the listener drops what is waiting when it starts again after a gap.
func TestContract_PRE8_TelegramPressesFromBeforeTheListenerAreDropped(t *testing.T) {
	te := newTGEnv(t)
	te.request("act-1")
	a, _ := te.tg.buttons(t)
	te.tg.press("123456789", tgChat, a) // pressed while the box was down
	stop := te.listen()
	if ans := te.tg.answer(t); ans["text"] != answerStale {
		t.Fatalf("a waiting press: answer = %v", ans)
	}
	if got := te.dec.got(); len(got) != 0 {
		t.Fatalf("a waiting press was decided: %+v", got)
	}
	te.tg.press("123456789", tgChat, a) // pressed while it listens
	if ans := te.tg.answer(t); ans["text"] != "Approved. Block 203.0.113.9 is being run." || len(te.dec.got()) != 1 {
		t.Fatalf("a new press: answer = %v, decisions %+v", ans, te.dec.got())
	}
	// The listener stopped for two minutes: what waits is dropped again.
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	te.clock.Add(2 * time.Minute)
	te.tg.press("123456789", tgChat, a)
	stop = te.listen()
	if ans := te.tg.answer(t); ans["text"] != answerStale || len(te.dec.got()) != 1 {
		t.Fatalf("after a two-minute gap: answer = %v, decisions %+v", ans, te.dec.got())
	}
	// The scheduler starting the job again 30 s after it stopped: what waits is taken.
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	te.clock.Add(30 * time.Second)
	te.tg.press("123456789", tgChat, a)
	te.start()
	if ans := te.tg.answer(t); ans["text"] != "Approved. Block 203.0.113.9 is being run." || len(te.dec.got()) != 2 {
		t.Fatalf("after a 30 s gap: answer = %v, decisions %+v", ans, te.dec.got())
	}
}

// L6: answers made on the receive loop (presses refused before Decide) have a short budget, so a Telegram that does not answer one
// does not hold the next press for long.
func TestTelegramAnswersOnTheReceiveLoopHaveAShortBudget(t *testing.T) {
	te := newTGEnv(t)
	te.listen()
	te.tg.mu.Lock()
	te.tg.hangAnswers = 1
	te.tg.mu.Unlock()
	start := time.Now()
	te.tg.press("123456789", tgChat, "a:x:y") // refused on the loop; Telegram never answers the answer
	te.tg.press("123456789", tgChat, "a:x:z")
	if ans := te.tg.answer(t); ans["text"] != "This button is not valid. Open Vedette to decide." {
		t.Fatalf("answer = %v", ans)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("the second press was answered after %v", d)
	}
}

// stopOnLog is a log handler that stops the listener (cancel) when a record with message msg is written: it lands a stop at an exact
// point of the listener's loop.
type stopOnLog struct {
	msg    string
	cancel context.CancelFunc
}

func (h stopOnLog) Enabled(context.Context, slog.Level) bool { return true }
func (h stopOnLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.msg {
		h.cancel()
	}
	return nil
}
func (h stopOnLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h stopOnLog) WithGroup(string) slog.Handler      { return h }

// A listener stopped while it reads the bot key returns nil, not "the saved key cannot be read" (#183): the stop is a stop, whatever
// the key read answered. The key is made unreadable and the stop lands inside openSecret (at its warning), the interleaving that
// failed TestContract_PRE8_TelegramPressesFromBeforeTheListenerAreDropped on CI when the stop cancelled the read of the key.
func TestTelegramListenerStoppedWhileReadingTheKeyReturnsNil(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	te := newTGEnv(t, func(c *notify.Config) {
		c.Log = slog.New(stopOnLog{msg: "notify: a saved channel secret cannot be opened", cancel: cancel})
	})
	te.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(te.ctx(), `UPDATE core_secret SET key_version = key_version + 100
			WHERE id = (SELECT secret_id FROM notify_channel WHERE type = 'telegram')`)
		return err
	})
	if err := te.job().Run(ctx); err != nil || ctx.Err() == nil {
		t.Fatalf("stopped while reading the key: %v (stopped: %v)", err, ctx.Err() != nil)
	}
	// Not stopped, the same unreadable key is an error of the listener.
	if err := te.job().Run(t.Context()); err == nil || !strings.Contains(err.Error(), "the saved key cannot be read") {
		t.Fatalf("an unreadable key: %v", err)
	}
}

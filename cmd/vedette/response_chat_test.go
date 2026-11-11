package main

import (
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-8 (D-96 (5), response INV-3) in the real wiring: notify's Config.Decisions is the adapter over the response service, and a
// decision a chat listener hands to it is mapped to a Vedette person and goes through the same gates as the app. The listeners are not built
// yet, so the test calls the port the way a listener will, after the platform was checked.

func TestWiringChatDecisionsPort(t *testing.T) {
	t.Parallel()
	s, _, a, _ := linkSetup(t)
	ctx := t.Context()
	svc := s.d.Response

	// notify is built with the adapter (read lazily: response is built after notify).
	n := newNotify(s.d)
	got := reflect.ValueOf(n).Elem().FieldByName("cfg").FieldByName("Decisions")
	if !got.IsValid() || got.IsNil() || got.Elem().Type() != reflect.TypeOf(responseDecisions{}) {
		t.Fatalf("notify.Config.Decisions is not the response adapter: %v", got)
	}
	var port notify.Decisions = responseDecisions{s.d}

	bao := s.addUser("bao@acme.example", routes.Operator)
	if _, err := n.SaveChannel(ctx, "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true, MinSeverity: notify.Low, Secret: "123456789:AAHexampleExampleExampleExample_0123456789",
		Fields: map[string]string{"chat_id": "-1002145678901"}, Approvals: true, Approvers: []notify.Approver{{UserID: bao.ID, Address: "100200"}}}); err != nil {
		t.Fatal(err)
	}
	st, err := svc.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	boss := response.Actor{ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Via: response.ViaApp}
	in := response.SettingsInput{MaxPerHour: st.MaxPerHour, ExpiryMin: 15, ApprovalChannels: []string{"email", "telegram"}, BreakerMaxPerHour: 100, MultiTargetMax: st.MultiTargetMax, Maintenance: st.Maintenance}
	in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = st.AI.Triggers, st.AI.BudgetHour, st.AI.BudgetDay
	if _, err := svc.SaveSettings(ctx, boss, in); err != nil {
		t.Fatal(err)
	}

	// A sender that is not on the list: a reply for the person, nothing decided, a line in the log.
	r, err := port.Decide(ctx, notify.Decision{Channel: channel.Telegram, ExternalID: "999", RequestID: a.ID, Approve: true})
	if err != nil || r.Status != "approver_not_listed" || r.Message == "" {
		t.Fatalf("unlisted: %+v %v", r, err)
	}
	if s.count(`SELECT count(*) FROM resp_log WHERE kind = 'refused' AND actor = '999 via telegram'`) != 1 || s.count(`SELECT count(*) FROM resp_block_entries`) != 0 {
		t.Fatal("the refusal is not logged, or something ran")
	}
	// D-191: the person on the list has not linked the ID yet: nothing is decided, the private answer holds a link code, which Bao types in
	// My account.
	r, err = port.Decide(ctx, notify.Decision{Channel: channel.Telegram, ExternalID: "100200", RequestID: a.ID, Approve: true})
	lc := regexp.MustCompile(`code (\d{6})`).FindStringSubmatch(r.Message)
	if err != nil || r.Status != "approver_not_linked" || lc == nil {
		t.Fatalf("unlinked: %+v %v", r, err)
	}
	if _, err := svc.ConfirmLink(ctx, response.Actor{ID: bao.ID, Email: "bao@acme.example", Via: response.ViaApp}, "telegram", lc[1]); err != nil {
		t.Fatal(err)
	}
	// The person on the list decides, once.
	r, err = port.Decide(ctx, notify.Decision{Channel: channel.Telegram, ExternalID: "100200", RequestID: a.ID, Approve: true})
	if err != nil || r.Status != "approved" || r.Message == "" {
		t.Fatalf("decision: %+v %v", r, err)
	}
	for range 1000 { // the items run in the background after the decision was answered (D-135 (9))
		if s.count(`SELECT count(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) == 1 {
			break
		}
		select {
		case <-t.Context().Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	if s.count(`SELECT count(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 1 {
		t.Fatal("the approved action did not run")
	}
	if s.count(`SELECT count(*) FROM resp_log WHERE kind = 'approved' AND actor = ?`, "Test operator via telegram (100200)") != 1 {
		t.Fatalf("the approval is not in the log as the person via telegram:\n%s", s.dumpDB())
	}
	r, err = port.Decide(ctx, notify.Decision{Channel: channel.Telegram, ExternalID: "100200", RequestID: a.ID, Approve: true})
	if err != nil || r.Status != "decided" {
		t.Fatalf("second: %+v %v", r, err)
	}
	if s.count(`SELECT count(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 1 {
		t.Fatal("the action ran twice")
	}
	// A box that is not ready answers with an error, not a decision.
	if _, err := (responseDecisions{&deps{}}).Decide(ctx, notify.Decision{Channel: channel.Telegram, ExternalID: "100200", RequestID: a.ID}); err == nil {
		t.Fatal("no response service, no error")
	}
}

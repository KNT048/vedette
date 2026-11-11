package response_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// Review of slice 13b-8 (D-135 (7) to (9) and the lows): the chat rate table, the volume of the log, detached runs, the recheck under the
// lock, and the gaps of the first round.

// ---- M1: the rate table ----

func TestChat_AFullRateTableNeverBlocksAListedApprover(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.svc.SetChatKeysMaxForTest(3)
	for i := range 3 {
		_, err := c.button("slack", fmt.Sprintf("U0S00%d", i), a.ID, true)
		c.mustCode(err, 403, "approver_not_listed")
	}
	for i := range 12 { // the table is full of strangers: a new stranger is turned away, and the box says so once
		_, err := c.button("slack", fmt.Sprintf("U0T0%02d", i), a.ID, true)
		c.mustCode(err, 429, "rate_limited")
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE '%chat rate table full%'`); n != 1 {
		t.Fatalf("%d lines about the full table, want 1 a minute", n)
	}
	if n := c.svc.ChatKeysForTest(); n != 3 {
		t.Fatalf("the table holds %d identities, want 3", n)
	}
	out, err := c.button("slack", slackOp, a.ID, true) // a listed approver is let in, the oldest stranger is forgotten
	c.must(err)
	if out.Status != "approved" || c.svc.ChatKeysForTest() > 3 {
		t.Fatalf("%+v keys=%d", out, c.svc.ChatKeysForTest())
	}
	if _, err := c.button("telegram", tgOp2, a.ID, true); err == nil { // decided already: but it got in
		t.Fatal("expected the refusal of a decided request")
	} else if _, code := apiCode(err); code != "decided" {
		t.Fatalf("a listed approver was turned away by the full table: %v", err)
	}
	c.clock.Advance(61 * time.Second) // the strangers age out and the next flood is logged again
	for i := range 3 {
		_, err := c.button("slack", fmt.Sprintf("U0V00%d", i), a.ID, true)
		c.mustCode(err, 403, "approver_not_listed")
	}
}

func TestChat_AFullTableOfListedApproversStillTakesAListedOne(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.svc.SetChatKeysMaxForTest(1)
	_, err := c.button("slack", slackOp2, a.ID, false) // the one place is taken by a listed approver (and the request is rejected)
	c.must(err)
	for _, who := range [][2]string{{"telegram", tgOp}, {"telegram", tgOp2}, {"slack", slackOp}} {
		_, err := c.button(who[0], who[1], a.ID, true)
		if _, code := apiCode(err); code != "decided" {
			t.Fatalf("%v: %v", who, err)
		}
	}
}

func TestChat_ManyIdentitiesDoNotGrowTheTable(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.svc.SetChatKeysMaxForTest(50)
	for i := range 300 {
		_, _ = c.button("slack", fmt.Sprintf("U0M%04d", i), a.ID, true)
		if n := c.svc.ChatKeysForTest(); n > 50 {
			t.Fatalf("after %d identities the table holds %d", i+1, n)
		}
	}
	// and the links and block list tables are not touched by chat
	if c.svc.LinkKeysForTest() != 0 {
		t.Fatalf("chat used the link table: %d", c.svc.LinkKeysForTest())
	}
}

// ---- M2: the volume of the log ----

func TestChat_AStrangerWritesOneLinePerWindow(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	auditBefore := c.count(`SELECT COUNT(*) FROM core_audit`)
	for range 100 {
		_, _ = c.button("slack", "U0ZZZ999", a.ID, true)
	}
	not := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'U0ZZZ999 via slack' AND detail LIKE 'approver_not_listed:%'`)
	rl := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'U0ZZZ999 via slack' AND detail LIKE 'rate_limited:%'`)
	if not != 1 || rl != 1 {
		t.Fatalf("100 refusals of one stranger: %d approver_not_listed lines and %d rate_limited lines, want 1 and 1", not, rl)
	}
	if n := c.count(`SELECT COUNT(*) FROM core_audit`) - auditBefore; n > 2 {
		t.Fatalf("%d audit lines for one stranger in a minute, want at most 2", n)
	}
	c.clock.Advance(61 * time.Second)
	_, _ = c.button("slack", "U0ZZZ999", a.ID, true)
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'U0ZZZ999 via slack' AND detail LIKE 'approver_not_listed: % (19 more refusals of this sender since the last line)'`) != 1 {
		t.Fatalf("the next window's line does not carry the count:\n%s", c.dump(`SELECT actor || ' | ' || detail FROM resp_log WHERE kind = 'refused'`))
	}
}

func TestChat_AChannelThatIsOffWritesOneLinePerWindowToo(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.note.chs[1].Enabled = false
	for range 19 {
		_, err := c.button("slack", slackOp, a.ID, true)
		c.mustCode(err, 403, "channel_not_allowed")
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'channel_not_allowed:%'`); n != 1 {
		t.Fatalf("%d lines, want 1", n)
	}
}

func TestChat_ManyStrangersAreBoundedByTheBudget(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	for i := range 300 {
		_, _ = c.button("slack", fmt.Sprintf("U0S%04d", i), a.ID, true)
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'approver_not_listed:%'`); n > 60 {
		t.Fatalf("%d lines from strangers in one minute, want at most 60", n)
	}
}

// ---- M3: slow approvals ----

func TestChat_ACompletingApprovalReturnsAtOnceAndTheItemsRunInTheBackground(t *testing.T) {
	c := newChatEnv(t)
	a := c.highRisk()
	c.twoPersonMedium(a)
	if _, err := c.button("slack", slackOp, a.ID, true); err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	c.exec.mu.Lock()
	c.exec.hold = hold // the device answers after "5 seconds": not before the test lets it
	c.exec.mu.Unlock()
	start := time.Now()
	out, err := c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "slack", ExternalID: slackOp2, RequestID: a.ID, Approve: true})
	took := time.Since(start)
	c.must(err)
	if took > time.Second {
		t.Fatalf("the decision took %v with a slow device", took)
	}
	if out.Status != "approved" || !strings.Contains(out.Message, "is being run") || strings.Contains(out.Message, "has run") {
		t.Fatalf("outcome: %+v", out)
	}
	got := c.only()
	if got.Status != response.StatusApproved || len(got.Approvals) != 2 {
		t.Fatalf("the decision is recorded before the item runs: %+v", got)
	}
	close(hold)
	c.svc.WaitSendsForTest()
	if got := c.only(); got.Status != response.StatusExecuted || c.exec.count() == 0 {
		t.Fatalf("the item did not run: %+v", got)
	}
}

func TestChat_CloseEndsADetachedRun(t *testing.T) {
	c := newChatEnv(t)
	a := c.highRisk()
	c.twoPersonMedium(a)
	if _, err := c.button("slack", slackOp, a.ID, true); err != nil {
		t.Fatal(err)
	}
	c.exec.mu.Lock()
	c.exec.hold = make(chan struct{}) // never answers
	c.exec.mu.Unlock()
	if _, err := c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "slack", ExternalID: slackOp2, RequestID: a.ID, Approve: true}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { c.svc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not end the detached run")
	}
}

// ---- L1: the recheck under the lock ----

func TestChat_TheRecheckUnderTheLock(t *testing.T) {
	cases := []struct {
		name string
		arm  func(c *chatEnv)
	}{
		{"user disabled", func(c *chatEnv) { u := c.users.m["u-op"]; u.Disabled = true; c.users.m["u-op"] = u }},
		{"user demoted", func(c *chatEnv) { u := c.users.m["u-op"]; u.Role = "viewer"; c.users.m["u-op"] = u }},
		{"taken off the list", func(c *chatEnv) {
			c.note.approvers["slack"] = []response.Approver{{UserID: "u-op2", Address: slackOp2}}
		}},
		{"the id now belongs to someone else", func(c *chatEnv) {
			c.note.approvers["slack"] = []response.Approver{{UserID: "u-op2", Address: slackOp}}
		}},
		{"channel off", func(c *chatEnv) { c.note.chs[1].Enabled = false }},
		{"no longer an approval channel", func(c *chatEnv) {
			c.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
		}},
	}
	for _, k := range cases {
		for _, approve := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s approve=%v", k.name, approve), func(t *testing.T) {
				c := newChatEnv(t)
				a := c.pending()
				c.svc.SetBeforeLockForTest(func() { k.arm(c) }) // the call has passed its checks and waits for the lock
				_, err := c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "slack", ExternalID: slackOp, RequestID: a.ID, Approve: approve})
				c.svc.WaitSendsForTest()
				if s, code := apiCode(err); s != 403 || (code != "approver_not_listed" && code != "channel_not_allowed") {
					t.Fatalf("error = %v", err)
				}
				if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 0 || c.exec.count() != 0 {
					t.Fatalf("a decision went through after the person was gone: %+v", got)
				}
			})
		}
	}
}

// ---- L2: ids that cannot be real ----

func TestChat_AnIdThatCannotBeRealIsLoggedAsAFixedText(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	bad := []string{"U0AAA111\u202e", "U0AAA\u200b111", "U0\u0410\u0410\u0410111", "\uff35\uff10AAA111", "U0AAA111\u2066", "U0AAA\u00a0111"}
	for _, ext := range bad {
		_, err := c.button("slack", ext, a.ID, true)
		c.mustCode(err, 403, "approver_not_listed")
	}
	if got := c.only(); got.Status != response.StatusPending {
		t.Fatal("decided")
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = '(invalid id) via slack'`); n != 1 {
		t.Fatalf("%d lines for ids that cannot be real, want one fixed line", n)
	}
	rows := c.dump(`SELECT actor || detail FROM resp_log`) + c.dump(`SELECT "user" || detail FROM core_audit`)
	for _, r := range []string{"\u202e", "\u200b", "\u0410", "\uff35", "\u2066", "\u00a0"} {
		if strings.Contains(rows, r) {
			t.Fatalf("the character %q of a sender is in the log", r)
		}
	}
	if n := c.svc.ChatKeysForTest(); n != 1 {
		t.Fatalf("ids that cannot be real use %d table entries, want 1", n)
	}
}

// ---- L3, L6, L7 ----

func TestChat_RecordReplyCodeRefusesHighRiskAndInAppOnly(t *testing.T) {
	c := newChatEnv(t)
	a := c.highRisk()
	rec := response.ReplyCodeRecord{RequestID: a.ID, UserID: "u-op", Address: zlOp, Approve: true, CodeHash: codeHashOf(a.ID, "u-op", "approve", "A-7KQ2MX"), ExpiresAt: c.clock.Now().Add(10 * time.Minute)}
	if err := c.svc.RecordReplyCode(c.ctx(), rec); err == nil {
		t.Fatal("a code was recorded for a high-risk request")
	}
	c2 := newChatEnv(t)
	b := c2.pending()
	c2.asAI(b.ID, inAppAI)
	rec.RequestID, rec.CodeHash = b.ID, codeHashOf(b.ID, "u-op", "approve", "A-7KQ2MX")
	if err := c2.svc.RecordReplyCode(c2.ctx(), rec); err == nil {
		t.Fatal("a code was recorded for an in-app-only request")
	}
	if c.count(`SELECT COUNT(*) FROM resp_tokens`) != 0 || c2.count(`SELECT COUNT(*) FROM resp_tokens`) != 0 {
		t.Fatal("a record was stored")
	}
}

func TestChat_ManyUsedCodesDoNotHideTheLiveOne(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	for i := range 250 { // old, used codes that expire later than the live one
		h := codeHashOf(fmt.Sprintf("req-old-%d", i), "u-op", "approve", "A-AAAAAA")
		c.exec1(`INSERT INTO resp_tokens (token_hash, kind, decision, action_id, user_id, address, channel, key_id, expires_at, used_at) VALUES (?, 'code', 'approve', ?, 'u-op', ?, 'zalo-personal', NULL, ?, ?)`,
			h, fmt.Sprintf("req-old-%d", i), zlOp, c.clock.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z"), c.clock.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	out, err := c.typed(zlOp, "A-7KQ2MX", true)
	c.must(err)
	if out.Status != "approved" {
		t.Fatalf("%+v", out)
	}
	_, err = c.typed(zlOp, "A-7KQ2MX", true) // a used one is refused (told "used" when it is within the newest 200 used records)
	if _, code := apiCode(err); code != "used" && code != "invalid_code" {
		t.Fatalf("a used code: %v", err)
	}
}

func TestChat_OnlyASCIISpaceIsTrimmedFromACode(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	for _, typed := range []string{"\u00a0A-7KQ2MX", "A-7KQ2MX\u2003", "\u0085A-7KQ2MX", "\u3000A-7KQ2MX"} {
		_, err := c.typed(zlOp, typed, true)
		c.mustCode(err, 400, "invalid_code")
	}
	if _, err := c.typed(zlOp, "\t a-7kq2mx \r\n\v\f", true); err != nil {
		t.Fatal(err)
	}
}

// ---- gaps of the first round ----

func TestChat_ZaloIgnoresARequestIdThatIsSent(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.fire(c.iocEvent("e9", "198.51.100.9"))
	var other response.ActionRequest
	for _, x := range c.actions() {
		if x.ID != a.ID {
			other = x
		}
	}
	if other.ID == "" {
		t.Fatal("no second request")
	}
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	_, err := c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, RequestID: other.ID, Approve: true, Code: "A-7KQ2MX"})
	c.svc.WaitSendsForTest()
	c.must(err)
	for _, x := range c.actions() {
		switch x.ID {
		case a.ID:
			if x.Status == response.StatusPending {
				t.Fatal("the request of the code was not decided")
			}
		case other.ID:
			if x.Status != response.StatusPending || len(x.Approvals) != 0 {
				t.Fatalf("the request named in the message was decided: %+v", x)
			}
		}
	}
}

func TestChat_TheSamePersonSendsBothCodesAtOnce(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		_, errs[0] = c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Approve: true, Code: "A-7KQ2MX"})
	})
	wg.Go(func() {
		_, errs[1] = c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Approve: false, Code: "R-7KQ2MX"})
	})
	wg.Wait()
	c.svc.WaitSendsForTest()
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		if s, code := apiCode(err); s != 409 || (code != "used" && code != "decided") {
			t.Fatalf("the loser got %v", err)
		}
	}
	got := c.only()
	if won != 1 || got.Status == response.StatusPending || c.tokenUsed() != 2 {
		t.Fatalf("%d winners: %+v", won, got)
	}
	if (got.Status == response.StatusRejected) != (len(got.Approvals) == 0) || len(got.Approvals) > 1 {
		t.Fatalf("both decisions left a mark: %+v", got)
	}
}

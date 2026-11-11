package response_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/response"
)

// Slice 13b-8: decisions from chat (INV-3, INV-2, INV-16, FORBID-4, D-96 (5), D-135). notify's listeners are not built yet: these tests call
// DecideFromChat the way the adapter in cmd/vedette does, after the platform was checked.

// codeHashOf is spec 7.1 written out again, independent of the module: the tests mint codes the way notify will.
func codeHashOf(request, user, decision, code string) string {
	sum := sha256.Sum256([]byte("vedette-reply-code-v1\n" + request + "\n" + user + "\n" + decision + "\n" + code))
	return hex.EncodeToString(sum[:])
}

func TestSpec71VectorMatchesTheFormula(t *testing.T) {
	if got := codeHashOf("req-20261109-0001", "u-lan", "approve", "A-7KQ2MX"); got != "1f16413d45bce5c596496fc0a4d169a0c09ade7bb044335507f4020e15060fa0" {
		t.Fatalf("approve: %s", got)
	}
	if got := codeHashOf("req-20261109-0001", "u-lan", "reject", "R-7KQ2MX"); got != "560dd02a99d9bc0e022a7b7c50a9d6834cc2c8ab8587c50089bda4ce7077b671" {
		t.Fatalf("reject: %s", got)
	}
}

type chatEnv struct{ *linkEnv }

// Slack ids of the two operators; Telegram and Zalo ids as well.
const (
	slackOp, slackOp2 = "U0AAA111", "U0BBB222"
	tgOp, tgOp2       = "1001", "1002"
	zlOp, zlOp2       = "zl-lan", "zl-bao"
)

func newChatEnv(t *testing.T) *chatEnv {
	t.Helper()
	l := newLinkEnv(t)
	l.note.chs = []response.NotifyChannel{
		{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 2},
		{Type: "slack", Label: "Slack", Configured: true, Enabled: true, Approvals: true, Approvers: 2},
		{Type: "telegram", Label: "Telegram", Configured: true, Enabled: true, Approvals: true, Approvers: 2},
		{Type: "zalo-personal", Label: "Zalo (personal)", Configured: true, Enabled: true, Approvals: true, Approvers: 2},
	}
	l.note.approvers = map[string][]response.Approver{
		"email":         {{UserID: "u-op", Address: "it@acme.example"}, {UserID: "u-op2", Address: "it2@acme.example"}},
		"slack":         {{UserID: "u-op", Address: slackOp}, {UserID: "u-op2", Address: slackOp2}},
		"telegram":      {{UserID: "u-op", Address: tgOp}, {UserID: "u-op2", Address: tgOp2}},
		"zalo-personal": {{UserID: "u-op", Address: zlOp}, {UserID: "u-op2", Address: zlOp2}},
	}
	l.saveSettings(func(in *response.SettingsInput) {
		in.ApprovalChannels = []string{"email", "slack", "telegram", "zalo-personal"}
	})
	return &chatEnv{l}
}

// button and typed wait for the items of a completing approval: they run in the background after the call returned (D-135 (9)).
func (c *chatEnv) button(channel, ext, reqID string, approve bool) (response.ChatOutcome, error) {
	out, err := c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: channel, ExternalID: ext, RequestID: reqID, Approve: approve})
	c.svc.WaitSendsForTest()
	return out, err
}

func (c *chatEnv) typed(ext, code string, approve bool) (response.ChatOutcome, error) {
	out, err := c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: ext, Approve: approve, Code: code})
	c.svc.WaitSendsForTest()
	return out, err
}

// mintCodeRaw stores a code record without the checks of RecordReplyCode (which refuses high-risk and in-app-only requests): what an old or
// forged record would look like.
func (c *chatEnv) mintCodeRaw(reqID, code string, approve bool) {
	c.t.Helper()
	decision := "reject"
	if approve {
		decision = "approve"
	}
	c.exec1(`INSERT INTO resp_tokens (token_hash, kind, decision, action_id, user_id, address, channel, key_id, expires_at, used_at) VALUES (?, 'code', ?, ?, ?, ?, 'zalo-personal', NULL, ?, NULL)`,
		codeHashOf(reqID, "u-op", decision, code), decision, reqID, "u-op", zlOp, c.clock.Now().Add(10*time.Minute).UTC().Format("2006-01-02T15:04:05.000Z"))
}

// mintCode does what notify does for one approver and one decision: record the hash before the message goes out.
func (c *chatEnv) mintCode(reqID, userID, address, code string, approve bool, life time.Duration) {
	c.t.Helper()
	decision := "reject"
	if approve {
		decision = "approve"
	}
	c.must(c.svc.RecordReplyCode(c.ctx(), response.ReplyCodeRecord{RequestID: reqID, UserID: userID, Address: address, Approve: approve,
		CodeHash: codeHashOf(reqID, userID, decision, code), ExpiresAt: c.clock.Now().Add(life)}))
}

// codes mints the A and R codes of one approver.
func (c *chatEnv) codes(reqID, userID, address, a, r string) {
	c.mintCode(reqID, userID, address, a, true, 10*time.Minute)
	c.mintCode(reqID, userID, address, r, false, 10*time.Minute)
}

func (c *chatEnv) twoPerson() response.ActionRequest {
	c.t.Helper()
	c.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
	c.rule("Two blocks", "ioc_connection", twoBlocks(), nil)
	c.fire(c.iocEvent("e2", "198.51.100.7"))
	a := c.only()
	if a.RequiresApprovals != 2 || a.Risk == response.RiskHigh {
		c.t.Fatalf("request: %+v", a)
	}
	return a
}

func (c *chatEnv) highRisk() response.ActionRequest {
	c.t.Helper()
	c.firewall("fgt_policy_disable")
	c.turnOn()
	c.exec.present = `"status":"disable"`
	c.rule("Cut the policy", "honeypot", []response.RuleAction{{ActionID: "fgt_policy_disable", Params: map[string]string{"id": "12"}, TTLMin: intp(60)}}, nil)
	c.fire(c.trap("h1", "192.168.10.157"))
	a := c.only()
	if a.Risk != response.RiskHigh || a.RequiresApprovals != 2 {
		c.t.Fatalf("request: %+v", a)
	}
	return a
}

func (c *chatEnv) mustCode(err error, status int, code string) { wantCode(c.t, err, status, code) }

// ---- INV-3, steps 1 to 3 ----

func TestChat_AnUnlistedExternalIDIsRefusedAndLogged(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	logs := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`)
	for _, ext := range []string{"U0ZZZ999", "", "u0aaa111", slackOp + " ", "U0AAA1111", "U0AAA\n111", strings.Repeat("A", 80)} {
		_, err := c.button("slack", ext, a.ID, true)
		c.mustCode(err, 403, "approver_not_listed")
	}
	// the id of the other channel is not an id on this one
	_, err := c.button("slack", tgOp, a.ID, true)
	c.mustCode(err, 403, "approver_not_listed")
	if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 0 || c.exec.count() != 0 {
		t.Fatalf("a refused sender decided: %+v", got)
	}
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`) != logs+5 { // one line per sender per window: five different senders (the ids that cannot be real share one)
		t.Fatal("the refusals are not in the log as one line per sender")
	}
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'U0ZZZ999 via slack' AND detail LIKE 'approver_not_listed:%'`) != 1 ||
		c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.refused' AND "user" = 'U0ZZZ999 via slack'`) != 1 {
		t.Fatal("the refusal does not name the sender and the channel")
	}
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE actor LIKE '%' || char(10) || '%' OR detail LIKE '%' || char(10) || '%'`) != 0 {
		t.Fatal("a line break of the sender got into the log")
	}
}

func TestChat_TwoListEntriesWithOneAddressAreNobody(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.note.approvers["slack"] = []response.Approver{{UserID: "u-op", Address: slackOp}, {UserID: "u-op2", Address: slackOp}}
	_, err := c.button("slack", slackOp, a.ID, true)
	c.mustCode(err, 403, "approver_not_listed")
	if c.only().Status != response.StatusPending {
		t.Fatal("an id that stands for two people decided")
	}
}

func TestChat_AChannelThatIsNotAnApprovalChannelIsRefused(t *testing.T) {
	cases := []struct {
		name string
		arm  func(c *chatEnv)
	}{
		{"not in approval_channels", func(c *chatEnv) {
			c.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email", "telegram", "zalo-personal"} })
		}},
		{"approvals off on the channel", func(c *chatEnv) { c.note.chs[1].Approvals = false }},
		{"channel disabled", func(c *chatEnv) { c.note.chs[1].Enabled = false }},
		{"no approvers", func(c *chatEnv) { c.note.chs[1].Approvers = 0 }},
		{"not set up", func(c *chatEnv) { c.note.chs[1].Configured = false }},
	}
	for _, k := range cases {
		t.Run(k.name, func(t *testing.T) {
			c := newChatEnv(t)
			a := c.pending()
			k.arm(c)
			_, err := c.button("slack", slackOp, a.ID, true)
			c.mustCode(err, 403, "channel_not_allowed")
			if !c.logHas("refused", "channel_not_allowed") || c.only().Status != response.StatusPending {
				t.Fatal("not logged, or it decided")
			}
		})
	}
	t.Run("channels chat does not have", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		for _, ch := range []string{"email", "zalo", "webhook", "", "SLACK", "slack "} {
			_, err := c.button(ch, slackOp, a.ID, true)
			c.mustCode(err, 403, "channel_not_allowed")
		}
		if c.only().Status != response.StatusPending {
			t.Fatal("decided")
		}
	})
}

func TestChat_ADisabledOrDemotedPersonIsRefused(t *testing.T) {
	cases := []struct {
		name string
		arm  func(c *chatEnv)
	}{
		{"disabled", func(c *chatEnv) { u := c.users.m["u-op"]; u.Disabled = true; c.users.m["u-op"] = u }},
		{"demoted to viewer", func(c *chatEnv) { u := c.users.m["u-op"]; u.Role = "viewer"; c.users.m["u-op"] = u }},
		{"deleted", func(c *chatEnv) { delete(c.users.m, "u-op") }},
	}
	for _, k := range cases {
		for _, approve := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s approve=%v", k.name, approve), func(t *testing.T) {
				c := newChatEnv(t)
				a := c.pending()
				c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
				k.arm(c)
				_, err := c.button("slack", slackOp, a.ID, approve)
				c.mustCode(err, 403, "approver_not_listed")
				code := "A-7KQ2MX"
				if !approve {
					code = "R-7KQ2MX"
				}
				_, err = c.typed(zlOp, code, approve)
				c.mustCode(err, 403, "approver_not_listed")
				if c.only().Status != response.StatusPending || c.count(`SELECT COUNT(*) FROM resp_tokens WHERE used_at IS NOT NULL`) != 0 {
					t.Fatal("a refused person decided or burned a code")
				}
			})
		}
	}
	t.Run("an admin may", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		u := c.users.m["u-op"]
		u.Role = "admin"
		c.users.m["u-op"] = u
		out, err := c.button("slack", slackOp, a.ID, true)
		c.must(err)
		if out.Status != "approved" {
			t.Fatalf("%+v", out)
		}
	})
}

// ---- INV-3, step 4: the risk policy ----

func TestChat_NeverApprovesInAppOnly(t *testing.T) {
	for _, ch := range []string{"slack", "telegram", "zalo-personal"} {
		for _, approve := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s approve=%v", ch, approve), func(t *testing.T) {
				c := newChatEnv(t)
				a := c.highRiskAIFor(ch)
				ext := map[string]string{"slack": slackOp, "telegram": tgOp, "zalo-personal": zlOp}[ch]
				var err error
				if ch == "zalo-personal" {
					code := "A-7KQ2MX"
					if !approve {
						code = "R-7KQ2MX"
					}
					_, err = c.typed(ext, code, approve)
				} else {
					_, err = c.button(ch, ext, a.ID, approve)
				}
				c.mustCode(err, 403, "in_app_required") // for Zalo this is checked before "high risk": the code of an in-app request says in_app_required
				got := c.only()
				if got.Status != response.StatusPending || len(got.Approvals) != 0 || c.exec.count() != 0 || c.count(`SELECT COUNT(*) FROM resp_tokens WHERE used_at IS NOT NULL`) != 0 {
					t.Fatalf("chat decided an in-app-only request: %+v", got)
				}
				if !c.logHas("refused", "in_app_required") {
					t.Fatal("not logged")
				}
			})
		}
	}
	t.Run("a low-risk AI request marked in-app only", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		c.asAI(a.ID, inAppAI)
		_, err := c.button("telegram", tgOp, a.ID, true)
		c.mustCode(err, 403, "in_app_required")
	})
}

// highRiskAIFor makes the high-risk AI request and, for Zalo, the codes that would have gone out for it.
func (c *chatEnv) highRiskAIFor(ch string) response.ActionRequest {
	c.t.Helper()
	a := c.highRisk()
	if ch == "zalo-personal" {
		c.mintCodeRaw(a.ID, "A-7KQ2MX", true)
		c.mintCodeRaw(a.ID, "R-7KQ2MX", false)
	}
	c.asAI(a.ID, inAppAI)
	return a
}

// twoPersonMedium makes the request one that needs two people without being high risk (a request over the multi-target limit looks like
// this): chat may take it, since only the risk and the length of the text decide the buttons (D-175).
func (c *chatEnv) twoPersonMedium(a response.ActionRequest) {
	c.t.Helper()
	c.exec1(`UPDATE resp_actions SET risk = 'medium' WHERE id = ?`, a.ID)
}

// D-175: a high-risk request is never decided from chat (no button is attached, and an old button or a forged callback is refused).
func TestChat_SlackAndTelegramRefuseHighRisk(t *testing.T) {
	for _, ch := range [][2]string{{"slack", slackOp}, {"telegram", tgOp}} {
		c := newChatEnv(t)
		a := c.highRisk()
		for _, approve := range []bool{true, false} {
			_, err := c.button(ch[0], ch[1], a.ID, approve)
			c.mustCode(err, 403, "channel_not_allowed")
		}
		if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 0 || c.exec.count() != 0 {
			t.Fatalf("%s: a chat decision went through: %+v", ch[0], got)
		}
	}
}

// D-175: a change too long to read in one message is not decided from chat either, whatever its risk.
func TestChat_AnOverLengthChangeIsNotDecidedFromChat(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	long := strings.Repeat("x", 3200)
	c.exec1(`UPDATE resp_actions SET title = ? WHERE id = ?`, "t", a.ID)
	c.exec1(`UPDATE resp_actions SET items = json_set(items, '$[0].change.after', ?) WHERE id = ?`, long, a.ID)
	c.exec1(`UPDATE resp_actions SET items = json_set(items, '$[0].change.cli', ?) WHERE id = ?`, strings.Repeat("show version\n", 300), a.ID)
	_, err := c.button("slack", slackOp, a.ID, true)
	c.mustCode(err, 403, "channel_not_allowed")
	if got := c.only(); got.Status != response.StatusPending {
		t.Fatalf("%+v", got)
	}
}

func TestChat_SlackAndTelegramTakeTwoPeopleOnAMediumRequest(t *testing.T) {
	for _, pair := range [][4]string{{"slack", slackOp, "slack", slackOp2}, {"telegram", tgOp, "telegram", tgOp2}, {"slack", slackOp, "telegram", tgOp2}} {
		t.Run(pair[0]+"+"+pair[2], func(t *testing.T) {
			c := newChatEnv(t)
			a := c.highRisk()
			c.twoPersonMedium(a)
			first, err := c.button(pair[0], pair[1], a.ID, true)
			c.must(err)
			if first.Status != "pending" || first.Approvals != 1 || first.Required != 2 || first.Message == "" {
				t.Fatalf("first: %+v", first)
			}
			if got := c.only(); got.Status != response.StatusPending || c.exec.count() != 0 {
				t.Fatalf("one person was enough: %+v", got)
			}
			second, err := c.button(pair[2], pair[3], a.ID, true)
			c.must(err)
			if second.Status != "approved" || second.Approvals != 2 {
				t.Fatalf("second: %+v", second)
			}
			got := c.only()
			if got.Status != response.StatusExecuted || got.Approvals[0].Via != response.Via(pair[0]) || got.Approvals[1].Via != response.Via(pair[2]) || c.exec.count() == 0 {
				t.Fatalf("after two: %+v", got)
			}
		})
	}
}

func TestChat_ZaloTakesLowAndMediumButNotHigh(t *testing.T) {
	t.Run("high is refused", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.highRisk()
		c.mintCodeRaw(a.ID, "A-7KQ2MX", true)
		c.mintCodeRaw(a.ID, "R-7KQ2MX", false)
		for _, d := range []struct {
			code    string
			approve bool
		}{{"A-7KQ2MX", true}, {"R-7KQ2MX", false}} {
			_, err := c.typed(zlOp, d.code, d.approve)
			c.mustCode(err, 403, "channel_not_allowed")
		}
		if c.only().Status != response.StatusPending || c.tokenUsed() != 0 || c.exec.count() != 0 {
			t.Fatal("Zalo decided a high-risk request, or burned a code")
		}
		if !c.logHas("refused", "channel_not_allowed") {
			t.Fatal("not logged")
		}
	})
	t.Run("low", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
		out, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.must(err)
		if out.Status != "approved" || c.only().Approvals[0].Via != response.ViaZaloPersonal {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("two people (multi-target)", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.twoPerson() // two blocks at once, over the multi-target limit: two people
		c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
		c.codes(a.ID, "u-op2", zlOp2, "A-8LR3NY", "R-8LR3NY")
		first, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.must(err)
		second, err := c.typed(zlOp2, "A-8LR3NY", true)
		c.must(err)
		if first.Status != "pending" || second.Status != "approved" || c.only().Status != response.StatusExecuted {
			t.Fatalf("%+v %+v", first, second)
		}
	})
}

// ---- INV-3, step 5: the reply code ----

func TestChat_ACodeWorksOnce(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	out, err := c.typed(zlOp, "  a-7kq2mx\n", true) // spec 7.1: the form is normalised
	c.must(err)
	if out.Status != "approved" || out.Approvals != 1 || out.Required != 1 {
		t.Fatalf("%+v", out)
	}
	if got := c.only(); got.Status != response.StatusExecuted || got.Approvals[0].UserID != "u-op" || got.Approvals[0].Via != response.ViaZaloPersonal || c.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 {
		t.Fatalf("after the code: %+v", got)
	}
	if c.tokenUsed() != 2 { // the code and the other code of this person for this request
		t.Fatalf("%d codes burned, want 2 (spec 7.1)", c.tokenUsed())
	}
	for _, tc := range []struct {
		code    string
		approve bool
	}{{"A-7KQ2MX", true}, {"R-7KQ2MX", false}} {
		_, err = c.typed(zlOp, tc.code, tc.approve)
		c.mustCode(err, 409, "used")
	}
	if len(c.only().Approvals) != 1 || c.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 {
		t.Fatal("a second use ran again")
	}
}

func TestChat_ACodeWorksOnceWhenSentTwiceAtOnce(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, errs[i] = c.svc.DecideFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Approve: true, Code: "A-7KQ2MX"})
		})
	}
	wg.Wait()
	c.svc.WaitSendsForTest()
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		if s, code := apiCode(err); s != 409 || (code != "used" && code != "decided") {
			t.Fatalf("a loser got %v", err)
		}
	}
	if won != 1 || len(c.only().Approvals) != 1 || c.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 {
		t.Fatalf("%d winners", won)
	}
}

func TestChat_ACodeIsBoundToRequestPersonAndDecision(t *testing.T) {
	// The record is the only thing that ties a code to a request, a person and a decision: change any of the three and the hash no longer fits.
	setup := func(t *testing.T) (*chatEnv, response.ActionRequest) {
		c := newChatEnv(t)
		a := c.pending()
		c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
		return c, a
	}
	t.Run("another request", func(t *testing.T) {
		c, a := setup(t)
		c.exec1(`UPDATE resp_tokens SET action_id = 'req-other' WHERE kind = 'code'`)
		_, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 400, "invalid_code")
		if c.only().ID != a.ID || len(c.only().Approvals) != 0 {
			t.Fatal("decided")
		}
	})
	t.Run("another person", func(t *testing.T) {
		c, _ := setup(t)
		c.exec1(`UPDATE resp_tokens SET user_id = 'u-op2' WHERE kind = 'code'`)
		_, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 400, "invalid_code")
		if len(c.only().Approvals) != 0 {
			t.Fatal("decided")
		}
	})
	t.Run("the other decision", func(t *testing.T) {
		c, _ := setup(t)
		c.exec1(`UPDATE resp_tokens SET decision = 'reject' WHERE kind = 'code' AND decision = 'approve'`)
		_, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 400, "invalid_code")
		if len(c.only().Approvals) != 0 {
			t.Fatal("decided")
		}
	})
	t.Run("an approve code does not reject and a reject code does not approve", func(t *testing.T) {
		c, _ := setup(t)
		_, err := c.typed(zlOp, "A-7KQ2MX", false)
		c.mustCode(err, 400, "invalid_code")
		_, err = c.typed(zlOp, "R-7KQ2MX", true)
		c.mustCode(err, 400, "invalid_code")
		if c.only().Status != response.StatusPending || c.tokenUsed() != 0 {
			t.Fatal("the wrong decision decided or burned")
		}
	})
	t.Run("the code of another person from another id", func(t *testing.T) {
		c, _ := setup(t)
		_, err := c.typed(zlOp2, "A-7KQ2MX", true) // listed, but this code was made for the other person's address
		c.mustCode(err, 400, "invalid_code")
		if !c.logHas("refused", "invalid_code") || c.only().Status != response.StatusPending || c.tokenUsed() != 0 {
			t.Fatal("not refused and logged")
		}
	})
	t.Run("a guess, a wrong form, nothing", func(t *testing.T) {
		c, _ := setup(t)
		for _, code := range []string{"A-7KQ2MY", "7KQ2MX", "A-7KQ2M", "A-7KQ2MXX", "A-0KQ2MX", "", "A-7KQ2MX\nA-7KQ2MX"} {
			_, err := c.typed(zlOp, code, true)
			c.mustCode(err, 400, "invalid_code")
		}
		if c.only().Status != response.StatusPending {
			t.Fatal("decided")
		}
	})
	t.Run("a code of someone who is not listed", func(t *testing.T) {
		c, _ := setup(t)
		_, err := c.typed("zl-stranger", "A-7KQ2MX", true)
		c.mustCode(err, 403, "approver_not_listed")
	})
}

func TestChat_AnEndedOrUsedCodeIsRefused(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		c.mintCode(a.ID, "u-op", zlOp, "A-7KQ2MX", true, 5*time.Minute)
		c.clock.Advance(6 * time.Minute)
		_, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 409, "expired")
		if c.only().Status != response.StatusPending || !c.logHas("refused", "expired") {
			t.Fatal("decided, or not logged")
		}
	})
	t.Run("the request ended first", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		c.mintCode(a.ID, "u-op", zlOp, "A-7KQ2MX", true, 14*time.Minute) // as long as a code may live: up to the end of the request
		c.clock.Advance(16 * time.Minute)                                // the request lives 15 minutes
		c.must(c.svc.Sweep(c.ctx()))
		if got := c.only(); got.Status != response.StatusExpired {
			t.Fatalf("the request is %s, want expired before the code is used", got.Status)
		}
		_, err := c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 409, "expired")
		if len(c.only().Approvals) != 0 || c.only().Status != response.StatusExpired {
			t.Fatal("an ended request was approved")
		}
	})
	t.Run("used for another decision", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
		out, err := c.typed(zlOp, "R-7KQ2MX", false)
		c.must(err)
		if out.Status != "rejected" || c.only().Status != response.StatusRejected || c.tokenUsed() != 2 {
			t.Fatalf("%+v", out)
		}
		_, err = c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 409, "used") // burned with the reject code
	})
	t.Run("request decided in the app", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.pending()
		c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
		_, err := c.svc.Approve(c.ctx(), oper2, a.ID, nil, "")
		c.must(err)
		_, err = c.typed(zlOp, "A-7KQ2MX", true)
		c.mustCode(err, 409, "decided")
		if c.tokenUsed() != 0 {
			t.Fatal("a refused decision burned the code")
		}
	})
}

func TestChat_ARefusedDecisionDoesNotBurnTheCode(t *testing.T) {
	c := newChatEnv(t)
	a := c.twoPerson()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	_, err := c.svc.Approve(c.ctx(), oper, a.ID, nil, "") // the same person, in the app
	c.must(err)
	_, err = c.typed(zlOp, "A-7KQ2MX", true)
	c.mustCode(err, 409, "same_approver")
	if c.tokenUsed() != 0 {
		t.Fatal("the gate refused the decision but the code was burned")
	}
	c.note.chs[3].Enabled = false // and a refusal at the channel gate neither
	_, err = c.typed(zlOp, "A-7KQ2MX", true)
	c.mustCode(err, 403, "channel_not_allowed")
	if c.tokenUsed() != 0 {
		t.Fatal("burned")
	}
}

func TestChat_ZaloRejectBurnsTheCodes(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	if _, err := c.typed(zlOp, "r-7kq2mx", false); err != nil {
		t.Fatal(err)
	}
	if got := c.only(); got.Status != response.StatusRejected || c.exec.count() != 0 || c.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("%+v", got)
	}
}

// ---- INV-2 ----

func TestChat_TheSamePersonByAppAndChatCountsOnce(t *testing.T) {
	c := newChatEnv(t)
	a := c.twoPerson()
	_, err := c.svc.Approve(c.ctx(), oper, a.ID, nil, "") // person A, in the app
	c.must(err)
	for _, tc := range []struct{ ch, ext string }{{"slack", slackOp}, {"telegram", tgOp}} { // person A, from two chats
		_, err = c.button(tc.ch, tc.ext, a.ID, true)
		c.mustCode(err, 409, "same_approver")
	}
	if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 1 {
		t.Fatalf("one person counted twice: %+v", got)
	}
	// and the other way round: chat first, then the app
	c2 := newChatEnv(t)
	a2 := c2.twoPerson()
	_, err = c2.button("slack", slackOp, a2.ID, true)
	c2.must(err)
	_, err = c2.svc.Approve(c2.ctx(), oper, a2.ID, nil, "")
	wantCode(t, err, 409, "same_approver")
	// the same person on two chats counts once as well
	_, err = c2.button("telegram", tgOp, a2.ID, true)
	c2.mustCode(err, 409, "same_approver")
	done, err := c2.button("telegram", tgOp2, a2.ID, true)
	c2.must(err)
	if done.Status != "approved" || done.Approvals != 2 {
		t.Fatalf("%+v", done)
	}
}

// D-135: a chat approval may be the second approval when the first came by email link (and the other way round); two links are still one too many.
func TestChat_LinkPlusChatIsTwoPeople(t *testing.T) {
	t.Run("link then chat", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.twoPerson()
		tok := c.mint(a.ID, "u-op", "it@acme.example")
		if _, err := c.decide(tok, "approve"); err != nil {
			t.Fatal(err)
		}
		done, err := c.button("slack", slackOp2, a.ID, true)
		c.must(err)
		got := c.only()
		if done.Status != "approved" || got.Status != response.StatusExecuted || len(got.Approvals) != 2 || got.Approvals[0].Via != response.ViaEmail || got.Approvals[1].Via != response.ViaSlack {
			t.Fatalf("link then chat: %+v %+v", done, got)
		}
	})
	t.Run("chat then link", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.twoPerson()
		tok := c.mint(a.ID, "u-op", "it@acme.example")
		if _, err := c.button("telegram", tgOp2, a.ID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := c.decide(tok, "approve"); err != nil {
			t.Fatal(err)
		}
		if got := c.only(); got.Status != response.StatusExecuted || got.Approvals[1].Via != response.ViaEmail {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("the same person by link and by chat", func(t *testing.T) {
		c := newChatEnv(t)
		a := c.twoPerson()
		tok := c.mint(a.ID, "u-op", "it@acme.example")
		if _, err := c.decide(tok, "approve"); err != nil {
			t.Fatal(err)
		}
		_, err := c.button("slack", slackOp, a.ID, true)
		c.mustCode(err, 409, "same_approver")
	})
	t.Run("two links are still one too many", func(t *testing.T) {
		c := newChatEnv(t)
		c.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
		c.rule("Two blocks", "ioc_connection", twoBlocks(), nil)
		c.fire(c.iocEvent("e2", "198.51.100.7"))
		a := c.only()
		tokA := c.mint(a.ID, "u-op", "it@acme.example")
		tokB := c.mint(a.ID, "u-op2", "it2@acme.example")
		if _, err := c.decide(tokA, "approve"); err != nil {
			t.Fatal(err)
		}
		_, err := c.decide(tokB, "approve")
		wantCode(t, err, 403, "in_app_required")
	})
}

// ---- the log ----

func TestChat_TheLogNamesThePersonTheChannelAndTheId(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	if _, err := c.button("slack", slackOp, a.ID, true); err != nil {
		t.Fatal(err)
	}
	want := "IT Operator via slack (U0AAA111)"
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'approved' AND actor = ?`, want) != 1 || c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.approve' AND "user" = ?`, want) != 1 {
		t.Fatalf("the approval is not in the log as %q:\n%s", want, c.dump(`SELECT kind || ' | ' || actor || ' | ' || detail FROM resp_log`))
	}
	c2 := newChatEnv(t)
	a2 := c2.pending()
	c2.codes(a2.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	if _, err := c2.typed(zlOp, "R-7KQ2MX", false); err != nil {
		t.Fatal(err)
	}
	if c2.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'rejected' AND actor = 'IT Operator via zalo-personal (zl-lan)'`) != 1 {
		t.Fatalf("the rejection is not named:\n%s", c2.dump(`SELECT kind || ' | ' || actor || ' | ' || detail FROM resp_log`))
	}
	// a refusal of a listed person after the gates names them too
	c3 := newChatEnv(t)
	a3 := c3.pending()
	if _, err := c3.svc.Approve(c3.ctx(), oper, a3.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	_, err := c3.button("telegram", tgOp2, a3.ID, true)
	wantCode(t, err, 409, "decided")
	if c3.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'IT Operator Two via telegram (1002)'`) != 1 {
		t.Fatalf("the refusal is not named:\n%s", c3.dump(`SELECT kind || ' | ' || actor || ' | ' || detail FROM resp_log`))
	}
}

func TestChat_ADecisionIsPublishedAfterCommit(t *testing.T) {
	c := newChatEnv(t)
	a := c.twoPerson()
	var mu sync.Mutex
	var got []response.DecisionEvent
	c.bus.Subscribe(response.EventDecisionMade, func(_ context.Context, ev events.Event) error {
		raw, _ := json.Marshal(ev.Data)
		var d response.DecisionEvent
		if err := json.Unmarshal(raw, &d); err == nil {
			mu.Lock()
			got = append(got, d)
			mu.Unlock()
		}
		return nil
	})
	before := c.seen.count(response.EventDecisionMade)
	_, _ = c.button("slack", "U0ZZZ999", a.ID, true) // a refusal publishes nothing
	if _, err := c.button("slack", slackOp, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.button("telegram", tgOp2, a.ID, true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "two response.decision.made events", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 2 })
	mu.Lock()
	defer mu.Unlock()
	if n := c.seen.count(response.EventDecisionMade); n != before+2 || len(got) != 2 {
		t.Fatalf("%d decision events, want 2 (the refusal must publish none)", n-before)
	}
	slices.SortFunc(got, func(x, y response.DecisionEvent) int {
		return strings.Compare(fmt.Sprint(x.Final), fmt.Sprint(y.Final))
	})
	if got[0].Final || !got[1].Final || got[0].Decision != "approved" || got[1].Decision != "approved" || got[0].RequestID != a.ID || got[0].By != "it@acme.example" || got[1].By != "it2@acme.example" {
		t.Fatalf("events: %+v (the first of two is not final, the second is)", got)
	}
}

// ---- the rate limit ----

func TestChat_RateLimitPerIdentity(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	for range 20 { // twenty tries at a request that is not there: every try counts, whatever came of it
		_, err := c.button("slack", slackOp, "req-nope", true)
		c.mustCode(err, 404, "not_found")
	}
	_, err := c.button("slack", slackOp, a.ID, true)
	c.mustCode(err, 429, "rate_limited")
	if c.only().Status != response.StatusPending {
		t.Fatal("decided while limited")
	}
	for range 30 {
		_, err = c.button("slack", slackOp, a.ID, true)
		c.mustCode(err, 429, "rate_limited")
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'rate_limited:%'`); n != 1 {
		t.Fatalf("%d rate_limited lines in one window, want 1", n)
	}
	// another identity, another channel, are not held up
	if _, err := c.button("telegram", tgOp, a.ID, false); err != nil {
		t.Fatalf("another identity was limited: %v", err)
	}
	// a minute later the identity may try again, and a new window logs again
	c.clock.Advance(61 * time.Second)
	_, err = c.button("slack", slackOp, a.ID, true)
	c.mustCode(err, 409, "decided")
	for range 25 {
		_, _ = c.button("slack", slackOp, a.ID, true)
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'rate_limited:%'`); n != 2 {
		t.Fatalf("%d rate_limited lines after the second window, want 2", n)
	}
}

func TestChat_GuessingCodesIsLimited(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	for range 20 {
		_, err := c.typed(zlOp, "A-AAAAAA", true)
		c.mustCode(err, 400, "invalid_code")
	}
	_, err := c.typed(zlOp, "A-7KQ2MX", true) // the right one is held up too: the limit is on the sender
	c.mustCode(err, 429, "rate_limited")
	c.clock.Advance(61 * time.Second)
	if _, err := c.typed(zlOp, "A-7KQ2MX", true); err != nil {
		t.Fatal(err)
	}
}

// ---- FORBID-4 ----

func TestForbid4_NoCodeAnywhere(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	_, _ = c.typed(zlOp, "A-7KQ2MY", true) // a wrong guess is not logged either
	_, _ = c.typed(zlOp2, "A-7KQ2MX", true)
	_, _ = c.typed(zlOp, " a-7kq2mx ", true)
	_, _ = c.typed(zlOp, "A-7KQ2MX", true)
	_, _ = c.typed(zlOp, "R-7KQ2MX", false)
	rows := c.dump(`SELECT id || ts || kind || actor || detail || prev_hash || hash FROM resp_log`) +
		c.dump(`SELECT "user" || action || target || detail FROM core_audit`) +
		c.dump(`SELECT id || title || approvals || sent_to || COALESCE(note, '') || items || COALESCE(ai, '') FROM resp_actions`) +
		c.dump(`SELECT token_hash || kind || action_id || user_id || address || channel || COALESCE(key_id, '') || COALESCE(decision, '') FROM resp_tokens`) +
		c.dump(`SELECT value FROM resp_settings`)
	list := fmt.Sprintf("%+v", c.actions())
	for _, secret := range []string{"A-7KQ2MX", "R-7KQ2MX", "A-7KQ2MY", "7KQ2MX", "7kq2mx", "7KQ2MY"} {
		if strings.Contains(rows, secret) || strings.Contains(strings.ToUpper(rows), strings.ToUpper(secret)) || strings.Contains(list, secret) {
			t.Fatalf("the code %q is in a stored row or in the list", secret)
		}
	}
	logs, err := c.svc.Log(c.ctx())
	c.must(err)
	for _, l := range logs {
		if strings.Contains(strings.ToUpper(l.Actor+l.Detail), "7KQ2M") {
			t.Fatalf("a code is in the log API: %+v", l)
		}
	}
}

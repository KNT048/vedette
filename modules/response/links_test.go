package response_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/response"
)

// Slice 13b-7: sending requests, approval links (INV-3, INV-4, INV-2, INV-16, POST-5, FORBID-4). The token format and its MAC belong to notify
// (the cmd test runs the real one); here a fake LinkTokens signs the id with the whole binding, so a record that was changed fails the check
// the way a real MAC would.

type fakeLinks struct {
	mu  sync.Mutex
	err error // Verify answers this instead of checking (a box that cannot read its key)
}

func macOf(id []byte, b response.LinkBinding, keyID string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%x|%s|%s|%s|%d|%s", id, b.RequestID, b.UserID, b.Channel, b.ExpiresAt.Unix(), keyID))
	return hex.EncodeToString(sum[:8])
}

func (f *fakeLinks) mint(b response.LinkBinding, keyID string) (token string, id []byte) {
	id = make([]byte, 16)
	_, _ = rand.Read(id)
	return "v1." + hex.EncodeToString(id) + "." + macOf(id, b, keyID), id
}

func (f *fakeLinks) ID(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(parts[1]) != 32 {
		return nil, response.ErrLinkInvalid
	}
	id, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, response.ErrLinkInvalid
	}
	return id, nil
}

func (f *fakeLinks) Verify(_ context.Context, token string, b response.LinkBinding, keyID string) error {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return err
	}
	id, e := f.ID(token)
	if e != nil || token != "v1."+hex.EncodeToString(id)+"."+macOf(id, b, keyID) {
		return response.ErrLinkInvalid
	}
	return nil
}

// linkEnv is an env whose email channel takes approvals for the two operators.
type linkEnv struct {
	*env
	links *fakeLinks
	ips   int // a new source address for every call that does not choose one, so the rate limit stays out of the way
}

func (l *linkEnv) ip() string {
	l.ips++
	return fmt.Sprintf("10.9.%d.%d", l.ips/250, l.ips%250+1)
}

func newLinkEnv(t *testing.T) *linkEnv {
	t.Helper()
	fl := &fakeLinks{}
	e := newEnv(t, func(c *response.Config) { c.Links = fl })
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 2}}
	e.note.approvers = map[string][]response.Approver{"email": {{UserID: "u-op", Address: "it@acme.example"}, {UserID: "u-op2", Address: "it2@acme.example"}}}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	return &linkEnv{env: e, links: fl}
}

func tsOf(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// mint does what notify does for one approver: sign a token and record it before any mail goes out. It returns the token.
func (l *linkEnv) mint(reqID, userID, address string) string {
	l.t.Helper()
	var req response.ActionRequest
	for _, a := range l.actions() {
		if a.ID == reqID {
			req = a
		}
	}
	exp := l.clock.Now().Add(30 * time.Minute)
	if end := tsOf(l.t, req.ExpiresAt); end.Before(exp) {
		exp = end
	}
	b := response.LinkBinding{RequestID: reqID, UserID: userID, Channel: "email", ExpiresAt: exp}
	token, id := l.links.mint(b, "k1")
	l.must(l.svc.RecordLink(l.ctx(), response.LinkRecord{ID: id, RequestID: reqID, UserID: userID, Channel: "email", Address: address, KeyID: "k1", ExpiresAt: exp}))
	return token
}

// mintRaw stores the record of a link without the checks of RecordLink (which refuses a high-risk request): what an old or forged record
// would look like in the table.
func (l *linkEnv) mintRaw(reqID, userID, address string) string {
	l.t.Helper()
	exp := l.clock.Now().Add(10 * time.Minute)
	b := response.LinkBinding{RequestID: reqID, UserID: userID, Channel: "email", ExpiresAt: exp}
	token, id := l.links.mint(b, "k1")
	sum := sha256.Sum256(id)
	l.exec1(`INSERT INTO resp_tokens (token_hash, kind, decision, action_id, user_id, address, channel, key_id, expires_at, used_at) VALUES (?, 'link', NULL, ?, ?, ?, 'email', 'k1', ?, NULL)`,
		hex.EncodeToString(sum[:]), reqID, userID, address, exp.UTC().Format("2006-01-02T15:04:05.000Z"))
	return token
}

// pending makes one pending request of one low-risk box action (one approver).
func (l *linkEnv) pending() response.ActionRequest {
	l.t.Helper()
	l.rule("Block", "ioc_connection", blockAction(60), nil)
	l.fire(l.iocEvent("e1", "198.51.100.7"))
	l.svc.WaitSendsForTest() // the approval request goes out in the background
	return l.only()
}

func (l *linkEnv) view(token string) response.ApprovalView {
	l.t.Helper()
	v, err := l.svc.LinkView(l.ctx(), token, l.ip())
	l.must(err)
	return v
}

func (l *linkEnv) decide(token, decision string) (response.ActionRequest, error) {
	return l.svc.DecideByLink(l.ctx(), token, decision, l.ip())
}

func (l *linkEnv) tokenUsed() int {
	return l.count(`SELECT COUNT(*) FROM resp_tokens WHERE used_at IS NOT NULL`)
}

// ---- INV-4 ----

func TestContract_INV4_GetNeverDecides(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	logs, audits := e.count(`SELECT COUNT(*) FROM resp_log`), e.count(`SELECT COUNT(*) FROM core_audit`)
	for range 50 {
		v := e.view(tok)
		if v.State != "ready" || v.Title == nil || *v.Title != a.Title || len(v.Items) != 1 || v.Approver == nil || *v.Approver != "IT Operator" || v.ExpiresAt == nil {
			t.Fatalf("view: %+v", v)
		}
	}
	got := e.only()
	if got.Status != response.StatusPending || len(got.Approvals) != 0 || e.tokenUsed() != 0 || e.exec.count() != 0 {
		t.Fatalf("a GET changed the request: %+v", got)
	}
	if e.count(`SELECT COUNT(*) FROM resp_log`) != logs || e.count(`SELECT COUNT(*) FROM core_audit`) != audits {
		t.Fatal("a GET wrote a log or audit line")
	}
	if e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatal("a GET ran the action")
	}
}

func TestContract_INV4_ViewOfAnEndedLinkShowsNothing(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "") // decided in the app
	e.must(err)
	v := e.view(tok)
	if v.State != "decided" || v.Title != nil || len(v.Items) != 0 || v.Approver != nil || v.ExpiresAt != nil || v.Status == nil {
		t.Fatalf("decided: %+v", v)
	}
	_, err = e.decide(tok, "approve")
	wantCode(t, err, 409, "decided")
	if !e.logHas("refused", "decided: This request is already executed") && !e.logHas("refused", "decided: This request is already approved") {
		t.Fatal("the refusal of a decided request is not in the log")
	}

	e2 := newLinkEnv(t)
	a2 := e2.pending()
	tok2 := e2.mint(a2.ID, "u-op", "it@acme.example")
	e2.clock.Advance(31 * time.Minute)
	if v := e2.view(tok2); v.State != "expired" || v.Title != nil || len(v.Items) != 0 {
		t.Fatalf("expired: %+v", v)
	}
	_, err = e2.decide(tok2, "approve")
	wantCode(t, err, 409, "expired")
	if !e2.logHas("refused", "expired: This link has expired") {
		t.Fatal("the refusal of an expired link is not in the log")
	}
}

func TestContract_INV4_TokenIsUsedOnce(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	got, err := e.decide(tok, "approve")
	e.must(err)
	if got.Status != response.StatusExecuted || len(got.Approvals) != 1 || got.Approvals[0].Via != response.ViaEmail || got.Approvals[0].UserID != "u-op" || got.Approvals[0].Email != "it@acme.example" {
		t.Fatalf("after the link: %+v", got)
	}
	if !e.logHas("approved", "via email") || e.tokenUsed() != 1 {
		t.Fatal("the decision is not in the log as via email, or the token was not burned")
	}
	if e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 {
		t.Fatal("the approved action did not run once")
	}
	_, err = e.decide(tok, "approve")
	wantCode(t, err, 409, "used")
	_, err = e.decide(tok, "reject")
	wantCode(t, err, 409, "used")
	if e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'it@acme.example' AND detail = 'used: This link was already used.'`) != 2 { // M1: a replay is a logged refusal, with the person it was mailed to
		t.Fatal("the replays are not in the log")
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.refused' AND target = ?`, a.ID) != 2 {
		t.Fatal("the replays are not in the audit trail")
	}
	if v := e.view(tok); v.State != "used" || v.Title != nil {
		t.Fatalf("view after use: %+v", v)
	}
	if e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 || len(e.only().Approvals) != 1 {
		t.Fatal("a second POST ran or approved again")
	}
}

func TestContract_INV4_ConcurrentPostsHaveOneWinner(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { _, errs[i] = e.svc.DecideByLink(e.ctx(), tok, "approve", fmt.Sprintf("192.0.2.%d", i+1)) })
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		wantCode(t, err, 409, "used") // a loser that read the token before the winner committed and the request after it is still told "used"
	}
	if won != 1 || e.tokenUsed() != 1 || len(e.only().Approvals) != 1 || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 {
		t.Fatalf("%d winners, %d used, %+v", won, e.tokenUsed(), e.only().Approvals)
	}
}

func TestContract_INV4_ForgedAndUnknownTokensAreRefused(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	parts := strings.Split(tok, ".")
	unknownID := "v1." + strings.Repeat("ab", 16) + "." + parts[2]
	wrongMAC := "v1." + parts[1] + "." + strings.Repeat("0", 16)
	for _, bad := range []string{"", "x", "v1.a.b", strings.Repeat("a", 5000), unknownID, wrongMAC} {
		_, err := e.decide(bad, "approve")
		wantCode(t, err, 404, "unknown")
		if v := e.view(bad); v.State != "unknown" || v.Title != nil || len(v.Items) != 0 || v.Status != nil {
			t.Fatalf("view of %q: %+v", bad, v)
		}
	}
	// the record was changed to another person: the token no longer fits it
	e.exec1(`UPDATE resp_tokens SET user_id = 'u-op2'`)
	_, err := e.decide(tok, "approve")
	wantCode(t, err, 404, "unknown")
	e.exec1(`UPDATE resp_tokens SET user_id = 'u-op', action_id = 'act-other'`)
	_, err = e.decide(tok, "approve")
	wantCode(t, err, 404, "unknown")
	e.exec1(`UPDATE resp_tokens SET action_id = ?, channel = 'zalo'`, a.ID)
	_, err = e.decide(tok, "approve")
	wantCode(t, err, 404, "unknown")
	if e.only().Status != response.StatusPending || e.tokenUsed() != 0 {
		t.Fatal("a forged link decided or burned something")
	}
	if e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`) != 0 {
		t.Fatal("a link that is not valid wrote to the log: anyone could fill it")
	}
	// the box cannot read its key: not a decision, an error
	e.exec1(`UPDATE resp_tokens SET channel = 'email'`)
	e.links.mu.Lock()
	e.links.err = errors.New("key store is down")
	e.links.mu.Unlock()
	if _, err := e.decide(tok, "approve"); err == nil || errors.Is(err, response.ErrLinkInvalid) {
		t.Fatalf("a key that cannot be read answered %v", err)
	}
	if e.only().Status != response.StatusPending {
		t.Fatal("decided without being able to check")
	}
}

func TestContract_INV4_NoLinkTokensMeansEveryLinkIsUnknown(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.DecideByLink(e.ctx(), "v1.aaaa.bbbb", "approve", "192.0.2.1")
	wantCode(t, err, 404, "unknown")
	v, err := e.svc.LinkView(e.ctx(), "v1.aaaa.bbbb", "192.0.2.1")
	e.must(err)
	if v.State != "unknown" {
		t.Fatalf("%+v", v)
	}
}

func TestContract_INV4_DecisionMustBeApproveOrReject(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	for _, d := range []string{"", "approved", "APPROVE", "approve "} {
		_, err := e.decide(tok, d)
		wantCode(t, err, 400, "invalid")
	}
	if e.tokenUsed() != 0 || e.only().Status != response.StatusPending {
		t.Fatal("a bad decision changed something")
	}
}

// The approver is checked again when the link is used (D-96 (4)); a refusal does not burn the token.
func TestContract_INV4_TheApproverIsCheckedAgain(t *testing.T) {
	cases := []struct {
		name string
		arm  func(e *linkEnv)
	}{
		{"disabled", func(e *linkEnv) { u := e.users.m["u-op"]; u.Disabled = true; e.users.m["u-op"] = u }},
		{"demoted to viewer", func(e *linkEnv) { u := e.users.m["u-op"]; u.Role = "viewer"; e.users.m["u-op"] = u }},
		{"no longer a user", func(e *linkEnv) { delete(e.users.m, "u-op") }},
		{"the sign-in email changed", func(e *linkEnv) { u := e.users.m["u-op"]; u.Email = "new@acme.example"; e.users.m["u-op"] = u }},
		{"removed from the channel list", func(e *linkEnv) {
			e.note.approvers = map[string][]response.Approver{"email": {{UserID: "u-op2", Address: "it2@acme.example"}}}
		}},
		{"listed with another address", func(e *linkEnv) {
			e.note.approvers = map[string][]response.Approver{"email": {{UserID: "u-op", Address: "other@acme.example"}}}
		}},
		{"channel not ready", func(e *linkEnv) { e.note.chs[0].Approvers = 0 }},
		{"channel approvals off", func(e *linkEnv) { e.note.chs[0].Approvals = false }},
		{"channel disabled", func(e *linkEnv) { e.note.chs[0].Enabled = false }},
		{"channel not an approval channel of response", func(e *linkEnv) {
			e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{} })
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newLinkEnv(t)
			a := e.pending()
			tok := e.mint(a.ID, "u-op", "it@acme.example")
			c.arm(e)
			if v := e.view(tok); v.State != "unknown" || v.Title != nil || len(v.Items) != 0 || v.Approver != nil || v.Status != nil { // low 5: spec 8
				t.Fatalf("the page of a link whose person may no longer approve: %+v", v)
			}
			for _, d := range []string{"approve", "reject"} {
				_, err := e.decide(tok, d)
				wantCode(t, err, 403, "approver_not_listed")
			}
			if e.tokenUsed() != 0 || e.only().Status != response.StatusPending || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
				t.Fatal("a refused link decided or burned the token")
			}
			if !e.logHas("refused", "approver_not_listed") {
				t.Fatal("the refusal is not in the log")
			}
		})
	}
}

// D-57 (20): a high-risk request is never decided through a link, whichever way the record got there.
func TestContract_INV4_HighRiskIsNeverDecidedByLink(t *testing.T) {
	e := newLinkEnv(t)
	e.firewall("fgt_policy_disable")
	e.turnOn()
	e.rule("Cut the policy", "honeypot", []response.RuleAction{{ActionID: "fgt_policy_disable", Params: map[string]string{"id": "12"}, TTLMin: intp(60)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	if a.Risk != response.RiskHigh {
		t.Fatalf("request: %+v", a)
	}
	exp := e.clock.Now().Add(10 * time.Minute)
	if err := e.svc.RecordLink(e.ctx(), response.LinkRecord{ID: make([]byte, 16), RequestID: a.ID, UserID: "u-op", Channel: "email", Address: "it@acme.example", KeyID: "k1", ExpiresAt: exp}); err == nil {
		t.Fatal("a link was recorded for a high-risk request") // low 6: no record, no link
	}
	tok := e.mintRaw(a.ID, "u-op", "it@acme.example") // a record that got there another way
	for _, d := range []string{"approve", "reject"} {
		_, err := e.decide(tok, d)
		wantCode(t, err, 403, "in_app_required")
	}
	if e.tokenUsed() != 0 || e.only().Status != response.StatusPending || e.exec.count() != 0 {
		t.Fatal("a high-risk request was decided by a link")
	}
}

// INV-16: a request the AI marked in-app only is not decided by link either, even when its risk is lower than high.
func TestContract_INV16_InAppOnlyIsNeverDecidedByLink(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	e.exec1(`UPDATE resp_actions SET ai = json_object('confidence', 0.9, 'evidence', json_array(), 'why', 'x', 'second_check', NULL, 'in_app_only', json('true')) WHERE id = ?`, a.ID)
	if err := e.svc.RecordLink(e.ctx(), response.LinkRecord{ID: make([]byte, 16), RequestID: a.ID, UserID: "u-op2", Channel: "email", Address: "it2@acme.example", KeyID: "k1", ExpiresAt: e.clock.Now().Add(10 * time.Minute)}); err == nil {
		t.Fatal("a link was recorded for an in-app-only request")
	}
	_, err := e.decide(tok, "approve")
	wantCode(t, err, 403, "in_app_required")
	if e.tokenUsed() != 0 || e.only().Status != response.StatusPending {
		t.Fatal("an in-app-only request was decided by a link")
	}
}

// A decision a gate refuses does not burn the token; the same link works once the gate opens.
func TestContract_INV4_RefusalDoesNotBurnTheToken(t *testing.T) {
	e := newLinkEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "honeypot", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	if a.Risk != response.RiskMedium || a.RequiresApprovals != 1 {
		t.Fatalf("request: %+v", a)
	}
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	_, err := e.svc.SetExecution(e.ctx(), admin, false, "")
	e.must(err)
	_, err = e.decide(tok, "approve")
	wantCode(t, err, 409, "execution_off")
	if e.tokenUsed() != 0 || e.only().Status != response.StatusPending || e.exec.count() != 0 {
		t.Fatal("a refused approval burned the token or reached the device")
	}
	e.turnOn()
	got, err := e.decide(tok, "approve")
	e.must(err)
	if len(got.Approvals) != 1 || e.tokenUsed() != 1 || e.exec.count() == 0 {
		t.Fatalf("after the gate opened: %+v", got)
	}
}

// Reject burns the token (D-96 (4)) and is a decision of its own.
func TestContract_INV4_RejectBurnsTheToken(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	got, err := e.decide(tok, "reject")
	e.must(err)
	if got.Status != response.StatusRejected || e.tokenUsed() != 1 || !e.logHas("rejected", "via email") || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("after reject: %+v", got)
	}
	_, err = e.decide(tok, "approve")
	wantCode(t, err, 409, "used")
}

// INV-2: one person counts once, across the app and a link; the second approver must be someone else.
func TestContract_INV2_SamePersonAcrossChannelsCountsOnce(t *testing.T) {
	e := newLinkEnv(t)
	e.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
	e.rule("Two blocks", "ioc_connection", twoBlocks(), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	if a.RequiresApprovals != 2 || a.Risk == response.RiskHigh {
		t.Fatalf("request: %+v", a)
	}
	tokA, tokB := e.mint(a.ID, "u-op", "it@acme.example"), e.mint(a.ID, "u-op2", "it2@acme.example")
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "") // person A, in the app
	e.must(err)
	_, err = e.decide(tokA, "approve") // person A again, by link
	wantCode(t, err, 409, "same_approver")
	if e.tokenUsed() != 0 {
		t.Fatal("a second approval by the same person burned the token")
	}
	if v := e.view(tokA); v.State != "ready" || v.ApprovedSoFar == nil || *v.ApprovedSoFar != 1 || v.RequiresApprovals == nil || *v.RequiresApprovals != 2 {
		t.Fatalf("view: %+v", v)
	}
	done, err := e.decide(tokB, "approve") // person B, by link
	e.must(err)
	if len(done.Approvals) != 2 || done.Approvals[0].Via != response.ViaApp || done.Approvals[1].Via != response.ViaEmail || done.Status != response.StatusExecuted {
		t.Fatalf("after two people: %+v", done)
	}
}

// ---- the rate limit ----

func TestContract_INV4_RateLimit(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	// 10 POSTs a minute per address, whatever the token
	for range 10 {
		_, err := e.svc.DecideByLink(e.ctx(), "v1."+strings.Repeat("cd", 16)+"."+strings.Repeat("0", 16), "approve", "198.51.100.9")
		wantCode(t, err, 404, "unknown")
	}
	_, err := e.svc.DecideByLink(e.ctx(), tok, "approve", "198.51.100.9")
	wantCode(t, err, 429, "rate_limited")
	if ae, ok := apierr.As(err); !ok || ae.Extra["retry_after"] != 60 {
		t.Fatalf("no Retry-After: %v", err)
	}
	if e.only().Status != response.StatusPending {
		t.Fatal("a limited POST decided")
	}
	// another address is not limited, and a minute later this one is not either
	if _, err := e.svc.DecideByLink(e.ctx(), tok, "approve", "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(61 * time.Second)
	if _, err := e.svc.DecideByLink(e.ctx(), tok, "approve", "198.51.100.9"); err == nil {
		t.Fatal("the used link answered 200")
	} else {
		wantCode(t, err, 409, "used")
	}
}

func TestContract_INV4_BadTokenLimit(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	bad := "v1." + strings.Repeat("ef", 16) + "." + strings.Repeat("1", 16)
	for range 20 { // 20 links that are not valid a minute from one address, then 429, GET and POST
		if v, err := e.svc.LinkView(e.ctx(), bad, "198.51.100.20"); err != nil || v.State != "unknown" {
			t.Fatalf("%+v %v", v, err)
		}
	}
	_, err := e.svc.LinkView(e.ctx(), tok, "198.51.100.20")
	wantCode(t, err, 429, "rate_limited")
	_, err = e.svc.DecideByLink(e.ctx(), tok, "approve", "198.51.100.20")
	wantCode(t, err, 429, "rate_limited")
	if v, err := e.svc.LinkView(e.ctx(), tok, "198.51.100.21"); err != nil || v.State != "ready" {
		t.Fatalf("another address: %+v %v", v, err)
	}
	// good links are never counted as bad ones
	for range 40 {
		if v, err := e.svc.LinkView(e.ctx(), tok, "198.51.100.22"); err != nil || v.State != "ready" {
			t.Fatalf("%+v %v", v, err)
		}
	}
}

// ---- FORBID-4 ----

func TestForbid4_NoTokenAnywhereInTheStoredRows(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	parts := strings.Split(tok, ".")
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	_, _ = e.decide(tok, "approve")
	_, _ = e.decide(tok, "approve")
	_, _ = e.decide("v1."+strings.Repeat("ab", 16)+"."+parts[2], "approve")
	_, _ = e.decide(tok, "reject")
	_ = e.view(tok)
	rows := e.dump(`SELECT id || ts || kind || actor || detail || prev_hash || hash FROM resp_log`) +
		e.dump(`SELECT "user" || action || target || detail FROM core_audit`) +
		e.dump(`SELECT id || title || approvals || sent_to || COALESCE(note, '') || items || COALESCE(ai, '') FROM resp_actions`) +
		e.dump(`SELECT token_hash || kind || action_id || user_id || address || channel || COALESCE(key_id, '') FROM resp_tokens`) +
		e.dump(`SELECT value FROM resp_settings`)
	for name, secret := range map[string]string{"token": tok, "id": parts[1], "mac": parts[2]} {
		if strings.Contains(rows, secret) {
			t.Fatalf("the %s of an approval link is in a stored row", name)
		}
	}
	js := fmt.Sprintf("%+v", e.actions())
	if strings.Contains(js, parts[1]) || strings.Contains(js, "v1.") {
		t.Fatal("the list of requests carries a link")
	}
	for _, x := range e.actions() {
		if len(x.EmailLinks) != 0 {
			t.Fatalf("email_links is not empty: %+v", x.EmailLinks)
		}
	}
	// only the hash of the id is stored
	sum := sha256.Sum256(mustHex(t, parts[1]))
	if e.count(`SELECT COUNT(*) FROM resp_tokens WHERE token_hash = ?`, hex.EncodeToString(sum[:])) != 1 {
		t.Fatal("the record is not the hash of the token id")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *env) dump(q string) string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), q)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		b.WriteString(s + "\n")
	}
	e.must(rows.Err())
	return b.String()
}

// ---- recording what notify makes ----

func TestRecordLinkChecksWhatItStores(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	exp := e.clock.Now().Add(10 * time.Minute)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	ok := response.LinkRecord{ID: id, RequestID: a.ID, UserID: "u-op", Channel: "email", Address: "it@acme.example", KeyID: "k1", ExpiresAt: exp}
	bad := map[string]func(l *response.LinkRecord){
		"short id":              func(l *response.LinkRecord) { l.ID = id[:8] },
		"zalo has no link yet":  func(l *response.LinkRecord) { l.Channel = "zalo" },
		"no address":            func(l *response.LinkRecord) { l.Address = " " },
		"no key":                func(l *response.LinkRecord) { l.KeyID = "" },
		"unknown request":       func(l *response.LinkRecord) { l.RequestID = "act-none" },
		"past":                  func(l *response.LinkRecord) { l.ExpiresAt = e.clock.Now().Add(-time.Minute) },
		"longer than 30 min":    func(l *response.LinkRecord) { l.ExpiresAt = e.clock.Now().Add(45 * time.Minute) },
		"longer than a request": func(l *response.LinkRecord) { l.ExpiresAt = tsOf(t, a.ExpiresAt).Add(5 * time.Second) },
	}
	for name, f := range bad {
		l := ok
		f(&l)
		if err := e.svc.RecordLink(e.ctx(), l); err == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	if e.count(`SELECT COUNT(*) FROM resp_tokens`) != 0 {
		t.Fatal("a refused record was stored")
	}
	e.must(e.svc.RecordLink(e.ctx(), ok))
	if err := e.svc.RecordLink(e.ctx(), ok); err == nil {
		t.Fatal("the same token id was recorded twice")
	}
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	l := ok
	l.ID = make([]byte, 16)
	_, _ = rand.Read(l.ID)
	if err := e.svc.RecordLink(e.ctx(), l); err == nil {
		t.Fatal("a link was recorded for a request that is decided")
	}
}

func TestRecordReplyCodeStoresOnlyTheHash(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	exp := e.clock.Now().Add(10 * time.Minute)
	h := "1f16413d45bce5c596496fc0a4d169a0c09ade7bb044335507f4020e15060fa0"
	c := response.ReplyCodeRecord{RequestID: a.ID, UserID: "u-op", Address: "zalo-1", Approve: true, CodeHash: h, ExpiresAt: exp}
	e.must(e.svc.RecordReplyCode(e.ctx(), c))
	c.CodeHash, c.Approve = "560dd02a99d9bc0e022a7b7c50a9d6834cc2c8ab8587c50089bda4ce7077b671", false
	e.must(e.svc.RecordReplyCode(e.ctx(), c))
	if e.count(`SELECT COUNT(*) FROM resp_tokens WHERE kind = 'code' AND channel = 'zalo-personal' AND key_id IS NULL AND decision = 'approve' AND token_hash = ?`, h) != 1 ||
		e.count(`SELECT COUNT(*) FROM resp_tokens WHERE kind = 'code' AND decision = 'reject'`) != 1 {
		t.Fatal("the codes are not stored by hash")
	}
	for _, bad := range []string{"", "A-7KQ2MX", strings.ToUpper(h), h[:63]} {
		c.CodeHash = bad
		if err := e.svc.RecordReplyCode(e.ctx(), c); err == nil {
			t.Errorf("hash %q stored", bad)
		}
	}
	// a reply code is not a link: it cannot be used as one
	if v, err := e.svc.LinkView(e.ctx(), "v1."+h[:32]+"."+h[32:48], "192.0.2.5"); err != nil || v.State != "unknown" {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestSweepForgetsOldTokens(t *testing.T) {
	e := newLinkEnv(t)
	a := e.pending()
	e.mint(a.ID, "u-op", "it@acme.example")
	e.must(e.svc.Sweep(e.ctx()))
	if e.count(`SELECT COUNT(*) FROM resp_tokens`) != 1 {
		t.Fatal("a fresh token was swept")
	}
	e.clock.Advance(8 * 24 * time.Hour)
	e.must(e.svc.Sweep(e.ctx()))
	if e.count(`SELECT COUNT(*) FROM resp_tokens`) != 0 {
		t.Fatal("a token that ended a week ago was kept")
	}
}

// ---- POST-5: sending ----

func TestPost5_SentToAndLogLine(t *testing.T) {
	e := newLinkEnv(t)
	e.note.sendSent = []string{"Email"}
	a := e.pending()
	if len(a.SentTo) != 1 || a.SentTo[0] != "Email" {
		t.Fatalf("sent_to = %v", a.SentTo)
	}
	asked := e.note.requests()
	if len(asked) != 1 {
		t.Fatalf("%d calls to notify", len(asked))
	}
	m := asked[0]
	if m.RequestID != a.ID || m.Title != a.Title || m.Risk != a.Risk || m.InAppOnly || len(m.Channels) != 1 || m.Channels[0] != "email" || !m.Expires.Equal(tsOf(t, a.ExpiresAt)) {
		t.Fatalf("message: %+v", m)
	}
	if m.What == "" || len(m.What) > 4096 || !strings.Contains(m.What, "Exact call:") || !strings.Contains(m.What, "198.51.100.7") {
		t.Fatalf("what: %q", m.What)
	}
	if !e.logHas("request", "Approval request sent to Email") {
		t.Fatal("no log line for the send")
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.request_sent'`) != 1 {
		t.Fatal("no audit line for the send")
	}
}

func TestPost5_AnErrorNeverFailsTheRequest(t *testing.T) {
	e := newLinkEnv(t)
	e.note.sendErr = errors.New("smtp: connection refused")
	e.note.sendSent = nil
	a := e.pending()
	if a.Status != response.StatusPending || len(a.SentTo) != 0 {
		t.Fatalf("request: %+v", a)
	}
	if !e.logHas("request", "still open in the app") || !e.logHas("request", "smtp: connection refused") {
		t.Fatal("the failure is not in the log")
	}
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, ""); err != nil {
		t.Fatalf("the request cannot be approved in the app: %v", err)
	}
	// a partial send keeps what arrived
	e2 := newLinkEnv(t)
	e2.note.sendSent, e2.note.sendErr = []string{"Email"}, errors.New("1 of 2 message(s) could not be sent")
	if a := e2.pending(); len(a.SentTo) != 1 || a.SentTo[0] != "Email" {
		t.Fatalf("partial: %+v", a.SentTo)
	}
}

func TestPost5_NobodyIsAskedWithoutAReadyChannel(t *testing.T) {
	cases := map[string]func(e *linkEnv){
		"no approval channel in the settings": func(e *linkEnv) {
			e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{} })
		},
		"channel has no approvers": func(e *linkEnv) { e.note.chs[0].Approvers = 0 },
		"channel off":              func(e *linkEnv) { e.note.chs[0].Enabled = false },
		"no channels at all":       func(e *linkEnv) { e.note.chs = nil },
	}
	for name, arm := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLinkEnv(t)
			arm(e)
			a := e.pending()
			if len(e.note.requests()) != 0 || len(a.SentTo) != 0 || e.logHas("request", "Approval request sent") || !e.logHas("request", "sent to the app only") {
				t.Fatalf("asked %d times, sent_to %v", len(e.note.requests()), a.SentTo)
			}
		})
	}
}

func TestPost5_AnotherChannelTypeIsSentToToo(t *testing.T) {
	e := newLinkEnv(t)
	e.note.chs = append(e.note.chs, response.NotifyChannel{Type: "slack", Label: "Slack #sec", Configured: true, Enabled: true, Approvals: true, Approvers: 1},
		response.NotifyChannel{Type: "telegram", Label: "Telegram", Configured: true, Enabled: true, Approvals: true, Approvers: 1})
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email", "slack"} })
	e.pending()
	m := e.note.requests()
	if len(m) != 1 || strings.Join(m[0].Channels, ",") != "email,slack" {
		t.Fatalf("channels: %+v", m)
	}
}

func TestPost5_APreApprovedRequestAsksNobody(t *testing.T) {
	e := newLinkEnv(t)
	e.rule("Block", "ioc_connection", blockAction(1440), func(in *response.RuleInput) { in.PreApproved = true })
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.svc.WaitSendsForTest()
	a := e.only()
	if !a.PreApproved || a.Status != response.StatusExecuted || len(e.note.requests()) != 0 {
		t.Fatalf("pre-approved: %+v, asked %d", a, len(e.note.requests()))
	}
}

// Sending happens after the creating transaction committed and holds neither a write transaction nor the service lock: inside the
// send, the request is already readable, a write goes through, and the request can be approved.
func TestPost5_SendingIsAfterCommitAndHoldsNoLock(t *testing.T) {
	e := newLinkEnv(t)
	var inside struct {
		visible, wrote, approved bool
		err                      error
	}
	e.note.onSend = func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			var n int
			if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT COUNT(*) FROM resp_actions WHERE status = 'pending'`).Scan(&n); err != nil {
				inside.err = err
				return
			}
			inside.visible = n == 1
			if inside.err = e.db.Write(e.ctx(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(e.ctx(), `INSERT INTO resp_done (rule_id, event_id, at) VALUES ('probe', 'probe', 'now')`)
				return err
			}); inside.err != nil {
				return
			}
			inside.wrote = true
			l, err := e.svc.Actions(e.ctx())
			if err == nil && len(l) == 1 {
				_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
			}
			inside.approved, inside.err = err == nil, err
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			inside.err = errors.New("a write or the service lock was held while sending")
		}
	}
	e.pending()
	if !inside.visible || !inside.wrote || !inside.approved || inside.err != nil {
		t.Fatalf("while sending: %+v", inside)
	}
}

// RequestProposal (AI plan) sends too, and its answer already shows where the request went; it does not hold the lock while sending.
func TestPost5_RequestProposalSends(t *testing.T) {
	e, _, _ := propEnv(t, true)
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 1}}
	e.note.sendSent = []string{"Email"}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	r := e.mustPropose(lowBody())
	e.svc.WaitSendsForTest()
	if r.Request == nil || len(e.note.requests()) != 1 {
		t.Fatalf("%+v, %d calls", r, len(e.note.requests()))
	}
	m := e.note.requests()[0]
	if m.RequestID != r.Request.ID || m.InAppOnly {
		t.Fatalf("message: %+v", m)
	}
	if got := e.full(r.Request.ID); len(got.SentTo) != 1 || got.SentTo[0] != "Email" {
		t.Fatalf("sent_to = %v", got.SentTo)
	}
}

// A high-risk AI request is sent as "open Vedette" only (INV-16): notify is told InAppOnly.
func TestPost5_HighRiskAIRequestIsSentInAppOnly(t *testing.T) {
	e, _, _ := propEnv(t, true)
	e.allowHigh()
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 1}}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	r := e.mustPropose(highBody())
	e.svc.WaitSendsForTest()
	m := e.note.requests()
	if r.Request == nil || len(m) != 1 || !m[0].InAppOnly || m[0].Risk != response.RiskHigh || m[0].RequestID != r.Request.ID {
		t.Fatalf("%+v %+v", r, m)
	}
	if !e.logHas("request", "in the app only") {
		t.Fatal("the log does not say that it went to the app only")
	}
}

// ---- M2: sending is in the background ----

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 500 {
		if ok() {
			return
		}
		select {
		case <-t.Context().Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("never became true: %s", what)
}

// A mail server that does not answer holds nothing: the engine goes on creating requests, a person approves in the app and a
// pre-approved action runs, while two sends wait on the blackhole and the rest wait for a slot.
func TestPost5_ABlackholedMailServerDelaysNothing(t *testing.T) {
	e := newLinkEnv(t)
	release := make(chan struct{})
	e.note.block = release
	e.note.sendSent = []string{"Email"}
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, ip := range []string{"198.51.100.7", "198.51.100.8", "198.51.100.9"} {
			e.fireNoWait(e.iocEvent(fmt.Sprintf("e%d", i), ip))
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the engine waited for a mail server that does not answer")
	}
	eventually(t, "two sends started", func() bool { return len(e.note.requests()) == 2 })
	l := e.actions()
	if len(l) != 3 {
		t.Fatalf("%d requests, want 3", len(l))
	}
	if _, err := e.svc.Approve(e.ctx(), oper, l[2].ID, nil, ""); err != nil { // a person is not held either
		t.Fatal(err)
	}
	e.rule("Pre", "honeypot", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(1440)}}, func(in *response.RuleInput) { in.PreApproved = true })
	e.fireNoWait(e.trap("h1", "192.168.10.157"))
	if e.count(`SELECT COUNT(*) FROM resp_actions WHERE pre_approved = 1 AND status = 'executed'`) != 1 {
		t.Fatal("a pre-approved action waited for the mail server")
	}
	if len(e.note.requests()) != 2 {
		t.Fatalf("%d sends at once, want at most 2", len(e.note.requests()))
	}
	close(release) // the server answers: the waiting request goes out too
	e.svc.WaitSendsForTest()
	if len(e.note.requests()) != 3 {
		t.Fatalf("%d sends in all, want 3 (the pre-approved one asks nobody)", len(e.note.requests()))
	}
	for _, a := range e.actions() {
		if !a.PreApproved && (len(a.SentTo) != 1 || a.SentTo[0] != "Email") {
			t.Fatalf("sent_to of %s: %v", a.ID, a.SentTo)
		}
	}
}

// Close ends the sends that are waiting on a mail server and returns; the request stays open in the app.
func TestPost5_CloseStopsTheSends(t *testing.T) {
	e := newLinkEnv(t)
	e.note.block = make(chan struct{}) // never released
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	eventually(t, "the send started", func() bool { return len(e.note.requests()) == 1 })
	closed := make(chan struct{})
	go func() { e.svc.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for a mail server")
	}
	a := e.only()
	if a.Status != response.StatusPending || len(a.SentTo) != 0 || !e.logHas("request", "still open in the app") {
		t.Fatalf("after Close: %+v", a)
	}
}

// When the budget runs out with several approvers, the ones mailed so far are kept and the line says the rest were skipped.
func TestPost5_BudgetRunningOutIsInTheLog(t *testing.T) {
	e := newLinkEnv(t)
	e.svc.SetSendBudgetForTest(50 * time.Millisecond)
	e.note.block = make(chan struct{})
	e.note.sendSent = []string{"Email"} // one approver was mailed before the budget ended
	a := e.pending()
	if len(a.SentTo) != 1 || a.SentTo[0] != "Email" || a.Status != response.StatusPending {
		t.Fatalf("request: %+v", a)
	}
	if !e.logHas("request", "budget ran out: approvers not yet mailed were skipped") || !e.logHas("request", "Approval request sent to Email") {
		t.Fatal("the log does not say that the budget ran out")
	}
}

// notify could not write its record after the mails went out: the line says some mail may have gone out all the same.
func TestPost5_UnsureSendIsSaidInTheLog(t *testing.T) {
	e := newLinkEnv(t)
	e.note.sendErr = fmt.Errorf("%w: write the records: disk full", response.ErrSendUnsure)
	a := e.pending()
	if a.Status != response.StatusPending || !e.logHas("request", "some mail may have gone out all the same") {
		t.Fatalf("%+v", a)
	}
}

// A real RequestProposal: the answer is already committed when the send starts, and the lock is free while it runs.
func TestPost5_RequestProposalHoldsNoLockWhileSending(t *testing.T) {
	e := planEnv(t)
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_vip_disable", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 1}}
	e.note.sendSent = []string{"Email"}
	e.note.block = make(chan struct{})
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_vip_disable","params":{"name":"NAS"},"asset_id":"a-nas","asset_name":"NAS"}`)
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1") // returns while the send waits on the blackhole
	e.must(err)
	eventually(t, "the send started", func() bool { return len(e.note.requests()) == 1 })
	l, err := e.svc.Actions(e.ctx())
	e.must(err)
	if len(l) != 1 || l[0].ID != a.ID || len(l[0].SentTo) != 0 {
		t.Fatalf("while sending: %+v", l)
	}
	if _, err := e.svc.Reject(e.ctx(), oper, a.ID, "no", ""); err != nil { // takes the service lock: it is free
		t.Fatal(err)
	}
	close(e.note.block)
	e.svc.WaitSendsForTest()
}

// ---- M4: the approver is checked again under the lock ----

func TestContract_INV4_ApproverRemovedWhileThePostWaitsForTheLock(t *testing.T) {
	for _, decision := range []string{"approve", "reject"} {
		t.Run(decision, func(t *testing.T) {
			e := newLinkEnv(t)
			a := e.pending()
			tok := e.mint(a.ID, "u-op", "it@acme.example")
			e.svc.SetBeforeLockForTest(func() { // the POST has passed its checks and waits for the lock; the person is taken off the list
				e.note.mu.Lock()
				e.note.approvers = map[string][]response.Approver{"email": {{UserID: "u-op2", Address: "it2@acme.example"}}}
				e.note.mu.Unlock()
			})
			_, err := e.decide(tok, decision)
			wantCode(t, err, 403, "approver_not_listed")
			if e.tokenUsed() != 0 || e.only().Status != response.StatusPending || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
				t.Fatal("a person removed while waiting decided")
			}
		})
	}
}

// flippingUsers answers like the directory for the first n lookups of a person and then as if the account had been demoted.
type flippingUsers struct {
	*fakeUsers
	mu   sync.Mutex
	id   string
	left int
}

func (f *flippingUsers) Lookup(ctx context.Context, id string) (response.User, bool, error) {
	u, ok, err := f.fakeUsers.Lookup(ctx, id)
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == f.id {
		if f.left--; f.left < 0 {
			u.Role = "viewer"
		}
	}
	return u, ok, err
}

// A rejection through a link reads the account again inside its transaction, as an approval does (the lookups: the check before, the one
// under the lock, and the one in the transaction).
func TestContract_INV4_RejectReadsTheAccountAgain(t *testing.T) {
	fl := &fakeLinks{}
	var fu *flippingUsers
	e := newEnv(t, func(c *response.Config) {
		c.Links = fl
		fu = &flippingUsers{fakeUsers: c.Users.(*fakeUsers), id: "u-op", left: 2}
		c.Users = fu
	})
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 2}}
	e.note.approvers = map[string][]response.Approver{"email": {{UserID: "u-op", Address: "it@acme.example"}}}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	l := &linkEnv{env: e, links: fl}
	fu.mu.Lock()
	fu.left = 1000 // rule creation and minting read the account too
	fu.mu.Unlock()
	a := l.pending()
	tok := l.mint(a.ID, "u-op", "it@acme.example")
	fu.mu.Lock()
	fu.left = 2
	fu.mu.Unlock()
	_, err := l.decide(tok, "reject")
	wantCode(t, err, 403, "forbidden")
	if l.tokenUsed() != 0 || l.only().Status != response.StatusPending {
		t.Fatal("a person demoted during the rejection rejected the request")
	}
}

// ---- a panic in a write section does not leave the service lock held (low 9) ----

type panickyUsers struct {
	*fakeUsers
	armed *bool
}

func (p panickyUsers) Lookup(ctx context.Context, id string) (response.User, bool, error) {
	if *p.armed {
		*p.armed = false
		panic("the directory blew up")
	}
	return p.fakeUsers.Lookup(ctx, id)
}

func TestApproveAfterAPanicInTheWriteSection(t *testing.T) {
	armed := false
	e := newEnv(t, func(c *response.Config) { c.Users = panickyUsers{fakeUsers: c.Users.(*fakeUsers), armed: &armed} })
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	armed = true
	func() {
		defer func() { _ = recover() }()
		_, _ = e.svc.Approve(e.ctx(), oper, a.ID, nil, "") // the lookup inside the transaction panics
	}()
	done := make(chan error, 1)
	go func() { _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, ""); done <- err }()
	select {
	case err := <-done:
		e.must(err)
	case <-time.After(15 * time.Second):
		t.Fatal("the service lock was left held by a panic")
	}
}

// ---- limiter: its own table, the whole address ----

func TestContract_INV4_LinkLimitIsPerWholeIPv6AddressAndNotTheBlocklists(t *testing.T) {
	e := newLinkEnv(t)
	bad := "v1." + strings.Repeat("ab", 16) + "." + strings.Repeat("0", 16)
	fetch0 := e.svc.FetchKeysForTest()
	for range 10 { // ten POSTs from one address of a /64 use up that address only
		_, err := e.svc.DecideByLink(e.ctx(), bad, "approve", "2001:db8:1:2::1")
		wantCode(t, err, 404, "unknown")
	}
	_, err := e.svc.DecideByLink(e.ctx(), bad, "approve", "2001:db8:1:2::1")
	wantCode(t, err, 429, "rate_limited")
	for _, other := range []string{"2001:db8:1:2::2", "2001:db8:1:2:ffff:ffff:ffff:ffff"} { // the same /64, other addresses
		if _, err := e.svc.DecideByLink(e.ctx(), bad, "approve", other); err != nil {
			wantCode(t, err, 404, "unknown")
		}
	}
	if e.svc.FetchKeysForTest() != fetch0 || e.svc.LinkKeysForTest() == 0 {
		t.Fatalf("link calls touched the block list table (%d keys, was %d) or not their own (%d)", e.svc.FetchKeysForTest(), fetch0, e.svc.LinkKeysForTest())
	}
	// and the block list pull of that /64 is not limited by the link calls
	for range 5 {
		if _, err := e.svc.FetchBlocklist(e.ctx(), strings.Repeat("0", 32), "2001:db8:1:2::1"); err != nil {
			wantCode(t, err, 404, "not_found")
		}
	}
}

// ---- D-124: two people, at most one by link ----

func TestContract_INV2_TwoPersonRuleAllowsOneLink(t *testing.T) {
	setup := func(t *testing.T) (*linkEnv, response.ActionRequest, string, string) {
		e := newLinkEnv(t)
		e.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
		e.rule("Two blocks", "ioc_connection", twoBlocks(), nil)
		e.fire(e.iocEvent("e1", "198.51.100.7"))
		e.svc.WaitSendsForTest()
		a := e.only()
		if a.RequiresApprovals != 2 || a.Risk == response.RiskHigh {
			t.Fatalf("request: %+v", a)
		}
		return e, a, e.mint(a.ID, "u-op", "it@acme.example"), e.mint(a.ID, "u-op2", "it2@acme.example")
	}
	t.Run("two links", func(t *testing.T) {
		e, a, tokA, tokB := setup(t)
		if _, err := e.decide(tokA, "approve"); err != nil {
			t.Fatal(err)
		}
		_, err := e.decide(tokB, "approve") // another person, another mail, still a link
		wantCode(t, err, 403, "in_app_required")
		if ae, _ := apierr.As(err); !strings.Contains(ae.Message, "only one of them may approve by email link") {
			t.Fatalf("message: %q", ae.Message)
		}
		got := e.only()
		if got.Status != response.StatusPending || len(got.Approvals) != 1 || e.tokenUsed() != 1 {
			t.Fatalf("the second link counted or burned: %+v", got)
		}
		done, err := e.svc.Approve(e.ctx(), oper2, a.ID, nil, "") // the same person, in the app, is fine
		e.must(err)
		if len(done.Approvals) != 2 || done.Approvals[1].Via != response.ViaApp || done.Status != response.StatusExecuted {
			t.Fatalf("link then app: %+v", done)
		}
	})
	t.Run("app then link", func(t *testing.T) {
		e, a, tokA, _ := setup(t)
		if _, err := e.svc.Approve(e.ctx(), oper2, a.ID, nil, ""); err != nil {
			t.Fatal(err)
		}
		done, err := e.decide(tokA, "approve")
		e.must(err)
		if len(done.Approvals) != 2 || done.Approvals[1].Via != response.ViaEmail || done.Status != response.StatusExecuted {
			t.Fatalf("app then link: %+v", done)
		}
	})
	t.Run("a rejection by link is not an approval", func(t *testing.T) {
		e, _, tokA, tokB := setup(t)
		if _, err := e.decide(tokA, "approve"); err != nil {
			t.Fatal(err)
		}
		got, err := e.decide(tokB, "reject")
		e.must(err)
		if got.Status != response.StatusRejected {
			t.Fatalf("reject: %+v", got)
		}
	})
}

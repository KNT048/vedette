package main

import (
	"encoding/base32"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-9 (D-97, D-98, response INV-16, INV-18) in the real wiring: the two-step code of core/auth (authenticator app)
// guards the approval of a high-risk AI request, once per person, once per code.

type aiPerson struct {
	actor response.Actor
	key   []byte
}

// totpUser creates an account with the authenticator-app method on, confirmed with the code of the current step.
func (s *stack) totpUser(email string, now func() time.Time) aiPerson {
	s.t.Helper()
	u := s.addUser(email, routes.Operator)
	setup, err := s.d.Auth.StartTOTP(s.t.Context(), u.ID, "", testUserSecret)
	if err != nil {
		s.t.Fatal(err)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.d.Auth.ConfirmTOTP(s.t.Context(), u.ID, "", auth.TOTPCode(key, auth.TOTPStep(now()))); err != nil {
		s.t.Fatal(err)
	}
	return aiPerson{actor: response.Actor{ID: u.ID, Name: u.Name, Email: u.Email, Via: response.ViaApp}, key: key}
}

func (p aiPerson) code(now time.Time) string { return auth.TOTPCode(p.key, auth.TOTPStep(now)) }

func apiErr(t *testing.T, err error, status int, code string) {
	t.Helper()
	e, ok := apierr.As(err)
	if !ok || e.Status != status || e.Code != code {
		t.Fatalf("error = %v, want %d %s", err, status, code)
	}
}

func TestWiringApproveHighRiskAIRequestWithTwoStepCodes(t *testing.T) {
	t.Parallel()
	clock := newManualClock(time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC))
	s := newStackWith(t, func(d *deps) { d.Clock = clock.now })
	for _, m := range []string{"notify", "inventory", "response"} {
		s.setModule(m, true)
	}
	ctx := t.Context()
	svc := s.d.Response
	ann, bob := s.totpUser("ann@acme.example", clock.now), s.totpUser("bob@acme.example", clock.now)
	none := s.addUser("cy@acme.example", routes.Operator) // no two-step sign-in
	boss := response.Actor{ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Via: response.ViaApp}

	// Two AI requests of two actions each (a second approver is needed above 1 target), in_app_only as a high-risk one is.
	st, err := svc.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := response.SettingsInput{MaxPerHour: st.MaxPerHour, ExpiryMin: 30, ApprovalChannels: st.ApprovalChannels, BreakerMaxPerHour: 100, MultiTargetMax: 1, Maintenance: st.Maintenance}
	in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = st.AI.Triggers, st.AI.BudgetHour, st.AI.BudgetDay
	if _, err := svc.SaveSettings(ctx, boss, in); err != nil {
		t.Fatal(err)
	}
	ri := response.RuleInput{Name: "Block both", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, MaxPerHour: 10,
		Actions: []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}}, {ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.src_ip}}"}}}}
	rule, err := svc.AddRule(ctx, boss, ri)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeRule(ctx, boss, rule.ID, ri); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []struct{ id, dest, src string }{{"e1", "198.51.100.7", "192.168.10.105"}, {"e2", "198.51.100.8", "192.168.10.106"}} {
		d := response.Det{ID: ev.id, Trigger: "ioc_connection", TS: store.FormatTS(clock.now()), Summary: "PC connected to " + ev.dest,
			Fields: map[string]string{"src_ip": ev.src, "device": "PC-SALES-02", "dest": ev.dest, "dest_kind": "ip", "dest_ip": ev.dest, "dest_domain": "", "feeds": "IPsum", "confidence": "0.92", "switch_port": ""}}
		if err := svc.StoreEvent(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	reqs, err := svc.Actions(ctx)
	if err != nil || len(reqs) != 2 || reqs[0].RequiresApprovals != 2 {
		t.Fatalf("requests: %v %+v", err, reqs)
	}
	a, b := reqs[0], reqs[1]
	for _, r := range reqs {
		s.exec(`UPDATE resp_actions SET source = 'ai', ai = '{"confidence":0.95,"evidence":[],"why":"test","second_check":null,"in_app_only":true}' WHERE id = ?`, r.ID)
	}

	clock.advance(time.Minute) // a code of a later step than the one that confirmed the method
	// No code: 400 code_required; a wrong code: 400 invalid_code; no two-step on the account: 403 twofa_required. Nothing is approved.
	_, err = svc.Approve(ctx, ann.actor, a.ID, nil, "")
	apiErr(t, err, 400, "code_required")
	_, err = svc.Approve(ctx, ann.actor, a.ID, nil, authtest.WrongTOTP(ann.key, clock.now()))
	apiErr(t, err, 400, "invalid_code")
	_, err = svc.Approve(ctx, response.Actor{ID: none.ID, Email: none.Email, Name: none.Name, Via: response.ViaApp}, a.ID, nil, "123456")
	apiErr(t, err, 403, "twofa_required")
	// The first person, with their own code.
	first, err := svc.Approve(ctx, ann.actor, a.ID, nil, ann.code(clock.now()))
	if err != nil || first.Status != response.StatusPending || len(first.Approvals) != 1 {
		t.Fatalf("first approval: %v %+v", err, first)
	}
	// The same code on another request: a code is used once (TOTP replay), so it opens nothing else.
	_, err = svc.Approve(ctx, ann.actor, b.ID, nil, ann.code(clock.now()))
	apiErr(t, err, 400, "invalid_code")
	// The same person on the same request: refused, no matter the code.
	clock.advance(time.Minute)
	_, err = svc.Approve(ctx, ann.actor, a.ID, nil, ann.code(clock.now()))
	apiErr(t, err, 409, "same_approver")
	// A second, different person with their own code: the request is approved.
	done, err := svc.Approve(ctx, bob.actor, a.ID, nil, bob.code(clock.now()))
	if err != nil || len(done.Approvals) != 2 || done.Approvals[0].UserID == done.Approvals[1].UserID || done.Status != response.StatusExecuted {
		t.Fatalf("second approval: %v %+v", err, done)
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action = 'auth.stepup' AND detail LIKE ?`, "purpose=response.approve."+a.ID+" %"); n != 2 {
		t.Fatalf("%d auth.stepup rows for the request, want 2", n)
	}

	// Rejecting with remember, and the breaker and the state, through the real routes.
	if _, err := svc.Reject(ctx, bob.actor, b.ID, "Our own scanner", "memory"); err != nil {
		t.Fatal(err)
	}
	c, v := s.do("GET", "/response/ai", "viewer", "")
	hints, _ := v["hints"].([]any)
	if c != 200 || len(hints) != 1 || at(v, "quality", "decided") != float64(2) || at(v, "quality", "rejected") != float64(1) || at(v, "gates", "paused_at") != nil {
		t.Fatalf("GET /response/ai: %d %v", c, v)
	}
	if c, _ := s.do("POST", "/response/ai/resume", "operator", ""); c != 403 {
		t.Errorf("resume as operator: %d", c)
	}
	if c, _ := s.do("POST", "/response/ai/resume", "viewer", ""); c != 403 {
		t.Errorf("resume as viewer: %d", c)
	}
	if c, v := s.do("POST", "/response/ai/resume", "admin", ""); c != 200 || at(v, "gates", "paused_at") != nil {
		t.Errorf("resume as admin: %d %v", c, v)
	}
}

// TOTP has no purpose, only replay protection. One code sent at the same moment to approve
// two different requests must pass for at most one of them (core/auth AdvanceTotpStep is a compare-and-set on last_step).
func TestWiringOneTOTPCodeRacingTwoRequestsPassesOnce(t *testing.T) {
	t.Parallel()
	clock := newManualClock(time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC))
	s := newStackWith(t, func(d *deps) { d.Clock = clock.now })
	for _, m := range []string{"notify", "inventory", "response"} {
		s.setModule(m, true)
	}
	ctx := t.Context()
	svc := s.d.Response
	ann := s.totpUser("ann@acme.example", clock.now)
	boss := response.Actor{ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Via: response.ViaApp}
	st, err := svc.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := response.SettingsInput{MaxPerHour: st.MaxPerHour, ExpiryMin: 30, ApprovalChannels: st.ApprovalChannels, BreakerMaxPerHour: 100, MultiTargetMax: 1, Maintenance: st.Maintenance}
	in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = st.AI.Triggers, st.AI.BudgetHour, st.AI.BudgetDay
	if _, err := svc.SaveSettings(ctx, boss, in); err != nil {
		t.Fatal(err)
	}
	ri := response.RuleInput{Name: "Block both", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, MaxPerHour: 10,
		Actions: []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}}, {ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.src_ip}}"}}}}
	rule, err := svc.AddRule(ctx, boss, ri)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeRule(ctx, boss, rule.ID, ri); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []struct{ id, dest, src string }{{"e1", "198.51.100.7", "192.168.10.105"}, {"e2", "198.51.100.8", "192.168.10.106"}} {
		d := response.Det{ID: ev.id, Trigger: "ioc_connection", TS: store.FormatTS(clock.now()), Summary: "PC connected to " + ev.dest,
			Fields: map[string]string{"src_ip": ev.src, "device": "PC-SALES-02", "dest": ev.dest, "dest_kind": "ip", "dest_ip": ev.dest, "dest_domain": "", "feeds": "IPsum", "confidence": "0.92", "switch_port": ""}}
		if err := svc.StoreEvent(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	reqs, err := svc.Actions(ctx)
	if err != nil || len(reqs) != 2 {
		t.Fatalf("requests: %v %+v", err, reqs)
	}
	for _, r := range reqs {
		s.exec(`UPDATE resp_actions SET source = 'ai', ai = '{"confidence":0.95,"evidence":[],"why":"test","second_check":null,"in_app_only":true}' WHERE id = ?`, r.ID)
	}
	clock.advance(time.Minute)
	code := ann.code(clock.now())
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, r := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = svc.Approve(ctx, ann.actor, r.ID, nil, code)
		}()
	}
	wg.Wait()
	passed := 0
	for _, err := range errs {
		if err == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("one TOTP code approved %d requests (errors %v)", passed, errs)
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action = 'auth.stepup'`); n != 1 {
		t.Fatalf("%d auth.stepup rows for one code, want 1", n)
	}
}

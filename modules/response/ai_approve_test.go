package response_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-9: approving an AI request with the two-step code (INV-16), hints (INV-18), the quality breaker (INV-15 (8)), the AI state.

// fakeTwoStep stands in for core/auth: a code belongs to one person and one purpose and works once; the line sent with it is kept.
type fakeTwoStep struct {
	mu    sync.Mutex
	calls []twoCall
	codes map[string]string // user|purpose -> the code that person was given for that purpose
	off   map[string]bool   // users without two-step sign-in
	used  map[string]bool
}
type twoCall struct{ user, code, purpose, summary string }

func (f *fakeTwoStep) give(user, purpose, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codes == nil {
		f.codes, f.used = map[string]string{}, map[string]bool{}
	}
	f.codes[user+"|"+purpose] = code
}

func (f *fakeTwoStep) Verify(_ context.Context, user, code, purpose, summary string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, twoCall{user, code, purpose, summary})
	switch {
	case f.off[user]:
		return apierr.New(403, "twofa_required", "Turn on two-step sign-in first.")
	case code == "":
		return apierr.New(400, "code_required", "Enter the code.").With("sent_to", "a***@acme.example").With("resend_after", 60)
	}
	key := user + "|" + purpose
	if f.codes[key] != code || f.used[key+"|"+code] {
		return apierr.New(400, "wrong_code", "That code is wrong.")
	}
	f.used[key+"|"+code] = true
	return nil
}

func (f *fakeTwoStep) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func newAIEnv(t *testing.T) (*env, *fakeTwoStep) {
	t.Helper()
	f := &fakeTwoStep{off: map[string]bool{}}
	e := newEnv(t, func(c *response.Config) { c.TwoStep = f })
	return e, f
}

const inAppAI = `{"confidence":0.95,"evidence":[],"why":"test","second_check":null,"in_app_only":true}`
const plainAI = `{"confidence":0.95,"evidence":[],"why":"test","second_check":null,"in_app_only":false}`

// asAI turns the request a rule made into an AI request (the proposal path is 13b-10; the approval does not care who asked).
func (e *env) asAI(id, meta string) {
	e.t.Helper()
	e.exec1(`UPDATE resp_actions SET source = 'ai', ai = ? WHERE id = ?`, meta, id)
}

// highRiskAI is a high-risk AI request: two actions, one of them a device action, so two different people and the code.
func (e *env) highRiskAI() response.ActionRequest {
	e.t.Helper()
	e.firewall("fgt_policy_disable")
	e.turnOn()
	e.exec.present = `"status":"disable"`
	e.rule("Cut the policy", "honeypot", []response.RuleAction{
		{ActionID: "fgt_policy_disable", Params: map[string]string{"id": "12"}, TTLMin: intp(60)},
		{ActionID: "msg_send", Params: map[string]string{"text": "Trap touched on {{trigger.source_device}}"}},
	}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	if a.Risk != response.RiskHigh || a.RequiresApprovals != 2 {
		e.t.Fatalf("request: %+v", a)
	}
	e.asAI(a.ID, inAppAI)
	return a
}

func purposeOf(id string) string { return "response.approve." + id }

func TestContract_INV16_CodeIsRequiredAndErrorsPassThrough(t *testing.T) {
	e, _ := newAIEnv(t)
	a := e.highRiskAI()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 400, "code_required")
	ae, _ := apierr.As(err)
	if ae.Extra["sent_to"] != "a***@acme.example" || ae.Extra["resend_after"] != 60 {
		t.Fatalf("the extra fields of VerifyTwoStep did not pass through: %v", ae.Extra)
	}
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "000000")
	wantCode(t, err, 400, "wrong_code")
	if got := e.only(); len(got.Approvals) != 0 || got.Status != response.StatusPending {
		t.Fatalf("a refused code approved something: %+v", got)
	}
	if e.exec.count() != 0 {
		t.Fatal("a refused code reached the device")
	}
}

func TestContract_INV16_ReplayedCodeAndCodeOfAnotherRequestFail(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	f.give(oper.ID, purposeOf(a.ID), "111111")
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "111111"); err != nil {
		t.Fatal(err)
	}
	// the same code once more, for the same request, by the person who has already approved: refused before the code is looked at again
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "111111")
	wantCode(t, err, 409, "same_approver")
	// a second person with a replay of the first person's code (a code is one person's, one time)
	_, err = e.svc.Approve(e.ctx(), admin, a.ID, nil, "111111")
	wantCode(t, err, 400, "wrong_code")
	// a code made for another request does not open this one (purpose binding)
	f.give(admin.ID, purposeOf("act-other"), "222222")
	_, err = e.svc.Approve(e.ctx(), admin, a.ID, nil, "222222")
	wantCode(t, err, 400, "wrong_code")
	if e.exec.count() != 0 {
		t.Fatal("a refused code reached the device")
	}
}

func TestContract_INV16_TwoFactorOffAndNoPort(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	f.off[oper.ID] = true
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "123456")
	wantCode(t, err, 403, "twofa_required")

	e2 := newEnv(t) // no TwoStep port: a request that needs a code cannot be approved at all
	a2 := e2.highRiskAI()
	_, err = e2.svc.Approve(e2.ctx(), oper, a2.ID, nil, "123456")
	wantCode(t, err, 403, "twofa_required")
	if e2.exec.count() != 0 || len(e2.only().Approvals) != 0 {
		t.Fatal("a nil port approved something")
	}
}

func TestContract_INV16_OnlyInTheApp(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	f.give(oper.ID, purposeOf(a.ID), "111111")
	for _, via := range []response.Via{"chat", "email", "link", response.ViaAuto} {
		w := oper
		w.Via = via
		_, err := e.svc.ApproveViaForTest(e.ctx(), w, a.ID, nil, "111111")
		wantCode(t, err, 403, "in_app_required")
	}
	if f.count() != 0 {
		t.Fatalf("a code was looked at for an approval that is not in the app (%d calls)", f.count())
	}
	if !e.logHas("refused", "in_app_required") {
		t.Fatal("the refusal is not in the log")
	}
}

func TestContract_INV16_SameApproverIsRefusedWithoutSpendingACode(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	f.give(oper.ID, purposeOf(a.ID), "111111")
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "111111"); err != nil {
		t.Fatal(err)
	}
	before := f.count()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "333333")
	wantCode(t, err, 409, "same_approver")
	if f.count() != before {
		t.Fatal("the second click of the same person looked at a code")
	}
}

func TestContract_INV16_TwoDifferentPeopleEachWithTheirOwnCode(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	f.give(oper.ID, purposeOf(a.ID), "111111")
	f.give(admin.ID, purposeOf(a.ID), "222222")
	dev := a.Items[0].ID
	first, err := e.svc.Approve(e.ctx(), oper, a.ID, []string{dev}, "111111")
	e.must(err)
	if first.Status != response.StatusPending || len(first.Approvals) != 1 || e.exec.count() != 0 {
		t.Fatalf("after the first approval: %+v", first)
	}
	// a wrong pick or a wrong code by the second person changes nothing
	_, err = e.svc.Approve(e.ctx(), admin, a.ID, []string{dev, a.Items[1].ID}, "222222")
	wantCode(t, err, 409, "selection_differs")
	_, err = e.svc.Approve(e.ctx(), admin, a.ID, nil, "111111")
	wantCode(t, err, 400, "wrong_code")
	done, err := e.svc.Approve(e.ctx(), admin, a.ID, nil, "222222")
	e.must(err)
	if done.Status != response.StatusExecuted || len(done.Approvals) != 2 || done.Approvals[0].UserID == done.Approvals[1].UserID {
		t.Fatalf("after the second approval: %+v", done)
	}
	if e.exec.count() == 0 {
		t.Fatal("two approvals did not reach the device")
	}
	var good []twoCall
	for _, c := range f.calls {
		if c.code == "111111" || c.code == "222222" {
			good = append(good, c)
		}
	}
	if len(good) < 2 || good[0].purpose != purposeOf(a.ID) || good[0].user != oper.ID {
		t.Fatalf("calls: %+v", f.calls)
	}
}

// The line sent with the code is built by the server from the stored request: the action, the target, the risk, and that an AI asked.
func TestContract_INV16_SummaryIsServerBuilt(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	f.give(oper.ID, purposeOf(a.ID), "111111")
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "111111"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("calls: %+v", f.calls)
	}
	got := f.calls[0].summary
	want, err := e.svc.ApproveSummaryForTest(e.ctx(), a.ID)
	e.must(err)
	if got != want || !strings.HasPrefix(got, "High-risk AI request: ") || !strings.Contains(got, `"`+a.Items[0].Title+`"`) || !strings.HasSuffix(got, ` on "`+a.AssetName+`"`) {
		t.Fatalf("summary %q, want the one built from the request %q", got, want)
	}
	if n := len([]rune(got)); n > 200 || strings.ContainsAny(got, "\r\n\t") {
		t.Fatalf("summary is not one short line: %d runes %q", n, got)
	}
}

// A request that is not a high-risk AI request needs no code: rule requests and low-risk AI requests approve as before.
func TestContract_INV16_OnlyHighRiskAIRequestsNeedACode(t *testing.T) {
	e, f := newAIEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	e.asAI(a.ID, plainAI)
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if f.count() != 0 {
		t.Fatal("a low-risk request asked for a code")
	}
}

// ---- INV-18: hints ----

func (e *env) reject(a response.ActionRequest, reason, remember string) response.ActionRequest {
	e.t.Helper()
	r, err := e.svc.Reject(e.ctx(), oper, a.ID, reason, remember)
	e.must(err)
	return r
}

// aiBlocks makes n pending low-risk AI requests, one per address, and lets the clock move on between them.
func (e *env) aiBlocks(n int) []response.ActionRequest {
	e.t.Helper()
	e.saveSettings(func(in *response.SettingsInput) { in.BreakerMaxPerHour = 200 })
	e.rule("Block", "ioc_connection", blockAction(60), func(in *response.RuleInput) { in.MaxPerHour = 100 })
	for i := 0; i < n; i++ {
		e.fire(e.iocEvent(fmt.Sprintf("ev%d", i), fmt.Sprintf("198.51.100.%d", 10+i)))
	}
	l := e.actions()
	if len(l) != n {
		e.t.Fatalf("%d requests, want %d", len(l), n)
	}
	for _, a := range l {
		e.asAI(a.ID, plainAI)
	}
	return l
}

func (e *env) hints() []response.Hint {
	e.t.Helper()
	s, err := e.svc.AIState(e.ctx())
	e.must(err)
	return s.Hints
}

func TestContract_INV18_RememberIsAHintOnly(t *testing.T) {
	e, _ := newAIEnv(t)
	l := e.aiBlocks(3)
	rulesBefore, settingsBefore := len(mustRules(e)), e.settings()
	got := e.reject(l[0], "Our scanner uses this address", "rule")
	if got.Status != response.StatusRejected {
		t.Fatalf("status %s", got.Status)
	}
	e.clock.Advance(time.Second)
	e.reject(l[1], "Looks wrong", "memory")
	e.clock.Advance(time.Second)
	e.reject(l[2], "no hint wanted", "none")
	h := e.hints()
	if len(h) != 2 || h[0].Kind != "memory" || h[1].Kind != "rule" || h[1].FromRequest != l[0].ID || h[1].Text != "Our scanner uses this address" {
		t.Fatalf("hints: %+v", h)
	}
	if len(mustRules(e)) != rulesBefore || e.settings().AI.Triggers == nil || len(e.settings().AI.Triggers) != len(settingsBefore.AI.Triggers) {
		t.Fatal("a hint changed a rule or a gate")
	}
	if !e.logHas("ai_note", "rule hint") || !e.logHas("ai_note", "memory hint") {
		t.Fatal("the hints are not in the log")
	}
	// a hint approves or rejects nothing by itself: a new request for the same address is still pending until a person decides
	e.exec1(`UPDATE resp_actions SET status = 'pending' WHERE id = ?`, l[2].ID)
	if got := e.actions(); len(got) != 3 {
		t.Fatalf("%d requests", len(got))
	}
	_, err := e.svc.Reject(e.ctx(), oper, l[2].ID, "x", "forever")
	wantCode(t, err, 400, "invalid")
}

func TestContract_INV18_RuleRequestsAndEmptyReasonsLeaveNoHint(t *testing.T) {
	e, _ := newAIEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	l := e.actions()
	e.asAI(l[0].ID, plainAI) // l[1] stays a rule request
	e.reject(l[1], "rule request", "rule")
	e.reject(l[0], "   ", "rule")
	if h := e.hints(); len(h) != 0 {
		t.Fatalf("hints: %+v", h)
	}
}

func TestContract_INV18_HintsAreCappedAtFifty(t *testing.T) {
	e, _ := newAIEnv(t)
	for i := 0; i < 50; i++ {
		e.exec1(`INSERT INTO resp_hints (id, ts, kind, text, from_request) VALUES (?, ?, 'memory', ?, 'act-old')`,
			"hint-old"+twoDigits(i), "2026-11-01T10:00:"+twoDigits(i)+".000Z", "old "+twoDigits(i))
	}
	l := e.aiBlocks(2)
	e.reject(l[0], "newest one", "rule")
	e.clock.Advance(time.Second)
	e.reject(l[1], "newest two", "rule")
	h := e.hints()
	if len(h) != 50 || h[0].Text != "newest two" || h[1].Text != "newest one" {
		t.Fatalf("%d hints, first %+v", len(h), h[0])
	}
	if n := e.count(`SELECT count(*) FROM resp_hints WHERE text IN ('old 00', 'old 01')`); n != 0 {
		t.Fatal("the oldest hints were kept")
	}
	if n := e.count(`SELECT count(*) FROM resp_hints`); n != 50 {
		t.Fatalf("%d rows", n)
	}
}

func twoDigits(i int) string { return fmt.Sprintf("%02d", i) }

// ---- INV-15 (8): the quality breaker ----

func (e *env) paused() bool {
	e.t.Helper()
	s, err := e.svc.AIState(e.ctx())
	e.must(err)
	return s.Gates.PausedAt != nil
}

func TestContract_INV15_BreakerNeedsFiveDecisions(t *testing.T) {
	e, _ := newAIEnv(t)
	l := e.aiBlocks(5)
	for i := 0; i < 4; i++ {
		e.clock.Advance(time.Second)
		e.reject(l[i], "no", "none")
		if e.paused() {
			t.Fatalf("paused after %d of %d rejected", i+1, i+1)
		}
	}
	e.clock.Advance(time.Second)
	e.reject(l[4], "no", "none")
	if !e.paused() {
		t.Fatal("5 of 5 rejected did not pause the AI")
	}
}

func TestContract_INV15_BreakerLooksAtTheLastTenAndMoreThanHalf(t *testing.T) {
	e, _ := newAIEnv(t)
	l := e.aiBlocks(11)
	for i := 0; i < 5; i++ { // five approved
		e.clock.Advance(time.Second)
		if _, err := e.svc.Approve(e.ctx(), oper, l[i].ID, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := 5; i < 10; i++ { // then four rejected, then the fifth: 5 of 10 is not more than half
		e.clock.Advance(time.Second)
		e.reject(l[i], "no", "none")
		if e.paused() && i < 10 {
			t.Fatalf("paused at %d decisions", i+1)
		}
	}
	s, err := e.svc.AIState(e.ctx())
	e.must(err)
	if s.Quality.Decided != 10 || s.Quality.Rejected != 5 || s.Gates.PausedAt != nil {
		t.Fatalf("quality %+v paused %v", s.Quality, s.Gates.PausedAt)
	}
	e.clock.Advance(time.Second)
	e.reject(l[10], "no", "none") // the oldest approval leaves the window: 6 of 10
	s, err = e.svc.AIState(e.ctx())
	e.must(err)
	if s.Quality.Decided != 10 || s.Quality.Rejected != 6 || s.Gates.PausedAt == nil || s.Gates.PausedReason == nil || !strings.Contains(*s.Gates.PausedReason, "6 of the last 10") || !s.Quality.Paused {
		t.Fatalf("quality %+v gates %+v", s.Quality, s.Gates)
	}
	if !e.logHas("breaker", "quality breaker") {
		t.Fatal("no breaker line in the log")
	}
	if len(e.note.msgs) == 0 {
		t.Fatal("no notice went out")
	}
	// while paused, the gate 13b-10 puts in front of a proposal refuses
	wantCode(t, response.CheckAIPausedForTest(e.settings()), 409, "ai_paused")
}

func TestContract_INV15_ResumeClearsThePauseAndIsAudited(t *testing.T) {
	e, _ := newAIEnv(t)
	l := e.aiBlocks(5)
	for _, a := range l {
		e.clock.Advance(time.Second)
		e.reject(a, "no", "none")
	}
	if !e.paused() {
		t.Fatal("not paused")
	}
	s, err := e.svc.ResumeAI(e.ctx(), admin)
	e.must(err)
	if s.Gates.PausedAt != nil || s.Gates.PausedReason != nil || s.Quality.Paused {
		t.Fatalf("after resume: %+v", s)
	}
	if err := response.CheckAIPausedForTest(e.settings()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'response.ai_resume' AND "user" LIKE 'admin@acme.example%'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	if !e.logHas("settings", "resumed by admin@acme.example") {
		t.Fatal("no log line")
	}
	// the window still holds the five rejections, but the pause is not set again by a read; the next decision looks again
	if e.paused() {
		t.Fatal("paused again without a decision")
	}
}

func TestAIStateShape(t *testing.T) {
	e, _ := newAIEnv(t)
	s, err := e.svc.AIState(e.ctx())
	e.must(err)
	if s.MinConfidence != 0.8 || s.RepeatDays != 7 || s.Notes == nil || s.Hints == nil || s.Gates.BudgetHour != 2 || s.Usage.Day != 0 {
		t.Fatalf("%+v", s)
	}
	l := e.aiBlocks(2)
	_ = l
	s, err = e.svc.AIState(e.ctx())
	e.must(err)
	if s.Usage.Hour != 2 || s.Usage.Day != 2 {
		t.Fatalf("usage %+v", s.Usage)
	}
}

// inStepUp reports whether the clock is being read by aiStepUp (the check before the approval transaction).
func inStepUp() bool {
	pc := make([]uintptr, 64)
	fr := runtime.CallersFrames(pc[:runtime.Callers(2, pc)])
	for {
		f, more := fr.Next()
		if strings.HasSuffix(f.Function, ".aiStepUp") {
			return true
		}
		if !more {
			return false
		}
	}
}

// L1: aiStepUp skips the code when it sees the request past its expiry ("the transaction answers"), but the
// transaction reads the clock again and does not know the code was skipped. When the wall clock steps back between the
// two reads (NTP step, manual change, VM resume), the transaction finds the request still pending and records an
// approval of a high-risk AI request without any two-step code (fail open). The transaction should refuse an
// in_app_only request that did not pass the step-up, whatever the clock says.
func TestContract_INV16_ClockStepBackCannotSkipTheCode(t *testing.T) {
	f := &fakeTwoStep{off: map[string]bool{}}
	var late atomic.Pointer[time.Time]
	e := newEnv(t, func(c *response.Config) {
		base := c.Clock
		c.TwoStep = f
		c.Clock = func() time.Time {
			if l := late.Load(); l != nil && inStepUp() {
				return *l // aiStepUp reads the clock just after the expiry...
			}
			return base() // ...and the transaction reads it after a step back
		}
	})
	a := e.highRiskAI()
	exp, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	e.must(err)
	l := exp.Add(time.Second)
	late.Store(&l)
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "") // no code at all
	late.Store(nil)
	got := e.only()
	if err == nil || len(got.Approvals) != 0 {
		t.Fatalf("a high-risk AI request took an approval without a two-step code (err=%v, approvals=%d, code checks=%d)", err, len(got.Approvals), f.count())
	}
}

type acceptAll struct{ n atomic.Int32 }

func (a *acceptAll) Verify(context.Context, string, string, string, string) error {
	a.n.Add(1)
	return nil
}

// The same person clicking approve many times at once, each with a code that passes (e.g. the codes of two adjacent TOTP
// steps): the transaction re-checks same_approver, so one person never counts twice.
func TestContract_INV16_SamePersonRaceCountsOnce(t *testing.T) {
	ok := &acceptAll{}
	e := newEnv(t, func(c *response.Config) { c.TwoStep = ok })
	a := e.highRiskAI()
	var wg sync.WaitGroup
	var wins atomic.Int32
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.Approve(context.Background(), oper, a.ID, nil, "123456"); err == nil {
				wins.Add(1)
			} else if ae, isAPI := apierr.As(err); !isAPI || ae.Code != "same_approver" {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected refusal: %v", err)
	}
	got := e.only()
	if wins.Load() != 1 || len(got.Approvals) != 1 || got.Status != response.StatusPending {
		t.Fatalf("one person counted %d times (approvals %d, status %s)", wins.Load(), len(got.Approvals), got.Status)
	}
}

// Two different people racing each other: both count once, the bundle runs once.
func TestContract_INV16_TwoPeopleRaceEachCountsOnce(t *testing.T) {
	for range 3 {
		ok := &acceptAll{}
		e := newEnv(t, func(c *response.Config) { c.TwoStep = ok })
		a := e.highRiskAI()
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, w := range []response.Actor{oper, admin} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.svc.Approve(context.Background(), w, a.ID, nil, "123456")
			}()
		}
		wg.Wait()
		got := e.only()
		if errs[0] != nil || errs[1] != nil || len(got.Approvals) != 2 || got.Approvals[0].UserID == got.Approvals[1].UserID || got.Status != response.StatusExecuted || ok.n.Load() != 2 {
			t.Fatalf("race: errs=%v approvals=%+v status=%s checks=%d", errs, got.Approvals, got.Status, ok.n.Load())
		}
	}
}

// L2: the line sent with the code puts the asset name (a device name from an event, an inventory hostname, or the
// name the AI planner wrote, plans.go) inside the sentence without quoting it, so a hostile name can state a risk the
// request does not have: "AI request: ... on FW-01, risk low, risk high".
func TestContract_INV16_SummaryRiskCannotBeSpoofedByTheAssetName(t *testing.T) {
	e, _ := newAIEnv(t)
	a := e.highRiskAI()
	e.exec1(`UPDATE resp_actions SET asset_name = ? WHERE id = ?`, "FW-01, risk low", a.ID)
	got, err := e.svc.ApproveSummaryForTest(e.ctx(), a.ID)
	e.must(err)
	if !strings.HasPrefix(got, "High-risk AI request: ") || !strings.HasSuffix(got, ` on "FW-01, risk low"`) || strings.Count(got, "-risk") != 1 {
		t.Fatalf("the summary of a high-risk request says %q", got)
	}
}

// L3: a rejection reason kept as a hint keeps invisible format characters (bidi overrides, Unicode tag
// characters that a person cannot see but a model reads), unlike the summary, which strips them. Hints are shown as
// advice and "memory" hints are meant for the AI later (13b-10, WP-25).
func TestContract_INV18_HintAndRejectNoteHaveNoInvisibleCharacters(t *testing.T) {
	e, _ := newAIEnv(t)
	l := e.aiBlocks(1)
	smuggled := "Our scanner \u202eRENNACS\u202c" + "\U000E0049\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065" + " uses this address"
	e.reject(l[0], smuggled, "memory")
	h := e.hints()
	if len(h) != 1 {
		t.Fatalf("%d hints", len(h))
	}
	note := e.only().Note
	for _, text := range []string{h[0].Text, *note} {
		for _, c := range text {
			if unicode.Is(unicode.Cf, c) || unicode.IsControl(c) || (c >= 0xE0000 && c <= 0xE007F) {
				t.Fatalf("the invisible character %U was kept: %q", c, text)
			}
		}
	}
	if h[0].Text != "Our scanner RENNACS uses this address" {
		t.Fatalf("hint %q", h[0].Text)
	}
}

// A demoted or disabled approver does not count: the account is read again inside the approval, for every in-app approval.
func TestContract_Approve_DemotedOrDisabledApproverDoesNotCount(t *testing.T) {
	e, _ := newAIEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	e.users.m["u-op"] = response.User{ID: "u-op", Name: "IT Operator", Email: "it@acme.example", Role: "viewer", TwoStep: true}
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 403, "forbidden")
	e.users.m["u-op"] = response.User{ID: "u-op", Name: "IT Operator", Email: "it@acme.example", Role: "operator", Disabled: true}
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 403, "forbidden")
	delete(e.users.m, "u-op")
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 403, "forbidden")
	if got := e.only(); len(got.Approvals) != 0 || got.Status != response.StatusPending {
		t.Fatalf("a refused approver counted: %+v", got)
	}
	e.users.m["u-op"] = response.User{ID: "u-op", Name: "IT Operator", Email: "it@acme.example", Role: "operator", TwoStep: true}
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
}

// The line shows only the actions this approver picked.
func TestContract_INV16_SummaryListsOnlyThePickedActions(t *testing.T) {
	e, f := newAIEnv(t)
	a := e.highRiskAI()
	dev := a.Items[0]
	f.give(oper.ID, purposeOf(a.ID), "111111")
	if _, err := e.svc.Approve(e.ctx(), oper, a.ID, []string{dev.ID}, "111111"); err != nil {
		t.Fatal(err)
	}
	got := f.calls[0].summary
	if !strings.Contains(got, `"`+dev.Title+`"`) || strings.Contains(got, a.Items[1].Title) {
		t.Fatalf("summary %q", got)
	}
}

// A resume clears the pause and nothing else: the window of the last 10 decisions stays (the mock's `resume` does the same), so the
// next decision on an AI request looks at it again. Contract note in INV-15 (8).
func TestContract_INV15_ResumeKeepsTheWindowAndTheNextDecisionLooksAgain(t *testing.T) {
	e, _ := newAIEnv(t)
	l := e.aiBlocks(6)
	for _, a := range l[:5] {
		e.clock.Advance(time.Second)
		e.reject(a, "no", "none")
	}
	_, err := e.svc.ResumeAI(e.ctx(), admin)
	e.must(err)
	if e.paused() {
		t.Fatal("still paused after resume")
	}
	e.clock.Advance(time.Second)
	if _, err := e.svc.Approve(e.ctx(), oper, l[5].ID, nil, ""); err != nil { // 5 of 6 rejected: still more than half
		t.Fatal(err)
	}
	if !e.paused() {
		t.Fatal("the next decision did not look at the window again")
	}
}

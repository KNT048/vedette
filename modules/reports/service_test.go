package reports

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

func (e *env) seed() {
	in := sampleInput()
	e.inv.devs, e.fnd.fs, e.kev.es, e.kev.at = in.devices, in.findings, in.kev, in.kevAt
}

func (e *env) saveSchedule(enabled bool, to ...string) {
	e.t.Helper()
	_, err := e.svc.SaveSchedule(e.ctx(), "admin@acme.example", ScheduleInput{Enabled: enabled, Day: 1, Hour: 8, Recipients: to})
	mustNoErr(e.t, err)
}

func apiCode(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func TestCleanInstallSchedule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s, err := e.svc.Schedule(e.ctx())
	mustNoErr(t, err)
	if s.Enabled || len(s.Recipients) != 0 || s.NextRun != nil || s.Day != 1 || s.Hour != 8 {
		t.Fatalf("a clean install sends nothing: %+v", s)
	}
}

func TestSaveScheduleRoundTripAuditsAndNextRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	got, err := e.svc.SaveSchedule(e.ctx(), "admin@acme.example", ScheduleInput{Enabled: true, Day: 1, Hour: 8, Recipients: []string{"Boss@acme.example"}})
	mustNoErr(t, err)
	if got.NextRun == nil || *got.NextRun != "2026-11-16T08:00:00.000Z" {
		t.Fatalf("next run = %v", got.NextRun)
	}
	again, _ := e.svc.Schedule(e.ctx())
	if !again.Enabled || again.Recipients[0] != "boss@acme.example" {
		t.Fatalf("stored = %+v", again)
	}
	if !slices.Equal(e.auditActions(), []string{"report.schedule"}) { // INV-10
		t.Fatalf("audit = %v", e.auditActions())
	}
	if _, err := e.svc.SaveSchedule(e.ctx(), "admin@acme.example", ScheduleInput{Enabled: true, Day: 9, Hour: 8}); apiCode(err) != "invalid_day" {
		t.Fatalf("err = %v", err)
	}
	if n := len(e.auditActions()); n != 1 {
		t.Fatal("a refused save must not be audited as a change")
	}
}

func TestSendNowPreconditions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	if _, err := e.svc.SendNow(e.ctx(), "op@acme.example"); apiCode(err) != "no_recipients" {
		t.Fatalf("no recipients: %v", err)
	}
	e.saveSchedule(false, "a@acme.example")
	e.mail.ready = false
	if _, err := e.svc.SendNow(e.ctx(), "op@acme.example"); apiCode(err) != "email_not_ready" {
		t.Fatalf("email not ready: %v", err)
	}
	if e.mail.count() != 0 || e.count(`SELECT count(*) FROM rep_history`) != 0 {
		t.Fatal("nothing is sent or recorded when a precondition fails (PRE-1)")
	}
}

func TestSendNowSendsToSavedRecipientsAndKeepsTheFigures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(false, "a@acme.example", "b@acme.example")
	h, err := e.svc.SendNow(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if h.Status != "sent" || h.Trigger != "manual" || len(h.Recipients) != 2 {
		t.Fatalf("history item = %+v", h)
	}
	if e.mail.count() != 1 || !slices.Equal(e.mail.sent[0].to, []string{"a@acme.example", "b@acme.example"}) { // FORBID-2
		t.Fatalf("sent = %+v", e.mail.sent)
	}
	m := e.mail.sent[0].m
	if !strings.Contains(m.Title, "4 things to do this week, 2 open findings") || m.Path != "/reports" || len(m.Items) == 0 || !strings.HasPrefix(m.Action, "Update Microsoft Windows on pc-old") {
		t.Fatalf("mail = %+v", m)
	}
	// The report of that week is frozen: change the data and read the old entry back (INV-2).
	e.fnd.fs = nil
	e.clock.Advance(48 * time.Hour)
	old, err := e.svc.HistoryEntry(e.ctx(), h.ID)
	mustNoErr(t, err)
	if old.Report.Counts.NewFindings != 1 || old.Report.GeneratedAt != ts(t0) {
		t.Fatalf("stored report changed: %+v", old.Report.Counts)
	}
	list, err := e.svc.History(e.ctx())
	mustNoErr(t, err)
	if len(list) != 1 || list[0].ID != h.ID {
		t.Fatalf("history = %+v", list)
	}
	if !slices.Equal(e.auditActions(), []string{"report.schedule", "report.send"}) {
		t.Fatalf("audit = %v", e.auditActions())
	}
}

func TestSendFailureIsRecordedWithAFixedMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(false, "a@acme.example")
	e.mail.err = errors.New("535 5.7.8 password hunter2 rejected by smtp.internal.example")
	h, err := e.svc.SendNow(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if h.Status != "failed" || h.Error != errSendFail || strings.Contains(h.Error, "hunter2") {
		t.Fatalf("failed item = %+v", h)
	}
	if e.count(`SELECT count(*) FROM rep_history WHERE status = 'failed'`) != 1 {
		t.Fatal("a failed attempt is in the history (POST-1)")
	}
}

func TestHistoryEntryNotFound(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.HistoryEntry(e.ctx(), "nope"); apiCode(err) != "not_found" {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryIsPruned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(false, "a@acme.example")
	for i := 0; i < MaxHistory+3; i++ {
		e.clock.Advance(time.Minute)
		_, err := e.svc.SendNow(e.ctx(), "op@acme.example")
		mustNoErr(t, err)
	}
	if n := e.count(`SELECT count(*) FROM rep_history`); n != MaxHistory {
		t.Fatalf("history rows = %d, want %d", n, MaxHistory)
	}
}

func TestRunScheduleSendsOncePerSlot(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(true, "a@acme.example") // Monday 08:00; now is Wednesday
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 0 {
		t.Fatal("saving a schedule must not send for a slot that already passed")
	}
	e.clock.now = time.Date(2026, 11, 16, 8, 0, 30, 0, time.UTC) // next Monday, just after 08:00
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	e.clock.Advance(10 * time.Minute)
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 1 {
		t.Fatalf("sent %d times for one slot", e.mail.count())
	}
	h, _ := e.svc.History(e.ctx())
	if len(h) != 1 || h[0].Trigger != "scheduled" {
		t.Fatalf("history = %+v", h)
	}
	e.clock.now = time.Date(2026, 11, 23, 8, 5, 0, 0, time.UTC)
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 2 {
		t.Fatal("the next week's slot is sent")
	}
}

func TestRunScheduleCatchUpWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(true, "a@acme.example")
	e.clock.now = time.Date(2026, 11, 16, 20, 0, 0, 0, time.UTC) // box was off at 08:00, back 12 hours later
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 1 {
		t.Fatal("a slot missed by 12 hours is sent once, late (POST-2)")
	}
	e.clock.now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) // off for more than a day past the next slot
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 1 {
		t.Fatal("a report that would be days late is skipped, not sent")
	}
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 1 {
		t.Fatal("a skipped slot is not retried")
	}
}

func TestRunScheduleOffOrNotReady(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(false, "a@acme.example")
	e.clock.now = time.Date(2026, 11, 16, 8, 1, 0, 0, time.UTC)
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 0 {
		t.Fatal("a schedule that is off sends nothing")
	}
	e.saveSchedule(true, "a@acme.example")
	e.clock.now = time.Date(2026, 11, 23, 8, 1, 0, 0, time.UTC)
	e.mail.ready = false
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	h, _ := e.svc.History(e.ctx())
	if len(h) != 1 || h[0].Status != "failed" || h[0].Error != errNotReady {
		t.Fatalf("a scheduled send with no email channel is a failed history row: %+v", h)
	}
}

func TestWeeklyAIIsStoredAndAttachedOnlyWhenFresh(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	p, err := e.svc.Preview(e.ctx())
	mustNoErr(t, err)
	if !p.AIAvailable || p.Report.AISummary != nil {
		t.Fatalf("preview = %+v", p)
	}
	sum, err := e.svc.WeeklyAI(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if sum.Model != "m" || sum.Tokens.Input != 10 || sum.GeneratedAt != ts(t0) {
		t.Fatalf("summary = %+v", sum)
	}
	p, _ = e.svc.Preview(e.ctx())
	if p.Report.AISummary == nil || p.Report.AISummary.Paragraphs[0] != "Commentary." {
		t.Fatal("the preview carries the stored commentary")
	}
	if p.Report.Counts.NewFindings != 1 {
		t.Fatal("the commentary never changes a figure (INV-5)")
	}
	e.clock.Advance(8 * 24 * time.Hour)
	p, _ = e.svc.Preview(e.ctx())
	if p.Report.AISummary != nil {
		t.Fatal("a commentary older than the report week must not be attached to a new report")
	}
	if len(e.ai.data) != 1 || strings.Contains(e.ai.data[0][0].Text, "10.0.0") {
		t.Fatal("device IPs are not part of the weekly prompt")
	}
}

func TestAIUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.ai.on = false
	if _, err := e.svc.WeeklyAI(e.ctx(), "op@acme.example"); apiCode(err) != "ai_unavailable" {
		t.Fatalf("err = %v", err)
	}
	p, err := e.svc.Preview(e.ctx())
	mustNoErr(t, err)
	if p.AIAvailable || p.Report.Counts.Devices != 3 {
		t.Fatalf("without AI the report is complete and ai_available is false (INV-5): %+v", p)
	}
	e.ai.on = true
	e.ai.err = apierr.New(429, "budget_reached", "cap")
	if _, err := e.svc.WeeklyAI(e.ctx(), "op@acme.example"); apiCode(err) != "budget_reached" {
		t.Fatalf("AI errors pass through: %v", err)
	}
	if e.count(`SELECT count(*) FROM rep_weekly_ai`) != 0 {
		t.Fatal("nothing is stored when the AI fails")
	}
}

func TestPdplFlow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	st, err := e.svc.Pdpl(e.ctx())
	mustNoErr(t, err)
	if st.Org != nil || st.Report != nil || st.Defaults.Name != "Acme Ltd" || !st.AIAvailable {
		t.Fatalf("clean state = %+v", st)
	}
	if _, err := e.svc.GeneratePdpl(e.ctx(), "op@acme.example"); apiCode(err) != "org_required" { // PRE-3
		t.Fatalf("err = %v", err)
	}
	if _, err := e.svc.PdplAI(e.ctx(), "op@acme.example"); apiCode(err) != "report_required" {
		t.Fatalf("err = %v", err)
	}
	bad := okOrg()
	bad.Name = ""
	if _, err := e.svc.SavePdplOrg(e.ctx(), "op@acme.example", bad); apiCode(err) != "invalid_name" {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.svc.SavePdplOrg(e.ctx(), "op@acme.example", okOrg()); err != nil {
		t.Fatal(err)
	}
	rep, err := e.svc.GeneratePdpl(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if rep.Inventory.Total != 3 || rep.GeneratedAt != ts(t0) || rep.Org.Name != "Acme Ltd" {
		t.Fatalf("report = %+v", rep)
	}
	sum, err := e.svc.PdplAI(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	st, _ = e.svc.Pdpl(e.ctx())
	if st.Report == nil || st.Report.AISummary == nil || st.Report.AISummary.GeneratedAt != sum.GeneratedAt || st.Report.ID != rep.ID {
		t.Fatalf("stored = %+v", st.Report)
	}
	// The organisation's name, tax code, address and contact person never go to the AI (D-238).
	prompt := e.ai.data[len(e.ai.data)-1][0].Text
	for _, secret := range []string{"Acme", "0312345678", "Main Street", "An Nguyen", "an@acme.example", "0901234567"} {
		if strings.Contains(prompt, secret) {
			t.Fatalf("AI prompt leaks %q:\n%s", secret, prompt)
		}
	}
	// A new report replaces the old one together with its commentary.
	rep2, err := e.svc.GeneratePdpl(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	st, _ = e.svc.Pdpl(e.ctx())
	if st.Report.ID != rep2.ID || st.Report.AISummary != nil {
		t.Fatalf("regenerated = %+v", st.Report)
	}
	want := []string{"report.pdpl_org", "report.pdpl_generate", "report.ai_summary", "report.pdpl_generate"}
	if !slices.Equal(e.auditActions(), want) {
		t.Fatalf("audit = %v, want %v", e.auditActions(), want)
	}
}

func TestSavingOrgKeepsTheGeneratedReport(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	_, err := e.svc.SavePdplOrg(e.ctx(), "op@acme.example", okOrg())
	mustNoErr(t, err)
	rep, err := e.svc.GeneratePdpl(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	o := okOrg()
	o.Employees = 99
	_, err = e.svc.SavePdplOrg(e.ctx(), "op@acme.example", o)
	mustNoErr(t, err)
	st, _ := e.svc.Pdpl(e.ctx())
	if st.Report == nil || st.Report.ID != rep.ID || st.Report.Org.Employees != 12 || st.Org.Employees != 99 {
		t.Fatalf("the report keeps the details it was made with: %+v", st)
	}
}

func TestNewServiceRequiresItsPorts(t *testing.T) {
	t.Parallel()
	if _, err := NewService(Config{}); err == nil {
		t.Fatal("NewService must refuse a config without its ports")
	}
}

func TestScheduledSendUsesTheRecipientsOfNowAndAFailedBuildIsRecorded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveSchedule(true, "a@acme.example", "gone@acme.example")
	e.clock.now = time.Date(2026, 11, 16, 8, 0, 30, 0, time.UTC)
	// A save that removed an address and re-armed the schedule after the slot: the old slot is dropped, nothing is mailed.
	e.saveSchedule(true, "a@acme.example")
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 0 {
		t.Fatal("a slot from before the last save was sent")
	}
	e.clock.now = time.Date(2026, 11, 23, 8, 0, 30, 0, time.UTC)
	e.fnd.err = errBoom
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	h, _ := e.svc.History(e.ctx())
	if len(h) != 1 || h[0].Status != "failed" || h[0].Error != errBuild || e.mail.count() != 0 {
		t.Fatalf("a report that cannot be built is a failed history row, not a lost slot: %+v", h)
	}
	if len(h[0].Recipients) != 1 || h[0].Recipients[0] != "a@acme.example" {
		t.Fatalf("recipients = %v", h[0].Recipients)
	}
}

func TestZoneChangeDoesNotSendTwice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	zone := "Asia/Ho_Chi_Minh"
	e.svc.cfg.Zone = func(context.Context) string { return zone }
	e.saveSchedule(true, "a@acme.example")
	e.clock.now = time.Date(2026, 11, 16, 1, 0, 30, 0, time.UTC) // Monday 08:00 in Ho Chi Minh
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 1 {
		t.Fatalf("sent %d", e.mail.count())
	}
	zone = "UTC"
	e.clock.now = time.Date(2026, 11, 16, 8, 0, 30, 0, time.UTC) // Monday 08:00 in the new zone
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	mustNoErr(t, e.svc.RunSchedule(e.ctx()))
	if e.mail.count() != 1 {
		t.Fatalf("a time zone change sent the same week twice: %d", e.mail.count())
	}
}

func TestWeeklyAIPromptHasNoDeviceNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	_, err := e.svc.WeeklyAI(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	txt := e.ai.data[0][0].Text
	for _, leak := range []string{"pc-old", "srv", "fw-01", "10.0.0"} {
		if strings.Contains(txt, leak) {
			t.Fatalf("weekly prompt names a device (%q):\n%s", leak, txt)
		}
	}
}

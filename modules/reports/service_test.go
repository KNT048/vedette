package reports

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
)

func apiCode(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// A clean install has the default definition: every section, the last 7 days, no recipient, so it sends nothing.
func TestCleanInstallDefinition(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d, err := e.svc.Definition(e.ctx())
	mustNoErr(t, err)
	if d.ID != DefinitionID || d.ScheduleKey != "reports.def:security" || len(d.Recipients) != 0 || d.Options != DefaultOptions {
		t.Fatalf("clean definition = %+v", d)
	}
	if e.count(`SELECT count(*) FROM rep_definition`) != 0 {
		t.Fatal("reading the definition writes nothing")
	}
}

func TestSaveDefinitionRoundTripAndAudit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	o := DefaultOptions
	o.Period, o.Grouping, o.Charts = PeriodLast30, groupCVE, false
	got, err := e.svc.SaveDefinition(e.ctx(), "admin@acme.example", DefinitionInput{Name: "  Monthly security  ", Options: o, Recipients: []string{" Boss@Acme.example ", "boss@acme.example", "it@acme.example"}})
	mustNoErr(t, err)
	if got.Name != "Monthly security" || !slices.Equal(got.Recipients, []string{"boss@acme.example", "it@acme.example"}) || got.UpdatedBy != "admin@acme.example" || got.UpdatedAt != ts(t0) {
		t.Fatalf("saved = %+v", got)
	}
	again, err := e.svc.Definition(e.ctx())
	mustNoErr(t, err)
	if again.Name != got.Name || again.Options != o || !slices.Equal(again.Recipients, got.Recipients) {
		t.Fatalf("read back = %+v", again)
	}
	if !slices.Equal(e.auditActions(), []string{"report.definition"}) {
		t.Fatalf("audit = %v", e.auditActions())
	}
}

func TestSendNowPreconditions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	if _, err := e.svc.SendNow(e.ctx(), "op@acme.example"); apiCode(err) != "no_recipients" { // PRE-1
		t.Fatalf("err = %v", err)
	}
	e.saveRecipients("boss@acme.example")
	e.mail.ready = false
	if _, err := e.svc.SendNow(e.ctx(), "op@acme.example"); apiCode(err) != "email_not_ready" {
		t.Fatalf("err = %v", err)
	}
	if e.count(`SELECT count(*) FROM rep_history`) != 0 || e.mail.count() != 0 {
		t.Fatal("a refused send writes no history and mails nothing")
	}
}

// A send mails exactly the saved recipients and keeps the document exactly as sent: changing the options later does not change it.
func TestSendNowKeepsTheDocumentAsSent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveRecipients("boss@acme.example", "it@acme.example")
	item, err := e.svc.SendNow(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if item.Status != "sent" || item.Trigger != "manual" || item.SentBy == nil || *item.SentBy != "op@acme.example" || item.Error != nil {
		t.Fatalf("item = %+v", item)
	}
	if e.mail.count() != 1 || !slices.Equal(e.mail.sent[0].to, []string{"boss@acme.example", "it@acme.example"}) || e.mail.sent[0].m.Path != "/reports/sent/"+item.ID {
		t.Fatalf("mail = %+v", e.mail.sent)
	}
	before, err := e.svc.Sent(e.ctx(), item.ID)
	mustNoErr(t, err)
	d, _ := e.svc.Definition(e.ctx())
	o := d.Options
	o.Period = PeriodLast30
	_, err = e.svc.SaveDefinition(e.ctx(), "admin@acme.example", DefinitionInput{Name: d.Name, Options: o, Recipients: d.Recipients})
	mustNoErr(t, err)
	e.views.vs = nil
	after, err := e.svc.Sent(e.ctx(), item.ID)
	mustNoErr(t, err)
	if after.Document.Period.Kind != PeriodLast7 || after.Document.Summary.Handled != before.Document.Summary.Handled || after.Document.Summary.Handled != 3 {
		t.Fatalf("the sent document changed: %+v", after.Document.Summary)
	}
	list, err := e.svc.History(e.ctx())
	mustNoErr(t, err)
	if len(list) != 1 || list[0].ID != item.ID || list[0].Title != "Security report" || list[0].Period.From != before.Document.Period.From {
		t.Fatalf("history = %+v", list)
	}
	if _, err := e.svc.Sent(e.ctx(), "missing"); apiCode(err) != "not_found" {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(e.auditActions(), []string{"report.definition", "report.send", "report.definition"}) {
		t.Fatalf("audit = %v", e.auditActions())
	}
}

func TestSendFailuresAreRecordedWithAFixedMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.saveRecipients("boss@acme.example")
	e.mail.err = errors.New("smtp 550 secret detail")
	item, err := e.svc.SendNow(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if item.Status != "failed" || item.Error == nil || *item.Error != errSendFail {
		t.Fatalf("item = %+v", item)
	}
	e.mail.err = nil
	e.views.err = errBoom // the document cannot be made: nothing is mailed, the attempt is recorded
	item, err = e.svc.send(e.ctx(), triggerSched, "")
	mustNoErr(t, err)
	if item.Status != "failed" || *item.Error != errBuild || item.SentBy != nil || item.Trigger != "schedule" || e.mail.count() != 0 {
		t.Fatalf("item = %+v", item)
	}
	sent, err := e.svc.Sent(e.ctx(), item.ID)
	mustNoErr(t, err)
	if sent.Document.Summary != nil || sent.Document.Period.Kind != PeriodLast7 {
		t.Fatalf("a failed document = %+v", sent.Document)
	}
}

func TestHistoryIsPruned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.saveRecipients("boss@acme.example")
	for range MaxHistory + 3 {
		_, err := e.svc.SendNow(e.ctx(), "op@acme.example")
		mustNoErr(t, err)
		e.clock.Advance(time.Minute)
	}
	if n := e.count(`SELECT count(*) FROM rep_history`); n != MaxHistory {
		t.Fatalf("history = %d", n)
	}
}

// The schedule's start marks the definition inside the schedule's transaction; the job mails it once, and a due time found more than
// a day late is dropped (POST-2). With no recipient or no email channel the schedule skips and says why.
func TestScheduleStartAndTheSendJob(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	fire := func(f schedule.Fire) error {
		return e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			_, err := e.svc.startSend(e.ctx(), tx, f)
			return err
		})
	}
	due := schedule.Fire{OwnerKey: ScheduleKey(DefinitionID), Subject: DefinitionID, Trigger: run.Schedule, By: run.System, DueAt: t0}
	var skip *schedule.SkipError
	if err := fire(due); !errors.As(err, &skip) || !strings.Contains(skip.Reason, "no recipient") {
		t.Fatalf("no recipient: %v", err)
	}
	e.saveRecipients("boss@acme.example")
	e.mail.ready = false
	if err := fire(due); !errors.As(err, &skip) || !strings.Contains(skip.Reason, "email channel") {
		t.Fatalf("email not ready: %v", err)
	}
	e.mail.ready = true
	mustNoErr(t, fire(due))
	mustNoErr(t, e.svc.RunPending(e.ctx()))
	mustNoErr(t, e.svc.RunPending(e.ctx())) // the mark was cleared: no second send
	list, _ := e.svc.History(e.ctx())
	if e.mail.count() != 1 || len(list) != 1 || list[0].Trigger != "schedule" || list[0].SentBy != nil {
		t.Fatalf("sends = %d, history = %+v", e.mail.count(), list)
	}
	// "Run once now" by a person: sent under their name
	e.clock.Advance(time.Minute)
	mustNoErr(t, fire(schedule.Fire{OwnerKey: due.OwnerKey, Subject: DefinitionID, Trigger: run.Manual, By: "admin@acme.example", DueAt: t0}))
	mustNoErr(t, e.svc.RunPending(e.ctx()))
	list, _ = e.svc.History(e.ctx())
	if len(list) != 2 || list[0].Trigger != "manual" || *list[0].SentBy != "admin@acme.example" {
		t.Fatalf("history = %+v", list)
	}
	// a due time marked while the box was off for two days
	mustNoErr(t, fire(due))
	e.clock.Advance(48 * time.Hour)
	mustNoErr(t, e.svc.RunPending(e.ctx()))
	if e.mail.count() != 2 || e.count(`SELECT count(*) FROM rep_definition WHERE send_due_at IS NOT NULL`) != 0 {
		t.Fatalf("a late due time: %d sends", e.mail.count())
	}
}

func TestScheduleOwnerRegisters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sch, err := schedule.New(schedule.Config{DB: e.db, Log: e.svc.cfg.Log, Clock: e.clock.Now})
	mustNoErr(t, err)
	mustNoErr(t, sch.Register(e.svc.ScheduleOwner()))
	v, err := sch.Get(e.ctx(), ScheduleKey(DefinitionID))
	mustNoErr(t, err)
	if v.Saved || v.Enabled || v.EditRole != "admin" {
		t.Fatalf("schedule = %+v", v)
	}
	if _, err := sch.Get(e.ctx(), ScheduleKey("other")); err == nil {
		t.Fatal("a definition that does not exist has no schedule")
	}
}

func TestPdplAIUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	e.ai.on = false
	_, err := e.svc.SavePdplOrg(e.ctx(), "op@acme.example", okOrg())
	mustNoErr(t, err)
	_, err = e.svc.GeneratePdpl(e.ctx(), "op@acme.example")
	mustNoErr(t, err)
	if _, err := e.svc.PdplAI(e.ctx(), "op@acme.example"); apiCode(err) != "ai_unavailable" {
		t.Fatalf("err = %v", err)
	}
	e.ai.on = true
	e.ai.err = apierr.New(429, "budget_reached", "cap")
	if _, err := e.svc.PdplAI(e.ctx(), "op@acme.example"); apiCode(err) != "budget_reached" {
		t.Fatalf("AI errors pass through: %v", err)
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
	// The organisation's name, tax code, address and contact person never go to the AI.
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

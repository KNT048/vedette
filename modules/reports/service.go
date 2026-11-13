package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Job names of the ai module (CONTRACT INV-5).
const (
	jobWeekly = "weekly-report"
	jobPdpl   = "pdpl-assessment"
)

// MaxHistory is how many sent reports are kept; older ones are removed when a new one is recorded.
const MaxHistory = 52

// Config is what NewService needs. Mail, AI, Modules, OrgName, Zone and Clock may be nil.
type Config struct {
	DB        *store.DB
	Audit     *audit.Log
	Inventory Inventory
	Findings  Findings
	KEV       KEV
	Mail      Mailer
	AI        AI
	Modules   Modules
	OrgName   func(context.Context) (string, error)
	Zone      func(context.Context) string // IANA name of the box time zone; "" or an unknown name = UTC
	Log       *slog.Logger
	Clock     func() time.Time
}

// Service owns the rep_ tables. Every mutation runs in one transaction with its core_audit row (SYS-3).
type Service struct {
	cfg Config
	now func() time.Time

	sendMu sync.Mutex // one send at a time: the job and a person's click must not mail the same report twice
}

// NewService returns the service. DB, Audit, Inventory, Findings, KEV and Log are required.
func NewService(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Inventory == nil || cfg.Findings == nil || cfg.KEV == nil || cfg.Log == nil {
		return nil, errors.New("reports: creating service: DB, Audit, Inventory, Findings, KEV and Log are required")
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Service{cfg: cfg, now: now}, nil
}

func (s *Service) clock() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

func (s *Service) loc(ctx context.Context) *time.Location {
	if s.cfg.Zone != nil {
		if name := s.cfg.Zone(ctx); name != "" {
			if l, err := time.LoadLocation(name); err == nil {
				return l
			}
		}
	}
	return time.UTC
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, user, action, target, detail string) error {
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: action, Target: target, Detail: detail})
}

// ---- weekly report ----

func (s *Service) weeklyInput(ctx context.Context, now time.Time) (weeklyInput, error) {
	devs, err := s.cfg.Inventory.Devices(ctx)
	if err != nil {
		return weeklyInput{}, fmt.Errorf("reports: reading devices: %w", err)
	}
	fs, err := s.cfg.Findings.All(ctx)
	if err != nil {
		return weeklyInput{}, fmt.Errorf("reports: reading findings: %w", err)
	}
	kev, at, err := s.cfg.KEV.Entries(ctx)
	if err != nil {
		return weeklyInput{}, fmt.Errorf("reports: reading the exploited list: %w", err)
	}
	kevNew, kevInUse, err := s.cfg.KEV.NewlyExploited(ctx)
	if err != nil {
		return weeklyInput{}, fmt.Errorf("reports: reading the exploited list: %w", err)
	}
	return weeklyInput{devices: devs, findings: fs, kev: kev, kevAt: at, kevNew: kevNew, kevInUse: kevInUse, now: now}, nil
}

// Weekly computes the report now (INV-1) and attaches the last AI commentary when it is from this week.
func (s *Service) Weekly(ctx context.Context) (WeeklyReport, error) {
	in, err := s.weeklyInput(ctx, s.clock())
	if err != nil {
		return WeeklyReport{}, err
	}
	r := buildWeekly(in)
	sum, err := s.loadWeeklyAI(ctx)
	if err != nil {
		return WeeklyReport{}, err
	}
	if sum != nil && sum.GeneratedAt > r.Period.From {
		r.AISummary = sum
	}
	return r, nil
}

// Preview is GET /reports/weekly/preview.
func (s *Service) Preview(ctx context.Context) (WeeklyPreview, error) {
	r, err := s.Weekly(ctx)
	if err != nil {
		return WeeklyPreview{}, err
	}
	return WeeklyPreview{Report: r, AIAvailable: s.aiOn(jobWeekly)}, nil
}

func (s *Service) aiOn(job string) bool { return s.cfg.AI != nil && s.cfg.AI.Available(job) }

func errAIUnavailable() *apierr.Error {
	return apierr.New(409, "ai_unavailable", "The AI assistant is off or no AI profile is assigned to this task. An administrator can turn it on or assign one in Settings, AI assistant.")
}

func (s *Service) loadWeeklyAI(ctx context.Context) (*AiSummary, error) {
	var raw string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT summary FROM rep_weekly_ai WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reports: reading the AI commentary: %w", err)
	}
	var out AiSummary
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("reports: reading the AI commentary: %w", err)
	}
	return &out, nil
}

func weeklyFacts(r WeeklyReport) string {
	var b strings.Builder
	c := r.Counts
	fmt.Fprintf(&b, "Period: %s to %s\nNew findings: %d\nResolved: %d\nOpen confirmed: %d\nOpen suspected: %d\nDevices: %d (%d not approved, %d new)\nNewly exploited in the last 7 days: %d, products in use among them: %d\n",
		r.Period.From, r.Period.To, c.NewFindings, c.Resolved, c.OpenConfirmed, c.OpenSuspected, c.Devices, c.DevicesUnapprove, c.DevicesNew, c.KevNew, c.KevMatched)
	b.WriteString("Top risks (product, number of devices, open findings, confirmed by a scan, worst severity):\n")
	for _, r := range r.TopRisks { // no device names in the prompt
		fmt.Fprintf(&b, "- %s | %d | %d | %d | %s\n", r.Product, r.Devices, r.Open, r.Confirmed, r.Severity)
	}
	b.WriteString("Open findings (CVE, product, status, severity):\n")
	for i, f := range r.Open {
		if i == 20 {
			break
		}
		fmt.Fprintf(&b, "- %s | %s | %s | %s\n", f.CVE, f.Product, f.Status, f.Severity)
	}
	return b.String()
}

const weeklyTask = `Write a short commentary on one week of a small company's network security report. Use only the figures and findings in the data block. Write at most 3 short paragraphs of plain English: what changed this week, what to do first, and what is still open. Never change or invent a figure, a CVE or a device. Reply with one JSON object only.`

const pdplTask = `Write a short commentary on a personal-data-protection self-assessment of a small company's network. Use only the facts in the data block, which are what the Vedette box could see. Write at most 3 short paragraphs of plain English: what the technical picture shows, which weaknesses to close first, and that duties about dossiers, procedures and contracts are outside what the box can see and need a responsible person. Do not say the company complies or does not comply with the law, and give no legal advice. Reply with one JSON object only.`

// WeeklyAI drafts the commentary of the weekly report with the customer's AI and keeps it for the preview and the next send.
func (s *Service) WeeklyAI(ctx context.Context, actor string) (AiSummary, error) {
	if !s.aiOn(jobWeekly) {
		return AiSummary{}, errAIUnavailable()
	}
	r, err := s.Weekly(ctx)
	if err != nil {
		return AiSummary{}, err
	}
	res, err := s.cfg.AI.Summarize(ctx, actor, jobWeekly, weeklyTask, []Block{{Source: "weekly report figures", Text: weeklyFacts(r)}})
	if err != nil {
		return AiSummary{}, err
	}
	sum := summaryOf(res, s.clock())
	raw, _ := json.Marshal(sum)
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rep_weekly_ai (id, summary) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET summary = excluded.summary`, string(raw)); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "report.ai_summary", "weekly", "")
	})
	if err != nil {
		return AiSummary{}, fmt.Errorf("reports: saving the AI commentary: %w", err)
	}
	return sum, nil
}

func summaryOf(r Summary, at time.Time) AiSummary {
	return AiSummary{Paragraphs: r.Paragraphs, Model: r.Model, Profile: r.Profile, Tokens: Tokens{Input: r.TokensIn, Output: r.TokensOut}, GeneratedAt: ts(at)}
}

// ---- schedule ----

type scheduleRow struct {
	enabled    bool
	zone       string
	day, hour  int
	recipients []string
	armedAt    time.Time
	lastSlot   time.Time
}

func (s *Service) loadSchedule(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (scheduleRow, error) {
	var r scheduleRow
	var rec, armed string
	var last sql.NullString
	err := q.QueryRowContext(ctx, `SELECT enabled, zone, day, hour, recipients, armed_at, last_slot_at FROM rep_schedule WHERE id = 1`).Scan(&r.enabled, &r.zone, &r.day, &r.hour, &rec, &armed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduleRow{day: 1, hour: 8, recipients: []string{}}, nil // never saved: off, no recipients (a clean install sends nothing)
	}
	if err != nil {
		return r, fmt.Errorf("reports: reading the schedule: %w", err)
	}
	if err := json.Unmarshal([]byte(rec), &r.recipients); err != nil {
		return r, fmt.Errorf("reports: reading the schedule: %w", err)
	}
	if r.armedAt, err = time.Parse(tsLayout, armed); err != nil {
		return r, fmt.Errorf("reports: reading the schedule: %w", err)
	}
	if last.Valid {
		if r.lastSlot, err = time.Parse(tsLayout, last.String); err != nil {
			return r, fmt.Errorf("reports: reading the schedule: %w", err)
		}
	}
	return r, nil
}

func (s *Service) scheduleView(ctx context.Context, r scheduleRow) Schedule {
	v := Schedule{Enabled: r.enabled, Day: r.day, Hour: r.hour, Recipients: nonNilS(r.recipients)}
	if r.enabled {
		n := ts(nextRun(s.clock(), s.loc(ctx), r.day, r.hour))
		v.NextRun = &n
	}
	return v
}

// Schedule is GET /reports/schedule.
func (s *Service) Schedule(ctx context.Context) (Schedule, error) {
	r, err := s.loadSchedule(ctx, s.cfg.DB.Reader())
	if err != nil {
		return Schedule{}, err
	}
	return s.scheduleView(ctx, r), nil
}

// SaveSchedule is PUT /reports/schedule (admin). Saving re-arms the schedule: a slot that has already passed is not sent late.
func (s *Service) SaveSchedule(ctx context.Context, actor string, in ScheduleInput) (Schedule, error) {
	in, aerr := checkSchedule(in)
	if aerr != nil {
		return Schedule{}, aerr
	}
	rec, _ := json.Marshal(in.Recipients)
	now := s.clock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rep_schedule (id, enabled, zone, day, hour, recipients, armed_at) VALUES (1, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled, zone = excluded.zone, last_slot_at = NULL, day = excluded.day, hour = excluded.hour, recipients = excluded.recipients, armed_at = excluded.armed_at`,
			in.Enabled, s.loc(ctx).String(), in.Day, in.Hour, string(rec), ts(now)); err != nil {
			return err
		}
		state := "off"
		if in.Enabled {
			state = "on"
		}
		return s.auditTx(ctx, tx, actor, "report.schedule", "weekly", fmt.Sprintf("%s, day %d, %02d:00, %d recipients", state, in.Day, in.Hour, len(in.Recipients)))
	})
	if err != nil {
		return Schedule{}, fmt.Errorf("reports: saving the schedule: %w", err)
	}
	return s.scheduleView(ctx, scheduleRow{enabled: in.Enabled, day: in.Day, hour: in.Hour, recipients: in.Recipients}), nil
}

// ---- history and sending ----

const (
	errNotReady = "The email channel is not ready, so nothing was sent. Check Settings, Alert channels, then send again."
	errBuild    = "The report could not be built, so nothing was sent. Try again in a few minutes."
	errSendFail = "The mail server did not accept the message. Check the email settings under Alert channels, then send again."
)

func historyItem(id string, at time.Time, trigger string, to []string, status, errText string) HistoryItem {
	return HistoryItem{ID: id, TS: ts(at), Trigger: trigger, Recipients: nonNilS(to), Status: status, Error: errText}
}

// History is GET /reports/weekly/history, newest first.
func (s *Service) History(ctx context.Context) ([]HistoryItem, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, trigger, recipients, status, error FROM rep_history ORDER BY ts DESC, id DESC LIMIT ?`, MaxHistory)
	if err != nil {
		return nil, fmt.Errorf("reports: reading the history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []HistoryItem{}
	for rows.Next() {
		var h HistoryItem
		var rec string
		var e sql.NullString
		if err := rows.Scan(&h.ID, &h.TS, &h.Trigger, &rec, &h.Status, &e); err != nil {
			return nil, fmt.Errorf("reports: reading the history: %w", err)
		}
		if err := json.Unmarshal([]byte(rec), &h.Recipients); err != nil {
			return nil, fmt.Errorf("reports: reading the history: %w", err)
		}
		h.Error = e.String
		out = append(out, h)
	}
	return out, rows.Err()
}

// HistoryEntry is GET /reports/weekly/history/{id}: the figures of that week as they were (INV-2).
func (s *Service) HistoryEntry(ctx context.Context, id string) (HistoryEntry, error) {
	var h HistoryEntry
	var rec, rep string
	var e sql.NullString
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT id, ts, trigger, recipients, status, error, report FROM rep_history WHERE id = ?`, id).Scan(&h.ID, &h.TS, &h.Trigger, &rec, &h.Status, &e, &rep)
	if errors.Is(err, sql.ErrNoRows) {
		return h, apierr.New(404, "not_found", "This report is not in the history.")
	}
	if err != nil {
		return h, fmt.Errorf("reports: reading a sent report: %w", err)
	}
	h.Error = e.String
	if err := json.Unmarshal([]byte(rec), &h.Recipients); err != nil {
		return h, fmt.Errorf("reports: reading a sent report: %w", err)
	}
	if err := json.Unmarshal([]byte(rep), &h.Report); err != nil {
		return h, fmt.Errorf("reports: reading a sent report: %w", err)
	}
	return h, nil
}

// SendNow is POST /reports/weekly/send: the report goes to the saved recipients (FORBID-2) and the attempt is recorded.
func (s *Service) SendNow(ctx context.Context, actor string) (HistoryItem, error) {
	sc, err := s.loadSchedule(ctx, s.cfg.DB.Reader())
	if err != nil {
		return HistoryItem{}, err
	}
	if len(sc.recipients) == 0 {
		return HistoryItem{}, bad("no_recipients", "There is no recipient. Add an email under Schedule and recipients, then send again.")
	}
	if s.cfg.Mail == nil {
		return HistoryItem{}, apierr.New(409, "email_not_ready", errNotReady)
	}
	if ok, _ := s.cfg.Mail.Ready(ctx); !ok {
		return HistoryItem{}, apierr.New(409, "email_not_ready", errNotReady)
	}
	return s.send(ctx, actor, "manual", time.Time{})
}

// send mails the report and records the attempt. The recipients are read again under the lock, so an address an admin removed
// while this send waited behind another is not mailed (FORBID-2). slot is the scheduled slot being sent (zero for a manual send):
// if the schedule was saved again since, the slot is dropped. Whatever happens, one history row is written, even if the report
// could not be built or the caller has gone (POST-1).
func (s *Service) send(ctx context.Context, actor, trigger string, slot time.Time) (HistoryItem, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	sc, err := s.loadSchedule(ctx, s.cfg.DB.Reader())
	if err != nil {
		return HistoryItem{}, err
	}
	to := sc.recipients
	if trigger == "scheduled" && (!sc.enabled || !slot.After(sc.armedAt)) {
		return HistoryItem{}, nil
	}
	if len(to) == 0 {
		return HistoryItem{}, bad("no_recipients", "There is no recipient. Add an email under Schedule and recipients, then send again.")
	}
	now := s.clock()
	status, errText := "sent", ""
	rep, berr := s.Weekly(ctx)
	switch {
	case berr != nil:
		s.cfg.Log.WarnContext(ctx, "reports: the weekly report could not be built", "error", berr)
		rep, status, errText = buildWeekly(weeklyInput{now: now}), "failed", errBuild
	case s.cfg.Mail == nil:
		status, errText = "failed", errNotReady
	default:
		if ok, _ := s.cfg.Mail.Ready(ctx); !ok {
			status, errText = "failed", errNotReady
		} else if err := s.cfg.Mail.Send(ctx, to, digest(rep)); err != nil {
			s.cfg.Log.WarnContext(ctx, "reports: the weekly report could not be sent", "error", err)
			status, errText = "failed", errSendFail
		}
	}
	h := historyItem(store.NewID("rep"), now, trigger, to, status, errText)
	raw, _ := json.Marshal(rep)
	rec, _ := json.Marshal(to)
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second) // the mail may be gone already: the row is written
	defer cancel()
	err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(wctx, `INSERT INTO rep_history (id, ts, trigger, recipients, status, error, report) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			h.ID, h.TS, trigger, string(rec), status, nullIfEmpty(errText), string(raw)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(wctx, `DELETE FROM rep_history WHERE id NOT IN (SELECT id FROM rep_history ORDER BY ts DESC, id DESC LIMIT ?)`, MaxHistory); err != nil {
			return err
		}
		return s.auditTx(wctx, tx, actor, "report.send", "weekly", fmt.Sprintf("%s, %s, %d recipients", trigger, status, len(to)))
	})
	if err != nil {
		return HistoryItem{}, fmt.Errorf("reports: recording the send: %w", err)
	}
	return h, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RunSchedule is the body of the weekly-send job: when the latest slot has passed and was not handled, send once (POST-2). The
// slot is marked handled before the send, so a crash cannot send it twice; a failed send is in the history and is not retried
// by itself (a person sends again).
func (s *Service) RunSchedule(ctx context.Context) error {
	sc, err := s.loadSchedule(ctx, s.cfg.DB.Reader())
	if err != nil || !sc.enabled {
		return err
	}
	now := s.clock()
	loc := s.loc(ctx)
	if sc.zone != loc.String() { // the box time zone changed: the slots move, so start again from now instead of risking a second send this week
		err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE rep_schedule SET zone = ?, armed_at = ?, last_slot_at = NULL WHERE id = 1`, loc.String(), ts(now))
			return err
		})
		return err
	}
	slot := slotAt(now, loc, sc.day, sc.hour)
	if !slot.After(sc.armedAt) || (!sc.lastSlot.IsZero() && !slot.After(sc.lastSlot)) {
		return nil
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE rep_schedule SET last_slot_at = ? WHERE id = 1`, ts(slot))
		return err
	})
	if err != nil {
		return fmt.Errorf("reports: marking the slot: %w", err)
	}
	if now.Sub(slot) > catchUp || len(sc.recipients) == 0 {
		return nil
	}
	_, err = s.send(ctx, "system", "scheduled", slot)
	return err
}

// digest is the email: a short summary and the things left to do, with a link to the full page. Names come from the network, so
// they were cleaned by buildWeekly and notify cleans them again.
func digest(r WeeklyReport) Mail {
	c := r.Counts
	m := Mail{
		Title: fmt.Sprintf("Weekly report: %d new, %d resolved, %d open", c.NewFindings, c.Resolved, c.OpenConfirmed+c.OpenSuspected),
		What: fmt.Sprintf("%d devices, %d not approved. %d vulnerabilities newly exploited in the last 7 days; products you use among them: %d.",
			c.Devices, c.DevicesUnapprove, c.KevNew, c.KevMatched),
		Path: "/reports",
	}
	for _, a := range r.Actions {
		switch a.Kind {
		case "fix":
			m.Items = append(m.Items, fmt.Sprintf("Fix %s on %s (%d open, first %s)", a.Product, a.Device, a.Count, a.CVE))
		case "verify":
			m.Items = append(m.Items, fmt.Sprintf("Check whether %s on %s is really affected (%d open, first %s)", a.Product, a.Device, a.Count, a.CVE))
		case "review_devices":
			m.Items = append(m.Items, fmt.Sprintf("Review %d devices waiting for approval", a.Count))
		case "plan_os":
			m.Items = append(m.Items, fmt.Sprintf("Plan to replace %d devices on an operating system that is no longer updated", a.Count))
		}
	}
	if len(m.Items) > 0 {
		m.Action = m.Items[0]
	}
	return m
}

// ---- PDPL ----

// Pdpl is GET /reports/pdpl.
func (s *Service) Pdpl(ctx context.Context) (PdplState, error) {
	org, rep, err := s.loadPdpl(ctx)
	if err != nil {
		return PdplState{}, err
	}
	st := PdplState{Org: org, Report: rep, AIAvailable: s.aiOn(jobPdpl)}
	if s.cfg.OrgName != nil {
		if n, err := s.cfg.OrgName(ctx); err == nil {
			st.Defaults.Name = n
		}
	}
	return st, nil
}

func (s *Service) loadPdpl(ctx context.Context) (*PdplOrg, *PdplReport, error) {
	var org, rep sql.NullString
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT org, report FROM rep_pdpl WHERE id = 1`).Scan(&org, &rep)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reports: reading the assessment: %w", err)
	}
	var o *PdplOrg
	var r *PdplReport
	if org.Valid {
		o = new(PdplOrg)
		if err := json.Unmarshal([]byte(org.String), o); err != nil {
			return nil, nil, fmt.Errorf("reports: reading the assessment: %w", err)
		}
	}
	if rep.Valid {
		r = new(PdplReport)
		if err := json.Unmarshal([]byte(rep.String), r); err != nil {
			return nil, nil, fmt.Errorf("reports: reading the assessment: %w", err)
		}
	}
	return o, r, nil
}

// SavePdplOrg is PUT /reports/pdpl/org: every field is checked (INV-8).
func (s *Service) SavePdplOrg(ctx context.Context, actor string, in PdplOrg) (PdplOrg, error) {
	org, aerr := checkOrg(in)
	if aerr != nil {
		return PdplOrg{}, aerr
	}
	raw, _ := json.Marshal(org)
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rep_pdpl (id, org) VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET org = excluded.org`, string(raw)); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "report.pdpl_org", clipRunes(org.Name, 120), "")
	})
	if err != nil {
		return PdplOrg{}, fmt.Errorf("reports: saving the organisation: %w", err)
	}
	return org, nil
}

// GeneratePdpl is POST /reports/pdpl/generate (PRE-3, POST-3). A new report replaces the old one, with its AI commentary.
func (s *Service) GeneratePdpl(ctx context.Context, actor string) (PdplReport, error) {
	org, _, err := s.loadPdpl(ctx)
	if err != nil {
		return PdplReport{}, err
	}
	if org == nil {
		return PdplReport{}, apierr.New(409, "org_required", "Fill in and save the organisation details first, then create the report.")
	}
	in, err := s.weeklyInput(ctx, s.clock())
	if err != nil {
		return PdplReport{}, err
	}
	var devs []Device // the PDPL inventory is the customer's network: this box is not in it
	for _, d := range in.devices {
		if !d.Box {
			devs = append(devs, d)
		}
	}
	rep := buildPdpl(pdplInput{devices: devs, findings: in.findings, kev: in.kev, modules: s.cfg.Modules, org: *org, id: store.NewID("pdpl"), now: in.now})
	raw, _ := json.Marshal(rep)
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE rep_pdpl SET report = ? WHERE id = 1`, string(raw)); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "report.pdpl_generate", rep.ID, "")
	})
	if err != nil {
		return PdplReport{}, fmt.Errorf("reports: saving the assessment: %w", err)
	}
	return rep, nil
}

func pdplFacts(r PdplReport) string {
	var b strings.Builder
	o := r.Org
	// The organisation's name, tax code, address and contact person do not go to the AI (data minimisation, D-238).
	fmt.Fprintf(&b, "Organisation: size %s, sector %s, %d employees, personal data of %s people; sensitive data: %t; cross-border transfer: %t; uses processors: %t; provides processing services: %t\n",
		o.Size, clip(o.Sector, 80), o.Employees, o.DataVolume, o.Sensitive, o.CrossBorder, o.Processors, o.ProcessingService)
	i := r.Inventory
	fmt.Fprintf(&b, "Devices: %d (%d not approved, %d fragile)\nTechnical measures (id: status, count):\n", i.Total, i.Unapproved, i.Fragile)
	for _, m := range r.Measures {
		fmt.Fprintf(&b, "- %s: %s, %d\n", m.ID, m.Status, m.N)
	}
	fmt.Fprintf(&b, "Open exploited-vulnerability findings: %d\nDuties (id: applies, regime):\n", len(r.Risks))
	for _, ob := range r.Obligations {
		fmt.Fprintf(&b, "- %s: %t, %s\n", ob.ID, ob.Applies, ob.Regime)
	}
	return b.String()
}

// PdplAI is POST /reports/pdpl/ai-summary (INV-5): the commentary is stored with the report and never changes it.
func (s *Service) PdplAI(ctx context.Context, actor string) (AiSummary, error) {
	if !s.aiOn(jobPdpl) {
		return AiSummary{}, errAIUnavailable()
	}
	_, rep, err := s.loadPdpl(ctx)
	if err != nil {
		return AiSummary{}, err
	}
	if rep == nil {
		return AiSummary{}, apierr.New(409, "report_required", "Create the report first; the AI needs something to comment on.")
	}
	res, err := s.cfg.AI.Summarize(ctx, actor, jobPdpl, pdplTask, []Block{{Source: "self-assessment figures", Text: pdplFacts(*rep)}})
	if err != nil {
		return AiSummary{}, err
	}
	sum := summaryOf(res, s.clock())
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT report FROM rep_pdpl WHERE id = 1`).Scan(&raw); err != nil {
			return err
		}
		var cur PdplReport
		if err := json.Unmarshal([]byte(raw), &cur); err != nil {
			return err
		}
		if cur.ID != rep.ID { // the report was generated again while the AI worked: the commentary is about the old one
			return apierr.New(409, "report_changed", "The report was created again while the AI was writing. Ask for the commentary again.")
		}
		cur.AISummary = &sum
		out, _ := json.Marshal(cur)
		if _, err := tx.ExecContext(ctx, `UPDATE rep_pdpl SET report = ? WHERE id = 1`, string(out)); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "report.ai_summary", rep.ID, "")
	})
	if err != nil {
		var ae *apierr.Error
		if errors.As(err, &ae) {
			return AiSummary{}, ae
		}
		return AiSummary{}, fmt.Errorf("reports: saving the AI commentary: %w", err)
	}
	return sum, nil
}

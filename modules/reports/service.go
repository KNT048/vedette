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

// Job name of the ai module (CONTRACT INV-5).
const jobPdpl = "pdpl-assessment"

// MaxHistory is how many sent reports are kept; older ones are removed when a new one is recorded.
const MaxHistory = 52

// Config is what NewService needs. Exposure, Detections, Feeds, Mail, AI, Modules, OrgName, Zone and Clock may be nil.
type Config struct {
	DB         *store.DB
	Audit      *audit.Log
	Inventory  Inventory
	Findings   Findings     // the PDPL assessment's risks
	Views      FindingViews // the periodic report's findings
	KEV        KEV
	Exposure   Exposure   // without it the External exposure section says the module is off
	Detections Detections // without it the Detections section says detection is off
	Feeds      Feeds      // without it Coverage lists no feed
	Mail       Mailer
	AI         AI
	Modules    Modules
	OrgName    func(context.Context) (string, error)
	Zone       func(context.Context) string // IANA name of the organisation's time zone; "" or an unknown name = UTC
	Log        *slog.Logger
	Clock      func() time.Time
}

// Service owns the rep_ tables. Every mutation runs in one transaction with its core_audit row (SYS-3).
type Service struct {
	cfg Config
	now func() time.Time

	sendMu sync.Mutex // one send at a time: the job and a person's click must not mail the same report twice
}

// NewService returns the service. DB, Audit, Inventory, Findings, Views, KEV and Log are required.
func NewService(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Inventory == nil || cfg.Findings == nil || cfg.Views == nil || cfg.KEV == nil || cfg.Log == nil {
		return nil, errors.New("reports: creating service: DB, Audit, Inventory, Findings, Views, KEV and Log are required")
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

func (s *Service) on(module string) bool {
	return s.cfg.Modules == nil || s.cfg.Modules.Enabled(module)
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, user, action, target, detail string) error {
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: action, Target: target, Detail: detail})
}

// coverageSources are the modules that see the network, in the order Coverage lists them.
var coverageSources = []string{"sensor-passive", "sensor-active", "agent-intake", "honeypot", "logs", "exposure", "ids"}

// detectionModules are the modules whose detections become incidents.
var detectionModules = []string{"honeypot", "logs", "sensor-passive", "ids"}

// Document is GET /reports/document: the report of the current period, made now with the saved definition (INV-1). Each section
// reads its own source; a source that cannot be read fails the document rather than show a section that is not true.
func (s *Service) Document(ctx context.Context) (Document, error) {
	def, err := s.Definition(ctx)
	if err != nil {
		return Document{}, err
	}
	return s.document(ctx, def)
}

func (s *Service) document(ctx context.Context, def Definition) (Document, error) {
	now, loc := s.clock(), s.loc(ctx)
	in := docInput{def: def, now: now, loc: loc}
	if s.cfg.OrgName != nil {
		if n, err := s.cfg.OrgName(ctx); err == nil {
			in.org = n
		}
	}
	sec := def.Options.Sections
	var err error
	if sec.Summary || sec.Handled || sec.Open || sec.New {
		if in.findings, err = s.cfg.Views.Views(ctx); err != nil {
			return Document{}, fmt.Errorf("reports: reading findings: %w", err)
		}
		in.reasons = func(ids []string) map[string][]Reason {
			rs, err := s.cfg.Views.Reasons(ctx, ids)
			if err != nil { // the status stands on the stored layer; only the reasons line is missing
				s.cfg.Log.WarnContext(ctx, "reports: the urgency reasons could not be read", "error", err)
			}
			return rs
		}
	}
	if sec.Coverage || sec.Detections {
		if in.devices, err = s.cfg.Inventory.Devices(ctx); err != nil {
			return Document{}, fmt.Errorf("reports: reading devices: %w", err)
		}
	}
	from, to := periodOf(def.Options.Period, now, loc)
	if sec.Exposure {
		in.exposure = &ReportExposure{ModuleOn: s.cfg.Exposure != nil && s.on("exposure"), Targets: []ExposureTarget{}}
		if in.exposure.ModuleOn {
			targets, err := s.cfg.Exposure.Targets(ctx, from, to)
			if err != nil {
				return Document{}, fmt.Errorf("reports: reading external exposure: %w", err)
			}
			if targets != nil {
				in.exposure.Targets = targets
			}
		}
	}
	if sec.Detections {
		watch := false
		for _, m := range detectionModules {
			watch = watch || s.on(m)
		}
		in.detections.on = s.cfg.Detections != nil && s.on("notify") && watch
		if in.detections.on {
			if in.detections.counts, in.detections.top, err = s.cfg.Detections.Period(ctx, from, to, maxTop*2); err != nil {
				return Document{}, fmt.Errorf("reports: reading incidents: %w", err)
			}
		}
	}
	if sec.Coverage {
		for _, m := range coverageSources {
			in.sources = append(in.sources, SourceOn{ID: m, On: s.cfg.Modules != nil && s.cfg.Modules.Enabled(m)})
		}
		if s.cfg.Feeds != nil && s.on("feeds") {
			if in.feeds, err = s.cfg.Feeds.Health(ctx); err != nil {
				return Document{}, fmt.Errorf("reports: reading the feeds: %w", err)
			}
		}
	}
	return buildDocument(in), nil
}

// ---- sending and the sent documents ----

const (
	errNotReady = "The email channel is not ready, so nothing was sent. Check Settings, Alert channels, then send again."
	errBuild    = "The report could not be made, so nothing was sent. Try again in a few minutes."
	errSendFail = "The mail server did not accept the message. Check the email settings under Alert channels, then send again."
)

func errNoRecipients() *apierr.Error {
	return bad("no_recipients", "There is no recipient. Add an email in Settings, then send again.")
}

// SendNow is POST /reports/send: the report goes to the saved recipients (FORBID-2) and the document is kept as sent.
func (s *Service) SendNow(ctx context.Context, actor string) (SentItem, error) {
	def, err := s.Definition(ctx)
	if err != nil {
		return SentItem{}, err
	}
	if len(def.Recipients) == 0 {
		return SentItem{}, errNoRecipients()
	}
	if s.cfg.Mail == nil {
		return SentItem{}, apierr.New(409, "email_not_ready", errNotReady)
	}
	if ok, _ := s.cfg.Mail.Ready(ctx); !ok {
		return SentItem{}, apierr.New(409, "email_not_ready", errNotReady)
	}
	return s.send(ctx, triggerManual, actor)
}

// send makes the document, mails it and records the attempt with the document. The recipients are read again under the lock, so an
// address an admin removed while this send waited behind another is not mailed (FORBID-2). Whatever happens once there is a
// recipient, one history row is written, even if the document could not be made or the caller has gone (POST-1). by is the person
// for a manual send, "" for the schedule.
func (s *Service) send(ctx context.Context, trigger, by string) (SentItem, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	def, err := s.Definition(ctx)
	if err != nil {
		return SentItem{}, err
	}
	to := def.Recipients
	if len(to) == 0 {
		return SentItem{}, errNoRecipients()
	}
	now := s.clock()
	id := store.NewID("rep")
	status, errText := "sent", ""
	doc, berr := s.document(ctx, def)
	switch {
	case berr != nil:
		s.cfg.Log.WarnContext(ctx, "reports: the report could not be made", "error", berr)
		from, to := periodOf(def.Options.Period, now, s.loc(ctx))
		doc = Document{DefinitionID: def.ID, Title: clip(def.Name, 120), GeneratedAt: ts(now), Period: DocPeriod{Kind: def.Options.Period, From: ts(from), To: ts(to), TZ: s.loc(ctx).String()}, Options: def.Options}
		status, errText = "failed", errBuild
	case s.cfg.Mail == nil:
		status, errText = "failed", errNotReady
	default:
		if ok, _ := s.cfg.Mail.Ready(ctx); !ok {
			status, errText = "failed", errNotReady
		} else if err := s.cfg.Mail.Send(ctx, to, digest(doc, id)); err != nil {
			s.cfg.Log.WarnContext(ctx, "reports: the report could not be sent", "error", err)
			status, errText = "failed", errSendFail
		}
	}
	item := SentItem{ID: id, DefinitionID: def.ID, Title: doc.Title, SentAt: ts(now), Period: SentPeriod{From: doc.Period.From, To: doc.Period.To},
		Trigger: trigger, Recipients: append([]string{}, to...), Status: status}
	if errText != "" {
		item.Error = &errText
	}
	if by != "" {
		item.SentBy = &by
	}
	raw, _ := json.Marshal(doc)
	rec, _ := json.Marshal(to)
	actor := by
	if actor == "" {
		actor = "system"
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second) // the mail may be gone already: the row is written
	defer cancel()
	err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(wctx, `INSERT INTO rep_history (id, definition_id, ts, title, period_from, period_to, trigger, recipients, status, error, sent_by, document)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			item.ID, item.DefinitionID, item.SentAt, item.Title, item.Period.From, item.Period.To, trigger, string(rec), status, item.Error, item.SentBy, string(raw)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(wctx, `DELETE FROM rep_history WHERE id NOT IN (SELECT id FROM rep_history ORDER BY ts DESC, id DESC LIMIT ?)`, MaxHistory); err != nil {
			return err
		}
		return s.auditTx(wctx, tx, actor, "report.send", def.ID, fmt.Sprintf("%s, %s, %d recipients", trigger, status, len(to)))
	})
	if err != nil {
		return SentItem{}, fmt.Errorf("reports: recording the send: %w", err)
	}
	return item, nil
}

const sentCols = `id, definition_id, ts, title, period_from, period_to, trigger, recipients, status, error, sent_by`

func scanSent(sc interface{ Scan(...any) error }, extra ...any) (SentItem, error) {
	var h SentItem
	var rec string
	var e, by sql.NullString
	dest := append([]any{&h.ID, &h.DefinitionID, &h.SentAt, &h.Title, &h.Period.From, &h.Period.To, &h.Trigger, &rec, &h.Status, &e, &by}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(rec), &h.Recipients); err != nil {
		return h, err
	}
	if h.Recipients == nil {
		h.Recipients = []string{}
	}
	if e.Valid {
		h.Error = &e.String
	}
	if by.Valid {
		h.SentBy = &by.String
	}
	return h, nil
}

// History is GET /reports/history, newest first.
func (s *Service) History(ctx context.Context) ([]SentItem, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT `+sentCols+` FROM rep_history ORDER BY ts DESC, id DESC LIMIT ?`, MaxHistory)
	if err != nil {
		return nil, fmt.Errorf("reports: reading the history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []SentItem{}
	for rows.Next() {
		h, err := scanSent(rows)
		if err != nil {
			return nil, fmt.Errorf("reports: reading the history: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Sent is GET /reports/history/{id}: the document exactly as it was sent (INV-2).
func (s *Service) Sent(ctx context.Context, id string) (SentReport, error) {
	var doc string
	h, err := scanSent(s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT `+sentCols+`, document FROM rep_history WHERE id = ?`, id), &doc)
	if errors.Is(err, sql.ErrNoRows) {
		return SentReport{}, apierr.New(404, "not_found", "This report is not in the history.")
	}
	if err != nil {
		return SentReport{}, fmt.Errorf("reports: reading a sent report: %w", err)
	}
	out := SentReport{SentItem: h}
	if err := json.Unmarshal([]byte(doc), &out.Document); err != nil {
		return SentReport{}, fmt.Errorf("reports: reading a sent report: %w", err)
	}
	return out, nil
}

// ---- PDPL ----

func (s *Service) aiOn(job string) bool { return s.cfg.AI != nil && s.cfg.AI.Available(job) }

func errAIUnavailable() *apierr.Error {
	return apierr.New(409, "ai_unavailable", "The AI assistant is off or no AI profile is assigned to this task. An administrator can turn it on or assign one in Settings, AI assistant.")
}

func summaryOfAI(r Summary, at time.Time) AiSummary {
	return AiSummary{Paragraphs: r.Paragraphs, Model: r.Model, Profile: r.Profile, Tokens: Tokens{Input: r.TokensIn, Output: r.TokensOut}, GeneratedAt: ts(at)}
}

const pdplTask = `Write a short commentary on a personal-data-protection self-assessment of a small company's network. Use only the facts in the data block, which are what the Vedette box could see. Write at most 3 short paragraphs of plain English: what the technical picture shows, which weaknesses to close first, and that duties about dossiers, procedures and contracts are outside what the box can see and need a responsible person. Do not say the company complies or does not comply with the law, and give no legal advice. Reply with one JSON object only.`

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
	all, err := s.cfg.Inventory.Devices(ctx)
	if err != nil {
		return PdplReport{}, fmt.Errorf("reports: reading devices: %w", err)
	}
	fs, err := s.cfg.Findings.All(ctx)
	if err != nil {
		return PdplReport{}, fmt.Errorf("reports: reading findings: %w", err)
	}
	kev, err := s.cfg.KEV.Entries(ctx)
	if err != nil {
		return PdplReport{}, fmt.Errorf("reports: reading the exploited list: %w", err)
	}
	var devs []Device // the PDPL inventory is the customer's network: this box is not in it
	for _, d := range all {
		if !d.Box {
			devs = append(devs, d)
		}
	}
	rep := buildPdpl(pdplInput{devices: devs, findings: fs, kev: kev, modules: s.cfg.Modules, org: *org, id: store.NewID("pdpl"), now: s.clock()})
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
	// The organisation's name, tax code, address and contact person do not go to the AI (data minimisation).
	fmt.Fprintf(&b, "Organisation: size %s, sector %s, %d employees, personal data of %s people; sensitive data: %t; cross-border transfer: %t; uses processors: %t; provides processing services: %t\n",
		o.Size, clip(o.Sector, 80), o.Employees, o.DataVolume, o.Sensitive, o.CrossBorder, o.Processors, o.ProcessingService)
	i := r.Inventory
	fmt.Fprintf(&b, "Devices: %d (%d not approved, %d fragile)\nTechnical measures (id: status, count):\n", i.Total, i.Unapproved, i.Fragile)
	for _, m := range r.Measures {
		fmt.Fprintf(&b, "- %s: %s, %d\n", m.ID, m.Status, m.N)
	}
	fmt.Fprintf(&b, "Open vulnerability findings: %d\nDuties (id: applies, regime):\n", len(r.Risks))
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
	sum := summaryOfAI(res, s.clock())
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

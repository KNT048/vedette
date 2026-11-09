package mitigation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
)

// Details is how the handlers answer: the finding page, as findings composes it (satisfied by
// *findings.FindingHandlers, which also asks this module's Provider for the "What to do" part).
type Details interface {
	Detail(ctx context.Context, rec findings.Record) (findings.Detail, error)
}

// ActionHandlers implements POST /findings/{id}/applied and POST /findings/{id}/ai (operator). Embed it
// in the composite handler; it implements no other operation.
type ActionHandlers struct {
	db      *store.DB
	audit   *audit.Log
	finding *findings.Service
	details Details
	ai      AI
	now     func() time.Time
}

// NewActionHandlers returns the handlers; every argument except clock is required.
func NewActionHandlers(db *store.DB, a *audit.Log, f *findings.Service, d Details, ai AI, clock func() time.Time) (*ActionHandlers, error) {
	if db == nil || a == nil || f == nil || d == nil || ai == nil {
		return nil, errors.New("mitigation: creating handlers: db, audit, findings, details and ai are required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &ActionHandlers{db: db, audit: a, finding: f, details: d, ai: ai, now: clock}, nil
}

// Limits on what the AI may hand back: its output is untrusted text (rules/security.md).
const (
	maxAIParagraphs = 20
	maxAISteps      = 30
	maxAICitations  = 20
	maxAIText       = 8000
)

func noPack() error {
	return apierr.New(400, "no_pack", "This CVE has no confirmed recommendation yet, so there is nothing to mark as applied.")
}

func aiUnavailable() error {
	return apierr.New(409, "ai_unavailable", "No AI profile is assigned to this job, or the AI assistant is off. Open Settings, AI assistant to set it up.")
}

// FindingsPostFindingsIDApplied implements findings_post_findings_id_applied (INV-1): it logs one item
// as applied, once, and never changes the finding's status.
func (h *ActionHandlers) FindingsPostFindingsIDApplied(ctx context.Context, req *oas.FindingsPostFindingsIDAppliedReq, params oas.FindingsPostFindingsIDAppliedParams) (*oas.FindingsPostFindingsIDAppliedOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	rec, err := h.finding.Get(ctx, params.ID)
	if err != nil {
		return nil, findings.ToAPIError(err)
	}
	if err := h.markApplied(ctx, rec, string(req.Item), p.Email); err != nil {
		return nil, err
	}
	d, err := h.details.Detail(ctx, rec)
	if err != nil {
		return nil, err
	}
	return findings.Into[oas.FindingsPostFindingsIDAppliedOK](d)
}

func (h *ActionHandlers) markApplied(ctx context.Context, rec findings.Record, item, user string) error {
	if err := findings.ValidUser(user); err != nil {
		return findings.ToAPIError(err)
	}
	var has int
	if err := h.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM mit_pack WHERE cve = ?`, rec.CVE).Scan(&has); err != nil {
		return fmt.Errorf("mitigation: looking up pack: %w", err)
	}
	if has == 0 {
		return noPack()
	}
	err := h.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO mit_applied (finding_id, item, ts, user) VALUES (?, ?, ?, ?) ON CONFLICT (finding_id, item) DO NOTHING`,
			rec.ID, item, store.FormatTS(h.now()), user)
		if err != nil {
			return fmt.Errorf("mitigation: logging applied item: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil // already logged: once per item
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: user, Action: "mitigation.applied", Target: rec.ID, Detail: rec.CVE + ": " + item})
	})
	if isForeignKey(err) { // the finding went away (device deleted) between the read and the write
		return findings.ToAPIError(fmt.Errorf("mitigation: logging applied item: %w", findings.ErrNotFound))
	}
	return err
}

// FindingsPostFindingsIDAi implements findings_post_findings_id_ai (INV-3): the customer's AI explains
// the finding or drafts a recommendation; the result is stored as an AI result and answered with its
// AI label data (model, profile, tokens, citations). 409 ai_unavailable when it cannot be used.
func (h *ActionHandlers) FindingsPostFindingsIDAi(ctx context.Context, req *oas.FindingsPostFindingsIDAiReq, params oas.FindingsPostFindingsIDAiParams) (*oas.FindingsPostFindingsIDAiOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if err := findings.ValidUser(p.Email); err != nil {
		return nil, findings.ToAPIError(err)
	}
	rec, err := h.finding.Get(ctx, params.ID)
	if err != nil {
		return nil, findings.ToAPIError(err)
	}
	skill := Skill(req.Skill)
	if !h.ai.Available(ctx, skill) {
		return nil, aiUnavailable()
	}
	before, err := h.details.Detail(ctx, rec)
	if err != nil {
		return nil, err
	}
	out, err := h.ai.Run(ctx, AIRequest{Skill: skill, Finding: before.Row, HasPack: before.Pack != nil, User: p.Email})
	if errors.Is(err, ErrAIUnavailable) {
		return nil, aiUnavailable()
	}
	if err != nil {
		return nil, fmt.Errorf("mitigation: running AI %s: %w", skill, err)
	}
	res := sanitizeAI(skill, h.now().UTC().Truncate(time.Millisecond), out)
	if err := h.storeAI(ctx, rec, res, out.ActivityID, p.Email); err != nil {
		return nil, err
	}
	d, err := h.details.Detail(ctx, rec)
	if err != nil {
		return nil, err
	}
	return findings.Into[oas.FindingsPostFindingsIDAiOK](d)
}

func (h *ActionHandlers) storeAI(ctx context.Context, rec findings.Record, res findings.AIResult, activityID, user string) error {
	payload, err := jsonOf(res)
	if err != nil {
		return err
	}
	var activity, profile any
	if activityID != "" {
		activity = activityID
	}
	if res.Profile != "" {
		profile = res.Profile
	}
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO mit_ai_output (finding_id, skill, payload, model, profile, created_at, activity_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			rec.ID, res.Skill, payload, res.Model, profile, store.FormatTS(res.TS), activity); err != nil {
			return fmt.Errorf("mitigation: storing AI result: %w", err)
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: user, Action: "mitigation.ai", Target: rec.ID, Detail: rec.CVE + ": " + res.Skill})
	})
	if isForeignKey(err) {
		return findings.ToAPIError(fmt.Errorf("mitigation: storing AI result: %w", findings.ErrNotFound))
	}
	return err
}

// sanitizeAI turns the AI module's answer into an AI result within the limits of the schema: text is
// cut, lists are capped, and a citation link survives only if it is an http(s) URL (it is shown as a link).
func sanitizeAI(skill Skill, ts time.Time, o AIOutput) findings.AIResult {
	r := findings.AIResult{
		Skill: string(skill), TS: ts, Model: clip(o.Model, 200), Profile: clip(o.Profile, 200),
		Tokens:     findings.Tokens{Input: max(o.InputTok, 0), Output: max(o.OutputTok, 0)},
		Paragraphs: []string{}, Steps: []string{}, Citations: []findings.Citation{},
	}
	for _, s := range o.Paragraphs[:min(len(o.Paragraphs), maxAIParagraphs)] {
		r.Paragraphs = append(r.Paragraphs, clip(s, maxAIText))
	}
	for _, s := range o.Steps[:min(len(o.Steps), maxAISteps)] {
		r.Steps = append(r.Steps, clip(s, maxAIText))
	}
	for _, c := range o.Citations[:min(len(o.Citations), maxAICitations)] {
		cc := findings.Citation{Title: clip(c.Title, 300)}
		if u, err := url.Parse(c.URL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && len(c.URL) <= 2000 {
			cc.URL = c.URL
		}
		r.Citations = append(r.Citations, cc)
	}
	return r
}

// clip cuts s to n characters, on a character boundary, and drops NUL and invalid UTF-8.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "�")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func isForeignKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("mitigation: encoding AI result: %w", err)
	}
	return string(b), nil
}

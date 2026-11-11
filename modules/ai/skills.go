package ai

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/knt048/vedette/core/apierr"
)

// Slice 4b of WP-25 (S-AI-7): the product skills. The list is in code (decision of the plan; the signed content pack in skills/ is
// deferred), the same eleven entries as SKILL_DEFS of the mock. The only thing stored is the switch of each skill (ai_skill_state);
// a skill with no row is on. What a switch does at run time: a job whose skill is off does not run (Ready, hence RunJob and
// Available), so its button is not offered and a scheduled call stops with 409 ai_unavailable. A skill with no job
// (fingerprint-fallback) has a switch that nothing reads yet.

// SkillView is a skill as the API shows it. Jobs is never null: empty = runs in batches, not tied to a job.
type SkillView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	What    string `json:"what"`
	Jobs    []Job  `json:"jobs"`
	Enabled bool   `json:"enabled"`
}

type skillDef struct {
	id, name, what string
	jobs           []Job
}

var skillDefs = []skillDef{
	{"explain-finding", "Explain a finding", "Says whether a vulnerability affects your devices, why, and how to patch or work around it.", []Job{JobExplainFinding}},
	{"cve-news", "CVE news", "Summarises advisories, public exploit code and blog posts the box fetched for a CVE.", []Job{JobCVENews}},
	{"log-digest", "Log digest", "Turns grouped log events into a short list of what to look at, most serious first.", []Job{JobLogDigest}},
	{"log-investigate", "Log investigation", "Digs into one alert with read-only tools (maximum level only).", []Job{JobLogInvestigate}},
	{"mitigation-config", "Mitigation config", "Drafts firewall configuration to block an attack until you can patch.", []Job{JobMitigationConfig}},
	{"fingerprint-fallback", "Device fingerprint fallback", "Names a device when the scanners recognise the banner but not the product.", nil},
	{"translate-advisory", "Translate advisory", "Translates a vendor advisory, keeping numbers and versions exact.", []Job{JobTranslateAdvisory}},
	{"weekly-report", "Weekly report", "Writes the one-page weekly summary from this week's numbers.", []Job{JobWeeklyReport}},
	{"pdpl-assessment", "Data protection assessment", "Fills the data protection self-assessment from inventory and scans.", []Job{JobPDPLAssessment}},
	{"ask-my-data", "Ask your data", "Answers questions about your devices and findings with read-only tools.", []Job{JobAskMyData}},
	{"response-plan", "Response plan", "Proposes what to do now when a device has a critical finding, for your own devices.", []Job{JobResponsePlan}},
}

func (d skillDef) view(on bool) SkillView {
	jobs := slices.Clone(d.jobs)
	if jobs == nil {
		jobs = []Job{}
	}
	return SkillView{ID: d.id, Name: d.name, What: d.what, Jobs: jobs, Enabled: on}
}

// loadSkills reads the switches that are off.
func (s *Service) loadSkills(ctx context.Context) (map[string]bool, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id FROM ai_skill_state WHERE enabled = 0`)
	if err != nil {
		return nil, fmt.Errorf("skills: %w", err)
	}
	defer func() { _ = rows.Close() }()
	off := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("skills: %w", err)
		}
		off[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("skills: %w", err)
	}
	return off, nil
}

// Skills returns the skills with their switches (`GET /ai/skills`, admin).
func (s *Service) Skills() []SkillView {
	off := *s.skillsOff.Load()
	out := make([]SkillView, 0, len(skillDefs))
	for _, d := range skillDefs {
		out = append(out, d.view(!off[d.id]))
	}
	return out
}

// SetSkill turns a skill on or off (`PUT /ai/skills/{id}`, admin).
func (s *Service) SetSkill(ctx context.Context, who, id string, enabled bool) (SkillView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return SkillView{}, err
	}
	i := slices.IndexFunc(skillDefs, func(d skillDef) bool { return d.id == id })
	if i < 0 {
		return SkillView{}, harnessNotFound("skill")
	}
	state := "off"
	if enabled {
		state = "on"
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_skill_state (id, enabled) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled`, id, b2i(enabled)); err != nil {
			return fmt.Errorf("ai: save skill switch: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.skill", id, state)
	})
	if err != nil {
		return SkillView{}, err
	}
	off := map[string]bool{}
	for k, v := range *s.skillsOff.Load() {
		off[k] = v
	}
	if enabled {
		delete(off, id)
	} else {
		off[id] = true
	}
	s.skillsOff.Store(&off)
	return skillDefs[i].view(enabled), nil
}

// skillOff returns the error for a job whose skill is switched off, nil otherwise.
func (s *Service) skillOff(job Job) error {
	off := *s.skillsOff.Load()
	for _, d := range skillDefs {
		if off[d.id] && slices.Contains(d.jobs, job) {
			return apierr.New(409, "ai_unavailable", fmt.Sprintf("The skill %q is turned off. An administrator turns it on in Settings, AI assistant, Skills.", d.name))
		}
	}
	return nil
}

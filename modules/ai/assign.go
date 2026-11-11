package ai

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
)

// SlotView is the primary and fallback profile id of one job (nil = none).
type SlotView struct {
	Primary  *string `json:"primary"`
	Fallback *string `json:"fallback"`
}

// AssignmentsView is the body and the answer of the assignments endpoints: all ten jobs, and the privacy rule.
type AssignmentsView struct {
	InternalOnly bool                `json:"internal_only"`
	Jobs         map[string]SlotView `json:"jobs"`
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func viewOf(a Assignments) AssignmentsView {
	v := AssignmentsView{InternalOnly: a.InternalOnly, Jobs: make(map[string]SlotView, len(Jobs()))}
	for _, j := range Jobs() {
		s := a.Jobs[j]
		v.Jobs[string(j)] = SlotView{Primary: ptr(s.Primary), Fallback: ptr(s.Fallback)}
	}
	return v
}

// Assignments returns the saved assignments.
func (s *Service) Assignments() AssignmentsView { return viewOf(s.snap.Load().assign) }

// SetAssignments saves the assignments and the privacy rule. A job left out of the body is unassigned. The whole state is checked
// first (INV-3): a cloud profile cannot hold a job that sends internal data while the rule is on.
func (s *Service) SetAssignments(ctx context.Context, who string, in AssignmentsView) (AssignmentsView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != "" {
		return AssignmentsView{}, s.errDegraded()
	}
	cur := s.snap.Load()
	asg := Assignments{InternalOnly: in.InternalOnly, Jobs: make(map[Job]Slot, len(in.Jobs))}
	for name, sl := range in.Jobs {
		var slot Slot
		if sl.Primary != nil {
			slot.Primary = *sl.Primary
		}
		if sl.Fallback != nil {
			slot.Fallback = *sl.Fallback
		}
		asg.Jobs[Job(name)] = slot
	}
	next := &snapshot{profiles: cur.profiles, assign: asg, cfg: cur.cfg}
	if err := next.check(); err != nil {
		return AssignmentsView{}, mapErr(err)
	}
	for _, j := range Jobs() { // all ten, so the saved rows and the router agree
		if _, ok := asg.Jobs[j]; !ok {
			asg.Jobs[j] = Slot{}
		}
	}
	now := s.cfg.Clock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, j := range Jobs() {
			slot := asg.Jobs[j]
			if _, err := tx.ExecContext(ctx, `UPDATE ai_assignment SET primary_profile_id = ?, fallback_profile_id = ? WHERE job = ?`, nullable(slot.Primary), nullable(slot.Fallback), string(j)); err != nil {
				return fmt.Errorf("ai: save assignment: %w", err)
			}
		}
		if err := upsertSetting(ctx, tx, "assign", struct {
			InternalOnly bool `json:"internal_only"`
		}{asg.InternalOnly}, now, who); err != nil {
			return err
		}
		rule := "off"
		if asg.InternalOnly {
			rule = "on"
		}
		return s.auditTx(ctx, tx, who, "ai.assign", "jobs", "privacy rule "+rule)
	})
	if err != nil {
		return AssignmentsView{}, err
	}
	if err := s.apply(ctx, next); err != nil {
		return AssignmentsView{}, err
	}
	return viewOf(asg), nil
}

// fastModel marks models meant for bulk work: a small, quick model suits a job that runs often on lots of text.
var fastModel = regexp.MustCompile(`(?i)haiku|mini|luna|flash|lite|nano|\b[1-9]b\b|:[1-9]b\b`)

// batchJobs run often on lots of text, so they get a fast model; the rest need reasoning and get a strong one.
var batchJobs = map[Job]bool{JobLogDigest: true, JobTranslateAdvisory: true, JobCVENews: true, JobWeeklyReport: true}

// Suggestion proposes assignments without saving them: a fast model for bulk jobs, a strong one for reasoning jobs; a job that
// sends internal data prefers an internal profile and a job on public data prefers the cloud. Profiles the rule forbids are left out.
func (s *Service) Suggestion(internalOnly bool) AssignmentsView {
	sn := s.snap.Load()
	asg := Assignments{InternalOnly: internalOnly, Jobs: make(map[Job]Slot, len(Jobs()))}
	for _, j := range Jobs() {
		var ok []Profile
		for _, p := range sn.profiles {
			// response-plan is opt-in (D-181): Suggest then Save must not switch it on, as AddProfile does not.
			if j != JobResponsePlan && asg.Allowed(j, p.Profile) {
				ok = append(ok, p.Profile)
			}
		}
		wantFast := batchJobs[j]
		rank := func(p Profile) int {
			r := 0
			if fastModel.MatchString(p.Model) != wantFast {
				r += 2
			}
			if j.CarriesInternalData() != (p.Location == LocationInternal) {
				r++
			}
			return r
		}
		sort.SliceStable(ok, func(a, b int) bool { return rank(ok[a]) < rank(ok[b]) })
		var slot Slot
		if len(ok) > 0 {
			slot.Primary = ok[0].ID
		}
		if len(ok) > 1 {
			slot.Fallback = ok[1].ID
		}
		asg.Jobs[j] = slot
	}
	return viewOf(asg)
}

// ConfigView is the shared token settings and which jobs can run now.
type ConfigView struct {
	Configured    bool            `json:"configured"`
	Tier          Tier            `json:"tier"`
	DailyCap      int             `json:"daily_cap"`
	RedactPII     bool            `json:"redact_pii"`
	TierEstimates map[Tier]*int   `json:"tier_estimates"`
	JobsReady     map[string]bool `json:"jobs_ready"`
}

// Config returns the settings. Tier is the level in force today: it is lower than the saved one after the shared cap was passed (INV-4).
func (s *Service) Config() ConfigView {
	sn := s.snap.Load()
	v := ConfigView{Tier: s.meter.Tier(), DailyCap: sn.cfg.DailyCap, RedactPII: s.redactPII(),
		TierEstimates: map[Tier]*int{}, JobsReady: make(map[string]bool, len(Jobs()))}
	for _, p := range sn.profiles {
		v.Configured = v.Configured || p.Usable()
	}
	for _, t := range []Tier{TierMin, TierMed, TierMax} {
		var n *int
		if tokens, ok := t.EstimatePerDay(); ok {
			n = &tokens
		}
		v.TierEstimates[t] = n
	}
	for _, j := range Jobs() {
		c, _ := s.router.Candidates(j)
		v.JobsReady[string(j)] = len(c) > 0
	}
	return v
}

// SetConfig saves the tier, the shared cap and the PII setting.
func (s *Service) SetConfig(ctx context.Context, who string, in Settings) (ConfigView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != "" {
		return ConfigView{}, s.errDegraded()
	}
	if err := in.validate(); err != nil {
		return ConfigView{}, mapErr(err)
	}
	cur := s.snap.Load()
	now := s.cfg.Clock()
	// redact_pii is the switch of the block-pii hook (INV-12): one row, written with the rest of the settings.
	hcur := s.harness.Load()
	on := map[string]bool{}
	for k, v := range hcur.builtin {
		on[k] = v
	}
	on[HookBlockPII] = in.RedactPII
	hnext, err := hcur.with(nil, on, nil)
	if err != nil {
		return ConfigView{}, err
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := upsertSetting(ctx, tx, "config", in, now, who); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ai_hook_state SET enabled = ? WHERE builtin_id = ?`, b2i(in.RedactPII), HookBlockPII); err != nil {
			return fmt.Errorf("ai: save the personal-data switch: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.config", "tier", fmt.Sprintf("tier=%s, cap=%d, redact_pii=%t", in.Tier, in.DailyCap, in.RedactPII))
	})
	if err != nil {
		return ConfigView{}, err
	}
	if err := s.meter.SetConfig(in.Tier, in.DailyCap); err != nil {
		return ConfigView{}, fmt.Errorf("ai: apply token settings: %w", err)
	}
	s.snap.Store(&snapshot{profiles: cur.profiles, assign: cur.assign, cfg: in})
	s.harness.Store(hnext)
	return s.Config(), nil
}

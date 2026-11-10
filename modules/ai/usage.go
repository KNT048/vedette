package ai

import (
	"context"
	"fmt"
	"time"
)

// Usage and runs are views on ai_activity (DATA_MODEL 4.9): one call, one place it is written (INV-17). The shared cap and the
// day are those of the meter, so a restart lands on the same numbers (INV-4).

// dayStart is the start of the box's day containing now, as a UTC timestamp string.
func (s *Service) dayStart(now time.Time) string {
	y, m, d := now.In(s.loc).Date()
	return FormatTS(time.Date(y, m, d, 0, 0, 0, 0, s.loc))
}

// seedMeter loads today's tokens from ai_activity into the meter, per profile id, so the level in
// force and the per-profile caps survive a restart. Usage of a profile that no longer exists counts in the shared total only.
func (s *Service) seedMeter(ctx context.Context) error {
	// By profile id: a rename does not reset a profile's cap, and a new profile that takes an old name does not inherit its usage. A row
	// with no id (the test of a draft that was never saved) counts in the shared total only.
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT COALESCE(profile_id, ''), SUM(tokens_in + tokens_out) FROM ai_activity WHERE ts >= ? AND tokens_in + tokens_out > 0 GROUP BY 1`, s.dayStart(s.cfg.Clock()))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	per := map[string]int{}
	for rows.Next() {
		var id string
		var tokens int
		if err := rows.Scan(&id, &tokens); err != nil {
			return err
		}
		if id == "" {
			id = "unsaved"
		}
		per[id] += tokens
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.meter.Seed(per)
	return nil
}

// TokenSum is a count of tokens.
type TokenSum struct {
	Input  int `json:"input"`
	Output int `json:"output"`
	Total  int `json:"total"`
}

// SkillUsage is the use of one job over the last 30 days.
type SkillUsage struct {
	Skill  string `json:"skill"`
	Runs   int    `json:"runs"`
	Tokens int    `json:"tokens"`
}

// DowngradeView is one automatic drop of the token level.
type DowngradeView struct {
	ID     string `json:"id"`
	TS     string `json:"ts"`
	From   Tier   `json:"from"`
	To     Tier   `json:"to"`
	Reason string `json:"reason"`
}

// UsageView is the token meter: today, 30 days, per job, and the drops of the level.
type UsageView struct {
	Tier       Tier            `json:"tier"`
	DailyCap   int             `json:"daily_cap"`
	Today      TokenSum        `json:"today"`
	Month      TokenSum        `json:"month"`
	BySkill    []SkillUsage    `json:"by_skill"`
	Downgrades []DowngradeView `json:"downgrades"`
}

func (s *Service) sumSince(ctx context.Context, since string) (TokenSum, error) {
	var t TokenSum
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0) FROM ai_activity WHERE ts >= ?`, since).Scan(&t.Input, &t.Output)
	t.Total = t.Input + t.Output
	return t, err
}

// Usage returns the token meter. The tier is the level in force today.
func (s *Service) Usage(ctx context.Context) (UsageView, error) {
	now := s.cfg.Clock()
	v := UsageView{Tier: s.meter.Tier(), DailyCap: s.snap.Load().cfg.DailyCap, BySkill: []SkillUsage{}, Downgrades: []DowngradeView{}}
	var err error
	if v.Today, err = s.sumSince(ctx, s.dayStart(now)); err != nil {
		return UsageView{}, fmt.Errorf("ai: usage: %w", err)
	}
	month := FormatTS(now.Add(-30 * 24 * time.Hour))
	if v.Month, err = s.sumSince(ctx, month); err != nil {
		return UsageView{}, fmt.Errorf("ai: usage: %w", err)
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT job, COUNT(*), SUM(tokens_in + tokens_out) AS t FROM ai_activity WHERE ts >= ? AND result <> 'blocked_by_hook' GROUP BY job ORDER BY t DESC, job`, month)
	if err != nil {
		return UsageView{}, fmt.Errorf("ai: usage by job: %w", err)
	}
	for rows.Next() {
		var u SkillUsage
		if err := rows.Scan(&u.Skill, &u.Runs, &u.Tokens); err != nil {
			_ = rows.Close()
			return UsageView{}, fmt.Errorf("ai: usage by job: %w", err)
		}
		v.BySkill = append(v.BySkill, u)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return UsageView{}, fmt.Errorf("ai: usage by job: %w", err)
	}
	_ = rows.Close()
	dg, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, from_tier, to_tier, reason FROM ai_downgrade ORDER BY ts DESC, id DESC LIMIT 20`)
	if err != nil {
		return UsageView{}, fmt.Errorf("ai: downgrades: %w", err)
	}
	defer func() { _ = dg.Close() }()
	for dg.Next() {
		var d DowngradeView
		if err := dg.Scan(&d.ID, &d.TS, &d.From, &d.To, &d.Reason); err != nil {
			return UsageView{}, fmt.Errorf("ai: downgrades: %w", err)
		}
		v.Downgrades = append(v.Downgrades, d)
	}
	return v, dg.Err()
}

// RunView is one AI call in the log of calls (sent content is not stored).
type RunView struct {
	ID        string `json:"id"`
	TS        string `json:"ts"`
	Skill     string `json:"skill"`
	Model     string `json:"model"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	Status    string `json:"status"` // ok, schema_error or capped
	Profile   string `json:"profile,omitempty"`
	Fallback  bool   `json:"fallback,omitempty"`
}

// Runs returns the last 200 calls, newest first. A call a hook stopped is not an AI call and is left out (it is in the activity log).
// Status: a call that got an answer is ok; one that cost tokens but gave no usable answer is schema_error; one that spent nothing
// (cap reached, no profile could answer) is capped.
func (s *Service) Runs(ctx context.Context) ([]RunView, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, job, model, tokens_in, tokens_out, result, profile FROM ai_activity WHERE result <> 'blocked_by_hook' ORDER BY seq DESC LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("ai: runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []RunView{}
	for rows.Next() {
		var r RunView
		var result string
		if err := rows.Scan(&r.ID, &r.TS, &r.Skill, &r.Model, &r.TokensIn, &r.TokensOut, &result, &r.Profile); err != nil {
			return nil, fmt.Errorf("ai: runs: %w", err)
		}
		switch {
		case result == string(ResultOK) || result == string(ResultFallbackUsed):
			r.Status = "ok"
		case r.TokensIn+r.TokensOut > 0:
			r.Status = "schema_error"
		default:
			r.Status = "capped"
		}
		r.Fallback = result == string(ResultFallbackUsed)
		out = append(out, r)
	}
	return out, rows.Err()
}

package response

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// AI plans, the writing side (S-RESP-1, 13b-11). A job asks the Planner for a plan for each open critical finding that has none, and
// savePlan keeps only what passed the same checks as a rule: a catalog action id and the typed values of its parameters, checked by
// the planner of rules. The AI has no write tool here and no way to reach a device: a plan is text for people plus proposals, and a
// proposal becomes a request only when a person asks for it (RequestProposal) and the request is approved (INV-14e, FORBID-5).

// ErrPlanUnavailable is what a Planner answers when the AI cannot be used now (no usable profile, daily cap). The job stops quietly:
// nothing is wrong, and nothing was spent.
var ErrPlanUnavailable = errors.New("response: the AI cannot make plans now")

const (
	maxPlansPerRun = 3               // plans asked for in one run of the job: a backlog is worked off over several runs, never in one burst of tokens
	planRetry      = time.Hour       // a finding whose plan was refused or failed is asked again after this
	planEvery      = 5 * time.Minute // how often the job looks
	maxPlanSteps   = 6               // steps in a plan
	maxPlanActions = 3               // steps of a plan that carry a proposal
	planPath       = "From the inventory record of the device. No device connection was read."
	planActor      = "ai:response"
)

// PlanTarget is an open critical finding and the device it is on: what the AI is asked about. Facts is untrusted text from the exploited
// list (it reaches the model only as a fenced data block).
type PlanTarget struct {
	FindingID, CVE, AssetID, AssetName, AssetIP, AssetKind string
	Facts                                                  string
}

// DraftParam is one value the AI chose for a parameter of an action.
type DraftParam struct{ Name, Value string }

// DraftStep is one step the AI drafted. ActionID and Params are empty for a step that only advises. Nothing else about a proposal comes
// from the AI: no command, no path, no body, no undo time.
type DraftStep struct {
	Kind, Title, Detail string // Kind is contain, check or patch
	ActionID            string
	Params              []DraftParam
}

// PlanAsk is one call of the Planner: the finding, and the actions the AI may propose (AIActions that are available now).
type PlanAsk struct {
	Target  PlanTarget
	Actions []AIAction
}

// PlanDraft is the AI's answer: the steps, and the model and profile that wrote them (shown on the plan, D-175 L6).
type PlanDraft struct {
	Model, Profile string
	Steps          []DraftStep
}

// Planner is the ai module as this module needs it (cmd/vedette adapts ai.Service.RunJob for the job response-plan). Available is false
// while the ai module is off or no profile is assigned and allowed for the job; then the job asks nothing. Plan answers ErrPlanUnavailable
// when the AI cannot be used after all. A nil Planner means no plan is ever written; everything else in this module works.
type Planner interface {
	Available(ctx context.Context) bool
	Plan(ctx context.Context, a PlanAsk) (PlanDraft, error)
}

// aiAvailable is the ai_available of GET /response/plans.
func (s *Service) aiAvailable(ctx context.Context) bool {
	return s.on() && s.cfg.Planner != nil && s.cfg.Planner.Available(ctx)
}

// PlanOpen is one run of the plan job: for each open critical finding without a plan (at most maxPlansPerRun) it asks the Planner and
// saves the plan if it passes. It returns how many plans were saved. With the module off, no Planner, or the AI not available it does
// nothing and asks nothing.
func (s *Service) PlanOpen(ctx context.Context) (int, error) {
	if !s.aiAvailable(ctx) || s.cfg.Critical == nil {
		return 0, nil
	}
	targets, err := s.cfg.Critical(ctx)
	if err != nil {
		return 0, fmt.Errorf("response: list the open critical findings: %w", err)
	}
	have := map[string]bool{}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT finding_id FROM resp_plans`)
	if err != nil {
		return 0, fmt.Errorf("response: read the plans: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		have[id] = true
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	saved := 0
	var actions []AIAction
	asked := 0
	for _, t := range targets {
		if have[t.FindingID] || s.recentlyTried(t.FindingID) {
			continue
		}
		if asked >= maxPlansPerRun {
			break
		}
		if actions == nil {
			all, err := s.AIActions(ctx)
			if err != nil {
				return saved, err
			}
			actions = []AIAction{}
			for _, a := range all {
				if a.Available {
					actions = append(actions, a)
				}
			}
		}
		asked++
		s.markTried(t.FindingID)
		d, err := s.cfg.Planner.Plan(ctx, PlanAsk{Target: t, Actions: actions})
		if errors.Is(err, ErrPlanUnavailable) {
			return saved, nil
		}
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "response: the AI could not make a plan", "finding", t.FindingID, "error", err)
			continue
		}
		ok, err := s.savePlan(ctx, t, d)
		if err != nil {
			return saved, err
		}
		if ok {
			saved++
		}
	}
	return saved, nil
}

func (s *Service) recentlyTried(id string) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	t, ok := s.planTried[id]
	return ok && s.now().Sub(t) < planRetry
}

func (s *Service) markTried(id string) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.planTried == nil || len(s.planTried) > 2000 {
		s.planTried = map[string]time.Time{}
	}
	s.planTried[id] = s.now()
}

// savePlan checks the draft and, if it passes, stores it; if not, nothing is stored and the refusal is written to the log and the audit
// (INV-19, FORBID-5). It returns whether a plan was stored.
func (s *Service) savePlan(ctx context.Context, t PlanTarget, d PlanDraft) (bool, error) {
	saved := false
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM resp_plans WHERE finding_id = ?`, t.FindingID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		cats, err := s.cats(ctx, tx)
		if err != nil {
			return err
		}
		cs, err := s.loadConns(ctx)
		if err != nil {
			return err
		}
		never, nt, err := s.neverTouchOrRefusal(ctx, tx)
		if err != nil {
			return err
		}
		var steps []storedStep
		reason := ""
		if nt != nil {
			reason = "the never-touch list cannot be read"
		} else {
			steps, reason = s.checkDraft(t, d, cats, cs, never)
		}
		if reason != "" {
			return s.step(ctx, tx, "response.plan_refused", t.FindingID, LogRefused, "plan_invalid: AI plan for "+t.CVE+" refused, nothing stored: "+reason, planActor)
		}
		id := newID("plan")
		why := t.CVE + " on " + t.AssetName
		if err := s.step(ctx, tx, "response.plan", id, LogProposal, "AI-generated plan stored for "+why+" ("+fmt.Sprint(len(steps))+" steps); nothing is requested until a person asks", planActor); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES (?,?,?,?,?,?,?,?,?,'[]',?)`,
			id, t.FindingID, t.CVE, t.AssetID, oneLine(t.AssetName, 120), s.ts(), oneLine(d.Model, 120), oneLine(d.Profile, 120), planPath, mustJSON(steps))
		saved = err == nil
		return err
	})
	if err != nil {
		return false, fmt.Errorf("response: store a plan: %w", err)
	}
	return saved, nil
}

// checkDraft turns a draft into stored steps, or says why it cannot. Everything of a proposal that is kept comes from the catalog and from
// CheckValues: the action id must be a catalog action that is enabled and allowed for the AI, the parameter names must be exactly the
// ones the action takes, and the values go through the planner of rules (type check, escaping, never-touch of the device, connection). The
// values stored are the checked ones; the undo time is the server's (as in Propose), never the AI's.
func (s *Service) checkDraft(t PlanTarget, d PlanDraft, cats map[string]catRow, cs conns, never []AllowEntry) ([]storedStep, string) {
	if len(d.Steps) == 0 || len(d.Steps) > maxPlanSteps {
		return nil, fmt.Sprintf("a plan has 1 to %d steps, this one has %d", maxPlanSteps, len(d.Steps))
	}
	var out []storedStep
	actions := 0
	why := t.CVE + " on " + t.AssetName
	for i, x := range d.Steps {
		if !slices.Contains([]string{"contain", "check", "patch"}, x.Kind) {
			return nil, fmt.Sprintf("step %d has an unknown kind", i+1)
		}
		st := storedStep{Kind: x.Kind, Title: oneLine(x.Title, 120), Detail: oneLine(x.Detail, 600)}
		if st.Title == "" || st.Detail == "" {
			return nil, fmt.Sprintf("step %d has no title or no text", i+1)
		}
		if x.ActionID != "" {
			if x.Kind != "contain" {
				return nil, fmt.Sprintf("step %d proposes an action but is not a contain step", i+1)
			}
			if actions++; actions > maxPlanActions {
				return nil, fmt.Sprintf("a plan proposes at most %d actions", maxPlanActions)
			}
			cat, ok := cats[x.ActionID]
			if !ok || !cat.Enabled || !cat.AIMayPropose {
				return nil, "step " + fmt.Sprint(i+1) + " names an action that is not in the catalog or not allowed for the AI: " + oneLine(x.ActionID, 60)
			}
			names := map[string]bool{}
			for _, p := range cat.params() {
				names[string(p)] = true
			}
			params := map[string]string{}
			for _, p := range x.Params {
				if !names[p.Name] {
					return nil, "step " + fmt.Sprint(i+1) + " gives a parameter the action does not take: " + oneLine(p.Name, 40)
				}
				if _, dup := params[p.Name]; dup {
					return nil, "step " + fmt.Sprint(i+1) + " gives a parameter twice: " + p.Name
				}
				params[p.Name] = p.Value
			}
			prop := storedProposal{ID: newID("pr"), ActionID: cat.ID, Params: params, AssetID: t.AssetID, AssetName: oneLine(t.AssetName, 120)}
			if cat.reversible() {
				ttl := 1440
				prop.TTLMin = &ttl
			}
			pl, f := s.planProposal(prop, t.AssetIP, why, cats, cs, never)
			if f != nil {
				return nil, "step " + fmt.Sprint(i+1) + " cannot be planned (" + f.code + "): " + oneLine(f.msg, 200)
			}
			checked := map[string]string{}
			for p, v := range pl.rec.Values {
				checked[string(p)] = v
			}
			prop.Params = checked
			st.Proposal = &prop
		} else if len(x.Params) > 0 {
			return nil, fmt.Sprintf("step %d gives parameters without an action", i+1)
		}
		out = append(out, st)
	}
	return out, ""
}

// planJob is the job of the plan writer.
func (s *Service) planJob() jobs.Job {
	return jobs.Job{Module: ModuleID, Name: "plan", Every: planEvery, Run: func(ctx context.Context) error {
		_, err := s.PlanOpen(ctx)
		return err
	}}
}

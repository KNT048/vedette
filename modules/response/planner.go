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
	maxPlansPerRun  = 3               // plans asked for in one run of the job: a backlog is worked off over several runs, never in one burst of tokens
	maxPlanCallsDay = 20              // plan calls in one UTC day: the daily AI cap is shared with Explain, Ask and the reports (D-181)
	planEvery       = 5 * time.Minute // how often the job looks
	maxPlanSteps    = 6               // steps in a plan
	maxPlanActions  = 3               // steps of a plan that carry a proposal
	planPath        = "From the inventory record of the device. No device connection was read."
	planActor       = "ai:response"
)

// PlanTarget is an open critical finding and the device it is on: what the AI is asked about.
type PlanTarget struct {
	FindingID, CVE, AssetID, AssetName, AssetIP, AssetKind string
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
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return 0, err
	}
	if checkAIPaused(st) != nil { // the quality breaker paused the AI (INV-15 (3)): no plan is asked for either
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
		if have[t.FindingID] || s.backedOff(t.FindingID) {
			continue
		}
		if asked >= maxPlansPerRun || !s.planCall(false) {
			break
		}
		if actions == nil {
			all, err := s.AIActions(ctx)
			if err != nil {
				return saved, err
			}
			actions = []AIAction{}
			for _, a := range all {
				// An action whose only value is free text (msg_send) is not offered: nothing ties it to the device, Propose does not take it from the
				// AI either (D-119), and a model that picks it writes text the type check refuses, which costs the whole plan.
				if a.Available && slices.ContainsFunc(a.Params, func(p AIParam) bool { return p.Type != string(PText) }) {
					actions = append(actions, a)
				}
			}
		}
		asked++
		s.planCall(true)
		d, err := s.cfg.Planner.Plan(ctx, PlanAsk{Target: t, Actions: actions})
		if errors.Is(err, ErrPlanUnavailable) {
			return saved, nil
		}
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "response: the AI could not make a plan", "finding", t.FindingID, "error", err)
			s.planFailed(t.FindingID)
			continue
		}
		ok, err := s.savePlan(ctx, t, d)
		if err != nil {
			return saved, err
		}
		if ok {
			saved++
		} else {
			s.planFailed(t.FindingID)
		}
	}
	return saved, nil
}

// planBackoff is how long a finding waits after its 1st, 2nd and 3rd failed or refused plan; after the 4th it is not asked again.
// ponytail: the counters live in memory, so a restart starts them again (the shared daily cap of the ai module bounds what that can
// cost); a table is the upgrade if restarts turn out to be frequent.
var planBackoff = []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour}

type planAttempt struct {
	n  int
	at time.Time
}

func (s *Service) backedOff(id string) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	f, ok := s.planFails[id]
	if !ok {
		return false
	}
	return f.n > len(planBackoff) || s.now().Sub(f.at) < planBackoff[f.n-1]
}

func (s *Service) planFailed(id string) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.planFails == nil || len(s.planFails) > 2000 {
		s.planFails = map[string]planAttempt{}
	}
	f := s.planFails[id]
	s.planFails[id] = planAttempt{n: f.n + 1, at: s.now()}
}

// planCall says whether another plan call fits today's budget; count=true also counts one.
func (s *Service) planCall(count bool) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	day := s.now().UTC().Format("2006-01-02")
	if s.planDay != day {
		s.planDay, s.planCalls = day, 0
	}
	if s.planCalls >= maxPlanCallsDay {
		return false
	}
	if count {
		s.planCalls++
	}
	return true
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
		st := storedStep{Kind: x.Kind, Title: truncRunes(cleanLine(x.Title), 120), Detail: truncRunes(cleanLine(x.Detail), 600)}
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
			if why := aboutTheDevice(Values(pl.rec.Values), cat, t.AssetIP, t.AssetName); why != "" {
				return nil, "step " + fmt.Sprint(i+1) + ": " + why
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

// aboutTheDevice is the evidence gate of Propose (INV-15 (3), D-119) for a plan: the values of an action must be about the device the
// finding is on (its address or its name), and an action that names a device part, or no address, needs that device's address for the
// never-touch check. Only an action with no target at all (every value is free text) is exempt. "" = passes. The same words refuse a
// proposal again when it is requested, against the inventory's own word about the device.
func aboutTheDevice(vals Values, cat catRow, ip, name string) string {
	if !slices.ContainsFunc(cat.params(), func(p ParamType) bool { return p != PText }) {
		return ""
	}
	if ip == "" && (!namesAnAddress(vals) || namesADevicePart(vals)) {
		return "no address is known for the device of the finding, so the never-touch list cannot be checked for this action (never_touch)"
	}
	f := foundEvidence{names: []string{name}}
	if ip != "" {
		f.relates = []string{ip}
	}
	if !f.relatesTo(vals, cat) {
		return "the action is not about the device of the finding (evidence_mismatch): its target is neither that address nor that name"
	}
	return ""
}

// planJob is the job of the plan writer.
func (s *Service) planJob() jobs.Job {
	return jobs.Job{Module: ModuleID, Name: "plan", Every: planEvery, Run: func(ctx context.Context) error {
		_, err := s.PlanOpen(ctx)
		return err
	}}
}

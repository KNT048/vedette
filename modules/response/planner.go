package response

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// AI plans, the writing side (S-RESP-1, 13b-11). A job asks the Planner for a plan for each open critical finding that has none, and
// savePlan keeps only what passed the same checks as a rule: a catalog action id and the typed values of its parameters, checked by
// the planner of rules. The AI has no write tool here and no way to reach a device: a plan is text for people plus proposals, and a
// proposal becomes a request only when a person asks for it (RequestProposal) and the request is approved (INV-14e, FORBID-5).

// ErrPlanUnavailable is what a Planner answers when the AI cannot be used now (no usable profile, or this month's AI budget is used up).
// The run stops: nothing is wrong here, nothing was spent, and a used-up budget is not quiet: the ai module puts it on Home and sends it
// to the alert channels (D-531).
var ErrPlanUnavailable = errors.New("response: the AI cannot make plans now")

const (
	maxPlansPerRun  = 3               // plans asked for in one run of the job: a backlog is worked off over several runs, never in one burst of tokens; with planEvery this is the job's burst fuse, not a quota (D-531: no daily cap of its own, the monthly AI budget is the limit)
	planEvery       = 5 * time.Minute // how often the job looks
	maxPlanSteps    = 6               // steps in a plan
	maxPlanActions  = 3               // steps of a plan that carry a proposal
	maxPlanEvidence = 3               // reads one proposal of a plan may cite
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
// from the AI: no command, no path, no body, no undo time. Confidence (0 to 1) and Evidence (ids of reads the box made, listed to the
// AI) are used only when the proposal is sent through Propose (D-310); they are not stored with the plan (INV-14e).
type DraftStep struct {
	Kind, Title, Detail string // Kind is contain, check or patch
	ActionID            string
	Params              []DraftParam
	Confidence          float64
	Evidence            []string
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
// when the AI cannot be used after all. Proposed is told what the job sent through Propose for a stored plan and what came of it, for
// the activity log of the ai module (D-312); it is not called when nothing was sent. A nil Planner means no plan is ever written;
// everything else in this module works.
type Planner interface {
	Available(ctx context.Context) bool
	Plan(ctx context.Context, a PlanAsk) (PlanDraft, error)
	Proposed(ctx context.Context, t PlanTarget, sent []SentProposal)
}

// SentProposal is one proposal of a stored plan that the plan job sent through Propose, and its outcome: request, suggestion or digest,
// or the code of the refusal. RequestID is set for a request.
type SentProposal struct {
	ProposalID, ActionID, Outcome, RequestID string
}

// aiAvailable is the ai_available of GET /response/plans.
func (s *Service) aiAvailable(ctx context.Context) bool {
	return s.on() && s.cfg.Planner != nil && s.cfg.Planner.Available(ctx)
}

// PlanOpen is one run of the plan job: for each open critical finding without a plan (at most maxPlansPerRun) it asks the Planner and
// saves the plan if it passes. It returns how many plans were saved. With the module off, no Planner, or the AI not available it does
// nothing and asks nothing.
func (s *Service) PlanOpen(ctx context.Context) (int, error) {
	if !s.on() || s.cfg.Critical == nil {
		return 0, nil
	}
	ran := s.ts()
	status := PlannerStatus{RanAt: &ran, Findings: []PlannerFinding{}}
	defer func() { s.keepStatus(status) }() // what this run did, for GET /response/plans (D-513); read-only
	if !s.aiAvailable(ctx) {
		status.Blocked = PlannerNoAI
		return 0, nil
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return 0, err
	}
	if checkAIPaused(st) != nil { // the quality breaker paused the AI (INV-15 (3)): no plan is asked for either
		status.Blocked = PlannerAIPaused
		return 0, nil
	}
	// The proposals of a new plan are also sent as AI requests when the admin lets the AI send requests for the finding trigger and the
	// execution switch is on (off by default, INV-7): with it off, no request could run, and a person's RequestProposal is refused too
	// (D-314).
	send := st.Execution && slices.Contains(st.AI.Triggers, "finding")
	status.Sending = send
	targets, err := s.cfg.Critical(ctx)
	if err != nil {
		return 0, fmt.Errorf("response: list the open critical findings: %w", err)
	}
	status.Considered = len(targets)
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
	stopped := ""
	for _, t := range targets {
		switch {
		case stopped != "":
			status.add(t, OutcomeAIUnavailable, stopped)
			continue
		case have[t.FindingID]:
			status.add(t, OutcomeHasPlan, "A plan was written for it on an earlier run (one plan per finding): its actions, and any request made from them, are in the plan below and in the Response log.")
			continue
		case s.backedOff(t.FindingID):
			status.add(t, OutcomeBackedOff, s.backoffReason(t.FindingID))
			continue
		case asked >= maxPlansPerRun:
			status.add(t, OutcomeLater, "Waiting for a later run: the AI is asked about at most 3 findings per run, every 5 minutes.")
			continue
		}
		if actions == nil {
			all, err := s.AIActions(ctx)
			if err != nil {
				return saved, err
			}
			actions = []AIAction{}
			for _, a := range all {
				// Only actions the gate can accept are offered: every value an address (aboutTheDevice); the rest could never pass and would cost the plan.
				if a.Available && offerable(paramTypes(a.Params)) {
					actions = append(actions, a)
				}
			}
		}
		asked++
		status.Asked = asked
		d, err := s.cfg.Planner.Plan(ctx, PlanAsk{Target: t, Actions: offeredFor(actions, t)})
		if errors.Is(err, ErrPlanUnavailable) {
			// the sentence of the ai module (budget used up, a fuse), never the provider's text; the rest of this run is not asked either
			stopped = "The AI cannot be used now (this month's AI budget, or a fuse of the AI module), so this run stopped."
			if why := strings.TrimPrefix(strings.TrimPrefix(err.Error(), ErrPlanUnavailable.Error()), ": "); why != "" && why != err.Error() {
				stopped = "The AI cannot be used now, so this run stopped: " + why
			}
			status.add(t, OutcomeAIUnavailable, stopped)
			continue
		}
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "response: the AI could not make a plan", "finding", t.FindingID, "error", err)
			s.planFailed(t.FindingID)
			status.add(t, OutcomeAIFailed, "The AI call failed or its answer could not be read (see AI activity); it is asked again after 1 hour.")
			continue
		}
		steps, why, err := s.savePlan(ctx, t, d)
		if err != nil {
			return saved, err
		}
		if steps == nil {
			s.planFailed(t.FindingID)
			if why == "" { // another run stored a plan for it first
				status.add(t, OutcomeHasPlan, "A plan was written for it at the same time by another run.")
				continue
			}
			status.add(t, OutcomePlanRefused, "The AI's plan failed the checks and was not stored: "+why)
			continue
		}
		saved++
		if !slices.ContainsFunc(steps, func(x storedStep) bool { return x.Proposal != nil }) {
			status.add(t, OutcomeNoAction, s.noActionReason(ctx, t, offeredFor(actions, t)))
			continue
		}
		if !send {
			status.add(t, OutcomeNotSent, notSentReason(st))
			continue
		}
		notes, err := s.sendPlan(ctx, t, d, steps, offeredFor(actions, t))
		if err != nil {
			return saved, err
		}
		if len(notes) == 0 { // the switch was turned off while the AI wrote the plan
			status.add(t, OutcomeNotSent, "The plan was stored, but sending was turned off while the AI wrote it.")
			continue
		}
		o, why := sentReason(notes)
		if o == OutcomeProposed {
			status.Proposed++
		}
		status.add(t, o, why)
	}
	return saved, nil
}

// offeredFor is the actions offered for one target: the block list action only when the device's address is one the list can publish
// (D-469). A plan for a LAN device that proposed it would be refused whole (not_publishable), cost the plan and back the finding off.
func offeredFor(actions []AIAction, t PlanTarget) []AIAction {
	a, err := netip.ParseAddr(t.AssetIP)
	if err == nil && publishable(a) {
		return actions
	}
	return slices.DeleteFunc(slices.Clone(actions), func(x AIAction) bool { return x.ID == "blocklist_add" })
}

// sendPlan sends each proposal of a plan just stored through Propose, as the AI (ai:response, D-310): the trigger is the finding, the
// evidence is the finding and the reads the AI cited (citedReads), the confidence is the AI's. Every gate of INV-15 runs there, so a
// refusal is logged by Propose and is the end of it: nothing is retried. Only an error that is not a refusal (the database) stops the
// run. The settings are read again first: the switch may have been turned off while the AI was writing the plan.
func (s *Service) sendPlan(ctx context.Context, t PlanTarget, d PlanDraft, steps []storedStep, offered []AIAction) ([]sentNote, error) {
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	if !st.Execution || !slices.Contains(st.AI.Triggers, "finding") || checkAIPaused(st) != nil {
		return nil, nil
	}
	var sent []SentProposal
	var notes []sentNote // for the planner status (D-513): the outcome and the box's sentence about it
	for i, step := range steps {
		if step.Proposal == nil {
			continue
		}
		x := d.Steps[i] // savePlan keeps every step, in order
		ev := append([]ProposedEvidence{{Kind: EvFinding, ID: t.FindingID}}, s.citedReads(ctx, x.Evidence, offered, step.Proposal.ActionID)...)
		why := truncRunes(cleanLine(t.CVE+" on "+t.AssetName+": "+step.Title), maxProposeWhy)
		res, err := s.Propose(ctx, ProposeBody{Trigger: "finding", ActionID: step.Proposal.ActionID, Params: step.Proposal.Params, Confidence: x.Confidence, Evidence: ev, Why: why})
		sp := SentProposal{ProposalID: step.Proposal.ID, ActionID: step.Proposal.ActionID, Outcome: res.Outcome}
		note := sentNote{outcome: res.Outcome, note: res.Note}
		if err != nil {
			ae, ok := asAPI(err)
			if !ok {
				return nil, err
			}
			sp.Outcome = ae.Code
			note = sentNote{outcome: ae.Code, note: "Refused (" + ae.Code + "): " + ae.Message}
		} else if res.Request != nil {
			sp.RequestID = res.Request.ID
			note.note = "Sent to the inbox for approval."
		}
		sent = append(sent, sp)
		notes = append(notes, note)
	}
	if len(sent) > 0 {
		s.cfg.Planner.Proposed(ctx, t, sent)
	}
	return notes, nil
}

// citedReads keeps, of the reads the AI cited for a proposal, those the box recorded through the connection of that action (D-313):
// a read of another connection could not count and would only look like support to the people who approve, and an id the box has no
// record of would refuse a proposal the finding alone may carry. For a high-risk action no read is kept: a read is not about the
// target, so it must not make the second check (two pieces of evidence about the target, INV-15 (9)) out of one finding and any
// read of the same device by anyone in the last day; a high-risk action from a plan then needs a person (RequestProposal).
func (s *Service) citedReads(ctx context.Context, ids []string, offered []AIAction, actionID string) []ProposedEvidence {
	i := slices.IndexFunc(offered, func(a AIAction) bool { return a.ID == actionID })
	port := s.cfg.Evidence.ConfigRead
	if i < 0 || offered[i].ConnectionID == "" || offered[i].Risk == RiskHigh || port == nil {
		return nil
	}
	var out []ProposedEvidence
	for _, id := range ids {
		if ref, ok, err := port(ctx, id); err == nil && ok && cleanLine(ref.Connection) == offered[i].ConnectionID {
			out = append(out, ProposedEvidence{Kind: EvConfigRead, ID: id})
		}
	}
	return out
}

// planBackoff is how long a finding waits after its 1st, 2nd and 3rd failed or refused plan; after the 4th it is not asked again.
// ponytail: the counters live in memory, so a restart starts them again (the monthly AI budget and the runaway fuse of the ai module
// bound what that can cost, D-531); a table is the upgrade if restarts turn out to be frequent.
// planEvidenceRE is the form of the id of a read the AI cites (the ai module's ids); Propose looks every one up again.
var planEvidenceRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

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

// savePlan checks the draft and, if it passes, stores it; if not, nothing is stored and the refusal is written to the log and the audit
// (INV-19, FORBID-5). It returns the stored steps (one per step of the draft, in order), or nil and the reason when no plan was stored.
func (s *Service) savePlan(ctx context.Context, t PlanTarget, d PlanDraft) ([]storedStep, string, error) {
	var saved []storedStep
	refusal := ""
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
			refusal = reason
			return s.step(ctx, tx, "response.plan_refused", t.FindingID, LogRefused, "plan_invalid: AI plan for "+t.CVE+" refused, nothing stored: "+reason, planActor)
		}
		id := newID("plan")
		why := t.CVE + " on " + t.AssetName
		if err := s.step(ctx, tx, "response.plan", id, LogProposal, "AI-generated plan stored for "+why+" ("+fmt.Sprint(len(steps))+" steps); nothing is requested until a person asks", planActor); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES (?,?,?,?,?,?,?,?,?,'[]',?)`,
			id, t.FindingID, t.CVE, t.AssetID, oneLine(t.AssetName, 120), s.ts(), oneLine(d.Model, 120), oneLine(d.Profile, 120), planPath, mustJSON(steps))
		if err == nil {
			saved = steps
		}
		return err
	})
	if err != nil {
		return nil, "", fmt.Errorf("response: store a plan: %w", err)
	}
	return saved, refusal, nil
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
			if why := aboutTheDevice(Values(pl.rec.Values), cat, t.AssetIP); why != "" {
				return nil, "step " + fmt.Sprint(i+1) + ": " + why
			}
			checked := map[string]string{}
			for p, v := range pl.rec.Values {
				checked[string(p)] = v
			}
			prop.Params = checked
			st.Proposal = &prop
			if math.IsNaN(x.Confidence) || x.Confidence < 0 || x.Confidence > 1 {
				return nil, fmt.Sprintf("step %d gives a confidence that is not a number from 0 to 1", i+1)
			}
			if len(x.Evidence) > maxPlanEvidence {
				return nil, fmt.Sprintf("step %d cites more than %d reads", i+1, maxPlanEvidence)
			}
			for _, id := range x.Evidence {
				if !planEvidenceRE.MatchString(id) {
					return nil, fmt.Sprintf("step %d cites a read whose id is not valid", i+1)
				}
			}
		} else if len(x.Params) > 0 || len(x.Evidence) > 0 {
			return nil, fmt.Sprintf("step %d gives parameters or evidence without an action", i+1)
		}
		out = append(out, st)
	}
	return out, ""
}

// aboutTheDevice is the evidence gate of Propose (INV-15 (3), D-119) for a plan, made stricter because nothing but the inventory ties a value
// to the device: EVERY value of the action must be the address of the device the finding is on, nothing else. A name is not accepted
// (names are self-announced by the device and fold Unicode), nor a CIDR, interface, MAC, VLAN, port or id, until evidence can tie them
// to the device; an action with only free-text values is refused too (plans send no messages). "" = passes. The same words refuse a
// proposal again when it is requested, against the inventory's own word about the device.
func aboutTheDevice(vals Values, cat catRow, ip string) string {
	if ip == "" {
		return "no address is known for the device of the finding, so the never-touch list cannot be checked for this action (never_touch)"
	}
	if !offerable(cat.params()) {
		return "the action takes values that nothing can tie to the device of the finding, or only free text (evidence_mismatch); a plan proposes only actions on the address of that device"
	}
	f := foundEvidence{relates: []string{ip}}
	for p, v := range vals {
		if p != PIP || !f.relatesTo(Values{p: v}, cat) {
			return "the action is not about the device of the finding (evidence_mismatch): every value must be the address of that device"
		}
	}
	return ""
}

// offerable says whether an action can pass aboutTheDevice at all: it takes at least one value and every value is an address.
func offerable(ps []ParamType) bool {
	return len(ps) > 0 && !slices.ContainsFunc(ps, func(p ParamType) bool { return p != PIP })
}

// planJob is the job of the plan writer.
func (s *Service) planJob() jobs.Job {
	return jobs.Job{Module: ModuleID, Name: "plan", Every: planEvery, Run: func(ctx context.Context) error {
		_, err := s.PlanOpen(ctx)
		return err
	}}
}

func paramTypes(ps []AIParam) []ParamType {
	out := make([]ParamType, len(ps))
	for i, p := range ps {
		out[i] = ParamType(p.Type)
	}
	return out
}

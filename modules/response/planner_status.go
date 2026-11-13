package response

import (
	"context"
	"net/netip"
	"slices"
	"strings"
)

// What the plan job did on its last run (item 20, S-RESP-2, D-513): read-only, so an empty inbox of proposals says why. Every reason is
// one of the job's own decision points in PlanOpen and sendPlan; nothing here changes what the job does.
// ponytail: kept in memory, so a restart shows "not run yet" until the next run (at most planEvery later); a table is the upgrade if
// people need the history.

// Blocked of a run that asked nothing at all.
const (
	PlannerNoAI     = "no_ai"     // no usable AI profile for the job, or the ai module is off
	PlannerAIPaused = "ai_paused" // the quality breaker paused AI proposals (INV-15)
)

// Outcome of one finding on the last run.
const (
	OutcomeProposed      = "proposed"       // a request was sent to the inbox
	OutcomeNoted         = "noted"          // a suggestion or digest note, no request (confidence below 0.8, or the AI budget per hour/day)
	OutcomeRefused       = "refused"        // a gate of Propose refused every proposal of the plan
	OutcomeNotSent       = "not_sent"       // the plan was stored; its proposals were not sent (switch off, or the finding trigger not allowed)
	OutcomeNoAction      = "no_action"      // the plan was stored without a proposal
	OutcomePlanRefused   = "plan_refused"   // the AI's plan failed the checks and was not stored
	OutcomeAIFailed      = "ai_failed"      // the AI call failed
	OutcomeAIUnavailable = "ai_unavailable" // the AI could not be used now (budget used up, a fuse): the run stopped
	OutcomeHasPlan       = "has_plan"       // a plan was written on an earlier run; one plan per finding
	OutcomeBackedOff     = "backed_off"     // waiting after failed or refused plans
	OutcomeLater         = "later"          // more findings than one run asks about
)

const maxStatusFindings = 20 // findings listed; the counts cover all of them

// PlannerStatus is the planner of GET /response/plans.
type PlannerStatus struct {
	RanAt      *string          `json:"ran_at"`
	Blocked    string           `json:"blocked"`
	Sending    bool             `json:"sending"`
	Considered int              `json:"considered"`
	Asked      int              `json:"asked"`
	Proposed   int              `json:"proposed"`
	Findings   []PlannerFinding `json:"findings"`
}

// PlannerFinding is what happened to one open critical finding on the last run.
type PlannerFinding struct {
	FindingID string `json:"finding_id"`
	CVE       string `json:"cve"`
	AssetName string `json:"asset_name"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason"`
}

func (st *PlannerStatus) add(t PlanTarget, outcome, reason string) {
	if len(st.Findings) < maxStatusFindings {
		st.Findings = append(st.Findings, PlannerFinding{FindingID: t.FindingID, CVE: t.CVE, AssetName: oneLine(t.AssetName, 120), Outcome: outcome, Reason: truncRunes(cleanLine(reason), 400)})
	}
}

func (s *Service) keepStatus(st PlannerStatus) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	s.planStatus = &st
}

// plannerStatus is a copy of the last run's status; a box that has not run the job yet answers ran_at null.
func (s *Service) plannerStatus() PlannerStatus {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.planStatus == nil {
		return PlannerStatus{Findings: []PlannerFinding{}}
	}
	st := *s.planStatus
	st.Findings = slices.Clone(st.Findings)
	return st
}

// backoffReason says when a backed-off finding is asked again.
func (s *Service) backoffReason(id string) string {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	f := s.planFails[id]
	if f.n > len(planBackoff) {
		return "Not asked again: the AI's last 4 plans for it failed or were refused (the reasons are in the Response log)."
	}
	return "The AI's last plan for it failed or was refused; it is asked again after " + f.at.Add(planBackoff[max(f.n, 1)-1]).UTC().Format("2006-01-02 15:04 UTC") + "."
}

// notSentReason is why the proposals of a stored plan were not sent (D-314).
func notSentReason(st Settings) string {
	if !st.Execution {
		return "The plan was stored, but the execution switch is off, so the AI sends no request. Turn it on in Response, Settings (high risk), or ask for approval of its actions from the plan."
	}
	return "The plan was stored, but the AI may not send requests for critical findings (Response, Settings, AI requests). Ask for approval of its actions from the plan."
}

// sentReason sums up what Propose answered for the proposals of one plan.
func sentReason(sent []sentNote) (string, string) {
	outcome := OutcomeRefused
	var why []string
	for _, x := range sent {
		switch {
		case x.outcome == OutcomeRequest:
			outcome = OutcomeProposed
		case (x.outcome == OutcomeSuggestion || x.outcome == OutcomeDigest) && outcome == OutcomeRefused:
			outcome = OutcomeNoted
		}
		if x.note != "" && !slices.Contains(why, x.note) {
			why = append(why, x.note)
		}
	}
	return outcome, strings.Join(why, " ")
}

type sentNote struct{ outcome, note string }

// noActionReason says why a stored plan carries no proposal: nothing could be offered for the device, or the AI chose none.
func (s *Service) noActionReason(ctx context.Context, t PlanTarget, offered []AIAction) string {
	if len(offered) > 0 {
		return "The AI proposed no action: in its view none of the " + itoa(len(offered)) + " actions it may propose fits this device."
	}
	rows, err := loadCatalog(ctx, s.cfg.DB.Reader())
	if err != nil {
		return "No action the AI may propose can be used for this device."
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return "No action the AI may propose can be used for this device."
	}
	var gaps []string
	lan := false
	for _, c := range rows {
		if !c.Enabled || !c.AIMayPropose || !offerable(c.params()) {
			continue
		}
		if c.ID == "blocklist_add" {
			if a, err := netip.ParseAddr(t.AssetIP); err != nil || !publishable(a) {
				lan = true
			}
			continue
		}
		if why := unavailable(c, cs); why != "" && len(gaps) < 3 {
			gaps = append(gaps, oneLine(c.Name, 80)+": "+strings.TrimRight(why, ".")+".")
		}
	}
	out := "No action the AI may propose can be used for this device."
	if lan {
		out += " The block list publishes public addresses only, and this device is on your network (D-469)."
	}
	if len(gaps) > 0 {
		return out + " " + strings.Join(gaps, " ")
	}
	if !lan {
		out += " Connect a firewall or switch (Settings, Connections), choose it for a block action and let the AI propose that action (Response, Actions)."
	}
	return out
}

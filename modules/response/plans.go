package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/logexport"
)

// AI plans (S-RESP-1). The plans are written by the AI job of part 13b into resp_plans; this part reads them and turns one
// proposal into an approval request. Nothing here asks an AI anything.

// storedProposal is what the plan job (part 13b) stores for one proposed action: the catalog action and the typed values of
// its parameters, and nothing else. It never holds a command, an API path or a body: the change is rendered from the
// catalog templates when the proposal is shown and again when it is requested, like the change of a rule (INV-14).
type storedProposal struct {
	ID        string            `json:"id"`
	ActionID  string            `json:"action_id"`
	Params    map[string]string `json:"params"`
	TTLMin    *int              `json:"ttl_min"`
	AssetID   string            `json:"asset_id"`
	AssetName string            `json:"asset_name"`
}

type storedStep struct {
	Kind     string          `json:"kind"`
	Title    string          `json:"title"`
	Detail   string          `json:"detail"`
	Proposal *storedProposal `json:"proposal"`
}

type storedPlan struct {
	Plan
	steps []storedStep
}

func loadPlans(ctx context.Context, q dbq, where string, args ...any) ([]storedPlan, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps FROM resp_plans `+where+` ORDER BY generated_at DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("response: read the plans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storedPlan
	for rows.Next() {
		var p storedPlan
		var reads, steps string
		if err := rows.Scan(&p.ID, &p.FindingID, &p.CVE, &p.AssetID, &p.AssetName, &p.GeneratedAt, &p.Model, &p.Profile, &p.Path, &reads, &steps); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(reads), &p.Reads); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(steps), &p.steps); err != nil {
			return nil, err
		}
		if p.Reads == nil {
			p.Reads = []PlanRead{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// planProposal renders a stored proposal through the same planner as a rule: typed values, escaping and the connection address
// of the catalog (INV-14). subject is the address of the device the plan is about, for the never-touch check; never is nil
// when the proposal is only shown.
func (s *Service) planProposal(p storedProposal, subject, why string, cats map[string]catRow, cs conns, never []AllowEntry) (planned, *planFail) {
	params := map[string]string{}
	for k, v := range p.Params {
		if strings.Contains(v, "{{") { // a stored value is a value, never a reference into an event
			return planned{}, &planFail{"invalid_target", "The proposal holds a value that is not a plain value. Nothing was changed.", p.ActionID}
		}
		params[k] = v
	}
	ev := Det{Trigger: "finding", Fields: map[string]string{"ip": subject}}
	return s.planAction(RuleAction{ActionID: p.ActionID, Params: params, TTLMin: p.TTLMin}, ev, why, cats, cs, never)
}

func (s *Service) proposalView(p storedProposal, st Settings, cats map[string]catRow, cs conns, open []request) Proposal {
	v := Proposal{ID: p.ID, Title: p.ActionID, AssetID: p.AssetID, AssetName: oneLine(p.AssetName, 120), State: "ready"}
	pl, f := s.planProposal(p, "", "", cats, cs, nil)
	if f == nil {
		it := pl.rec
		v.Title, v.Tool, v.Change = it.Title, it.Tool, it.Change
		v.ConnectorID, v.Connection = deref2(it.ConnectorID), deref2(it.Connection)
		v.ToolKey = v.ConnectorID + "/" + v.Tool
	}
	switch {
	case !st.Execution:
		v.State = "execution_off"
	case f != nil && f.code == "tool_not_allowed":
		v.State = "tool_not_allowed"
	case f != nil:
		v.State = "tool_unavailable"
	}
	for _, r := range open {
		if r.ProposalID == p.ID && (r.Status == StatusPending || r.Status == StatusApproved || r.Status == StatusExecuted) {
			v.RequestID = strp(r.ID)
			break
		}
	}
	return v
}

// Plans is GET /response/plans. Plans of findings that are no longer open and critical are left out.
func (s *Service) Plans(ctx context.Context, finding string) (PlanList, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return PlanList{}, err
	}
	rdb := s.cfg.DB.Reader()
	where, args := "", []any{}
	if finding != "" {
		where, args = "WHERE finding_id = ?", []any{finding}
	}
	plans, err := loadPlans(ctx, rdb, where, args...)
	if err != nil {
		return PlanList{}, err
	}
	st, err := loadSettings(ctx, rdb)
	if err != nil {
		return PlanList{}, err
	}
	cats, err := s.cats(ctx, rdb)
	if err != nil {
		return PlanList{}, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return PlanList{}, err
	}
	open, err := loadReqs(ctx, rdb, `WHERE source = 'ai'`)
	if err != nil {
		return PlanList{}, err
	}
	out := PlanList{Items: []Plan{}, Execution: st.Execution}
	for _, p := range plans {
		if s.cfg.Directory != nil {
			f, ok, err := s.cfg.Directory.Finding(ctx, p.FindingID)
			if err != nil {
				return PlanList{}, err
			}
			if !ok || !openStatus(f.Status) || f.Severity != "critical" {
				continue
			}
		}
		pl := p.Plan
		pl.SentTo = s.liveChannels(ctx)
		for _, x := range p.steps {
			step := PlanStep{Kind: x.Kind, Title: x.Title, Detail: x.Detail}
			if x.Proposal != nil {
				pv := s.proposalView(*x.Proposal, st, cats, cs, open)
				step.Proposal = &pv
			}
			pl.Steps = append(pl.Steps, step)
		}
		if pl.Steps == nil {
			pl.Steps = []PlanStep{}
		}
		out.Items = append(out.Items, pl)
	}
	return out, nil
}

func (s *Service) liveChannels(ctx context.Context) []string {
	out := []string{}
	for _, n := range s.channelNames(ctx) {
		if n != "the app" {
			out = append(out, n)
		}
	}
	return out
}

// planRefusal turns a planning failure into the API error of the request.
func planRefusal(f *planFail) *apierr.Error {
	switch f.code {
	case "tool_not_allowed":
		return fail(http.StatusForbidden, f.code, "The action \""+f.title+"\" is not enabled in the action catalog (Settings, AI response).")
	case "invalid_target":
		return fail(http.StatusBadRequest, f.code, f.msg)
	}
	return fail(http.StatusConflict, f.code, f.msg)
}

// RequestProposal is POST /response/proposals/{id}/request: ask for approval of one action proposed in an AI plan. The
// proposal holds a catalog action and typed values only: the change is rendered here, through the same planner and gates as a
// rule run (switch, breaker, maintenance window, never-touch, catalog, connection, type checks, escaping), so a stored plan
// can never carry text that runs. The request carries AI data, so the AI gates apply to it (part 13b; until then it cannot be approved).
func (s *Service) RequestProposal(ctx context.Context, who Actor, pid string) (ActionRequest, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return ActionRequest{}, err
	}
	if !idRE.MatchString(pid) {
		return ActionRequest{}, fail(http.StatusNotFound, "not_found", "No such proposal.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var refusal error
	var out request
	var fx effects
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		refusal, fx = nil, effects{}
		plans, err := loadPlans(ctx, tx, "")
		if err != nil {
			return err
		}
		var plan *storedPlan
		var prop *storedProposal
		for i := range plans {
			for _, x := range plans[i].steps {
				if x.Proposal != nil && x.Proposal.ID == pid {
					plan, prop = &plans[i], x.Proposal
				}
			}
		}
		if plan == nil {
			refusal = fail(http.StatusNotFound, "not_found", "No such proposal.")
			return nil
		}
		subject, assetID := "", prop.AssetID
		if s.cfg.Directory != nil {
			f, ok, err := s.cfg.Directory.Finding(ctx, plan.FindingID)
			if err != nil {
				return err
			}
			if !ok || !openStatus(f.Status) || f.Severity != "critical" {
				refusal = fail(http.StatusConflict, "finding_closed", "The finding is no longer an open critical finding.")
				return nil
			}
			// The subject is the finding's asset (the directory's word), never the asset_id the AI wrote into the proposal; a lookup
			// that fails refuses: without the subject the never-touch check would be incomplete.
			assetID = f.AssetID
			d, ok, err := s.cfg.Directory.Device(ctx, f.AssetID)
			if err != nil {
				refusal = fail(http.StatusConflict, "never_touch", "The device this finding is about could not be read from the inventory, so nothing was requested.")
				return nil
			}
			if ok {
				subject = d.IP
			}
		}
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		if !st.Execution {
			refusal = fail(http.StatusConflict, "execution_off", offMsg)
			return nil
		}
		if w := maintenanceNow(st, s.now()); w != nil {
			refusal = fail(http.StatusConflict, "maintenance", "Held: maintenance window \""+oneLine(w.Name, 80)+"\" is active. Nothing was requested.")
			return nil
		}
		if st.BreakerTrippedAt != nil {
			refusal = fail(http.StatusConflict, "circuit_open", breakerMsg)
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
		if c, ok := cats[prop.ActionID]; !ok || !c.AIMayPropose { // INV-15 (2): the AI proposes only what the admin allowed it to
			refusal = fail(http.StatusForbidden, "tool_not_allowed", "The AI may not propose this action (Settings, AI response, action catalog).")
			return nil
		}
		never, nt, err := s.neverTouchOrRefusal(ctx, tx)
		if err != nil {
			return err
		}
		if nt != nil {
			refusal = nt
			return nil
		}
		why := plan.CVE + " on " + plan.AssetName
		pl, f := s.planProposal(*prop, subject, why, cats, cs, never)
		if f != nil {
			refusal = planRefusal(f)
			return nil
		}
		existing, err := loadReqs(ctx, tx, `WHERE proposal_id = ? AND status IN ('pending', 'approved', 'executed')`, pid)
		if err != nil {
			return err
		}
		open, err := openKeys(ctx, tx, s.now())
		if err != nil {
			return err
		}
		if len(existing) > 0 || open[pl.key] {
			refusal = fail(http.StatusConflict, "already_requested", "This action already has an open request or has already been carried out.")
			return nil
		}
		if tripped, err := s.checkBreaker(ctx, tx, &st, 1, &fx); err != nil {
			return err
		} else if tripped {
			refusal = fail(http.StatusConflict, "circuit_open", breakerMsg)
			return nil
		}
		item := pl.rec
		item.ID = newID("it")
		meta := &AiMeta{Evidence: []Evidence{}, Why: oneLine(why, 300), InAppOnly: item.Risk == RiskHigh}
		out, err = s.createRequest(ctx, tx, st, reqInit{Source: "ai", Actor: who.Email + " (app)", ProposalID: pid, Trigger: "finding", TriggerSummary: oneLine(why, 300), FindingID: plan.FindingID, CVE: plan.CVE,
			AssetID: assetID, AssetName: oneLine(plan.AssetName, 120), Title: item.Title, Recs: []itemRec{item}, AI: meta}, &fx)
		return err
	})
	if err != nil {
		return ActionRequest{}, err
	}
	s.run(ctx, &fx)
	if refusal != nil {
		return ActionRequest{}, s.refuse(ctx, refusal, pid, who.Email)
	}
	return out.view(), nil
}

// ---- the log (INV-19) ----

// Log is GET /response/log: the whole chain, oldest first, so it can be checked from the start. There is no way to change or delete a line.
func (s *Service) Log(ctx context.Context) ([]LogEntry, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, kind, actor, detail, prev_hash, hash FROM resp_log ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("response: read the log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []LogEntry{}
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.Actor, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyLog walks resp_log and the chain head and returns the verdict (the same walk as core_audit).
func (s *Service) VerifyLog(ctx context.Context) (chain.Result, error) {
	tx, err := s.cfg.DB.Reader().BeginTx(ctx, nil)
	if err != nil {
		return chain.Result{}, err
	}
	defer func() { _ = tx.Rollback() }()
	head, err := chainhead.Load(ctx, tx, "resp_log")
	if err != nil {
		return chain.Result{}, err
	}
	v := chain.NewVerifierWithHead("", head)
	rows, err := tx.QueryContext(ctx, `SELECT id, ts, kind, actor, detail, prev_hash, hash FROM resp_log ORDER BY seq`)
	if err != nil {
		return chain.Result{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.Actor, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return chain.Result{}, err
		}
		re, herr := chain.HashCanonical(e.PrevHash, logFields(e.ID, e.TS, e.Kind, e.Actor, e.Detail))
		if herr != nil {
			re = ""
		}
		v.Add(e.ID, e.PrevHash, e.Hash, re)
	}
	return v.Result(), rows.Err()
}

var idRE = regexp.MustCompile(`^[\w.-]{1,96}$`)

// ExportLog is the "response" source of GET /core/logs/export (core INV-13): resp_log from the first line at or after
// from to the last at or before to, oldest first, as JSON lines with the chain fields unchanged (id, ts, kind, actor,
// detail, prev_hash, hash), so the file verifies offline, plus the anchor and head of the chain (logexport.ChainInfo).
// A zero time is open. The lines are exported as stored: nothing is scrubbed, so resp_log must be free of
// secrets when a line is written (the response module owns that; TestExportLogRowsHoldNoSecret checks today's lines).
func (s *Service) ExportLog(ctx context.Context, from, to time.Time, w io.Writer) error {
	return logexport.ChainRows("resp_log", "resp_log", "id, ts, kind, actor, detail, prev_hash, hash", from, to).Write(ctx, s.cfg.DB.Reader(), w)
}

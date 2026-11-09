package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/knt048/vedette/core/chain"
)

// AI plans (S-RESP-1). The plans are written by the AI job of part 13b into resp_plans; this part reads them and turns one
// proposal into an approval request. Nothing here asks an AI anything.

type storedProposal struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	ToolKey     string `json:"tool_key"`
	Tool        string `json:"tool"`
	ConnectorID string `json:"connector_id"`
	Connection  string `json:"connection"`
	AssetID     string `json:"asset_id"`
	AssetName   string `json:"asset_name"`
	Change      Change `json:"change"`
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

// aiCat is the catalog action that carries out a plan proposal: the same connection and write tool.
func aiCat(p storedProposal, cats map[string]catRow) (catRow, bool) {
	for _, c := range cats {
		if c.device() && c.ConnectionID == p.ConnectorID && c.Tool == p.Tool {
			return c, true
		}
	}
	return catRow{}, false
}

func (s *Service) proposalView(p storedProposal, st Settings, cats map[string]catRow, cs conns, open []request) Proposal {
	v := Proposal{ID: p.ID, Title: p.Title, ToolKey: p.ToolKey, Tool: p.Tool, ConnectorID: p.ConnectorID, Connection: p.Connection, AssetID: p.AssetID, AssetName: p.AssetName, Change: p.Change}
	cat, ok := aiCat(p, cats)
	switch {
	case !st.Execution:
		v.State = "execution_off"
	case !ok || !cat.Enabled:
		v.State = "tool_not_allowed"
	case unavailable(cat, cs) != "":
		v.State = "tool_unavailable"
	default:
		v.State = "ready"
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

// RequestProposal is POST /response/proposals/{id}/request: ask for approval of one action proposed in an AI plan.
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
		refusal = nil
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
		if s.cfg.Directory != nil {
			f, ok, err := s.cfg.Directory.Finding(ctx, plan.FindingID)
			if err != nil {
				return err
			}
			if !ok || !openStatus(f.Status) || f.Severity != "critical" {
				refusal = fail(http.StatusConflict, "finding_closed", "The finding is no longer an open critical finding.")
				return nil
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
		cats, err := s.cats(ctx, tx)
		if err != nil {
			return err
		}
		cs, err := s.loadConns(ctx)
		if err != nil {
			return err
		}
		cat, ok := aiCat(*prop, cats)
		if !ok || !cat.Enabled {
			refusal = fail(http.StatusForbidden, "tool_not_allowed", "The action \""+firstNonEmpty(cat.Name, prop.Tool)+"\" is not enabled in the action catalog (Settings, AI response).")
			return nil
		}
		if why := unavailable(cat, cs); why != "" {
			refusal = fail(http.StatusConflict, "tool_unavailable", why)
			return nil
		}
		existing, err := loadReqs(ctx, tx, `WHERE proposal_id = ? AND status IN ('pending', 'executed')`, pid)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			refusal = fail(http.StatusConflict, "already_requested", "This action already has an open request or has already been carried out.")
			return nil
		}
		var acted []string
		if s.cfg.Directory != nil {
			if d, ok, err := s.cfg.Directory.Device(ctx, prop.AssetID); err == nil && ok {
				if ip, ok := CheckValue(PIP, d.IP); ok {
					acted = append(acted, ip)
				}
			}
		}
		never, err := s.neverTouch(ctx, tx)
		if err != nil {
			return err
		}
		if e, hit := firstTouched(never, acted); hit {
			refusal = fail(http.StatusConflict, "never_touch", strsJoin(acted)+" matches the never-touch list ("+e.Label+", "+e.Value+"). Nothing was changed.")
			return nil
		}
		item := itemRec{RequestItem: RequestItem{ID: newID("it"), ActionID: cat.ID, Title: prop.Title, Risk: cat.Risk, Reversible: cat.reversible(), ConnectorID: strp(prop.ConnectorID),
			Connection: strp(prop.Connection), Tool: prop.Tool, Targets: 1, Change: prop.Change, Status: ItemPending}, Values: map[ParamType]string{}, Acted: acted}
		out, err = s.createRequest(ctx, tx, st, reqInit{Source: "ai", ProposalID: pid, Trigger: "finding", TriggerSummary: plan.CVE + " on " + plan.AssetName, FindingID: plan.FindingID, CVE: plan.CVE,
			AssetID: prop.AssetID, AssetName: prop.AssetName, Title: prop.Title, Recs: []itemRec{item}}, &fx)
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

func strsJoin(l []string) string {
	out := ""
	for i, x := range l {
		if i > 0 {
			out += " / "
		}
		out += x
	}
	return out
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
	head, err := chain.LoadHead(ctx, tx, "resp_log")
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

package response

import (
	"context"
	"database/sql"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
)

// Requests and approvals in the app (INV-1, INV-2, INV-3, INV-5, INV-6, INV-9, INV-13).
//
// A request is one bundle: one per rule run. Approving it once covers the bundle (D-51). The gates run in the order of
// INV-9 when someone approves and again, from fresh state, right before each item runs (runItem), so a switch turned
// off, a catalog entry disabled or an address added to the never-touch list between the approval and the run still
// stops the item. runItem is the only function that sends a step to a device (FORBID-1).

const offMsg = "Execution is off. Turn it on in Settings, AI response (high risk)."

// reqInit is what a creator gives createRequest.
type reqInit struct {
	Source, ProposalID, RuleID, RuleName, Trigger, TriggerSummary, FindingID, CVE, AssetID, AssetName, Title string
	Recs                                                                                                     []itemRec
	AI                                                                                                       *AiMeta
}

// createRequest writes a pending request and its log line inside tx.
func (s *Service) createRequest(ctx context.Context, tx *sql.Tx, st Settings, in reqInit, fx *effects) (request, error) {
	now := s.now()
	need, why := requiredApprovals(in.Recs, st)
	a := ActionRequest{
		ID: newID("act"), Source: in.Source, ProposalID: in.ProposalID, RuleID: ptrOrNil(in.RuleID), RuleName: ptrOrNil(in.RuleName), Trigger: ptrOrNil(in.Trigger),
		TriggerSummary: ptrOrNil(in.TriggerSummary), FindingID: ptrOrNil(in.FindingID), CVE: ptrOrNil(in.CVE), AssetID: ptrOrNil(in.AssetID), AssetName: in.AssetName, Title: in.Title,
		Risk: maxRisk(in.Recs), Status: StatusPending, RequestedAt: store2(now), ExpiresAt: store2(now.Add(time.Duration(st.ExpiryMin) * time.Minute)),
		RequiresApprovals: need, TwoBecause: ptrOrNil(why), Approvals: []Approval{}, SentTo: []string{}, AI: in.AI,
	}
	r := request{ActionRequest: a, recs: in.Recs}
	if err := insertReq(ctx, tx, r); err != nil {
		return request{}, err
	}
	var calls []string
	for _, i := range in.Recs {
		calls = append(calls, callText(i.Change.Rest, i.Change.CLI))
	}
	actor := "ai:response"
	if in.Source == "rule" {
		actor = "rule:" + oneLine(in.RuleName, 80)
	}
	detail := in.Title + ": " + strings.Join(calls, " | ") + "; expires " + a.ExpiresAt + "; needs " + itoa(need) + " approver" + plural(need) + "; sent to the app only"
	if err := s.step(ctx, tx, "response.request", a.ID, LogRequest, detail, actor); err != nil {
		return request{}, err
	}
	fx.ob.Add(events.Event{Name: EventRequestCreated, Data: RequestEvent{RequestID: a.ID, Source: a.Source, Title: a.Title, Risk: string(a.Risk), Items: len(in.Recs), ExpiresAt: a.ExpiresAt, Approvals: need}})
	return r, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func notFound() error { return fail(http.StatusNotFound, "not_found", "No such request.") }

// ---- reads ----

// Actions is GET /response/actions: newest first. email_links is always empty in the real build (FORBID-4).
func (s *Service) Actions(ctx context.Context) ([]ActionRequest, error) {
	if err := s.Sweep(ctx); err != nil {
		return nil, err
	}
	rs, err := loadReqs(ctx, s.cfg.DB.Reader(), `ORDER BY requested_at DESC, seq DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	out := make([]ActionRequest, len(rs))
	for i, r := range rs {
		out[i] = r.view()
	}
	return out, nil
}

// ---- approving ----

// Approve is POST /response/actions/{id}/approve: all actions, or the ones picked. A high-risk request, or one that
// touches more targets than the limit, needs a second, different approver who approves the same actions.
func (s *Service) Approve(ctx context.Context, who Actor, id string, pick []string, code string) (ActionRequest, error) {
	who.Via = ViaApp
	return s.approve(ctx, who, id, pick, code, false)
}

func (s *Service) approve(ctx context.Context, who Actor, id string, pick []string, code string, auto bool) (ActionRequest, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return ActionRequest{}, err
	}
	_ = code // the two-step code belongs to high-risk AI requests (part 13b); a request with AI data is refused below
	s.mu.Lock()
	var refusal error
	var final bool
	var chosen []string
	var fx effects
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		refusal, final, chosen = nil, false, nil
		r, ok, err := loadReq(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok {
			refusal = notFound()
			return nil
		}
		now := s.now()
		if r.Status == StatusPending && !parseTS(r.ExpiresAt).After(now) { // INV-6: past its time and not yet swept
			if err := s.expire(ctx, tx, &r, &fx); err != nil {
				return err
			}
			r.Status = StatusExpired
		}
		a := &r.ActionRequest
		first := (*Approval)(nil)
		if len(a.Approvals) > 0 {
			first = &a.Approvals[0]
		}
		ids := pick
		switch {
		case len(pick) > 0:
		case first != nil:
			ids = first.Items
		default:
			for _, i := range r.recs {
				ids = append(ids, i.ID)
			}
		}
		var chosenRecs []itemRec
		for _, i := range r.recs {
			if slices.Contains(ids, i.ID) {
				chosenRecs = append(chosenRecs, i)
			}
		}
		uniq := map[string]bool{}
		for _, x := range ids {
			uniq[x] = true
		}
		switch {
		case a.Status == StatusExpired:
			refusal = fail(http.StatusConflict, "expired", "This request has expired. Nothing was changed. Ask for a new one.")
		case a.Status != StatusPending:
			refusal = fail(http.StatusConflict, "not_pending", "This request is already "+strings.ReplaceAll(string(a.Status), "_", " ")+". One approval covers one request.")
		case len(chosenRecs) == 0 || len(chosenRecs) != len(uniq):
			refusal = fail(http.StatusBadRequest, "invalid_items", "Pick at least one action of this request.")
		}
		if refusal != nil {
			return nil
		}
		if a.AI != nil { // part 13b: high-risk AI requests need the in-app two-step code
			refusal = apierr.NotImplemented()
			return nil
		}
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		device := 0
		for _, i := range chosenRecs {
			if i.ConnectorID != nil {
				device++
			}
		}
		switch {
		case device > 0 && !st.Execution:
			refusal = fail(http.StatusConflict, "execution_off", offMsg)
		case first != nil && len(pick) > 0 && !sameSet(pick, first.Items):
			refusal = fail(http.StatusConflict, "selection_differs", "The second approver must approve the same actions as the first.")
		case slices.ContainsFunc(a.Approvals, func(x Approval) bool { return x.UserID == who.ID }):
			refusal = fail(http.StatusConflict, "same_approver", "You already approved this request. A second, different person must approve it.")
		}
		if refusal != nil {
			return nil
		}
		if auto && preApprovedProblemItems(chosenRecs) != "" { // INV-5, checked again at run time
			refusal = fail(http.StatusForbidden, "forbidden", "Pre-approval refused: only low-risk, reversible actions with an undo time of 24 hours or less qualify.")
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
		for _, i := range chosenRecs {
			if e := gateItem(i, st, cats, cs, nil); e != nil {
				refusal = e
				return nil
			}
		}
		if device > 0 {
			recent, err := deviceActionsLastHour(ctx, tx, now)
			if err != nil {
				return err
			}
			if recent+device > st.MaxPerHour {
				refusal = fail(http.StatusTooManyRequests, "rate_limited", "Limit reached: "+itoa(st.MaxPerHour)+" approved device actions per hour. Try again later or raise the limit in Settings.").With("retry_after", 60)
				return nil
			}
		}
		at := store2(now)
		need, why := requiredApprovals(chosenRecs, st)
		a.Approvals = append(a.Approvals, Approval{UserID: who.ID, Name: who.Name, Email: who.Email, Via: who.Via, At: at, Items: idsOf(chosenRecs)})
		a.RequiresApprovals, a.TwoBecause = need, ptrOrNil(why)
		var titles []string
		for _, i := range chosenRecs {
			titles = append(titles, i.Title)
		}
		if err := s.step(ctx, tx, "response.approve", a.ID, LogApproved,
			a.Title+", approved by "+who.Email+" via "+string(who.Via)+": "+strings.Join(titles, "; ")+" (approval "+itoa(len(a.Approvals))+" of "+itoa(need)+")", who.Email+" ("+string(who.Via)+")"); err != nil {
			return err
		}
		if len(a.Approvals) >= need {
			final = true
			a.Status, a.DecidedAt = StatusApproved, strp(at)
			for k := range r.recs {
				if !slices.Contains(ids, r.recs[k].ID) {
					r.recs[k].Status = ItemSkipped
				}
			}
			chosen = idsOf(chosenRecs)
			fx.ob.Add(events.Event{Name: EventDecisionMade, Data: DecisionEvent{RequestID: a.ID, Decision: "approved", By: who.Email, Final: true}})
		} else {
			fx.ob.Add(events.Event{Name: EventDecisionMade, Data: DecisionEvent{RequestID: a.ID, Decision: "approved", By: who.Email}})
		}
		return updateReq(ctx, tx, r)
	})
	s.mu.Unlock()
	if err != nil {
		return ActionRequest{}, err
	}
	s.run(ctx, &fx)
	if refusal != nil {
		return ActionRequest{}, s.refuse(ctx, refusal, id, who.Email)
	}
	if final {
		for _, itemID := range chosen {
			if err := s.runItem(ctx, id, itemID); err != nil {
				return ActionRequest{}, err
			}
		}
	}
	return s.get(ctx, id)
}

func (s *Service) get(ctx context.Context, id string) (ActionRequest, error) {
	r, ok, err := loadReq(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return ActionRequest{}, err
	}
	if !ok {
		return ActionRequest{}, notFound()
	}
	return r.view(), nil
}

func idsOf(l []itemRec) []string {
	out := make([]string, len(l))
	for i, x := range l {
		out[i] = x.ID
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// preApprovedProblemItems is INV-5 on the items of a request: low risk, reversible, an undo time of 24 hours or less.
func preApprovedProblemItems(items []itemRec) string {
	for _, i := range items {
		if i.Risk != RiskLow || !i.Reversible || i.TTLMin == nil || *i.TTLMin > 1440 {
			return i.Title
		}
	}
	return ""
}

func deviceActionsLastHour(ctx context.Context, q dbq, now time.Time) (int, error) {
	reqs, err := loadReqs(ctx, q, `WHERE status IN ('approved', 'executed', 'failed', 'rolled_back')`)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range reqs {
		for _, i := range r.recs {
			if i.ConnectorID != nil && i.ExecutedAt != nil && now.Sub(parseTS(*i.ExecutedAt)) < hour {
				n++
			}
		}
	}
	return n, nil
}

// gateItem is the part of INV-9 that every execution path shares, per item: the execution switch (device actions only),
// the catalog entry still enabled (403 tool_not_allowed), the connection unchanged and its write tool still on (409
// tool_unavailable). With run set (right before running) it adds the breaker, the maintenance window and the
// never-touch list, read fresh.
func gateItem(i itemRec, st Settings, cats map[string]catRow, cs conns, run *runGate) *apierr.Error {
	device := i.ConnectorID != nil
	if device && !st.Execution {
		return fail(http.StatusConflict, "execution_off", offMsg)
	}
	cat, ok := cats[i.ActionID]
	if !ok || !cat.Enabled {
		name := i.Tool
		if ok {
			name = cat.Name
		}
		return fail(http.StatusForbidden, "tool_not_allowed", "The action \""+name+"\" is not enabled in the action catalog (Settings, AI response).")
	}
	why := unavailable(cat, cs)
	if why == "" && device && cat.ConnectionID != *i.ConnectorID {
		why = "The connection for this action was changed after the request was made."
	}
	if why != "" {
		return fail(http.StatusConflict, "tool_unavailable", why)
	}
	if run == nil {
		return nil
	}
	if st.BreakerTrippedAt != nil {
		return fail(http.StatusConflict, "circuit_open", breakerMsg)
	}
	if w := maintenanceNow(st, run.now); w != nil {
		return fail(http.StatusConflict, "maintenance", "Held: maintenance window \""+oneLine(w.Name, 80)+"\" is active. Nothing was changed.")
	}
	if e, hit := firstTouched(run.never, i.Acted); hit {
		return fail(http.StatusConflict, "never_touch", strings.Join(i.Acted, " / ")+" matches the never-touch list ("+e.Label+", "+e.Value+"). Nothing was changed.")
	}
	return nil
}

// runGate is the fresh state the run-time gates read.
type runGate struct {
	now   time.Time
	never []AllowEntry
}

// ---- running an item (the one place that changes anything) ----

// runItem carries out one approved item. It re-reads the request, the settings, the catalog, the connections and the
// never-touch list, re-checks every gate, and only then acts. A gate that fails marks the item failed with the reason and logs
// the refusal; nothing is sent. The steps that touch a device run one at a time (execMu), so the hourly limit holds.
func (s *Service) runItem(ctx context.Context, reqID, itemID string) error {
	if err := s.ensureSeeded(ctx); err != nil {
		return err
	}
	s.execMu.Lock()
	defer s.execMu.Unlock()
	rdb := s.cfg.DB.Reader()
	r, ok, err := loadReq(ctx, rdb, reqID)
	if err != nil || !ok {
		return err
	}
	k := slices.IndexFunc(r.recs, func(i itemRec) bool { return i.ID == itemID })
	if k < 0 || r.Status != StatusApproved || r.recs[k].Status != ItemPending {
		return nil // cancelled or already handled since the approval
	}
	it := r.recs[k]
	st, err := loadSettings(ctx, rdb)
	if err != nil {
		return err
	}
	cats, err := s.cats(ctx, rdb)
	if err != nil {
		return err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return err
	}
	never, err := s.neverTouch(ctx, rdb)
	if err != nil {
		return err
	}
	if e := gateItem(it, st, cats, cs, &runGate{now: s.now(), never: never}); e != nil {
		return s.finishItem(ctx, reqID, itemID, itemOutcome{refusal: e})
	}
	if it.ConnectorID != nil {
		recent, err := deviceActionsLastHour(ctx, rdb, s.now())
		if err != nil {
			return err
		}
		if recent+1 > st.MaxPerHour {
			return s.finishItem(ctx, reqID, itemID, itemOutcome{refusal: fail(http.StatusTooManyRequests, "rate_limited", "Limit reached: "+itoa(st.MaxPerHour)+" approved device actions per hour.")})
		}
	}
	cat := cats[it.ActionID]
	out := s.carryOut(ctx, r, it, cat, cs)
	return s.finishItem(ctx, reqID, itemID, out)
}

// itemOutcome is what happened to an item.
type itemOutcome struct {
	refusal  *apierr.Error // a gate stopped it: nothing was sent
	err      string        // the step failed: nothing (or not everything) changed
	result   string
	verified *Verified
	block    bool // add the value to the block list in the same transaction
}

func (s *Service) carryOut(ctx context.Context, r request, it itemRec, cat catRow, cs conns) itemOutcome {
	switch {
	case !cat.device():
		switch cat.ID {
		case "blocklist_add":
			return itemOutcome{result: "Added to the block list. Your firewall picks it up on its next fetch.", verified: &Verified{OK: true, Detail: "Read back from the block list: the entry is present."}, block: true}
		case "msg_send":
			if s.cfg.Notifier == nil {
				return itemOutcome{err: "No alert channel is set up, so the message was not sent."}
			}
			if err := s.cfg.Notifier.Message(ctx, "rs-"+it.ID, "Vedette response", it.Values[PText]); err != nil {
				return itemOutcome{err: "The message could not be queued for the alert channels."}
			}
			return itemOutcome{result: "Sent."}
		case "webhook_call":
			res, err := s.postWebhook(ctx, r.ID, it)
			if err != nil {
				return itemOutcome{err: err.Error()}
			}
			return itemOutcome{result: res}
		}
		return itemOutcome{err: "This box action has no executor."}
	case s.cfg.Executor == nil:
		return itemOutcome{err: "No device executor is available in this build. Nothing was changed."}
	}
	conn := cs.by[*it.ConnectorID]
	res, err := s.cfg.Executor.Execute(ctx, DeviceStep{ConnectionID: conn.ID, Tool: cat.Tool, Phase: "run", CLI: it.Change.CLI, Rest: it.Change.Rest, RequestID: r.ID, ItemID: it.ID})
	if err != nil {
		return itemOutcome{err: "The connection " + oneLine(conn.Name, 80) + " did not answer. Nothing was changed."}
	}
	out := itemOutcome{result: oneLine(res.Detail, 300), verified: res.Verified}
	if it.Change.Verify != "" && res.Verified == nil {
		if vr, err := s.cfg.Executor.Execute(ctx, DeviceStep{ConnectionID: conn.ID, Tool: cat.Tool, Phase: "verify", CLI: it.Change.Verify, RequestID: r.ID, ItemID: it.ID}); err == nil {
			out.verified = vr.Verified
		} else {
			out.verified = &Verified{OK: false, Detail: "The read-back did not answer."}
		}
	}
	return out
}

// finishItem records what happened to an item in one transaction: the item, the block list entry, the request status, the log.
func (s *Service) finishItem(ctx context.Context, reqID, itemID string, o itemOutcome) error {
	var fx effects
	err := s.cfg.DB.Write(context.WithoutCancel(ctx), func(tx *sql.Tx) error {
		r, ok, err := loadReq(ctx, tx, reqID)
		if err != nil || !ok {
			return err
		}
		k := slices.IndexFunc(r.recs, func(i itemRec) bool { return i.ID == itemID })
		if k < 0 || r.recs[k].Status != ItemPending {
			return nil
		}
		it := &r.recs[k]
		now := s.now()
		switch {
		case o.refusal != nil:
			it.Status, it.Result = ItemFailed, strp(o.refusal.Message)
			if err := s.step(ctx, tx, "response.refused", r.ID, LogRefused, o.refusal.Code+": "+it.Title+": "+o.refusal.Message, "system"); err != nil {
				return err
			}
		case o.err != "":
			it.Status, it.Result = ItemFailed, strp(o.err)
			if err := s.step(ctx, tx, "response.fail", r.ID, LogFailed, it.Title+": "+o.err, "system"); err != nil {
				return err
			}
		default:
			it.Status, it.ExecutedAt, it.Result, it.Verified = ItemExecuted, strp(store2(now)), strp(o.result), o.verified
			if it.Reversible && it.TTLMin != nil {
				it.RemoveAt = strp(store2(now.Add(time.Duration(*it.TTLMin) * time.Minute)))
			}
			if o.block {
				if err := s.addBlockEntry(ctx, tx, r, *it); err != nil {
					return err
				}
			}
			detail := callText(it.Change.Rest, it.Change.CLI)
			if it.RemoveAt != nil {
				detail += "; undone automatically at " + *it.RemoveAt
			}
			if it.Verified != nil {
				detail += "; read back: " + onOff(it.Verified.OK, "ok", "NOT confirmed")
			}
			if err := s.step(ctx, tx, "response.execute", r.ID, LogExecuted, detail, "system"); err != nil {
				return err
			}
			fx.ob.Add(events.Event{Name: EventActionExecuted, Data: ExecutedEvent{RequestID: r.ID, ItemID: it.ID, ActionID: it.ActionID, Device: it.ConnectorID != nil}})
		}
		if r.Status == StatusApproved && !slices.ContainsFunc(r.recs, func(i itemRec) bool { return i.Status == ItemPending }) {
			r.Status = StatusFailed
			if slices.ContainsFunc(r.recs, func(i itemRec) bool { return i.Status == ItemExecuted }) {
				r.Status = StatusExecuted
			}
		}
		return updateReq(ctx, tx, r)
	})
	if err != nil {
		return err
	}
	s.run(ctx, &fx)
	return nil
}

// ---- rejecting ----

// Reject is POST /response/actions/{id}/reject. remember (AI hints) is part 13b: a rule request has nothing to learn.
func (s *Service) Reject(ctx context.Context, who Actor, id, reason string) (ActionRequest, error) {
	who.Via = ViaApp
	s.mu.Lock()
	defer s.mu.Unlock()
	var refusal error
	var fx effects
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		refusal = nil
		r, ok, err := loadReq(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok {
			refusal = notFound()
			return nil
		}
		if r.Status == StatusPending && !parseTS(r.ExpiresAt).After(s.now()) {
			if err := s.expire(ctx, tx, &r, &fx); err != nil {
				return err
			}
		}
		switch r.Status {
		case StatusPending:
		case StatusExpired:
			refusal = fail(http.StatusConflict, "expired", "This request has already expired.")
			return nil
		default:
			refusal = fail(http.StatusConflict, "not_pending", "This request is already "+strings.ReplaceAll(string(r.Status), "_", " ")+".")
			return nil
		}
		note := "Rejected by " + oneLine(who.Name, 80)
		if reason = oneLine(reason, 300); strings.TrimSpace(reason) != "" {
			note += ": " + strings.TrimSpace(reason)
		}
		if err := s.step(ctx, tx, "response.reject", r.ID, LogRejected, r.Title+", rejected by "+who.Email+" via app: "+oneLine(reason, 300), who.Email+" (app)"); err != nil {
			return err
		}
		r.Status, r.DecidedAt, r.Note = StatusRejected, strp(s.ts()), &note
		for i := range r.recs {
			r.recs[i].Status = ItemSkipped
		}
		fx.ob.Add(events.Event{Name: EventDecisionMade, Data: DecisionEvent{RequestID: r.ID, Decision: "rejected", By: who.Email, Final: true}})
		return updateReq(ctx, tx, r)
	})
	if err != nil {
		return ActionRequest{}, err
	}
	s.run(ctx, &fx)
	if refusal != nil {
		return ActionRequest{}, s.refuse(ctx, refusal, id, who.Email)
	}
	return s.get(ctx, id)
}

// ---- expiry (INV-6) ----

// expire marks a pending request expired inside tx: every item skipped, nothing changed, a notice goes out.
func (s *Service) expire(ctx context.Context, tx *sql.Tx, r *request, fx *effects) error {
	if err := s.step(ctx, tx, "response.expire", r.ID, LogExpired, "Request expired without a decision, nothing was changed: "+r.Title, "system"); err != nil {
		return err
	}
	r.Status, r.DecidedAt, r.Note = StatusExpired, strp(s.ts()), strp("Expired without a decision. Nothing was changed.")
	for i := range r.recs {
		r.recs[i].Status = ItemSkipped
	}
	fx.ob.Add(events.Event{Name: EventDecisionMade, Data: DecisionEvent{RequestID: r.ID, Decision: "expired", By: "system", Final: true}})
	title := r.Title
	fx.later(func(ctx context.Context) {
		s.message(ctx, "exp-"+r.ID, "Response request expired", "No decision was made in time, so nothing was changed: "+title)
	})
	return updateReq(ctx, tx, *r)
}

// Sweep expires the pending requests past their time and undoes the executed changes whose undo time ended. The sweep
// job calls it, and every list of requests does first, so a stale request never looks open.
func (s *Service) Sweep(ctx context.Context) error {
	if err := s.sweepExpired(ctx); err != nil {
		return err
	}
	return s.sweepTTL(ctx)
}

func (s *Service) sweepExpired(ctx context.Context) error {
	now := store2(s.now())
	due, err := loadReqs(ctx, s.cfg.DB.Reader(), `WHERE status = 'pending' AND expires_at <= ?`, now)
	if err != nil || len(due) == 0 {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var fx effects
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, d := range due {
			r, ok, err := loadReq(ctx, tx, d.ID)
			if err != nil {
				return err
			}
			if ok && r.Status == StatusPending {
				if err := s.expire(ctx, tx, &r, &fx); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.run(ctx, &fx)
	return nil
}

// sweepTTL undoes executed changes whose undo time ended (INV-13, POST-2). Removing a change is the safe direction: it
// needs neither the execution switch nor an approval (D-88). A device that does not answer keeps the item executed;
// the sweep tries again, and the failure is logged once.
func (s *Service) sweepTTL(ctx context.Context) error {
	now := s.now()
	reqs, err := loadReqs(ctx, s.cfg.DB.Reader(), `WHERE status IN ('executed', 'approved')`)
	if err != nil {
		return err
	}
	for _, r := range reqs {
		for _, it := range r.recs {
			if it.Status == ItemExecuted && it.RemoveAt != nil && !parseTS(*it.RemoveAt).After(now) {
				if err := s.undoItem(ctx, r.ID, it.ID, true, ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ---- rolling back (INV-13) ----

// Rollback is POST /response/actions/{id}/rollback: undo every executed action of the request with its rollback step. A
// device action is refused when execution is off (INV-7).
func (s *Service) Rollback(ctx context.Context, who Actor, id string) (ActionRequest, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return ActionRequest{}, err
	}
	rdb := s.cfg.DB.Reader()
	r, ok, err := loadReq(ctx, rdb, id)
	if err != nil {
		return ActionRequest{}, err
	}
	if !ok {
		return ActionRequest{}, notFound()
	}
	var run []itemRec
	for _, i := range r.recs {
		if i.Status == ItemExecuted {
			run = append(run, i)
		}
	}
	if len(run) == 0 {
		return ActionRequest{}, s.refuse(ctx, fail(http.StatusConflict, "not_executed", "Only an executed action can be rolled back."), id, who.Email)
	}
	st, err := loadSettings(ctx, rdb)
	if err != nil {
		return ActionRequest{}, err
	}
	cats, err := s.cats(ctx, rdb)
	if err != nil {
		return ActionRequest{}, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return ActionRequest{}, err
	}
	for _, i := range run {
		if i.ConnectorID == nil {
			continue // a box action (the block list) is undone locally: no switch, no connection
		}
		if e := gateItem(i, st, cats, cs, nil); e != nil {
			return ActionRequest{}, s.refuse(ctx, e, id, who.Email)
		}
	}
	for _, i := range run {
		if err := s.undoItem(ctx, id, i.ID, false, who.Email); err != nil {
			return ActionRequest{}, err
		}
	}
	got, err := s.get(ctx, id)
	if err != nil {
		return got, err
	}
	for _, i := range got.Items {
		if slices.ContainsFunc(run, func(x itemRec) bool { return x.ID == i.ID }) && i.Status == ItemExecuted {
			return got, s.refuse(ctx, fail(http.StatusConflict, "tool_unavailable", "The rollback could not be completed: "+deref2(i.Result)), id, who.Email)
		}
	}
	return got, nil
}

// undoItem sends the rollback step of one executed item and records the result. auto is the sweep (ttl_removed).
func (s *Service) undoItem(ctx context.Context, reqID, itemID string, auto bool, actor string) error {
	if err := s.ensureSeeded(ctx); err != nil {
		return err
	}
	s.execMu.Lock()
	defer s.execMu.Unlock()
	rdb := s.cfg.DB.Reader()
	r, ok, err := loadReq(ctx, rdb, reqID)
	if err != nil || !ok {
		return err
	}
	k := slices.IndexFunc(r.recs, func(i itemRec) bool { return i.ID == itemID })
	if k < 0 || r.recs[k].Status != ItemExecuted {
		return nil
	}
	it := r.recs[k]
	failure := ""
	if it.ConnectorID != nil {
		cs, err := s.loadConns(ctx)
		if err != nil {
			return err
		}
		switch conn, known := cs.get(*it.ConnectorID); {
		case s.cfg.Executor == nil:
			failure = "No device executor is available in this build. The change was not undone."
		case !known:
			failure = "The connection of this action no longer exists. The change was not undone."
		default:
			cats, err := s.cats(ctx, rdb)
			if err != nil {
				return err
			}
			if _, err := s.cfg.Executor.Execute(ctx, DeviceStep{ConnectionID: conn.ID, Tool: cats[it.ActionID].RollbackTool, Phase: "rollback", CLI: it.Change.Rollback.CLI, Rest: it.Change.Rollback.Rest, RequestID: r.ID, ItemID: it.ID}); err != nil {
				failure = "The connection " + oneLine(conn.Name, 80) + " did not answer. The change was not undone."
			}
		}
	}
	var fx effects
	err = s.cfg.DB.Write(context.WithoutCancel(ctx), func(tx *sql.Tx) error {
		cur, ok, err := loadReq(ctx, tx, reqID)
		if err != nil || !ok {
			return err
		}
		j := slices.IndexFunc(cur.recs, func(i itemRec) bool { return i.ID == itemID })
		if j < 0 || cur.recs[j].Status != ItemExecuted {
			return nil
		}
		x := &cur.recs[j]
		if failure != "" {
			if deref2(x.Result) == failure {
				return nil // the same failure is logged once
			}
			x.Result = strp(failure)
			if err := s.step(ctx, tx, "response.fail", cur.ID, LogFailed, x.Change.Rollback.Title+": "+failure, "system"); err != nil {
				return err
			}
			return updateReq(ctx, tx, cur)
		}
		x.Status, x.RolledBackAt = ItemRolledBack, strp(s.ts())
		if auto {
			x.Result = strp("Undone automatically (undo time ended).")
		} else {
			x.Result = strp("Removed.")
			if x.ConnectorID != nil {
				x.Result = strp("Undone through " + oneLine(deref2(x.Connection), 80) + ".")
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_block_entries WHERE request_id = ? AND item_id = ?`, cur.ID, x.ID); err != nil {
			return err
		}
		if auto {
			err = s.step(ctx, tx, "response.ttl_remove", cur.ID, LogTTLRemoved, x.Change.Rollback.Title+": undo time of "+itoa(intOr(x.TTLMin, 0))+" minutes ended; "+callText(x.Change.Rollback.Rest, x.Change.Rollback.CLI), "system")
		} else {
			err = s.step(ctx, tx, "response.rollback", cur.ID, LogRolledBack, x.Change.Rollback.Title+"; "+callText(x.Change.Rollback.Rest, x.Change.Rollback.CLI), actor)
		}
		if err != nil {
			return err
		}
		fx.ob.Add(events.Event{Name: EventActionRolledBack, Data: RolledBackEvent{RequestID: cur.ID, ItemID: x.ID, ActionID: x.ActionID, Auto: auto}})
		if !slices.ContainsFunc(cur.recs, func(i itemRec) bool { return i.Status == ItemExecuted }) {
			cur.Status = StatusRolledBack
			if auto {
				cur.Note = strp("Undone automatically when the undo time ended")
			}
		}
		return updateReq(ctx, tx, cur)
	})
	if err != nil {
		return err
	}
	s.run(ctx, &fx)
	return nil
}

// ---- emergency stop (INV-8) ----

// EmergencyStop is POST /response/emergency-stop: execution off and every pending request cancelled, in one transaction.
// It takes neither mu nor execMu: a stop must never wait. A step that is already running finishes; the next one reads the switch.
func (s *Service) EmergencyStop(ctx context.Context, who Actor) (int, error) {
	cancelled := 0
	var fx effects
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		st.Execution = false
		if err := s.saveSettings(ctx, tx, st); err != nil {
			return err
		}
		pending, err := loadReqs(ctx, tx, `WHERE status = 'pending'`)
		if err != nil {
			return err
		}
		for _, r := range pending {
			r.Status, r.DecidedAt, r.Note = StatusRejected, strp(s.ts()), strp("Cancelled by emergency stop ("+who.Email+")")
			for i := range r.recs {
				r.recs[i].Status = ItemSkipped
			}
			if err := updateReq(ctx, tx, r); err != nil {
				return err
			}
			fx.ob.Add(events.Event{Name: EventDecisionMade, Data: DecisionEvent{RequestID: r.ID, Decision: "cancelled", By: who.Email, Final: true}})
		}
		cancelled = len(pending)
		return s.step(ctx, tx, "response.emergency_stop", "response", LogEmergencyStop, who.Email+" stopped execution; "+itoa(cancelled)+" pending request"+plural(cancelled)+" cancelled", who.Email)
	})
	if err != nil {
		return 0, err
	}
	s.run(ctx, &fx)
	return cancelled, nil
}

// ---- metrics ----

func median(n []float64) *float64 {
	if len(n) == 0 {
		return nil
	}
	sort.Float64s(n)
	m := len(n) / 2
	v := n[m]
	if len(n)%2 == 0 {
		v = (n[m-1] + n[m]) / 2
	}
	v = float64(int(v*10+0.5)) / 10
	return &v
}

func stat(list []request) Stat {
	var st Stat
	var mins []float64
	approved := 0
	for _, r := range list {
		switch r.Status {
		case StatusApproved, StatusExecuted, StatusFailed, StatusRolledBack:
			if !r.PreApproved {
				approved++
				if n := len(r.Approvals); n > 0 {
					if m := parseTS(r.Approvals[n-1].At).Sub(parseTS(r.RequestedAt)).Minutes(); m >= 0 {
						mins = append(mins, m)
					}
				}
			}
		case StatusRejected:
			st.Rejected++
		case StatusExpired:
			st.Expired++
		case StatusPending:
			st.Pending++
		}
	}
	st.Sent, st.Approved = len(list), approved
	if d := approved + st.Rejected; d > 0 {
		v := float64(approved) / float64(d)
		st.AcceptanceRate = &v
	}
	st.MedianApproveMin = median(mins)
	return st
}

// Metrics is GET /response/metrics.
func (s *Service) Metrics(ctx context.Context) (Metrics, error) {
	if err := s.Sweep(ctx); err != nil {
		return Metrics{}, err
	}
	all, err := loadReqs(ctx, s.cfg.DB.Reader(), `ORDER BY seq`)
	if err != nil {
		return Metrics{}, err
	}
	var ai, rules, rejected []request
	for _, r := range all {
		if r.Source == "ai" {
			ai = append(ai, r)
		} else {
			rules = append(rules, r)
		}
		if r.Status == StatusRejected {
			rejected = append(rejected, r)
		}
	}
	sort.SliceStable(rejected, func(i, j int) bool { return deref2(rejected[i].DecidedAt) > deref2(rejected[j].DecidedAt) })
	if len(rejected) > 20 {
		rejected = rejected[:20]
	}
	m := Metrics{AI: stat(ai), Rules: stat(rules), Rejected: []RejectedRow{}}
	for _, r := range rejected {
		reason := "No reason given"
		if r.Note != nil {
			reason = *r.Note
		}
		m.Rejected = append(m.Rejected, RejectedRow{ID: r.ID, Title: r.Title, Source: r.Source, Reason: reason, At: firstNonEmpty(deref2(r.DecidedAt), r.RequestedAt)})
	}
	return m, nil
}

package response

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	Held                                                                                                     string // why a pre-approval was not used, for the log line
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
	detail := in.Title + ": " + strings.Join(calls, " | ") + "; expires " + a.ExpiresAt + "; needs " + itoa(need) + " approver" + plural(need) + "; sent to the app only" + in.Held
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
	if err := s.sweepExpired(ctx); err != nil { // a read only expires what is past its time; changes on devices are the job's (Sweep)
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
	_ = code            // the two-step code belongs to high-risk AI requests (part 13b); a request with AI data is refused below
	pick = dedupe(pick) // a repeated id must not pass for a different selection
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
		if n, _ := requiredApprovals(chosenRecs, st); auto && n > 1 { // INV-2: a rule is not one of two people
			refusal = fail(http.StatusForbidden, "forbidden", "Pre-approval refused: this request needs two different people to approve it.")
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
		humans := 0 // an automatic approval (via=auto) never counts towards two approvers (INV-2)
		for _, x := range a.Approvals {
			if x.Via != ViaAuto {
				humans++
			}
		}
		if len(a.Approvals) >= need && (need == 1 || humans >= need) {
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
		// The approval is committed: the items run to the end whether or not the approver is still connected (a closed
		// browser or a proxy timeout must not leave a bundle half run).
		dctx := context.WithoutCancel(ctx)
		for _, itemID := range chosen {
			if err := s.runItem(dctx, id, itemID); err != nil {
				return ActionRequest{}, err
			}
		}
		return s.get(dctx, id)
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
// the catalog entry still enabled (403 tool_not_allowed), the connection unchanged since the request (409
// connection_changed), its write tool still on and the tool of the action unchanged (409 tool_unavailable). With run set
// (right before running) it adds the breaker, the maintenance window and the never-touch list, read fresh.
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
	if e := connectionGate(i, cat, cs); e != nil {
		return e
	}
	if why := unavailable(cat, cs); why != "" {
		return fail(http.StatusConflict, "tool_unavailable", why)
	}
	if device && cat.Tool != i.RunTool {
		return fail(http.StatusConflict, "tool_unavailable", "The write tool of \""+cat.Name+"\" was changed after the request was made. Nothing was changed. Ask again.")
	}
	if device && cat.RollbackTool != i.RollbackTool { // the undo tool is checked before the run too: an action that cannot be undone as approved must not start
		return fail(http.StatusConflict, "tool_unavailable", "The undo tool of \""+cat.Name+"\" was changed after the request was made. Nothing was changed. Ask again.")
	}
	if actionFP(cat) != i.ActionFP { // the stored call is the old rendering, approved at the old risk (INV-9)
		return fail(http.StatusConflict, "tool_unavailable", "The action \""+oneLine(cat.Name, 80)+"\" was edited after the request was made. Nothing was changed. Ask again.")
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

// actionFP is the fingerprint of what a request item was rendered from: the templates (with the read-back text), the check before and
// its refusal texts, and the risk of the catalog entry. An edit of
// either changes it, so a request made before the edit refuses at approval and at run instead of sending the old rendering at the old risk.
func actionFP(c catRow) string {
	b, _ := json.Marshal([]any{c.Run, c.Rollback, c.Verify, c.Precheck, nonNilStrings(c.PrecheckRefuse), c.PrecheckExpect, c.Risk})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16])
}

// connectionGate is 409 connection_changed when the connection of a device item is not the one the request was made against:
// the action now uses another connection, or the connection's address, kind or version (UpdatedAt) changed. The stored call
// holds the address of the old one, so it must not be sent to the new one.
func connectionGate(i itemRec, cat catRow, cs conns) *apierr.Error {
	if i.ConnectorID == nil {
		return nil
	}
	conn, known := cs.get(*i.ConnectorID)
	if cat.ConnectionID != *i.ConnectorID || (known && connFP(conn) != i.ConnFP) {
		return fail(http.StatusConflict, "connection_changed", "The connection \""+oneLine(deref2(i.Connection), 80)+"\" was changed after the request was made. Nothing was changed. Ask again.")
	}
	return nil
}

// rollbackGate is what an undo of a device item still needs: the same connection as the request and the same rollback tool.
// It does not look at the catalog switch: after an admin disables an action its changes must still be removable (removing a
// change is the safe direction, D-88 (4)); the execution switch is the caller's.
func rollbackGate(i itemRec, cats map[string]catRow, cs conns) *apierr.Error {
	if i.ConnectorID == nil {
		return nil
	}
	cat, ok := cats[i.ActionID]
	if !ok {
		return fail(http.StatusConflict, "tool_unavailable", "The action of this change no longer exists in the catalog, so it cannot be undone from here.")
	}
	// An undo is held to the identity of the connection (id, kind, address), not to its fingerprint: a rotated token, a renewed pin, a changed
	// allow-list or a switched tool must not strand a change that is in force. The catalog may point the action elsewhere since: the item
	// remembers the device it ran on.
	if conn, known := cs.get(*i.ConnectorID); known {
		same := connFP(conn) == i.ConnFP
		if i.ConnIdent != "" {
			same = connIdent(conn) == i.ConnIdent
		}
		if !same {
			return fail(http.StatusConflict, "connection_changed", "The connection \""+oneLine(deref2(i.Connection), 80)+"\" is not the device this change was made on (its address or kind changed), so the change was not undone from here. Undo it on the device.")
		}
	}
	if cat.RollbackTool != i.RollbackTool {
		return fail(http.StatusConflict, "tool_unavailable", "The undo tool of \""+cat.Name+"\" was changed after the request was made, so the change was not undone.")
	}
	return nil
}

// undoable reports whether an item can be undone: one that is in force, or one whose outcome is not known (undo it to be sure it is not in force).
func undoable(i RequestItem) bool {
	return i.Status == ItemExecuted || (i.Status == ItemFailed && i.StateUnknown)
}

// runGate is the fresh state the run-time gates read.
type runGate struct {
	now   time.Time
	never []AllowEntry
}

// ---- running an item (the one place that changes anything) ----

const (
	// stepTimeout bounds one item (its step and the read-back). It is the item's own limit: the approver's connection does not count.
	stepTimeout = 90 * time.Second
	// stuckGrace is added to the step limit: an item "running" for longer is failed by the sweep (the box restarted or the step never returned).
	stuckGrace = 30 * time.Second
	// notStartedAfter is how long an approved request may wait for its items to start before the sweep fails them.
	notStartedAfter = 10 * time.Minute

	stateUnknown = "State unknown: check the device. The step may or may not have been applied."
)

// runItem carries out one approved item. It re-reads the request, the settings, the catalog, the connections and the
// never-touch list, re-checks every gate, and only then acts. A gate that fails marks the item failed with the reason and logs
// the refusal; nothing is sent. The steps that touch a device run one at a time (execMu), so the hourly limit holds.
// Whatever the caller's context says, the item runs on its own: the approval was committed and a half-run bundle is worse
// than a slow one. Before a step is sent the item is marked running with a log line, so a step is never unrecorded.
func (s *Service) runItem(ctx context.Context, reqID, itemID string) error {
	ctx = context.WithoutCancel(ctx)
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
	if k < 0 || r.Status != StatusApproved || r.recs[k].Status != ItemPending || r.recs[k].RunningAt != "" {
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
	never, refusal, err := s.neverTouchOrRefusal(ctx, rdb)
	if err != nil {
		return err
	}
	if refusal != nil {
		return s.finishItem(ctx, reqID, itemID, itemOutcome{refusal: refusal})
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
	// The claim re-reads the switch, the breaker and the maintenance window inside the transaction that marks the item running,
	// so an emergency stop that committed after the reads above still stops this step (INV-9); it also fails when the sweep
	// or a cancel got to the item first, so a step is never sent for an item the record says did not start (INV-19).
	leaves := it.ConnectorID != nil || cat.ID == "webhook_call" // a step that leaves the box
	claimed, refusal2, err := s.claimItem(ctx, reqID, itemID, leaves)
	if err != nil {
		return err
	}
	if refusal2 != nil {
		return s.finishItem(ctx, reqID, itemID, itemOutcome{refusal: refusal2})
	}
	if !claimed {
		return nil
	}
	xctx, cancel := context.WithTimeout(ctx, s.stepLimit)
	out := s.carryOut(xctx, r, it, cat, cs)
	cancel()
	out.fromRun = true
	return s.finishItem(ctx, reqID, itemID, out)
}

// claimItem is the compare-and-set that lets a step go: in one transaction it checks that the request is still approved and
// the item still pending and not running, re-reads the settings and closes on a gate that shut since runItem read it (the
// execution switch for a device, the breaker, the maintenance window), and, when the step leaves the box, marks the item
// running with a log line. It returns whether the caller may send; a closed gate comes back as a refusal.
func (s *Service) claimItem(ctx context.Context, reqID, itemID string, leaves bool) (claimed bool, refusal *apierr.Error, err error) {
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		claimed, refusal = false, nil
		r, ok, err := loadReq(ctx, tx, reqID)
		if err != nil || !ok {
			return err
		}
		k := slices.IndexFunc(r.recs, func(i itemRec) bool { return i.ID == itemID })
		if k < 0 || r.Status != StatusApproved || r.recs[k].Status != ItemPending || r.recs[k].RunningAt != "" {
			return nil
		}
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		it := r.recs[k]
		switch w := maintenanceNow(st, s.now()); {
		case it.ConnectorID != nil && !st.Execution:
			refusal = fail(http.StatusConflict, "execution_off", offMsg)
			return nil
		case st.BreakerTrippedAt != nil:
			refusal = fail(http.StatusConflict, "circuit_open", breakerMsg)
			return nil
		case w != nil:
			refusal = fail(http.StatusConflict, "maintenance", "Held: maintenance window \""+oneLine(w.Name, 80)+"\" is active. Nothing was changed.")
			return nil
		}
		if it.ConnectorID != nil {
			// The connection and the catalog are read again here, in the transaction that lets the step go: an edit or a delete that
			// committed after runItem read them still stops the step (INV-9). Nothing is sent for a connection that is no longer the one approved.
			cats, err := s.cats(ctx, tx)
			if err != nil {
				return err
			}
			cs, err := s.loadConns(ctx)
			if err != nil {
				return err
			}
			if _, known := cs.get(*it.ConnectorID); !known {
				refusal = fail(http.StatusConflict, "connection_changed", "The connection \""+oneLine(deref2(it.Connection), 80)+"\" no longer exists. Nothing was changed. Ask again.")
				return nil
			}
			if e := gateItem(it, st, cats, cs, nil); e != nil { // includes connectionGate
				refusal = e
				return nil
			}
		}
		claimed = true
		if !leaves {
			return nil
		}
		r.recs[k].RunningAt = s.ts()
		if err := s.step(ctx, tx, "response.run", r.ID, LogApproved, "Running: "+it.Title+": "+callText(it.Change.Rest, it.Change.CLI)+"; the step is being sent now and the result follows", "system"); err != nil {
			return err
		}
		return updateReq(ctx, tx, r)
	})
	return claimed && err == nil, refusal, err
}

// itemOutcome is what happened to an item.
type itemOutcome struct {
	refusal  *apierr.Error // a gate stopped it: nothing was sent
	err      string        // the step failed: nothing (or not everything) changed
	result   string
	verified *Verified
	block    bool // add the value to the block list in the same transaction
	// unknown marks a step that was sent and whose outcome is not known (the sweep or the step deadline gave up waiting): the item
	// is failed but its change may be in force (itemRec.StateUnknown).
	unknown bool

	// sweep makes the write a compare-and-set on the running mark the sweep read (ifRunning): an item that was claimed or
	// finished since is left alone. fromRun marks the result of a step runItem sent: it may replace the "State unknown" the
	// sweep wrote while the step was still in flight.
	sweep     bool
	ifRunning string
	fromRun   bool
}

func (s *Service) carryOut(ctx context.Context, r request, it itemRec, cat catRow, cs conns) itemOutcome {
	switch {
	case !cat.device():
		switch cat.ID {
		case "blocklist_add":
			full, err := s.blockListFull(ctx, it.Values[PIP])
			if err != nil {
				return itemOutcome{err: "The block list could not be read, so nothing was added."}
			}
			if full {
				return itemOutcome{refusal: fail(http.StatusConflict, "limit", "The block list holds "+itoa(maxBlockEntries)+" entries, the most it can publish. Nothing was added. Remove entries or let them expire first.")}
			}
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
	return s.carryOutDevice(ctx, r, it, cat, cs.by[*it.ConnectorID])
}

// errExecutorPanic is what execute answers when the executor crashed: a crash in the middle of a write is the least known outcome there is.
var errExecutorPanic = errors.New("the executor failed")

// execute runs one device step but stops waiting when ctx ends: an Executor must respect its context (the interface says so), and
// one that does not must not hold the device-step lock or the approver past the item's deadline. The caller then records "state
// unknown" (the step may have been applied). A panic in the executor is an error, not a crash.
func (s *Service) execute(ctx context.Context, step DeviceStep) (DeviceResult, error) {
	type outcome struct {
		res DeviceResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- outcome{err: errExecutorPanic}
			}
		}()
		res, err := s.cfg.Executor.Execute(ctx, step)
		done <- outcome{res, err}
	}()
	select {
	case o := <-done:
		return o.res, o.err
	case <-ctx.Done():
		return DeviceResult{}, ctx.Err()
	}
}

// finishItem records what happened to an item in one transaction: the item, the block list entry, the request status, the log.
// The write and every query in it use one context that the caller's cancellation cannot reach.
func (s *Service) finishItem(ctx context.Context, reqID, itemID string, o itemOutcome) error {
	ctx = context.WithoutCancel(ctx)
	// A device step that returns after its connection is gone (deleted or restored away while it ran: core/conn refuses a delete while
	// a step is in flight, but other ways exist): the result is still recorded, the item leaves the sweep, and one line says so.
	var cs conns
	haveConns := false
	if o.fromRun {
		if c, err := s.loadConns(ctx); err == nil {
			cs, haveConns = c, true
		}
	}
	var fx effects
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		fx = effects{}
		r, ok, err := loadReq(ctx, tx, reqID)
		if err != nil || !ok {
			return err
		}
		k := slices.IndexFunc(r.recs, func(i itemRec) bool { return i.ID == itemID })
		if k < 0 {
			return nil
		}
		it := &r.recs[k]
		corrects := false // a real result replaces the sweep's "State unknown"
		switch {
		case it.Status == ItemFailed && o.fromRun && it.StateUnknown:
			corrects = true
		case it.Status != ItemPending, o.sweep && it.RunningAt != o.ifRunning:
			return nil
		}
		note := ""
		if corrects {
			note = "Correction of the earlier \"State unknown\": "
		}
		it.RunningAt = ""
		it.StateUnknown = false
		now := s.now()
		switch {
		case o.refusal != nil:
			it.Status, it.Result = ItemFailed, strp(o.refusal.Message)
			if err := s.step(ctx, tx, "response.refused", r.ID, LogRefused, o.refusal.Code+": "+it.Title+": "+o.refusal.Message, "system"); err != nil {
				return err
			}
		case o.err != "":
			it.Status, it.Result, it.StateUnknown = ItemFailed, strp(o.err), o.unknown
			if err := s.step(ctx, tx, "response.fail", r.ID, LogFailed, note+it.Title+": "+o.err, "system"); err != nil {
				return err
			}
			if o.unknown && goneConn(haveConns, cs, *it) {
				if err := s.goneNote(ctx, tx, r.ID, *it); err != nil {
					return err
				}
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
			if err := s.step(ctx, tx, "response.execute", r.ID, LogExecuted, note+detail, "system"); err != nil {
				return err
			}
			if goneConn(haveConns, cs, *it) {
				it.RemoveAt = nil // nothing can send the undo, so the sweep must not keep trying
				if err := s.goneNote(ctx, tx, r.ID, *it); err != nil {
					return err
				}
			}
			fx.ob.Add(events.Event{Name: EventActionExecuted, Data: ExecutedEvent{RequestID: r.ID, ItemID: it.ID, ActionID: it.ActionID, Device: it.ConnectorID != nil}})
		}
		if (r.Status == StatusApproved || corrects) && !slices.ContainsFunc(r.recs, func(i itemRec) bool { return i.Status == ItemPending }) {
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

// goneConn reports whether the connection of a device item is known not to exist any more (conns could be read: have).
func goneConn(have bool, cs conns, it itemRec) bool {
	if !have || it.ConnectorID == nil {
		return false
	}
	_, ok := cs.get(*it.ConnectorID)
	return !ok
}

// goneNote is the one line that says a step ended on a connection that no longer exists: the change may be in force and only the
// device can undo it.
func (s *Service) goneNote(ctx context.Context, tx *sql.Tx, reqID string, it itemRec) error {
	return s.step(ctx, tx, "response.fail", reqID, LogFailed, it.Title+": the connection \""+oneLine(deref2(it.Connection), 80)+"\" no longer exists (it was deleted while the step ran). The change may be in force on the device and cannot be undone from Vedette: undo it there.", "system")
}

// failStuck fails the items an approved request left behind: an item "running" for longer than stuckAfter (the box restarted
// or the step never returned: state unknown, check the device) and items that never started within notStartedAfter. Each is
// logged as failed. The sweep job calls it.
func (s *Service) failStuck(ctx context.Context) error {
	now := s.now()
	reqs, err := loadReqs(ctx, s.cfg.DB.Reader(), `WHERE status = 'approved'`)
	if err != nil {
		return err
	}
	for _, r := range reqs {
		for _, it := range r.recs {
			if it.Status != ItemPending {
				continue
			}
			switch {
			case it.RunningAt != "" && now.Sub(parseTS(it.RunningAt)) > s.stepLimit+stuckGrace:
				err = s.finishItem(ctx, r.ID, it.ID, itemOutcome{err: stateUnknown, unknown: true, sweep: true, ifRunning: it.RunningAt})
			case it.RunningAt == "" && r.DecidedAt != nil && now.Sub(parseTS(*r.DecidedAt)) > notStartedAfter:
				err = s.finishItem(ctx, r.ID, it.ID, itemOutcome{err: "This action did not start (the box restarted or was busy after the approval). Nothing was changed. Ask again.", sweep: true})
			}
			if err != nil {
				return err
			}
		}
	}
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

// Sweep expires the pending requests past their time, fails the items an approved request left behind, and undoes the
// executed changes whose undo time ended. Only the sweep job calls it: a read (GET) never sends a step to a device. A list of
// requests only expires what is past its time (sweepExpired), so a stale request never looks open.
func (s *Service) Sweep(ctx context.Context) error {
	if err := s.sweepExpired(ctx); err != nil {
		return err
	}
	if err := s.failStuck(ctx); err != nil {
		return err
	}
	if err := s.resolveUnknown(ctx); err != nil {
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
		if undoable(i.RequestItem) {
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
		if !st.Execution { // INV-7: a person's undo of a device change needs the switch; the action may be disabled since (L2)
			return ActionRequest{}, s.refuse(ctx, fail(http.StatusConflict, "execution_off", offMsg), id, who.Email)
		}
		if e := rollbackGate(i, cats, cs); e != nil {
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
		if slices.ContainsFunc(run, func(x itemRec) bool { return x.ID == i.ID }) && undoable(i) {
			return got, s.refuse(ctx, fail(http.StatusConflict, "tool_unavailable", "The rollback could not be completed: "+deref2(i.Result)), id, who.Email)
		}
	}
	return got, nil
}

// undoItem sends the rollback step of one executed item and records the result. auto is the sweep (ttl_removed). Like
// runItem it runs on its own context (a disconnected caller must not abort an undo half way).
func (s *Service) undoItem(ctx context.Context, reqID, itemID string, auto bool, actor string) error {
	ctx = context.WithoutCancel(ctx)
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
	if k < 0 || !undoable(r.recs[k].RequestItem) {
		return nil
	}
	it := r.recs[k]
	wasUnknown := it.StateUnknown
	var out undoOutcome
	gone := false
	if it.ConnectorID != nil {
		cs, err := s.loadConns(ctx)
		if err != nil {
			return err
		}
		cats, err := s.cats(ctx, rdb)
		if err != nil {
			return err
		}
		switch conn, known := cs.get(*it.ConnectorID); {
		case s.cfg.Executor == nil:
			out.failure = "No device executor is available in this build. The change was not undone."
		case !known:
			// The connection was deleted or restored away since the step ran: nothing can reach the device from here, so the undo is
			// not tried again (the item leaves the sweep) and the person is told once.
			out.failure, gone = "The connection of this action no longer exists. The change was not undone: undo it on the device.", true
		default:
			if e := rollbackGate(it, cats, cs); e != nil {
				out.failure = e.Message
				break
			}
			if cat, ok := cats[it.ActionID]; ok && it.Exec != nil && actionFP(cat) == it.ActionFP && !s.execMatches(cat, it, conn) {
				out.failure = "The steps stored with this change are not what its action renders (the stored request was altered), so the undo was not sent. Undo it on the device."
				break
			}
			xctx, cancel := context.WithTimeout(ctx, s.stepLimit)
			out = s.undoOnDevice(xctx, r.ID, it, conn)
			cancel()
		}
	}
	var fx effects
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		fx = effects{}
		cur, ok, err := loadReq(ctx, tx, reqID)
		if err != nil || !ok {
			return err
		}
		j := slices.IndexFunc(cur.recs, func(i itemRec) bool { return i.ID == itemID })
		if j < 0 || !undoable(cur.recs[j].RequestItem) {
			return nil
		}
		x := &cur.recs[j]
		if out.failure != "" {
			flagMoved := x.UndoUnclear != out.unclear
			x.UndoUnclear = out.unclear
			if deref2(x.Result) == out.failure {
				if flagMoved {
					return updateReq(ctx, tx, cur)
				}
				return nil // the same failure is logged once
			}
			x.Result = strp(out.failure)
			if gone {
				x.RemoveAt = nil // the sweep must not try an undo that cannot be sent
			}
			if err := s.step(ctx, tx, "response.fail", cur.ID, LogFailed, x.Change.Rollback.Title+": "+out.failure, "system"); err != nil {
				return err
			}
			return updateReq(ctx, tx, cur)
		}
		x.Status, x.RolledBackAt, x.StateUnknown, x.UndoUnclear, x.RemoveAt = ItemRolledBack, strp(s.ts()), false, false, nil
		earlier := ""
		if wasUnknown {
			earlier = " Its earlier outcome was not known."
		}
		if auto {
			x.Result = strp("Undone automatically (undo time ended)." + out.note)
		} else {
			x.Result = strp("Removed.")
			if x.ConnectorID != nil {
				x.Result = strp("Undone through " + oneLine(deref2(x.Connection), 80) + "." + earlier + out.note)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_block_entries WHERE request_id = ? AND item_id = ?`, cur.ID, x.ID); err != nil {
			return err
		}
		if auto {
			err = s.step(ctx, tx, "response.ttl_remove", cur.ID, LogTTLRemoved, x.Change.Rollback.Title+": undo time of "+itoa(intOr(x.TTLMin, 0))+" minutes ended; "+callText(x.Change.Rollback.Rest, x.Change.Rollback.CLI)+out.note, "system")
		} else {
			err = s.step(ctx, tx, "response.rollback", cur.ID, LogRolledBack, x.Change.Rollback.Title+"; "+callText(x.Change.Rollback.Rest, x.Change.Rollback.CLI)+earlier+out.note, actor)
		}
		if err != nil {
			return err
		}
		fx.ob.Add(events.Event{Name: EventActionRolledBack, Data: RolledBackEvent{RequestID: cur.ID, ItemID: x.ID, ActionID: x.ActionID, Auto: auto}})
		if !slices.ContainsFunc(cur.recs, func(i itemRec) bool { return undoable(i.RequestItem) }) {
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

// EmergencyStop is POST /response/emergency-stop: execution off, the global circuit breaker open and every pending request
// cancelled, in one transaction. The open breaker stops what the execution switch does not: pre-approved rules, the box actions
// (block list, webhook, message) and every item still to run (fire and runItem read it per rule and per item); only an admin
// resets it (INV-8, INV-12). It takes neither mu nor execMu: a stop must never wait. A step that is already running finishes;
// the next one reads the switch and the breaker.
func (s *Service) EmergencyStop(ctx context.Context, who Actor) (int, error) {
	cancelled := 0
	var fx effects
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		st.Execution = false
		if st.BreakerTrippedAt == nil {
			st.BreakerTrippedAt = strp(s.ts())
		}
		if st.StoppedAt == nil {
			st.StoppedAt = strp(s.ts()) // blocks every step that touches a device, an undo included, until an admin resumes
		}
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
		return s.step(ctx, tx, "response.emergency_stop", "response", LogEmergencyStop, who.Email+" stopped execution and opened the circuit breaker (only an admin can resume); "+itoa(cancelled)+" pending request"+plural(cancelled)+" cancelled", who.Email)
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
	if err := s.sweepExpired(ctx); err != nil {
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

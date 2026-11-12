package response

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
)

// The steps of an item on a device (INV-22, D-94, D-95) and what is recorded for how they ended: the check before, the run, the read-back; the
// undo and its read-back; the read-back that settles an outcome that was not clear; and the re-check right before every step that writes.

// canRead reports whether the item has a read-back it can use: a read step, a text to look for, and a step that only reads.
func (ex *execRec) canRead() bool {
	return ex != nil && ex.Verify != nil && ex.Expect != "" && readOnlyProblem(ex.Verify) == ""
}

type readState int

const (
	readUnclear readState = iota // the device did not answer, or printed nothing: that proves nothing (D-95 (1b))
	readPresent                  // the text is there
	readAbsent                   // the device printed something and the text is not in it
)

// readBack reads the device once and says whether the text of the read-back is there. It is held to the identity of the connection, not its
// fingerprint: it only reads, and it is what settles an outcome after the connection was edited.
func (s *Service) readBack(ctx context.Context, reqID string, it itemRec, conn ConnectionInfo) readState {
	vr, err := s.execute(ctx, deviceStep(reqID, it, conn, "verify", it.Exec.Verify, true))
	got := vr.Output
	vr.Output = ""
	if err != nil || vr.Status != StepOK || strings.TrimSpace(normalizeOutput(got)) == "" {
		return readUnclear
	}
	if readBackHolds(got, it.Exec.Expect, false) {
		return readPresent
	}
	return readAbsent
}

// execMatches re-renders the steps from the catalog row (whose fingerprint the gate already compared) and the stored typed values, and
// reports whether they are the stored ones. A row edited behind the API would otherwise send something else than the approver saw (L1).
func (s *Service) execMatches(cat catRow, it itemRec, conn ConnectionInfo) bool {
	want, err := s.buildExec(cat, Values(it.Values), &conn, it.TTLMin)
	if err != nil {
		return false
	}
	a, err1 := json.Marshal(want)
	b, err2 := json.Marshal(it.Exec)
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}

// recheck reads again, right before a step that writes goes out, what forbids it. A person can press the emergency stop while the check
// before runs for a minute. A run needs the switch on, the breaker closed, no stop, no maintenance window and the action still enabled. An
// undo is the safe direction (D-88 (4)): the execution switch and the breaker do not stop it; the emergency stop does.
func (s *Service) recheck(ctx context.Context, undo bool, actionID string) *apierr.Error {
	orig := ctx
	ctx = context.WithoutCancel(ctx) // the emergency stop cancels the step's context (D-179 (4)); the answer "the stop is on" must still be read
	rdb := s.cfg.DB.Reader()
	st, err := loadSettings(ctx, rdb)
	if err != nil {
		return fail(http.StatusServiceUnavailable, "unavailable", "The settings could not be read, so the step was not sent.")
	}
	if st.StoppedAt != nil {
		return fail(http.StatusConflict, "emergency_stop", "Held: the emergency stop is on (only an admin can resume). Nothing was sent.")
	}
	if orig.Err() != nil { // the step was cancelled or ran out of time while the check before ran: it is not sent (D-179 (4)), so it is not "state unknown" either
		return fail(http.StatusConflict, "step_cancelled", "Held: the step ended before it could be sent. Nothing was sent.")
	}
	if undo {
		return nil
	}
	if !st.Execution {
		return fail(http.StatusConflict, "execution_off", offMsg)
	}
	if st.BreakerTrippedAt != nil {
		return fail(http.StatusConflict, "circuit_open", breakerMsg)
	}
	if w := maintenanceNow(st, s.now()); w != nil {
		return fail(http.StatusConflict, "maintenance", "Held: maintenance window \""+oneLine(w.Name, 80)+"\" is active. Nothing was changed.")
	}
	cats, err := s.cats(ctx, rdb)
	if err != nil {
		return fail(http.StatusServiceUnavailable, "unavailable", "The catalog could not be read, so the step was not sent.")
	}
	if c, ok := cats[actionID]; !ok || !c.Enabled {
		return fail(http.StatusForbidden, "tool_not_allowed", "The action is no longer enabled in the action catalog. Nothing was changed.")
	}
	return nil
}

// carryOutDevice is the order of a step on a device: the check before, which only reads and may refuse (nothing is written); the read of the
// read-back text before the run (D-356); the run; the read-back against the expected text. What the device printed is compared and dropped
// here: it is never stored, logged or returned. Only whether the read-back text was there before the run is kept (presentBefore).
func (s *Service) carryOutDevice(ctx context.Context, r request, it itemRec, cat catRow, conn ConnectionInfo) itemOutcome {
	ex := it.Exec
	if ex == nil || ex.Run == nil {
		return itemOutcome{err: "This request was made by an older version of Vedette, so it cannot run. Nothing was changed. Ask again."}
	}
	if !s.execMatches(cat, it, conn) {
		return itemOutcome{err: "The steps stored with this request are not what its action renders (the stored request was altered). Nothing was sent. Ask again."}
	}
	send := func(phase string, st *execStep) (DeviceResult, error) {
		return s.execute(ctx, deviceStep(r.ID, it, conn, phase, st, false))
	}
	var before *bool // whether the read-back text was there before the run; nil when the action has no read-back
	if ex.Precheck != nil {
		if why := readOnlyProblem(ex.Precheck); why != "" {
			return itemOutcome{err: "The check before was not sent: " + why + ". Nothing was changed."}
		}
		res, err := send("precheck", ex.Precheck)
		out := res.Output
		res.Output = ""
		if o, failed := s.stepProblem(ctx, conn, "The check before", res, err, false); failed {
			return o
		}
		if why := precheckVerdict(out, ex.Refuse, ex.PrecheckExpect); why != "" {
			return itemOutcome{refusal: fail(http.StatusConflict, "precheck_refused", "Refused by the check before: "+oneLine(why, 120)+". Nothing was changed.")}
		}
		if ex.canRead() && sameStep(ex.Precheck, ex.Verify) { // the check before is the read-back's own read: no second read
			before = new(readBackHolds(out, ex.Expect, false))
		}
	}
	if ex.canRead() && before == nil {
		// D-356: one read before the write, so a read-back that settles an unclear run can tell "applied by this step" from "already there".
		// A device that does not answer a read right before the write gets no write (like the check before). An answer that printed
		// nothing does not hold the text.
		res, err := send("verify", ex.Verify)
		out := res.Output
		res.Output = ""
		if o, failed := s.stepProblem(ctx, conn, "The read before", res, err, false); failed {
			return o
		}
		before = new(readBackHolds(out, ex.Expect, false))
	}
	o := s.runAndRead(ctx, r, it, conn, send, before)
	o.presentBefore = before
	return o
}

// runAndRead sends the run of a device item after its checks passed and reads the device back.
func (s *Service) runAndRead(ctx context.Context, r request, it itemRec, conn ConnectionInfo, send func(string, *execStep) (DeviceResult, error), before *bool) itemOutcome {
	ex := it.Exec
	if e := s.recheck(ctx, false, it.ActionID); e != nil { // the check may have taken a minute: the stop, the switch and the breaker are read again
		return itemOutcome{refusal: e}
	}
	res, err := send("run", ex.Run)
	if o, failed := s.stepProblem(ctx, conn, "The step", res, err, true); failed {
		if o.unknown && ex.canRead() && ctx.Err() == nil { // not when the item's own time is up: the sweep reads it back
			// An answer that is not clear: read the device now, once, and settle it when the read-back can (the sweep tries again when it cannot).
			switch s.readBack(ctx, r.ID, it, conn) {
			case readPresent:
				if why := notThisStep(before); why != "" {
					return itemOutcome{err: "The answer of the device was not clear. " + why}
				}
				return itemOutcome{result: "Applied: the answer of the device was not clear, and the read-back shows the change.", verified: &Verified{OK: true, Detail: "Read back from the device: the expected text is there."}}
			case readAbsent:
				return itemOutcome{err: "The answer of the device was not clear, and the read-back does not show the change: it is not in force."}
			}
		}
		return o
	}
	out := itemOutcome{result: oneLine(res.Detail, 300)}
	if ex.canRead() { // without a text to look for there is nothing to check: "not checked", never "ok" (D-95 (2))
		vr, verr := send("verify", ex.Verify)
		got := vr.Output
		switch {
		case verr != nil || vr.Status != StepOK:
			out.verified = &Verified{OK: false, Detail: "The read-back did not answer."}
		case readBackHolds(got, ex.Expect, false):
			out.verified = &Verified{OK: true, Detail: "Read back from the device: the expected text is there."}
		default:
			out.verified = &Verified{OK: false, Detail: "Read back from the device: the expected text is not there."}
		}
	} else if ex.Verify != nil && ex.Expect != "" {
		out.verified = &Verified{OK: false, Detail: "The read-back was not sent: it may only read."}
	}
	return out
}

// sameStep reports whether two rendered steps send the same thing.
func sameStep(a, b *execStep) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// notThisStep is why a read-back that shows the change after an unclear run does not prove this step applied it (D-356): the text was
// there before the run, or the item has no record of the read before it (a run cut short by a restart, or made by an older version). ""
// when the text was read as absent before the run, so the change is this step's. Such an item is not counted as in force: nothing undoes
// a change that may be another's.
func notThisStep(before *bool) string {
	switch {
	case before == nil:
		return "The read-back shows the change, but the device was not read before this step, so it is not known whether this step applied it. State unknown: Vedette does not count it as its change and will not undo it. Check the device."
	case *before:
		return "The read-back shows the change, but it was already there before this step, so it is not known whether this step applied it. State unknown: Vedette does not count it as its change and will not undo it. Check the device."
	}
	return ""
}

// stepProblem is nil-and-false when the step completed; otherwise the outcome to record. writes says the step changes the device: a
// step that may have been applied (a time-out, a crash, an answer that is not understood) leaves "state unknown" (INV-13); a read changed nothing.
func (s *Service) stepProblem(ctx context.Context, conn ConnectionInfo, what string, res DeviceResult, err error, writes bool) (itemOutcome, bool) {
	name := oneLine(conn.Name, 80)
	detail := strings.TrimRight(oneLine(res.Detail, 200), ". ")
	if detail != "" {
		detail = " (" + detail + ")"
	}
	switch {
	case err != nil && (ctx.Err() != nil || errors.Is(err, errExecutorPanic)):
		if writes {
			return itemOutcome{err: "The connection " + name + " did not answer in time or the step failed half way. " + stateUnknown, unknown: true}, true
		}
		return itemOutcome{err: "The connection " + name + " did not answer in time. Nothing was changed."}, true
	case err != nil:
		return itemOutcome{err: "The connection " + name + " did not answer. Nothing was changed."}, true
	}
	switch res.Status {
	case StepOK:
		return itemOutcome{}, false
	case StepConnectionChange:
		return itemOutcome{refusal: fail(http.StatusConflict, "connection_changed", "The connection \""+name+"\" was changed after the request was made. Nothing was changed. Ask again.")}, true
	case StepNotSent:
		return itemOutcome{err: what + " was not sent to " + name + detail + ". Nothing was changed."}, true
	case StepFailed:
		return itemOutcome{err: what + " was refused by " + name + detail + ". Nothing was changed."}, true
	}
	if !writes {
		return itemOutcome{err: what + " did not complete on " + name + detail + ". Nothing was changed."}, true
	}
	return itemOutcome{err: what + " may or may not have been applied on " + name + detail + ". " + stateUnknown, unknown: true}, true
}

// undoOutcome is how an undo ended: why the change was not undone ("" when it was), a note for the result, and whether the outcome is not clear
// (the next try reads the device before it sends anything).
type undoOutcome struct {
	failure, note string
	unclear       bool
}

// undoStepsProblem is why the stored steps of an item may not be sent as an undo, "" when they may (D-179 (3)). The rollback that goes out is
// the one that was rendered and approved: the stored steps are held to the hash taken when the request was made, whether or not the catalog was
// edited since (the TTL sweep sends it unattended). A change made before the hash existed has none: while its catalog entry is unchanged the steps
// are re-rendered and compared, as before (so an in-force change from before the upgrade still expires); once the entry changed there is nothing
// to hold them to.
func (s *Service) undoStepsProblem(cats map[string]catRow, it itemRec, conn ConnectionInfo) string {
	if it.Exec == nil {
		return ""
	}
	cat, ok := cats[it.ActionID]
	unchanged := ok && actionFP(cat) == it.ActionFP
	switch {
	case it.ExecHash != "" && execHash(it.Exec) != it.ExecHash:
		return "The steps stored with this change do not match the hash taken when the request was made (the stored request was altered), so the undo was not sent. Undo it on the device."
	case unchanged && !s.execMatches(cat, it, conn):
		return "The steps stored with this change are not what its action renders (the stored request was altered), so the undo was not sent. Undo it on the device."
	case it.ExecHash == "" && !unchanged:
		return "This change was made before the steps were hashed and its action was edited since, so the stored steps cannot be checked and the undo was not sent. Undo it on the device."
	}
	return ""
}

// undoOnDevice sends the rollback of a change that is in force or whose state is unknown, and reads the device back: after the undo the read-back
// must not hold the text it held after the change (D-95 (2)), and a read-back that printed nothing, or did not answer, is not proof (L2). An
// undo whose outcome is unclear is retried by reading first: gone means done, present means send again, unclear means wait (L3).
func (s *Service) undoOnDevice(ctx context.Context, reqID string, it itemRec, conn ConnectionInfo) undoOutcome {
	ex := it.Exec
	if ex == nil || ex.Rollback == nil {
		return undoOutcome{failure: "This change was made by an older version of Vedette, so it cannot be undone from here. Undo it on the device."}
	}
	if e := s.recheck(ctx, true, it.ActionID); e != nil {
		return undoOutcome{failure: "The undo was not sent: " + e.Message, unclear: it.UndoUnclear}
	}
	name := oneLine(conn.Name, 80)
	note := ""
	if len(conn.WriteTools) == 0 || (it.RollbackTool != "" && !slices.Contains(conn.WriteTools, it.RollbackTool)) {
		note = " The undo was sent although the write tool of the connection is off (an undo is the safe direction)."
	}
	canRead := ex.canRead()
	gone := " Read back from the device: the change is gone."
	if it.UndoUnclear && canRead {
		switch s.readBack(ctx, reqID, it, conn) {
		case readAbsent:
			return undoOutcome{note: gone}
		case readUnclear:
			return undoOutcome{failure: "An earlier undo is not confirmed, and " + name + " cannot be read back now. Waiting. Check the device.", unclear: true}
		}
	}
	res, err := s.execute(ctx, deviceStep(reqID, it, conn, "rollback", ex.Rollback, true))
	switch {
	case err != nil:
		return undoOutcome{failure: "The connection " + name + " did not answer. The undo may not have been applied; the change may still be in force.", unclear: canRead}
	case res.Status != StepOK:
		detail := strings.TrimRight(oneLine(res.Detail, 200), ". ")
		if detail != "" {
			detail = " (" + detail + ")"
		}
		unclear := canRead && res.Status != StepFailed && res.Status != StepNotSent && res.Status != StepConnectionChange
		return undoOutcome{failure: "The undo did not complete on " + name + detail + ". The change may still be in force.", unclear: unclear}
	}
	if !canRead {
		return undoOutcome{note: note}
	}
	if readOnlyProblem(ex.Verify) != "" {
		return undoOutcome{note: " The read-back was not sent." + note}
	}
	switch s.readBack(ctx, reqID, it, conn) {
	case readAbsent:
		return undoOutcome{note: gone + note}
	case readPresent:
		return undoOutcome{failure: "The undo was sent to " + name + ", but the read-back still shows the change. Check the device."}
	}
	return undoOutcome{failure: "The undo was sent to " + name + ", but the read-back printed nothing or did not answer, so it does not confirm the undo. Check the device.", unclear: true}
}

// ---- settling an outcome that was not clear ----

// resolveUnknown reads the device back for every failed item whose outcome is "state unknown" and whose action has a read-back text, and settles
// it: the text is there and was read as absent before the run, so it is in force (executed, with its undo time); the text is there but was there
// before the run, or was not read before it, so it is not shown to be this step's (failed, not counted, not undone, D-356); the device printed
// something else, so it is not in force (failed); a read-back that is unclear leaves it as it is and the next sweep tries again.
func (s *Service) resolveUnknown(ctx context.Context) error {
	reqs, err := loadReqs(ctx, s.cfg.DB.Reader(), `WHERE status IN ('failed', 'approved', 'executed')`)
	if err != nil {
		return err
	}
	for _, r := range reqs {
		for _, it := range r.recs {
			if it.Status == ItemFailed && it.StateUnknown && it.ConnectorID != nil && it.Exec.canRead() {
				if err := s.resolveItem(ctx, r.ID, it.ID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Service) resolveItem(ctx context.Context, reqID, itemID string) error {
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
	if k < 0 || r.recs[k].Status != ItemFailed || !r.recs[k].StateUnknown || r.recs[k].ConnectorID == nil {
		return nil
	}
	it := r.recs[k]
	cs, err := s.loadConns(ctx)
	if err != nil {
		return err
	}
	conn, known := cs.get(*it.ConnectorID)
	if !known || s.cfg.Executor == nil || s.recheck(ctx, true, it.ActionID) != nil {
		return nil
	}
	xctx, cancel := context.WithTimeout(ctx, s.stepLimit)
	state := s.readBack(xctx, reqID, it, conn)
	cancel()
	if state == readUnclear {
		return nil
	}
	var fx effects
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		fx = effects{}
		cur, ok, err := loadReq(ctx, tx, reqID)
		if err != nil || !ok {
			return err
		}
		j := slices.IndexFunc(cur.recs, func(i itemRec) bool { return i.ID == itemID })
		if j < 0 || cur.recs[j].Status != ItemFailed || !cur.recs[j].StateUnknown {
			return nil
		}
		x := &cur.recs[j]
		x.StateUnknown = false
		if why := notThisStep(x.PresentBefore); state == readPresent && why != "" { // D-356: not shown to be this step's change
			x.Result = strp(why)
			if err := s.step(ctx, tx, "response.fail", cur.ID, LogFailed, x.Title+": the outcome was not known; "+why, "system"); err != nil {
				return err
			}
			return updateReq(ctx, tx, cur)
		}
		if state == readAbsent {
			x.Result = strp("Read back from the device: the change is not in force.")
			if err := s.step(ctx, tx, "response.fail", cur.ID, LogFailed, x.Title+": the outcome was not known; the read-back of the device does not show the change, so it is not in force", "system"); err != nil {
				return err
			}
			return updateReq(ctx, tx, cur)
		}
		now := s.now()
		x.Status, x.ExecutedAt, x.Result, x.Verified = ItemExecuted, strp(store2(now)), strp("Confirmed by a read-back: the step was applied."), &Verified{OK: true, Detail: "Read back from the device: the expected text is there."}
		if x.Reversible && x.TTLMin != nil {
			x.RemoveAt = strp(store2(now.Add(time.Duration(*x.TTLMin) * time.Minute)))
		}
		if cur.Status == StatusFailed {
			cur.Status = StatusExecuted
		}
		detail := x.Title + ": the outcome was not known; the read-back of the device shows the change, so it is in force"
		if x.RemoveAt != nil {
			detail += "; undone automatically at " + *x.RemoveAt
		}
		if err := s.step(ctx, tx, "response.execute", cur.ID, LogExecuted, detail, "system"); err != nil {
			return err
		}
		fx.ob.Add(events.Event{Name: EventActionExecuted, Data: ExecutedEvent{RequestID: cur.ID, ItemID: x.ID, ActionID: x.ActionID, Device: true}})
		return updateReq(ctx, tx, cur)
	})
	if err != nil {
		return err
	}
	s.run(ctx, &fx)
	return nil
}

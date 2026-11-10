package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
)

// WP-13b slice 13b-10 (D-97, INV-15, INV-16, FORBID-5): AI proposals. The ai module calls Service.Propose as the service identity
// ai:response; there is no HTTP route for it in the real build. The AI names a catalog action and typed values and points at the
// evidence. The server, not the prompt, decides whether that becomes an approval request, a suggestion note, a digest note or a
// refusal. The body has no field that could hold a command, a path, a template or a header (INV-14, TestProposeBodyHasNoCommandField).

// AIActor is the actor of everything an AI proposal does: the log, the audit and the request carry this name. It is not a user: no
// session, no role, and it can never approve anything (INV-1).
const AIActor = "ai:response"

// Limits of a proposal, checked before any gate.
const (
	maxProposeEvidence = 10
	maxProposeParams   = 20
	maxProposeParam    = 200
	maxProposeEvID     = 120
	maxProposeWhy      = 400
	maxAINotes         = 50
	secondCheckMinEv   = 2
	secondCheckMinConf = 0.9
)

// Evidence kinds a proposal may name.
const (
	EvFinding    = "finding"
	EvIocHit     = "ioc_hit"
	EvConfigRead = "config_read"
)

// ProposedEvidence names one piece of evidence: the kind and the id the server looks up. The AI never supplies the summary.
type ProposedEvidence struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// ProposeBody is what the AI sends. Every field is a name or a typed value; the change itself is rendered by the server from the
// catalog templates, exactly as for a rule.
type ProposeBody struct {
	Trigger    string             `json:"trigger"`
	ActionID   string             `json:"action_id"`
	Params     map[string]string  `json:"params"`
	Confidence float64            `json:"confidence"`
	Evidence   []ProposedEvidence `json:"evidence"`
	Why        string             `json:"why"`
}

// Outcomes of a proposal that was not refused.
const (
	OutcomeRequest    = "request"
	OutcomeSuggestion = "suggestion"
	OutcomeDigest     = "digest"
)

// ProposedRequest is all the AI gets back about the request it caused: where to find it and how risky it is, never the rendered change,
// the address, the body or the headers (D-119). The people who approve see the rest in the app.
type ProposedRequest struct {
	ID                string `json:"id"`
	Status            Status `json:"status"`
	Risk              Risk   `json:"risk"`
	Title             string `json:"title"`
	RequiresApprovals int    `json:"requires_approvals"`
	ExpiresAt         string `json:"expires_at"`
	InAppOnly         bool   `json:"in_app_only"`
}

// ProposeResult is what Propose answers when the proposal was not refused.
type ProposeResult struct {
	Outcome string           `json:"outcome"`
	Note    string           `json:"note"`
	Request *ProposedRequest `json:"request"`
}

// EvidenceRef is a piece of evidence a port found: what it says in one line, and the addresses, ports and names it is about (the
// target of an action must be one of them, compared by type).
type EvidenceRef struct {
	// ID is the canonical id of the object when it differs from the id asked for; "" = the id asked for.
	ID      string
	Summary string
	Relates []string
	// Connection is, for a connection read, the id of the connection it went through. A read relates to an action only when this is the
	// connection of that action (D-119); "" = it relates to nothing.
	Connection string
}

// EvidencePorts look up evidence the module does not own. A nil port, or a lookup that says not found, means the evidence does not
// exist: the proposal is refused (422 evidence_invalid, D-97). A finding is looked up through Directory.
type EvidencePorts struct {
	// IocHit finds a known-bad connection by id (logs, WP-24). Nil until that module offers a read-only lookup (D-119).
	IocHit func(ctx context.Context, id string) (EvidenceRef, bool, error)
	// ConfigRead finds a read the AI made, by its read record. Nil until the ai module offers a lookup of the reads it really made,
	// at most 24 hours old (D-119): an existing read tool proves nothing.
	ConfigRead func(ctx context.Context, id string) (EvidenceRef, bool, error)
}

var triggerRE = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)
var paramKeyRE = regexp.MustCompile(`^[a-z_]{1,32}$`)

func aiFail(status int, code, msg string) error { return fail(status, code, "AI request: "+msg) }

// checkProposal validates the body at the boundary: values, sizes and characters. It returns the cleaned body.
func checkProposal(in ProposeBody) (ProposeBody, error) {
	bad := func(msg string) (ProposeBody, error) {
		return ProposeBody{}, aiFail(http.StatusBadRequest, "invalid", msg)
	}
	if !triggerRE.MatchString(in.Trigger) || !idRE.MatchString(in.ActionID) {
		return bad("send trigger, action_id, params, confidence (0 to 1), evidence and why.")
	}
	if math.IsNaN(in.Confidence) || math.IsInf(in.Confidence, 0) || in.Confidence < 0 || in.Confidence > 1 {
		return bad("confidence must be a number from 0 to 1.")
	}
	if len(in.Params) > maxProposeParams {
		return bad("too many params.")
	}
	for k, v := range in.Params {
		if !paramKeyRE.MatchString(k) {
			return bad("a param name is not valid.")
		}
		if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxProposeParam {
			return bad("a param value is longer than " + itoa(maxProposeParam) + " characters or is not text.")
		}
	}
	if utf8.RuneCountInString(in.Why) > maxProposeWhy {
		return bad("why is longer than " + itoa(maxProposeWhy) + " characters.")
	}
	in.Why = cleanLine(in.Why)
	if in.Why == "" {
		return bad("say why in one line.")
	}
	if len(in.Evidence) > maxProposeEvidence {
		return bad("at most " + itoa(maxProposeEvidence) + " pieces of evidence.")
	}
	var ev []ProposedEvidence
	for _, e := range in.Evidence {
		if e.Kind != EvFinding && e.Kind != EvIocHit && e.Kind != EvConfigRead {
			return bad("an evidence kind must be finding, ioc_hit or config_read.")
		}
		if e.ID == "" || utf8.RuneCountInString(e.ID) > maxProposeEvID || cleanLine(e.ID) != e.ID {
			return bad("an evidence id is empty, longer than " + itoa(maxProposeEvID) + " characters or not plain text.")
		}
		if !slices.Contains(ev, e) { // the same object twice is one piece of evidence: it must not count twice for the second check
			ev = append(ev, e)
		}
	}
	in.Evidence = ev
	return in, nil
}

// foundEvidence is the answer of the lookups for one piece of evidence. id is the canonical id the lookup returned.
type foundEvidence struct {
	ProposedEvidence
	id      string
	ok      bool
	err     error // the lookup failed: carried to the evidence gate, so the gates before it still answer first
	summary string
	relates []string // addresses, ports and ids it is about
	names   []string // host names it is about: they never match an address
	conn    string   // for a connection read: the connection it went through
	finding *FindingInfo
	asset   *DeviceInfo
}

// lookupEvidence resolves every piece of evidence the proposal names. Not found and a failing lookup are both left in the answer: the
// evidence gate decides, after the gates before it. The same object cited twice is one piece.
func (s *Service) lookupEvidence(ctx context.Context, list []ProposedEvidence) []foundEvidence {
	var out []foundEvidence
	for _, e := range list {
		f := foundEvidence{ProposedEvidence: e, id: e.ID}
		switch e.Kind {
		case EvFinding:
			f.err = s.lookupFinding(ctx, &f)
		case EvIocHit:
			f.err = s.lookupPort(ctx, &f, s.cfg.Evidence.IocHit)
		case EvConfigRead:
			f.err = s.lookupPort(ctx, &f, s.cfg.Evidence.ConfigRead)
		}
		if f.ok && slices.ContainsFunc(out, func(o foundEvidence) bool { return o.ok && o.id == f.id }) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// lookupFinding finds a finding that is still open: a closed, false-positive or resolved finding is not evidence (as plans, openStatus).
func (s *Service) lookupFinding(ctx context.Context, f *foundEvidence) error {
	if s.cfg.Directory == nil {
		return nil
	}
	fi, ok, err := s.cfg.Directory.Finding(ctx, f.ID)
	if err != nil || !ok || !openStatus(fi.Status) {
		return err
	}
	name := fi.AssetID
	if d, ok, err := s.cfg.Directory.Device(ctx, fi.AssetID); err != nil {
		return err
	} else if ok {
		f.asset = &d
		name = firstNonEmpty(d.Name, d.IP, fi.AssetID)
		if d.IP != "" {
			f.relates = []string{d.IP}
		}
		if d.Name != "" {
			f.names = []string{d.Name}
		}
	}
	f.ok, f.finding, f.id = true, &fi, fi.ID
	f.summary = truncRunes(cleanLine("Finding "+fi.CVE+" on "+name+" ("+fi.Severity+")"), 200)
	return nil
}

func (s *Service) lookupPort(ctx context.Context, f *foundEvidence, port func(context.Context, string) (EvidenceRef, bool, error)) error {
	if port == nil {
		return nil
	}
	ref, ok, err := port(ctx, f.ID)
	if err != nil || !ok {
		return err
	}
	f.ok, f.summary, f.conn = true, truncRunes(cleanLine(ref.Summary), 200), cleanLine(ref.Connection)
	if id := cleanLine(ref.ID); id != "" {
		f.id = truncRunes(id, maxProposeEvID)
	}
	for _, r := range ref.Relates {
		if r = cleanLine(r); r != "" && len(f.relates) < 20 {
			f.relates = append(f.relates, r)
		}
	}
	return nil
}

// relatesTo says whether the evidence is about the action. Typed: an address, MAC or domain relates only to a target of the same type
// (compared in its canonical spelling), a host name only to a name or text target, an id or port by exact text. A connection read relates
// only to a device action through that same connection; a box action never has a connection, so no read can justify it (D-119).
func (f foundEvidence) relatesTo(vals Values, cat catRow) bool {
	if f.conn != "" {
		return cat.device() && cat.ConnectionID == f.conn
	}
	for p, v := range vals {
		switch p {
		case PIP, PCIDR, PDomain, PMAC:
			if slices.ContainsFunc(f.relates, func(r string) bool { c, ok := CheckValue(p, r); return ok && c == v }) {
				return true
			}
		default:
			if slices.Contains(f.relates, v) || (p == PName || p == PText) && slices.ContainsFunc(f.names, func(n string) bool { return strings.EqualFold(n, v) }) {
				return true
			}
		}
	}
	return false
}

// subjectsOfEvidence are the addresses of the devices the cited findings are about, for the never-touch check of an action: every
// one of them, not only the first.
func subjectsOfEvidence(ev []foundEvidence) []string {
	var out []string
	for _, e := range ev {
		if e.ok && e.asset != nil {
			if ip, ok := CheckValue(PIP, e.asset.IP); ok && !slices.Contains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	return out
}

const (
	maxProposalsPerHour = 60 // calls of any outcome (D-119)
	proposalLogEvery    = time.Minute
)

// proposalRate counts a call and refuses the 61st in an hour (429 rate_limited with Retry-After). A refusal is logged once per minute
// with the number refused since the last line, like the event backlog drops of StoreEvent, so a runaway caller cannot grow the log.
func (s *Service) proposalRate(ctx context.Context) error {
	now := s.now()
	s.limitMu.Lock()
	keep := s.proposeTimes[:0]
	for _, t := range s.proposeTimes {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	if len(keep) < maxProposalsPerHour {
		s.proposeTimes = append(keep, now)
		s.limitMu.Unlock()
		return nil
	}
	s.proposeTimes = keep
	s.proposeSkipped++
	n, due := s.proposeSkipped, s.proposeLoggedAt.IsZero() || now.Sub(s.proposeLoggedAt) >= proposalLogEvery
	if due {
		s.proposeSkipped, s.proposeLoggedAt = 0, now
	}
	wait := int((keep[0].Add(time.Hour).Sub(now) + time.Second - 1) / time.Second)
	s.limitMu.Unlock()
	err := aiFail(http.StatusTooManyRequests, "rate_limited", "more than "+itoa(maxProposalsPerHour)+" proposals in one hour ("+itoa(n)+" refused since the last line). Try again later.")
	if ae, ok := asAPI(err); ok {
		err = ae.With("retry_after", wait)
	}
	if due {
		return s.refuse(ctx, err, "response.ai", AIActor)
	}
	return err
}

// Propose is the one entry for an AI proposal. The gates run in the order of INV-15 (the mock web/src/features/response/ai.ts is the
// reference) and the whole decision is one write transaction under the service lock, so two proposals at once cannot both pass "already
// open" or the budget. A refusal is an error carrying the code and status of the mock and is recorded in resp_log; a note (suggestion
// or digest) is a normal result. Nothing here approves anything: a request is created pending, never pre-approved. With the module off
// nothing is read, written or published.
func (s *Service) Propose(ctx context.Context, in ProposeBody) (ProposeResult, error) {
	if !s.on() {
		return ProposeResult{}, aiFail(http.StatusNotFound, "not_found", "the response module is off.")
	}
	if err := s.proposalRate(ctx); err != nil {
		return ProposeResult{}, err
	}
	b, err := checkProposal(in)
	if err != nil {
		return ProposeResult{}, s.refuse(ctx, err, "response.ai", AIActor)
	}
	if err := s.ensureSeeded(ctx); err != nil {
		return ProposeResult{}, err
	}
	ev := s.lookupEvidence(ctx, b.Evidence)
	var refusal error
	var out ProposeResult
	var fx effects
	s.mu.Lock()
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) (err error) {
		fx = effects{}
		out, refusal, err = s.proposeInTx(ctx, tx, b, ev, &fx)
		return err
	})
	s.mu.Unlock() // events and the breaker notice go out with the lock released: a subscriber may call back into this service
	if err != nil {
		return ProposeResult{}, err
	}
	s.run(ctx, &fx)
	if refusal != nil {
		return ProposeResult{}, s.refuse(ctx, refusal, "response.ai", AIActor)
	}
	return out, nil
}

// proposeInTx runs the gates. It returns a refusal (written nothing, apart from a breaker trip the gate itself commits), or a result.
func (s *Service) proposeInTx(ctx context.Context, tx *sql.Tx, b ProposeBody, found []foundEvidence, fx *effects) (out ProposeResult, refusal error, err error) {
	no := func(status int, code, msg string) (ProposeResult, error, error) {
		return ProposeResult{}, aiFail(status, code, msg), nil
	}
	st, err := loadSettings(ctx, tx)
	if err != nil {
		return out, nil, err
	}
	cats, err := s.cats(ctx, tx)
	if err != nil {
		return out, nil, err
	}
	cat, ok := cats[b.ActionID]
	if !ok {
		return no(http.StatusBadRequest, "invalid", "there is no such action in the action catalog.")
	}
	// 1. maintenance window
	if w := maintenanceNow(st, s.now()); w != nil {
		return no(http.StatusConflict, "maintenance", "held, maintenance window \""+oneLine(w.Name, 80)+"\" is active.")
	}
	// 2. circuit breaker
	if st.BreakerTrippedAt != nil {
		return no(http.StatusConflict, "circuit_open", breakerMsg)
	}
	// 3. AI paused by the quality breaker
	if e := checkAIPaused(st); e != nil {
		return out, e, nil
	}
	// 4. trigger the admin allowed, and one that some kind of evidence can prove
	if !slices.Contains(st.AI.Triggers, b.Trigger) {
		return no(http.StatusForbidden, "trigger_not_allowed", "the admin has not allowed the AI to send requests for this trigger.")
	}
	var proof []string
	if t := s.trigger(b.Trigger); t != nil {
		proof = t.AIEvidence
	}
	if len(proof) == 0 {
		return no(http.StatusForbidden, "trigger_not_allowed", "no kind of evidence can prove this trigger, so the AI cannot send requests for it. Only triggers backed by a finding or a known-bad connection are open to the AI.")
	}
	// 5. action flagged for the AI
	if !cat.Enabled || !cat.AIMayPropose {
		return no(http.StatusForbidden, "action_not_ai_allowed", "the action \""+oneLine(cat.Name, 80)+"\" is not enabled for AI proposals in the action catalog.")
	}
	// 6. plan it through the planner rules use: typed values, never-touch, available. Undoable actions get 24 hours, others no undo time.
	// The devices of the cited findings are the subjects of the never-touch check, every one of them.
	cs, err := s.loadConns(ctx)
	if err != nil {
		return out, nil, err
	}
	never, nt, err := s.neverTouchOrRefusal(ctx, tx)
	if err != nil {
		return out, nil, err
	}
	if nt != nil {
		return out, aiFail(nt.Status, nt.Code, nt.Message), nil
	}
	prop := storedProposal{ActionID: cat.ID, Params: b.Params}
	if cat.reversible() {
		ttl := 1440
		prop.TTLMin = &ttl
	}
	subjects := subjectsOfEvidence(found)
	var pl planned
	for i, subject := range append(subjects, "")[:max(len(subjects), 1)] {
		p, pf := s.planProposal(prop, subject, b.Why, cats, cs, never)
		if pf != nil {
			return no(http.StatusConflict, pf.code, pf.msg)
		}
		if i == 0 {
			pl = p
		}
	}
	// 7. evidence: there is some, every piece exists, one of them proves the trigger, one is about the target
	if len(found) == 0 {
		return no(http.StatusBadRequest, "evidence_missing", "a request must reference at least one real object: a finding id, a known-bad connection id or a connection read.")
	}
	var evidence []Evidence
	for _, f := range found {
		if f.err != nil {
			s.cfg.Log.ErrorContext(ctx, "response: look up AI evidence", "kind", f.Kind, "error", f.err)
			return no(http.StatusServiceUnavailable, "evidence_unavailable", "the evidence could not be looked up just now. Nothing was requested.")
		}
		if !f.ok {
			return no(http.StatusUnprocessableEntity, "evidence_invalid", "the evidence "+f.Kind+" \""+truncRunes(f.ID, 40)+"\" does not exist, or is a finding that is no longer open. The AI cannot invent evidence.")
		}
		evidence = append(evidence, Evidence{Kind: f.Kind, ID: f.id, Summary: f.summary})
	}
	// An action that names a device part or no address acts on "the device the finding is about": without a finding the never-touch list
	// cannot be checked. (After the evidence exists, so a proposal with no evidence is told that first.)
	if (!namesAnAddress(Values(pl.rec.Values)) || namesADevicePart(Values(pl.rec.Values))) && len(subjects) == 0 {
		return no(http.StatusConflict, "never_touch", "no finding gives the device this action acts on, so the never-touch list cannot be checked. Nothing was requested.")
	}
	if !slices.ContainsFunc(evidence, func(e Evidence) bool { return slices.Contains(proof, e.Kind) }) {
		return no(http.StatusUnprocessableEntity, "evidence_mismatch", "none of the evidence proves the trigger \""+b.Trigger+"\": it needs "+strings.Join(proof, " or ")+".")
	}
	related := map[string]bool{} // by canonical id: only these count for the repeat rule and the second check
	for _, f := range found {
		if f.relatesTo(pl.rec.Values, cats[cat.ID]) {
			related[f.id] = true
		}
	}
	if len(related) == 0 {
		return no(http.StatusUnprocessableEntity, "evidence_mismatch", "none of the evidence is about the target of this action.")
	}
	var targets []string
	for _, p := range cat.params() {
		if v := pl.rec.Values[p]; v != "" {
			targets = append(targets, v)
		}
	}
	target := strings.Join(targets, ", ")
	title := pl.rec.Title
	// 8. low confidence is a suggestion, not a request
	if b.Confidence < AIMinConfidence {
		detail := "Suggestion only, no approval request: " + title + " (confidence " + fmtConf(b.Confidence) + " is below " + fmtConf(AIMinConfidence) + ")"
		if err := s.saveNote(ctx, tx, OutcomeSuggestion, "Consider: "+title, b, cat.ID, target, evidence, detail); err != nil {
			return out, nil, err
		}
		return ProposeResult{Outcome: OutcomeSuggestion, Note: "Confidence " + fmtConf(b.Confidence) + " is below " + fmtConf(AIMinConfidence) + ": saved as a suggestion note, no approval request was sent."}, nil, nil
	}
	// 9. one open request per target and action
	open, err := openKeys(ctx, tx, s.now())
	if err != nil {
		return out, nil, err
	}
	if open[pl.key] {
		return no(http.StatusConflict, "already_open", "there is already an open request or active change for "+truncRunes(cleanLine(target), 120)+" with this action.")
	}
	// 10. rejected by a person in the last 7 days: not again, unless there is related evidence the earlier request did not have
	rejected, err := loadReqs(ctx, tx, `WHERE source = 'ai' AND status = 'rejected' AND `+byPersonSQL+` AND decided_at >= ?`, store.FormatTS(s.now().AddDate(0, 0, -AIRepeatDays)))
	if err != nil {
		return out, nil, err
	}
	known, repeated := map[string]bool{}, false
	for _, r := range rejected {
		if r.AI != nil && slices.ContainsFunc(r.recs, func(i itemRec) bool { return planKey(i.RequestItem) == pl.key }) {
			repeated = true
			for _, e := range r.AI.Evidence {
				known[e.ID] = true
			}
		}
	}
	if repeated {
		fresh := false
		for id := range related {
			fresh = fresh || !known[id]
		}
		if !fresh {
			return no(http.StatusConflict, "repeat_blocked", "this was rejected within the last "+itoa(AIRepeatDays)+" days and there is no new evidence about the target, so it is not asked again.")
		}
	}
	// 11. budget: over it, the proposal goes to the digest
	hourN, dayN, err := s.aiUsage(ctx, tx)
	if err != nil {
		return out, nil, err
	}
	if hourN >= st.AI.BudgetHour || dayN >= st.AI.BudgetDay {
		detail := "Over budget (" + itoa(st.AI.BudgetHour) + " per hour, " + itoa(st.AI.BudgetDay) + " per day): moved to the digest instead of asking now: " + title
		if err := s.saveNote(ctx, tx, OutcomeDigest, title, b, cat.ID, target, evidence, detail); err != nil {
			return out, nil, err
		}
		return ProposeResult{Outcome: OutcomeDigest, Note: "Budget reached (" + itoa(st.AI.BudgetHour) + " per hour, " + itoa(st.AI.BudgetDay) + " per day): added to the digest."}, nil, nil
	}
	// 12. high risk: the deterministic second check, on the evidence that is about the target
	high := pl.rec.Risk == RiskHigh
	var second *SecondCheck
	if high {
		ok := len(related) >= secondCheckMinEv && b.Confidence >= secondCheckMinConf
		second = &SecondCheck{OK: ok, Notes: "Second check passed: 2 or more pieces of evidence about the target and confidence of 0.9 or more."}
		if !ok {
			second.Notes = "Second check failed: a high-risk action needs at least 2 pieces of evidence about the target (got " + itoa(len(related)) + ") and confidence of 0.9 or more (got " + fmtConf(b.Confidence) + ")."
			return no(http.StatusUnprocessableEntity, "second_check_failed", second.Notes)
		}
	}
	// 13. the request. The global breaker counts it like a rule's request; it is never pre-approved and never via=auto.
	if tripped, err := s.checkBreaker(ctx, tx, &st, 1, fx); err != nil {
		return out, nil, err
	} else if tripped {
		return no(http.StatusConflict, "circuit_open", breakerMsg)
	}
	rec := pl.rec
	rec.ID = newID("it")
	init := reqInit{Source: "ai", Actor: AIActor, ProposalID: "ai:" + newID("p"), Trigger: b.Trigger, TriggerSummary: b.Why, AssetName: target, Title: title, Recs: []itemRec{rec},
		AI: &AiMeta{Confidence: b.Confidence, Evidence: evidence, Why: b.Why, SecondCheck: second, InAppOnly: high}}
	if i := slices.IndexFunc(found, func(f foundEvidence) bool { return f.finding != nil }); i >= 0 {
		init.FindingID, init.CVE = found[i].finding.ID, found[i].finding.CVE
	}
	for _, f := range found { // the device shown is the one whose address is the target, as in the mock
		if f.asset != nil && slices.Contains(targets, f.asset.IP) {
			init.AssetID, init.AssetName = f.asset.ID, truncRunes(cleanLine(firstNonEmpty(f.asset.Name, f.asset.IP)), 120)
			break
		}
	}
	r, err := s.createRequest(ctx, tx, st, init, fx)
	if err != nil {
		return out, nil, err
	}
	line := title + ": confidence " + fmtConf(b.Confidence) + ", evidence " + evidenceLine(evidence)
	if second != nil {
		line += "; " + second.Notes
	}
	if err := s.step(ctx, tx, "response.proposal", r.ID, LogProposal, line, AIActor); err != nil {
		return out, nil, err
	}
	note := "Request sent for approval."
	if high {
		note = "Request sent. High risk: two different people must approve, in the app with the two-step code."
	}
	return ProposeResult{Outcome: OutcomeRequest, Note: note, Request: &ProposedRequest{ID: r.ID, Status: r.Status, Risk: r.Risk, Title: r.Title,
		RequiresApprovals: r.RequiresApprovals, ExpiresAt: r.ExpiresAt, InAppOnly: high}}, nil, nil
}

func evidenceLine(l []Evidence) string {
	parts := make([]string, len(l))
	for i, e := range l {
		parts[i] = e.Kind + " " + e.ID
	}
	return strings.Join(parts, ", ")
}

func fmtConf(f float64) string { return fmt.Sprintf("%g", f) }

// aiUsage counts the AI requests of the last hour and the last day.
func (s *Service) aiUsage(ctx context.Context, q dbq) (hour, day int, err error) {
	now := s.now()
	for _, w := range []struct {
		n *int
		d time.Duration
	}{{&hour, time.Hour}, {&day, 24 * time.Hour}} {
		since := store.FormatTS(now.Add(-w.d))
		if err := q.QueryRowContext(ctx, `SELECT count(*) FROM resp_actions WHERE source = 'ai' AND requested_at >= ?`, since).Scan(w.n); err != nil {
			return 0, 0, fmt.Errorf("response: count the AI requests: %w", err)
		}
	}
	return hour, day, nil
}

// saveNote stores a suggestion or digest note (the newest 50 of each kind are kept) and writes the log line, inside tx.
func (s *Service) saveNote(ctx context.Context, tx *sql.Tx, kind, title string, b ProposeBody, actionID, target string, ev []Evidence, detail string) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resp_ai_notes (id, ts, kind, title, why, confidence, action_id, target, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID("note"), s.ts(), kind, truncRunes(cleanLine(title), 200), b.Why, b.Confidence, actionID, truncRunes(cleanLine(target), 200), string(raw)); err != nil {
		return fmt.Errorf("response: save an AI note: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resp_ai_notes WHERE kind = ?1 AND rowid NOT IN (SELECT rowid FROM resp_ai_notes WHERE kind = ?1 ORDER BY ts DESC, rowid DESC LIMIT ?2)`, kind, maxAINotes); err != nil {
		return fmt.Errorf("response: trim the AI notes: %w", err)
	}
	return s.step(ctx, tx, "response.ai_note", "response.ai", LogAINote, detail, AIActor)
}

// ---- what the AI may propose ----

// AIParam is one typed value of an action the AI may propose. Name is the key to send in params; Pattern or Min and Max say what the
// type accepts (the server checks the type again and the AI cannot widen it).
type AIParam struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Label   string `json:"label"`
	Pattern string `json:"pattern,omitempty"`
	Min     int    `json:"min,omitempty"`
	Max     int    `json:"max,omitempty"`
}

// AIAction is an enabled catalog action with ai_may_propose, as the AI sees it: a name, what it does, how risky it is and the typed
// values it takes. Never a command, a path, a body or a template. Available is false when the action cannot run now (no connection,
// connection not ready): a proposal for it is refused 409.
type AIAction struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Risk        Risk      `json:"risk"`
	Reversible  bool      `json:"reversible"`
	Available   bool      `json:"available"`
	Params      []AIParam `json:"params"`
}

var paramPattern = map[ParamType]string{PDomain: domainRE.String(), PMAC: macRE.String(), PInterface: interfaceRE.String(), PName: nameRE.String(), PText: textRE.String(), PID: digitsRE.String()}
var paramRange = map[ParamType][2]int{PPort: {1, 65535}, PVLAN: {1, 4094}, PID: {1, 2147483647}}

// AIActions lists what the AI may propose, in catalog order, for the ai module to build its tool schema from.
func (s *Service) AIActions(ctx context.Context) ([]AIAction, error) {
	if !s.on() {
		return []AIAction{}, nil // the module is off: nothing to propose
	}
	if err := s.ensureSeeded(ctx); err != nil {
		return nil, err
	}
	rd := s.cfg.DB.Reader()
	rows, err := loadCatalog(ctx, rd)
	if err != nil {
		return nil, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return nil, err
	}
	out := []AIAction{}
	for _, c := range rows {
		if !c.Enabled || !c.AIMayPropose {
			continue
		}
		a := AIAction{ID: c.ID, Name: oneLine(c.Name, 120), Description: truncRunes(cleanLine(c.Description), 300), Risk: c.Risk, Reversible: c.reversible(), Available: unavailable(c, cs) == "", Params: []AIParam{}}
		for _, p := range c.params() {
			ap := AIParam{Name: string(p), Type: string(p), Label: ParamLabel[p], Pattern: paramPattern[p]}
			if r, ok := paramRange[p]; ok {
				ap.Min, ap.Max = r[0], r[1]
			}
			a.Params = append(a.Params, ap)
		}
		out = append(out, a)
	}
	return out, nil
}

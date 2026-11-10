package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/store"
)

// WP-13b slice 13b-9 (D-97, D-98, INV-15 (8), INV-16, INV-18): approving a high-risk AI request with the two-step code, the hints a
// rejection can leave, the quality breaker and the AI state.

// AI thresholds of the contract (INV-15). Propose reads them for the proposal gates.
const (
	AIMinConfidence = 0.8 // AI_MIN_CONFIDENCE
	AIRepeatDays    = 7   // AI_REPEAT_DAYS

	qualityWindow = 10 // the last decided AI requests the breaker looks at
	qualityMin    = 5  // decisions needed before the breaker may trip
	maxHints      = 50 // resp_hints keeps the newest
	maxSummary    = 200
)

// TwoStep checks the two-step code of a person for one purpose. cmd/vedette adapts core/auth.VerifyTwoStep; its errors are API
// errors (400 code_required, invalid_code, wrong_code, 403 twofa_required, 429 with Retry-After, 503) and pass through unchanged
// (INV-16). A nil TwoStep means no code can be checked: a high-risk AI request is refused with 403 twofa_required.
type TwoStep interface {
	Verify(ctx context.Context, userID, code, purpose, summary string) error
}

// Remember is what a rejection keeps of its reason (INV-18). It is a hint for the people who read it, nothing more.
const (
	RememberNone   = "none"
	RememberRule   = "rule"
	RememberMemory = "memory"
)

// Hint is a rejection reason kept as advice (INV-18). Nothing reads it to change a rule, a prompt or a decision.
type Hint struct {
	ID          string `json:"id"`
	TS          string `json:"ts"`
	Kind        string `json:"kind"` // rule or memory
	Text        string `json:"text"`
	FromRequest string `json:"from_request"`
}

// AiNote is a suggestion or digest line the AI left instead of a request (Propose writes them, propose.go).
type AiNote struct {
	ID         string     `json:"id"`
	TS         string     `json:"ts"`
	Kind       string     `json:"kind"`
	Title      string     `json:"title"`
	Why        string     `json:"why"`
	Confidence float64    `json:"confidence"`
	ActionID   string     `json:"action_id"`
	Target     string     `json:"target"`
	Evidence   []Evidence `json:"evidence"`
}

// AiQuality is how the last decided AI requests went.
type AiQuality struct {
	Decided  int  `json:"decided"`
	Rejected int  `json:"rejected"`
	Paused   bool `json:"paused"`
}

// AiUsage counts the AI requests made in the last hour and day.
type AiUsage struct {
	Hour int `json:"hour"`
	Day  int `json:"day"`
}

// AiState is GET /response/ai.
type AiState struct {
	Gates         AiGates   `json:"gates"`
	MinConfidence float64   `json:"min_confidence"`
	RepeatDays    int       `json:"repeat_days"`
	Usage         AiUsage   `json:"usage"`
	Quality       AiQuality `json:"quality"`
	Notes         []AiNote  `json:"notes"`
	Hints         []Hint    `json:"hints"`
}

// ---- approving (INV-16) ----

// aiStepUp is the part of an approval that comes before its transaction, for a high-risk AI request: in the app only, not already
// approved by this person, then the two-step code for this request. The code is checked outside the transaction because checking it
// writes (the limiter, the replay guard, the audit line). Anything that is not such a request returns (false, nil) here and the
// transaction answers (not found, expired, not pending). A code is spent only when the cheap refusals have passed, so a wrong pick or
// a second click by the same person does not cost one. stepped is true only when the code of this person for this request passed: the
// transaction refuses an in_app_only request that did not get it (L1), so a path that reaches the approval without this check, or a
// clock that moved back between the two reads, fails closed.
func (s *Service) aiStepUp(ctx context.Context, who Actor, id string, pick []string, code string) (stepped bool, err error) {
	r, ok, err := loadReq(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return false, err
	}
	if !ok || r.AI == nil || !r.AI.InAppOnly || r.Status != StatusPending || !parseTS(r.ExpiresAt).After(s.now()) {
		return false, nil
	}
	if who.Via != ViaApp {
		return false, fail(http.StatusForbidden, "in_app_required", "A high-risk AI request can only be approved in the app with your two-step code, not from chat or email.")
	}
	var first *Approval
	if len(r.Approvals) > 0 {
		first = &r.Approvals[0]
	}
	have := func(x string) bool { return slices.ContainsFunc(r.recs, func(i itemRec) bool { return i.ID == x }) }
	switch {
	case slices.ContainsFunc(r.Approvals, func(x Approval) bool { return x.UserID == who.ID }):
		return false, fail(http.StatusConflict, "same_approver", "You already approved this request. A second, different person must approve it.")
	case slices.ContainsFunc(pick, func(x string) bool { return !have(x) }):
		return false, fail(http.StatusBadRequest, "invalid_items", "Pick at least one action of this request.")
	case first != nil && len(pick) > 0 && !sameSet(pick, first.Items):
		return false, fail(http.StatusConflict, "selection_differs", "The second approver must approve the same actions as the first.")
	}
	if s.cfg.TwoStep == nil {
		return false, errTwofaRequired()
	}
	ids := pick
	switch {
	case len(ids) > 0:
	case first != nil:
		ids = first.Items
	}
	if err := s.cfg.TwoStep.Verify(ctx, who.ID, code, "response.approve."+r.ID, approveSummary(r, ids)); err != nil {
		return false, err
	}
	return true, nil
}

func errTwofaRequired() error {
	return fail(http.StatusForbidden, "twofa_required", "Turn on two-step sign-in for your account first (My account), then try again.")
}

// approveSummary is the line the approver sees with the code, built here from the stored request and from nothing the caller sent
// (OWASP Transaction Authorization): the risk first, then what is approved (only the picked actions, or all of them when none are
// picked), on what, in quotes so a name cannot pass for part of the sentence. A list that does not fit says "and N more". One line, at
// most 200 characters, no control, format or filler character (core/auth checks the same).
func approveSummary(r request, ids []string) string {
	var titles []string
	for _, i := range r.recs {
		if len(ids) == 0 || slices.Contains(ids, i.ID) {
			titles = append(titles, quoted(i.Title, 80))
		}
	}
	head := strings.ToUpper(string(r.Risk)[:1]) + string(r.Risk)[1:] + "-risk AI request: "
	tail := ""
	if t := quoted(r.AssetName, 60); t != `""` {
		tail = " on " + t
	}
	room := maxSummary - len([]rune(head)) - len([]rune(tail))
	for n := len(titles); n >= 0; n-- {
		more := ""
		if n < len(titles) {
			more = " and " + itoa(len(titles)-n) + " more"
		}
		list := strings.Join(titles[:n], ", ")
		if len([]rune(list))+len([]rune(more)) <= room {
			return head + list + more + tail
		}
	}
	return head + tail
}

// quoted is s as one clean line in double quotes, cut to n characters; a quote inside becomes an apostrophe.
func quoted(s string, n int) string {
	return `"` + truncRunes(strings.ReplaceAll(cleanLine(s), `"`, "'"), n) + `"`
}

// cleanLine makes s plain one-line text: control, format (bidi marks, zero-width characters), Unicode tag, variation-selector and
// filler characters (Hangul fillers, braille blank, combining grapheme joiner) are dropped, other separators become spaces, and runs of
// space become one. What a person cannot see must not reach a summary, a hint or a note a model may read later.
func cleanLine(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case isInvisible(r):
			return -1
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	return strings.Join(strings.Fields(s), " ")
}

func isInvisible(r rune) bool {
	switch {
	case unicode.Is(unicode.Cf, r), r >= 0xE0000 && r <= 0xE007F, r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	switch r {
	case 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F, 0x17B4, 0x17B5, 0x180E:
		return true
	}
	return false
}

func truncRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		if n < 1 {
			return ""
		}
		return string(r[:n-1]) + "…"
	}
	return s
}

// ---- hints (INV-18) and the quality breaker (INV-15 (8)) ----

// keepHint stores the reason of a rejected AI request as a hint, inside tx, and drops all but the newest 50.
func (s *Service) keepHint(ctx context.Context, tx *sql.Tx, r request, kind, reason string) error {
	text := truncRunes(cleanLine(reason), 300)
	if text == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resp_hints (id, ts, kind, text, from_request) VALUES (?, ?, ?, ?, ?)`, newID("hint"), s.ts(), kind, text, r.ID); err != nil {
		return fmt.Errorf("response: save a hint: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resp_hints WHERE rowid NOT IN (SELECT rowid FROM resp_hints ORDER BY ts DESC, rowid DESC LIMIT ?)`, maxHints); err != nil {
		return fmt.Errorf("response: trim the hints: %w", err)
	}
	label := "a memory hint"
	if kind == RememberRule {
		label = "a rule hint"
	}
	return s.step(ctx, tx, "response.ai_hint", r.ID, LogAINote, "Rejection reason saved as "+label+": "+truncRunes(text, 200), "system")
}

// byPersonSQL keeps a request out of the AI's record unless somebody really decided it: a rejection counts only when a person wrote it
// (the server words that note "Rejected by <name>"). A cancellation (an action edited, the emergency stop) is also status rejected but is
// no verdict on the AI: it counts for neither the quality breaker nor the 7-day repeat rule (D-119).
const byPersonSQL = `(status <> 'rejected' OR note LIKE 'Rejected by %')`

// decidedStatuses are the statuses of a request somebody decided (not pending, not expired).
const decidedStatuses = `('approved', 'executed', 'failed', 'rolled_back', 'rejected')`

// aiQuality looks at the last 10 decided AI requests.
func aiQuality(ctx context.Context, q dbq, paused bool) (AiQuality, error) {
	rs, err := loadReqs(ctx, q, `WHERE source = 'ai' AND decided_at IS NOT NULL AND status IN `+decidedStatuses+` AND `+byPersonSQL+` ORDER BY decided_at DESC, seq DESC LIMIT ?`, qualityWindow)
	if err != nil {
		return AiQuality{}, err
	}
	out := AiQuality{Decided: len(rs), Paused: paused}
	for _, r := range rs {
		if r.Status == StatusRejected {
			out.Rejected++
		}
	}
	return out, nil
}

// qualityTrips: at least 5 of the last 10 are decided and more than half of them were rejected.
func qualityTrips(q AiQuality) bool { return q.Decided >= qualityMin && q.Rejected*2 > q.Decided }

// checkAIQuality runs after every decision on an AI request, inside the decision's transaction. When the breaker trips it pauses the
// AI (ai.paused_at), writes a breaker line and sends an admin notice. It never rejects or approves anything.
func (s *Service) checkAIQuality(ctx context.Context, tx *sql.Tx, fx *effects) error {
	st, err := loadSettings(ctx, tx)
	if err != nil || st.AI.PausedAt != nil {
		return err
	}
	q, err := aiQuality(ctx, tx, false)
	if err != nil || !qualityTrips(q) {
		return err
	}
	reason := itoa(q.Rejected) + " of the last " + itoa(q.Decided) + " AI requests were rejected"
	st.AI.PausedAt, st.AI.PausedReason = strp(s.ts()), strp(reason)
	if err := s.saveSettings(ctx, tx, st); err != nil {
		return err
	}
	detail := "AI proposals paused by the quality breaker: " + reason + ". An admin can resume them in Settings, AI response."
	if err := s.step(ctx, tx, "response.ai_paused", "response", LogBreaker, detail, "system"); err != nil {
		return err
	}
	at := *st.AI.PausedAt
	fx.later(func(ctx context.Context) { s.message(ctx, "aipause-"+at, "AI proposals paused", detail) })
	return nil
}

// checkAIPaused is the pause gate of a new AI proposal: Propose calls it, with the settings it already read, among its gates (after the
// circuit breaker, before the trigger check, in the order of the mock).
func checkAIPaused(st Settings) error {
	if st.AI.PausedAt == nil {
		return nil
	}
	why := "quality breaker"
	if st.AI.PausedReason != nil && *st.AI.PausedReason != "" {
		why = *st.AI.PausedReason
	}
	return fail(http.StatusConflict, "ai_paused", "AI request: AI proposals are paused ("+why+"). An admin can resume them.")
}

// ---- the AI state ----

// AIState is GET /response/ai.
func (s *Service) AIState(ctx context.Context) (AiState, error) {
	rd := s.cfg.DB.Reader()
	st, err := loadSettings(ctx, rd)
	if err != nil {
		return AiState{}, err
	}
	q, err := aiQuality(ctx, rd, st.AI.PausedAt != nil)
	if err != nil {
		return AiState{}, err
	}
	out := AiState{Gates: st.AI, MinConfidence: AIMinConfidence, RepeatDays: AIRepeatDays, Quality: q, Notes: []AiNote{}, Hints: []Hint{}}
	now := s.now()
	for _, w := range []struct {
		n *int
		d time.Duration
	}{{&out.Usage.Hour, time.Hour}, {&out.Usage.Day, 24 * time.Hour}} {
		if err := rd.QueryRowContext(ctx, `SELECT count(*) FROM resp_actions WHERE source = 'ai' AND requested_at >= ?`, store.FormatTS(now.Add(-w.d))).Scan(w.n); err != nil {
			return AiState{}, fmt.Errorf("response: count the AI requests: %w", err)
		}
	}
	rows, err := rd.QueryContext(ctx, `SELECT id, ts, kind, title, why, confidence, action_id, target, evidence FROM resp_ai_notes ORDER BY ts DESC, rowid DESC LIMIT 100`)
	if err != nil {
		return AiState{}, fmt.Errorf("response: read the AI notes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n AiNote
		var ev string
		if err := rows.Scan(&n.ID, &n.TS, &n.Kind, &n.Title, &n.Why, &n.Confidence, &n.ActionID, &n.Target, &ev); err != nil {
			return AiState{}, fmt.Errorf("response: read the AI notes: %w", err)
		}
		if err := json.Unmarshal([]byte(ev), &n.Evidence); err != nil || n.Evidence == nil {
			n.Evidence = []Evidence{}
		}
		out.Notes = append(out.Notes, n)
	}
	if err := rows.Err(); err != nil {
		return AiState{}, fmt.Errorf("response: read the AI notes: %w", err)
	}
	hr, err := rd.QueryContext(ctx, `SELECT id, ts, kind, text, from_request FROM resp_hints ORDER BY ts DESC, rowid DESC LIMIT ?`, maxHints)
	if err != nil {
		return AiState{}, fmt.Errorf("response: read the hints: %w", err)
	}
	defer func() { _ = hr.Close() }()
	for hr.Next() {
		var h Hint
		if err := hr.Scan(&h.ID, &h.TS, &h.Kind, &h.Text, &h.FromRequest); err != nil {
			return AiState{}, fmt.Errorf("response: read the hints: %w", err)
		}
		out.Hints = append(out.Hints, h)
	}
	return out, hr.Err()
}

// ResumeAI is POST /response/ai/resume: an admin clears the pause the quality breaker set. It is audited and logged.
func (s *Service) ResumeAI(ctx context.Context, who Actor) (AiState, error) {
	s.mu.Lock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		st.AI.PausedAt, st.AI.PausedReason = nil, nil
		if err := s.saveSettings(ctx, tx, st); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.ai_resume", "response", LogSettings, "AI proposals resumed by "+who.Email, who.Email+" (app)")
	})
	s.mu.Unlock()
	if err != nil {
		return AiState{}, err
	}
	return s.AIState(ctx)
}

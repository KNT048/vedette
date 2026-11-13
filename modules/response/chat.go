package response

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// Decisions from chat (INV-3, slice 13b-8, D-96 (5), D-135, docs/specs/approval-tokens.md 5 to 7).
//
// notify owns the line to Slack, Telegram and Zalo and has checked the platform (Slack team and channel, Telegram chat, the Zalo session)
// before it calls DecideFromChat. This module maps the sender to a Vedette person and keeps every gate: the same approve and reject as the
// app, so INV-2, INV-9 and the rest still apply, and a Zalo reply code is burned in the transaction that records the decision.

const (
	chatPerMin = 20 // decisions per channel identity per minute (the same identity pressing buttons or typing codes)
	// replyKeep is how many code records of one address are looked at: two per request, and records live a week after they end.
	replyKeep = 200
)

// extIDRE is what a platform id looks like (Slack U..., a Telegram number, a Zalo id). Anything else cannot be on a list.
var extIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// replyCodeRE is a reply code after the form of spec 7.1 was applied: the prefix says approve (A) or reject (R), then six letters of the
// alphabet without 0, 1, I and O.
var replyCodeRE = regexp.MustCompile(`^[AR]-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$`)

// ChatDecision is what a listener of notify passes after it checked the platform: the sender's id on the platform, the request from the
// button (empty for a Zalo reply code, which names the request itself), the decision and the code that was typed (Zalo only).
type ChatDecision struct {
	Channel    string // slack, telegram or zalo-personal
	ExternalID string
	RequestID  string
	Approve    bool
	Code       string
}

// ChatOutcome says what was recorded. Status is "approved" (the approval that completes the request: it runs now), "pending" (an approval
// was recorded and another person must still approve) or "rejected". Approvals and Required are the counts after the decision. Message is
// a short private reply for the person who pressed the button. A refusal is an error (an *apierr.Error), never an outcome.
type ChatOutcome struct {
	RequestID string // the request that was decided (a Zalo reply code names it only through its record)
	Status    string
	Approvals int
	Required  int
	Message   string
}

func chatVia(channel string) (Via, bool) {
	switch Via(channel) {
	case ViaSlack, ViaTelegram, ViaZaloPersonal:
		return Via(channel), true
	}
	return "", false
}

// replyCodeHash is the hash of spec 7.1: SHA-256 of the fixed label, the request, the person, the decision and the normalised code, each
// on its own line. notify makes the same value when it records a code; the plain code is never stored.
func replyCodeHash(requestID, userID, decision, code string) string {
	sum := sha256.Sum256([]byte("vedette-reply-code-v1\n" + requestID + "\n" + userID + "\n" + decision + "\n" + code))
	return hex.EncodeToString(sum[:])
}

// normalizeReplyCode applies spec 7.1: no white space at the ends, ASCII letters upper case; the result must have the form of a code.
func normalizeReplyCode(s string) (string, bool) {
	s = strings.Trim(s, " \t\r\n\v\f") // spec 7.1: ASCII white space only (not NBSP or the other Unicode spaces)
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	s = string(b)
	return s, replyCodeRE.MatchString(s)
}

// chatGate runs the first three checks of INV-3: the channel is an approval channel of this module and ready (403 channel_not_allowed),
// the sender matches exactly one entry of that channel's list (403 approver_not_listed), and that person is an active operator or admin
// (the same 403). It is run again under the service lock. A directory or notify that cannot answer is an error: nothing is decided.
func (s *Service) chatGate(ctx context.Context, st Settings, channel, ext string) (User, *apierr.Error, error) {
	notAllowed := fail(http.StatusForbidden, "channel_not_allowed", "Approvals from "+truncRunes(cleanLine(channel), 32)+" are not turned on for response.")
	if _, ok := chatVia(channel); !ok {
		return User{}, notAllowed, nil
	}
	if ok, err := s.channelReady(ctx, st, channel); err != nil {
		return User{}, nil, err
	} else if !ok {
		return User{}, notAllowed, nil
	}
	notListed := errChatNotListed()
	if !extIDRE.MatchString(ext) || s.cfg.Users == nil || s.cfg.Notifier == nil {
		return User{}, notListed, nil
	}
	list, err := s.cfg.Notifier.Approvers(ctx, channel)
	if err != nil {
		return User{}, nil, err
	}
	var hit []Approver
	for _, a := range list {
		if a.Address == ext {
			hit = append(hit, a)
		}
	}
	if len(hit) != 1 { // none: not listed; two: an id that stands for two people is nobody
		return User{}, notListed, nil
	}
	u, ok, err := s.cfg.Users.Lookup(ctx, hit[0].UserID)
	if err != nil {
		return User{}, nil, err
	}
	if !ok || u.Disabled || (u.Role != "operator" && u.Role != "admin") {
		return u, notListed, nil
	}
	return u, nil, nil
}

func errChatNotListed() *apierr.Error {
	return fail(http.StatusForbidden, "approver_not_listed", "You are not an approver on this channel, or your Vedette account can no longer approve requests.")
}

// runDetached runs the items of a completed approval in the background (M3, D-135 (9)): a decision from chat is recorded and answered at
// once, the way a button must be answered, and the device steps (slow, up to 90 s an item) run on a goroutine the service tracks. Close
// ends them; an item cut short that way is marked unknown by the same rules as one that timed out. The caller's cancellation does not
// reach them (an approval that was committed runs to the end).
func (s *Service) runDetached(ctx context.Context, id string, items []string) {
	dctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	s.sendWG.Add(1)
	go func() {
		defer s.sendWG.Done()
		defer stop()
		go func() {
			select {
			case <-s.bg.Done():
				stop()
			case <-dctx.Done():
			}
		}()
		for _, itemID := range items {
			if err := s.runItem(dctx, id, itemID); err != nil {
				s.cfg.Log.ErrorContext(dctx, "response: run an approved item", "request", id, "item", itemID, "error", err)
				return
			}
		}
	}()
}

// codeRow is a stored reply code record that matched what was typed.
type codeRow struct {
	hash, request, user string
	expires             time.Time
	used                bool
}

// findCode looks for the record of the typed code among the codes of this sender (address = ExternalID): the hash is made with the request,
// person and decision of each record and compared in constant time (spec 7.1), so a code is bound to all three. A code of someone else, a
// code for the other decision or a wrong guess matches nothing. Used and expired are not decided here: the caller does it after the risk
// policy (INV-3 order).
func (s *Service) findCode(ctx context.Context, ext string, u User, code string, approve bool) (codeRow, bool, error) {
	norm, ok := normalizeReplyCode(code)
	if !ok || approve != (norm[0] == 'A') {
		return codeRow{}, false, nil
	}
	decision := "reject"
	if approve {
		decision = "approve"
	}
	// Unused codes first, so a person with many old, used codes cannot push the live one out of the window; used ones only to say "used".
	for _, state := range []string{"IS NULL", "IS NOT NULL"} {
		c, hit, err := s.matchCode(ctx, ext, u, decision, norm, state)
		if err != nil || hit {
			return c, hit, err
		}
	}
	return codeRow{}, false, nil
}

// matchCode compares the typed code with the records of the sender that are unused (state "IS NULL") or used ("IS NOT NULL").
func (s *Service) matchCode(ctx context.Context, ext string, u User, decision, norm, state string) (codeRow, bool, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT token_hash, action_id, user_id, expires_at, used_at FROM resp_tokens WHERE kind = 'code' AND channel = 'zalo-personal' AND address = ? AND decision = ? AND used_at `+state+` ORDER BY expires_at DESC LIMIT ?`, ext, decision, replyKeep)
	if err != nil {
		return codeRow{}, false, fmt.Errorf("response: read reply codes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var found codeRow
	var hit bool
	for rows.Next() {
		var c codeRow
		var expires string
		var used sql.NullString
		if err := rows.Scan(&c.hash, &c.request, &c.user, &expires, &used); err != nil {
			return codeRow{}, false, fmt.Errorf("response: read reply codes: %w", err)
		}
		c.expires, c.used = parseTS(expires), used.Valid
		// every row is compared (no early exit that tells which one matched), and the record must belong to the person this sender is
		if subtle.ConstantTimeCompare([]byte(replyCodeHash(c.request, c.user, decision, norm)), []byte(c.hash)) == 1 && c.user == u.ID && !hit {
			found, hit = c, true
		}
	}
	return found, hit, rows.Err()
}

// DecideFromChat takes a decision made in Slack, Telegram or a personal Zalo chat (notify calls it through Config.Decisions). The order of
// the checks is the one of INV-3: the rate limit of the sender, the channel, the sender on the list of that channel, the person (active,
// operator or above), the risk policy of the channel, for Zalo the reply code (matches request, person and decision, not used, not ended),
// then the same approve or reject as the app with via set to the channel. A refusal is an *apierr.Error and is logged as "refused" with the
// sender; a decision a gate refuses does not burn the code.
func (s *Service) DecideFromChat(ctx context.Context, d ChatDecision) (ChatOutcome, error) {
	if !s.on() {
		return ChatOutcome{}, fail(http.StatusForbidden, "channel_not_allowed", "Response is turned off.")
	}
	target := "chat"
	if extIDRE.MatchString(d.RequestID) {
		target = d.RequestID
	}
	// What a sender can make the box remember or write is bounded: an id or a channel that cannot be real shares one fixed name (D-135 (7), (8)).
	chName, idName := "(invalid channel)", "(invalid id)"
	if _, ok := chatVia(d.Channel); ok {
		chName = d.Channel
	}
	if extIDRE.MatchString(d.ExternalID) {
		idName = d.ExternalID
	}
	key := "chat:" + chName + "|" + idName
	anon := idName + " via " + chName
	// stranger refuses a sender that is not a known approver: one log line per window per sender, with the count of those held back.
	stranger := func(e *apierr.Error) error {
		if log, hidden := s.chatNoteDue("ref|" + key); log {
			le := e
			if hidden > 0 {
				le = fail(e.Status, e.Code, fmt.Sprintf("%s (%d more refusals of this sender since the last line)", e.Message, hidden))
			}
			_ = s.refuse(ctx, le, target, anon)
		}
		return e
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return ChatOutcome{}, err
	}
	allowed, full := s.chatAllow(key, false)
	var u User
	var gate *apierr.Error
	gated := false
	if full { // the table is full and this sender is new: only a listed approver is let in
		if u, gate, err = s.chatGate(ctx, st, d.Channel, d.ExternalID); err != nil {
			return ChatOutcome{}, err
		}
		if gate != nil {
			e := fail(http.StatusTooManyRequests, "rate_limited", "Too many senders at once. Try again in a minute.").With("retry_after", 60)
			if s.chatFullDue() {
				_ = s.refuse(ctx, fail(http.StatusTooManyRequests, "rate_limited", "chat rate table full: new senders that are not approvers are refused until it drains"), target, "system")
			}
			return ChatOutcome{}, e
		}
		allowed, _ = s.chatAllow(key, true)
		gated = true
	}
	if !allowed {
		e := errRateLimited()
		if log, hidden := s.chatNoteDue("rl|" + key); log {
			le := e
			if hidden > 0 {
				le = fail(e.Status, e.Code, fmt.Sprintf("%s (%d more since the last line)", e.Message, hidden))
			}
			_ = s.refuse(ctx, le, target, anon)
		}
		return ChatOutcome{}, e
	}
	if !gated {
		if u, gate, err = s.chatGate(ctx, st, d.Channel, d.ExternalID); err != nil {
			return ChatOutcome{}, err
		}
	}
	if gate != nil {
		return ChatOutcome{}, stranger(gate)
	}
	s.chatMarkListed(key)
	via, _ := chatVia(d.Channel)
	zalo := via == ViaZaloPersonal
	name := u.Name
	if name == "" {
		name = u.Email
	}
	who := Actor{ID: u.ID, Name: name, Email: u.Email, Via: via, Chat: d.ExternalID}
	refuse := func(e *apierr.Error) (ChatOutcome, error) {
		return ChatOutcome{}, s.refuse(ctx, e, target, who.refuseActor())
	}
	// D-191: the ID must be one its person linked (D-414: by the confirm link). Not linked: nothing is decided and the answer says how to link.
	if linked, err := s.isLinked(ctx, u, d.Channel, d.ExternalID); err != nil {
		return ChatOutcome{}, err
	} else if !linked {
		return ChatOutcome{}, s.chatNotLinked(ctx, d.Channel, d.ExternalID, target, who.refuseActor())
	}

	// The request: from the button, or (Zalo) from the record of the code.
	var rec codeRow
	reqID := d.RequestID
	if zalo {
		var found bool
		if rec, found, err = s.findCode(ctx, d.ExternalID, u, d.Code, d.Approve); err != nil {
			return ChatOutcome{}, err
		}
		if !found {
			return refuse(fail(http.StatusBadRequest, "invalid_code", "That code is not valid. Reply with the code from the latest message."))
		}
		reqID = rec.request
	}
	if !extIDRE.MatchString(reqID) {
		return refuse(fail(http.StatusNotFound, "not_found", "No such request."))
	}
	target = reqID
	r, found, err := loadReq(ctx, s.cfg.DB.Reader(), reqID)
	if err != nil {
		return ChatOutcome{}, err
	}
	if !found {
		return refuse(fail(http.StatusNotFound, "not_found", "No such request."))
	}
	withID := func(e *apierr.Error) *apierr.Error { return e.With("request_id", r.ID) }

	// The risk policy of the channel (D-96 (3)); it applies to approve and reject alike, as for a link.
	switch {
	case r.AI != nil && r.AI.InAppOnly:
		return refuse(withID(fail(http.StatusForbidden, "in_app_required", "This request can only be approved in the app. Open Vedette, sign in and decide it there.")))
	case zalo && r.Risk != RiskLow && r.Risk != RiskMedium:
		return refuse(withID(fail(http.StatusForbidden, "channel_not_allowed", "A high-risk request cannot be decided by a Zalo reply code. Open Vedette, sign in and decide it there.")))
	case chatNoButtons(r):
		// D-175: a chat decision is for a change that is low or medium risk and fits one message, as sent (buttons are not attached to any
		// other); an older button or a forged callback gets the same answer.
		return refuse(withID(fail(http.StatusForbidden, "channel_not_allowed", "This request cannot be decided from chat: it is high risk, or too long to read in one message. Open Vedette, sign in and decide it there.")))
	}

	lk := &linkOpt{recheck: func(ctx context.Context) (*apierr.Error, error) { // the person and the channel are read again once this call holds the lock
		st, err := loadSettings(ctx, s.cfg.DB.Reader())
		if err != nil {
			return nil, err
		}
		u2, gate, err := s.chatGate(ctx, st, d.Channel, d.ExternalID)
		if err != nil || gate != nil {
			return gate, err
		}
		if u2.ID != u.ID { // the id was given to someone else while this call waited: it is not the person who was checked
			return errChatNotListed(), nil
		}
		if linked, err := s.isLinked(ctx, u2, d.Channel, d.ExternalID); err != nil || !linked { // unlinked while this call waited
			return errChatNotLinked(d.Channel), err
		}
		return nil, nil
	}, detach: true}
	if zalo { // used or ended: said after the policy; the transaction reads both again
		now := s.now()
		switch {
		case rec.used:
			return refuse(withID(fail(http.StatusConflict, "used", "This code was already used.")))
		case !rec.expires.After(now):
			return refuse(withID(fail(http.StatusConflict, "expired", "This code has expired. Ask for a new approval request.")))
		}
		lk.hash, lk.kind, lk.requestID, lk.userID = rec.hash, "code", rec.request, rec.user
	}

	var out ActionRequest
	if d.Approve {
		out, err = s.approve(ctx, who, r.ID, nil, "", false, lk)
	} else {
		out, err = s.reject(ctx, who, r.ID, "in "+d.Channel, RememberNone, lk)
	}
	if err != nil {
		if ae, ok := apierr.As(err); ok && ae.Status == http.StatusConflict {
			if ae.Code == "not_pending" {
				ae = fail(http.StatusConflict, "decided", ae.Message)
			}
			return ChatOutcome{}, withID(ae)
		}
		return ChatOutcome{}, err
	}
	o := ChatOutcome{RequestID: r.ID, Approvals: len(out.Approvals), Required: out.RequiresApprovals}
	switch {
	case !d.Approve:
		o.Status, o.Message = "rejected", "Rejected. Nothing was changed."
	case out.Status == StatusPending:
		o.Status, o.Message = "pending", fmt.Sprintf("Approved. %d of %d approvals are in; a second, different person must approve it too.", o.Approvals, o.Required)
	default:
		o.Status, o.Message = "approved", "Approved. The action is being run; see Vedette for the result."
	}
	return o, nil
}

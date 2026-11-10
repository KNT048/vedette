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
	s = strings.TrimSpace(s)
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	s = string(b)
	return s, replyCodeRE.MatchString(s)
}

// chatActorText is the actor of a line about a sender that is not (yet) a known person: what they claim to be, cut and cleaned.
func chatActorText(channel, ext string) string {
	return truncRunes(cleanLine(ext), 64) + " via " + truncRunes(cleanLine(channel), 32)
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
	notListed := fail(http.StatusForbidden, "approver_not_listed", "You are not an approver on this channel, or your Vedette account can no longer approve requests.")
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
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT token_hash, action_id, user_id, expires_at, used_at FROM resp_tokens WHERE kind = 'code' AND channel = 'zalo-personal' AND address = ? AND decision = ? ORDER BY expires_at DESC LIMIT ?`, ext, decision, replyKeep)
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
	anon := chatActorText(d.Channel, d.ExternalID)
	key := "chat:" + truncRunes(cleanLine(d.Channel), 32) + "|" + truncRunes(cleanLine(d.ExternalID), 64)
	if !s.allowLink(key, chatPerMin, true) {
		e := errRateLimited()
		if s.allowLink("note:"+key, 1, true) { // one line per window: a flood must not fill the log
			return ChatOutcome{}, s.refuse(ctx, e, target, anon)
		}
		return ChatOutcome{}, e
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return ChatOutcome{}, err
	}
	u, gate, err := s.chatGate(ctx, st, d.Channel, d.ExternalID)
	if err != nil {
		return ChatOutcome{}, err
	}
	if gate != nil {
		return ChatOutcome{}, s.refuse(ctx, gate, target, anon)
	}
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
	}

	lk := &linkOpt{recheck: func(ctx context.Context) (*apierr.Error, error) { // the person and the channel are read again once this call holds the lock
		st, err := loadSettings(ctx, s.cfg.DB.Reader())
		if err != nil {
			return nil, err
		}
		if _, gate, err := s.chatGate(ctx, st, d.Channel, d.ExternalID); err != nil || gate != nil {
			return gate, err
		}
		return nil, nil
	}}
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
	o := ChatOutcome{Approvals: len(out.Approvals), Required: out.RequiresApprovals}
	switch {
	case !d.Approve:
		o.Status, o.Message = "rejected", "Rejected. Nothing was changed."
	case out.Status == StatusPending:
		o.Status, o.Message = "pending", fmt.Sprintf("Approved. %d of %d approvals are in; a second, different person must approve it too.", o.Approvals, o.Required)
	default:
		o.Status, o.Message = "approved", "Approved. The action runs now; see Vedette for the result."
	}
	return o, nil
}

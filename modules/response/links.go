package response

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// Approval links and sending approval requests (INV-3, INV-4, POST-5; slice 13b-7, D-96, docs/specs/approval-tokens.md).
//
// A request is sent to its approvers after the transaction that created it committed, never inside it (sendApproval). notify makes one
// signed link for each email approver and hands the record to RecordLink before the mail goes out; only the hash of the token id is
// stored. The page behind the link reads (LinkView, writes nothing); only the POST decides (DecideByLink). The decision goes through the
// same approve and reject as the app, so every gate of INV-9 still applies, and the token is burned in the transaction that records the
// decision: a decision a gate refused leaves it alive (D-96 (4)).

const (
	linkPostPerMin = 10 // POSTs on links per source address per minute
	linkBadPerMin  = 20 // links that are not valid per source address per minute
	// approvalWhatMax is the most of the change that goes into a message (spec 4.6, 11); the rest is "open Vedette".
	approvalWhatMax = 4096
	// sendBudget is how long sending one request may take (D-96 (2)): SMTP is slow and a send must not hold a request for ever.
	sendBudget = 60 * time.Second
	// tokenKeep is how long a record stays after it ended (DATA_MODEL 4.11).
	tokenKeep = 7 * 24 * time.Hour
)

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrLinkInvalid is what LinkTokens answers for a token that is malformed, has a wrong MAC or does not match the record it was
// found with. The caller answers 404 unknown for it and for a token without a record, so nothing can be probed.
var ErrLinkInvalid = errors.New("response: the approval link is not valid")

// Approver is a person who may approve on a channel, as the channel's saved list names them.
type Approver struct{ UserID, Address string }

// ApprovalMessage is one approval request to send. What is plain text of at most 4 KiB. Channels are the channel types the request may
// go to (empty sends nothing). InAppOnly means every channel only says to open Vedette: no link, no button, no code.
type ApprovalMessage struct {
	RequestID string
	Title     string
	What      string
	Risk      Risk
	InAppOnly bool
	Channels  []string
	Expires   time.Time
}

// LinkBinding is what a link is bound to: the request, the person, the channel and the moment it ends.
type LinkBinding struct {
	RequestID string
	UserID    string
	Channel   string
	ExpiresAt time.Time
}

// LinkTokens checks approval links (cmd/vedette wires notify.VerifyApprovalLink). A nil LinkTokens means no link can be checked: every
// link is unknown.
type LinkTokens interface {
	// ID returns the 16 bytes of the token id after a check of the form only (it proves nothing about who made the token).
	ID(token string) ([]byte, error)
	// Verify checks the MAC against the binding read from the stored record and the key the record names. It writes and burns nothing.
	// ErrLinkInvalid for a token that does not match; any other error means the box could not check.
	Verify(ctx context.Context, token string, b LinkBinding, keyID string) error
}

// LinkRecord is a link notify made, as it is stored: ID is the token id (the 16 bytes), Address where the link was sent.
type LinkRecord struct {
	ID        []byte
	RequestID string
	UserID    string
	Channel   string
	Address   string
	KeyID     string
	ExpiresAt time.Time
}

// ReplyCodeRecord is one reply code of one approver for one request: CodeHash is the lowercase hex hash of spec 7.1 (the code itself
// never reaches this module).
type ReplyCodeRecord struct {
	RequestID string
	UserID    string
	Address   string
	Approve   bool
	CodeHash  string
	ExpiresAt time.Time
}

// tokenRow is a stored record.
type tokenRow struct {
	hash, action, user, address, channel, keyID string
	expires                                     time.Time
	used                                        bool
}

func hashID(id []byte) string {
	sum := sha256.Sum256(id)
	return hex.EncodeToString(sum[:])
}

// ---- recording what notify made ----

// recordCheck reads the request a token or code is for: it must exist, be pending and end after the token does.
func (s *Service) recordCheck(ctx context.Context, tx dbq, requestID string, expires time.Time, link bool) error {
	r, ok, err := loadReq(ctx, tx, requestID)
	if err != nil {
		return err
	}
	now := s.now()
	switch {
	case !ok:
		return errors.New("response: no such request for the token")
	case r.Status != StatusPending:
		return errors.New("response: the request is no longer pending")
	case link && ((r.Risk != RiskLow && r.Risk != RiskMedium) || (r.AI != nil && r.AI.InAppOnly)):
		return errors.New("response: a high-risk or in-app-only request has no approval link (D-57 (20))")
	case !expires.After(now) || expires.After(now.Add(31*time.Minute)):
		return errors.New("response: a token lives at most 30 minutes")
	case expires.After(parseTS(r.ExpiresAt).Add(time.Second)):
		return errors.New("response: a token never outlives its request")
	}
	return nil
}

// RecordLink stores the record of an approval link before the mail with it goes out (notify.TokenRecorder). Only the hash of the token
// id is kept. Only email carries a link in 13b.
func (s *Service) RecordLink(ctx context.Context, l LinkRecord) error {
	if len(l.ID) != 16 || l.Channel != "email" || strings.TrimSpace(l.Address) == "" || l.KeyID == "" || l.UserID == "" {
		return errors.New("response: the approval link record is not valid")
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := s.recordCheck(ctx, tx, l.RequestID, l.ExpiresAt, true); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO resp_tokens (token_hash, kind, decision, action_id, user_id, address, channel, key_id, expires_at, used_at) VALUES (?, 'link', NULL, ?, ?, ?, ?, ?, ?, NULL)`,
			hashID(l.ID), l.RequestID, l.UserID, l.Address, l.Channel, l.KeyID, store2(l.ExpiresAt)); err != nil {
			return fmt.Errorf("response: store an approval link: %w", err)
		}
		return nil
	})
}

// RecordReplyCode stores the hash of one reply code before the message with it is sent (notify.TokenRecorder; 13b-8 reads it).
func (s *Service) RecordReplyCode(ctx context.Context, c ReplyCodeRecord) error {
	if !hashRE.MatchString(c.CodeHash) || strings.TrimSpace(c.Address) == "" || c.UserID == "" {
		return errors.New("response: the reply code record is not valid")
	}
	decision := "reject"
	if c.Approve {
		decision = "approve"
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := s.recordCheck(ctx, tx, c.RequestID, c.ExpiresAt, false); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO resp_tokens (token_hash, kind, decision, action_id, user_id, address, channel, key_id, expires_at, used_at) VALUES (?, 'code', ?, ?, ?, ?, 'zalo-personal', NULL, ?, NULL)`,
			c.CodeHash, decision, c.RequestID, c.UserID, c.Address, store2(c.ExpiresAt)); err != nil {
			return fmt.Errorf("response: store a reply code: %w", err)
		}
		return nil
	})
}

// sweepTokens forgets the records that ended more than a week ago.
func (s *Service) sweepTokens(ctx context.Context) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM resp_tokens WHERE expires_at < ?`, store2(s.now().Add(-tokenKeep)))
		return err
	})
}

// ---- reading a link ----

func linkMsg(state string) string {
	switch state {
	case "used":
		return "This link was already used."
	case "expired":
		return "This link has expired. Ask for a new approval request."
	}
	return "This link is not valid."
}

// linkKey is the source of a link call for the rate limit: the whole address (an IPv6 host owns a /64, but one /128 is one client and
// the table caps how many are remembered), the cut text for anything that is not an address.
func linkKey(from string) string {
	a, err := netip.ParseAddr(from)
	if err != nil {
		if ap, err2 := netip.ParseAddrPort(from); err2 == nil {
			a, err = ap.Addr(), nil
		}
	}
	if err != nil {
		return oneLine(from, 64)
	}
	return a.Unmap().WithZone("").String()
}

func errUnknownLink() *apierr.Error { return fail(http.StatusNotFound, "unknown", linkMsg("unknown")) }

func errRateLimited() *apierr.Error {
	return fail(http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again in a minute.").With("retry_after", 60)
}

// linkRecord finds the record of a token and checks its MAC. ok is false for a token that does not exist or does not match (malformed,
// no record, wrong MAC, a record of another kind); err means the box could not tell.
func (s *Service) linkRecord(ctx context.Context, token string) (rec tokenRow, ok bool, err error) {
	if s.cfg.Links == nil {
		return rec, false, nil
	}
	id, err := s.cfg.Links.ID(token)
	if err != nil {
		return rec, false, nil
	}
	var expires string
	var used sql.NullString
	var key sql.NullString
	rec.hash = hashID(id)
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT action_id, user_id, address, channel, key_id, expires_at, used_at FROM resp_tokens WHERE token_hash = ? AND kind = 'link'`, rec.hash).
		Scan(&rec.action, &rec.user, &rec.address, &rec.channel, &key, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, fmt.Errorf("response: read an approval link: %w", err)
	}
	rec.keyID, rec.expires, rec.used = key.String, parseTS(expires), used.Valid
	b := LinkBinding{RequestID: rec.action, UserID: rec.user, Channel: rec.channel, ExpiresAt: rec.expires}
	if err := s.cfg.Links.Verify(ctx, token, b, rec.keyID); err != nil {
		if errors.Is(err, ErrLinkInvalid) {
			return rec, false, nil
		}
		return rec, false, fmt.Errorf("response: check an approval link: %w", err)
	}
	return rec, true, nil
}

// linkState is what a link and its request say: used, expired, decided or ready (same order as the mock).
func (s *Service) linkState(rec tokenRow, r request) string {
	now := s.now()
	switch {
	case rec.used:
		return "used"
	case !rec.expires.After(now) || r.Status == StatusExpired || (r.Status == StatusPending && !parseTS(r.ExpiresAt).After(now)):
		return "expired"
	case r.Status != StatusPending:
		return "decided"
	}
	return "ready"
}

// LinkView is GET /response/approve/{token}. It reads and never writes (not a decision, not a log line, not a burned token), so a link
// scanner that opens every link in a mail changes nothing. Anything but "ready" shows none of the request. A source address that keeps
// sending links that are not valid gets 429.
func (s *Service) LinkView(ctx context.Context, token, from string) (ApprovalView, error) {
	key := linkKey(from)
	if !s.allowLink("bad:"+key, linkBadPerMin, false) {
		return ApprovalView{}, errRateLimited()
	}
	blank := ApprovalView{State: "unknown", Items: []ApprovalItem{}}
	unknown := func() (ApprovalView, error) {
		s.allowLink("bad:"+key, linkBadPerMin, true)
		return blank, nil
	}
	rec, ok, err := s.linkRecord(ctx, token)
	if err != nil {
		return ApprovalView{}, err
	}
	if !ok {
		return unknown()
	}
	r, found, err := loadReq(ctx, s.cfg.DB.Reader(), rec.action)
	if err != nil {
		return ApprovalView{}, err
	}
	if !found {
		return unknown()
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return ApprovalView{}, err
	}
	if _, valid, err := s.approverValid(ctx, rec, st); err != nil { // spec 8: a link of someone who may no longer approve is not a link
		return ApprovalView{}, err
	} else if !valid {
		return blank, nil
	}
	state := s.linkState(rec, r)
	approved := len(r.Approvals)
	v := ApprovalView{State: state, Items: []ApprovalItem{}, Status: &r.Status, RequiresApprovals: &r.RequiresApprovals, ApprovedSoFar: &approved}
	if state != "ready" {
		return v, nil
	}
	for _, i := range r.recs {
		v.Items = append(v.Items, ApprovalItem{Title: i.Title, Risk: i.Risk, Change: i.Change})
	}
	title, expires := r.Title, store2(rec.expires)
	v.Title, v.ExpiresAt = &title, &expires
	if u, ok, err := s.cfg.Users.Lookup(ctx, rec.user); err == nil && ok && u.Name != "" {
		name := u.Name
		v.Approver = &name
	}
	return v, nil
}

// ---- deciding through a link ----

// DecideByLink is POST /response/approve/{token}. The order is the one of D-96 (4): the rate limit, a token that is not known (404), one
// that ended or was used or whose request was decided (409), the approver (403 approver_not_listed), the risk policy (403
// in_app_required), then the decision with via=email. The token is burned in the transaction of the decision: a decision the gates
// refuse leaves it alive, and of two POSTs at once one wins and the other gets 409 used. Nothing here writes for a token that is not
// known (an attacker must not fill the log); refusals of a known link are logged like any refusal (INV-19), without the token.
func (s *Service) DecideByLink(ctx context.Context, token, decision, from string) (ActionRequest, error) {
	key := linkKey(from)
	if !s.allowLink("bad:"+key, linkBadPerMin, false) || !s.allowLink("post:"+key, linkPostPerMin, true) {
		return ActionRequest{}, errRateLimited()
	}
	if decision != "approve" && decision != "reject" {
		return ActionRequest{}, fail(http.StatusBadRequest, "invalid", "Send decision as approve or reject.")
	}
	unknown := func() (ActionRequest, error) {
		s.allowLink("bad:"+key, linkBadPerMin, true)
		return ActionRequest{}, errUnknownLink()
	}
	rec, ok, err := s.linkRecord(ctx, token)
	if err != nil {
		return ActionRequest{}, err
	}
	if !ok {
		return unknown()
	}
	r, found, err := loadReq(ctx, s.cfg.DB.Reader(), rec.action)
	if err != nil {
		return ActionRequest{}, err
	}
	if !found {
		return unknown()
	}
	withID := func(e *apierr.Error) *apierr.Error { return e.With("request_id", r.ID) }
	// A refusal of a link that is known is logged like any refusal (INV-19, the mock does the same), with the request and the address.
	switch state := s.linkState(rec, r); state {
	case "used", "expired":
		return ActionRequest{}, s.refuse(ctx, withID(fail(http.StatusConflict, state, linkMsg(state))), r.ID, rec.address)
	case "decided":
		if s.linkUsed(ctx, rec.hash) { // the winner of two POSTs at once burned it after we read it: say so
			return ActionRequest{}, s.refuse(ctx, withID(fail(http.StatusConflict, "used", linkMsg("used"))), r.ID, rec.address)
		}
		return ActionRequest{}, s.refuse(ctx, withID(fail(http.StatusConflict, "decided", "This request is already "+strings.ReplaceAll(string(r.Status), "_", " ")+".")), r.ID, rec.address)
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return ActionRequest{}, err
	}
	u, valid, err := s.approverValid(ctx, rec, st)
	if err != nil {
		return ActionRequest{}, err
	}
	notListed := func() *apierr.Error {
		return withID(fail(http.StatusForbidden, "approver_not_listed", "This link no longer belongs to a valid approver."))
	}
	if !valid {
		return ActionRequest{}, s.refuse(ctx, notListed(), r.ID, rec.address)
	}
	if (r.Risk != RiskLow && r.Risk != RiskMedium) || (r.AI != nil && r.AI.InAppOnly) { // D-57 (20): a link is a bearer credential
		return ActionRequest{}, s.refuse(ctx, withID(fail(http.StatusForbidden, "in_app_required", "This request can only be approved in the app. Open Vedette, sign in and decide it there.")), r.ID, u.Email)
	}
	name := u.Name
	if name == "" {
		name = u.Email
	}
	who := Actor{ID: u.ID, Name: name, Email: u.Email, Via: ViaEmail}
	// M4: the people and the channel are read again once this call holds the service lock, because a person can be removed while it waits.
	lk := &linkOpt{hash: rec.hash, recheck: func(ctx context.Context) (*apierr.Error, error) {
		st, err := loadSettings(ctx, s.cfg.DB.Reader())
		if err != nil {
			return nil, err
		}
		if _, ok, err := s.approverValid(ctx, rec, st); err != nil || !ok {
			return notListed(), err
		}
		return nil, nil
	}}
	var out ActionRequest
	if decision == "approve" {
		out, err = s.approve(ctx, who, r.ID, nil, "", false, lk)
	} else {
		out, err = s.reject(ctx, who, r.ID, "through an email link", RememberNone, lk)
	}
	if ae, ok := apierr.As(err); ok && ae.Status == http.StatusConflict {
		if ae.Code == "not_pending" { // decided between the check above and the transaction
			code := "decided"
			if s.linkUsed(ctx, rec.hash) {
				code = "used"
			}
			ae = fail(http.StatusConflict, code, ae.Message)
		}
		return ActionRequest{}, withID(ae)
	}
	return out, err
}

// linkOpt is what a decision through a link adds to approve and reject: the hash of the token, burned in the decision transaction, and a
// check that runs right after the service lock is taken.
type linkOpt struct {
	hash    string
	recheck func(ctx context.Context) (*apierr.Error, error)
}

// linkUsed reads whether the link was burned (by another call that decided first).
func (s *Service) linkUsed(ctx context.Context, hash string) bool {
	var used sql.NullString
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT used_at FROM resp_tokens WHERE token_hash = ? AND kind = 'link'`, hash).Scan(&used)
	return err == nil && used.Valid
}

// approverValid is the check of D-96 (4) made again when the link is used (spec 3.5): the person is still an active operator or admin,
// the address the link went to is still their sign-in email, they are still on the list of the channel, and the channel is ready and
// one of the approval channels of this module. A directory or notify that cannot answer is an error: the decision is not made.
func (s *Service) approverValid(ctx context.Context, rec tokenRow, st Settings) (User, bool, error) {
	if s.cfg.Users == nil || s.cfg.Notifier == nil {
		return User{}, false, nil
	}
	u, ok, err := s.cfg.Users.Lookup(ctx, rec.user)
	if err != nil {
		return User{}, false, err
	}
	if !ok || u.Disabled || (u.Role != "operator" && u.Role != "admin") || !strings.EqualFold(strings.TrimSpace(rec.address), u.Email) {
		return u, false, nil
	}
	if !slices.Contains(st.ApprovalChannels, rec.channel) {
		return u, false, nil
	}
	chans, err := s.channels(ctx)
	if err != nil {
		return u, false, err
	}
	if !slices.ContainsFunc(chans, func(c NotifyChannel) bool { return c.Type == rec.channel && chanReady(c) }) {
		return u, false, nil
	}
	list, err := s.cfg.Notifier.Approvers(ctx, rec.channel)
	if err != nil {
		return u, false, err
	}
	return u, slices.ContainsFunc(list, func(a Approver) bool {
		return a.UserID == rec.user && strings.EqualFold(strings.TrimSpace(a.Address), strings.TrimSpace(rec.address))
	}), nil
}

// tokenGate runs first inside the decision transaction of a link: the token must still be there, unused and not ended. This is what makes
// the loser of two POSTs at once see "used" and not a refusal about the request. It reads only.
func tokenGate(ctx context.Context, tx dbq, hash string, now time.Time) (*apierr.Error, error) {
	var expires string
	var used sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT expires_at, used_at FROM resp_tokens WHERE token_hash = ? AND kind = 'link'`, hash).Scan(&expires, &used)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return errUnknownLink(), nil
	case err != nil:
		return nil, fmt.Errorf("response: read an approval link: %w", err)
	case used.Valid:
		return fail(http.StatusConflict, "used", linkMsg("used")), nil
	case !parseTS(expires).After(now):
		return fail(http.StatusConflict, "expired", linkMsg("expired")), nil
	}
	return nil, nil
}

// burnToken marks the link used. It is the last step before a decision is recorded, in the same transaction; no row changed means
// someone else used it first.
func burnToken(ctx context.Context, tx *sql.Tx, hash, at string) (*apierr.Error, error) {
	res, err := tx.ExecContext(ctx, `UPDATE resp_tokens SET used_at = ? WHERE token_hash = ? AND kind = 'link' AND used_at IS NULL`, at, hash)
	if err != nil {
		return nil, fmt.Errorf("response: burn an approval link: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fail(http.StatusConflict, "used", linkMsg("used")), nil
	}
	return nil, nil
}

// ---- sending a request to its approvers ----

// approvalChannels are the types of the approval channels that are still ready: the ones the settings name and the channel can take.
func (s *Service) approvalChannels(ctx context.Context, st Settings) ([]string, error) {
	chans, err := s.channels(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range chans {
		if chanReady(c) && slices.Contains(st.ApprovalChannels, c.Type) {
			out = append(out, c.Type)
		}
	}
	return out, nil
}

// ErrSendUnsure is what a Notifier wraps an error in when the failure may have come after some messages had already gone out (notify
// could not write its record of them): the request log line then says so instead of claiming nobody was told.
var ErrSendUnsure = errors.New("response: some messages may have gone out")

// maxSends is how many requests are being sent at once; the others wait for a slot inside their own budget.
const maxSends = 2

// queueSend sends the approval request in the background (M2): a mail server that does not answer must not hold the rule engine, the
// AI port or a person's request. Two sends run at once; the 60 second budget counts from here, so a request that waits too long for a
// slot is dropped (and logged) instead of piling up. The box shutting down (Close) ends them all.
func (s *Service) queueSend(ctx context.Context, id string) {
	if s.cfg.Notifier == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.WithoutCancel(ctx), s.budget) // the caller's request may end at once; the box shutting down ends this
	s.sendWG.Add(1)
	go func() {
		defer s.sendWG.Done()
		defer stop()
		go func() { // the box shutting down (Close) ends the send
			select {
			case <-s.bg.Done():
				stop()
			case <-ctx.Done():
			}
		}()
		select {
		case s.sendSem <- struct{}{}:
			defer func() { <-s.sendSem }()
		case <-ctx.Done():
			s.noteSend(ctx, id, nil, "sent to the app only: sending was busy or the box was stopping")
			return
		}
		s.sendApproval(ctx, id)
	}()
}

// noteSend records where a request went: sent_to (when anything went) and one log line.
func (s *Service) noteSend(ctx context.Context, id string, sent []string, detail string) {
	wctx := context.WithoutCancel(ctx) // the messages left: the record of where is written even if the budget ended
	if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		var title string
		if err := tx.QueryRowContext(wctx, `SELECT title FROM resp_actions WHERE id = ?`, id).Scan(&title); err != nil {
			return err
		}
		if len(sent) > 0 {
			if _, err := tx.ExecContext(wctx, `UPDATE resp_actions SET sent_to = ? WHERE id = ?`, mustJSON(nonNilS(sent)), id); err != nil {
				return err
			}
		}
		return s.step(wctx, tx, "response.request_sent", id, LogRequest, title+": "+detail, "system")
	}); err != nil {
		s.cfg.Log.ErrorContext(wctx, "response: record where a request was sent", "request", id, "error", err)
	}
}

// sendApproval tells the approvers about a request that was just created (POST-5). It runs in the background after the creating
// transaction committed (queueSend), never inside a write transaction and without s.mu. A failure never fails the request: it stays open
// in the app. sent_to and one log line say where it went.
func (s *Service) sendApproval(ctx context.Context, id string) {
	r, ok, err := loadReq(ctx, s.cfg.DB.Reader(), id)
	if err != nil || !ok || r.Status != StatusPending {
		return
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "response: approval request not sent", "request", id, "error", err)
		return
	}
	types, err := s.approvalChannels(ctx, st)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "response: approval request not sent", "request", id, "error", err)
		return
	}
	if len(types) == 0 { // no ready approval channel: the app only, as the mock says
		s.noteSend(ctx, id, nil, "sent to the app only: no approval channel is ready")
		return
	}
	msg := ApprovalMessage{RequestID: r.ID, Title: truncRunes(cleanLine(r.Title), 200), What: approvalText(r), Risk: r.Risk, InAppOnly: r.AI != nil && r.AI.InAppOnly,
		Channels: types, Expires: parseTS(r.ExpiresAt)}
	sent, sendErr := s.cfg.Notifier.RequestApproval(ctx, msg)
	detail := "Approval request sent to " + joinNonEmpty(sent...) + onEmpty(len(sent), "nobody")
	if sendErr != nil {
		s.cfg.Log.WarnContext(ctx, "response: approval request not sent", "request", id, "error", sendErr)
		detail += "; it is still open in the app (a channel failed: " + truncRunes(cleanLine(sendErr.Error()), 200) + ")"
		if errors.Is(sendErr, ErrSendUnsure) {
			detail += "; some mail may have gone out all the same: notify could not write its record of it"
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		detail += "; the send budget ran out: approvers not yet mailed were skipped"
	}
	if msg.InAppOnly {
		detail += "; in the app only, no link"
	}
	s.noteSend(ctx, id, sent, detail)
}

// approvalText is what the approver reads in the message: each action, the exact call, and how many people must approve. Plain text, one
// line per fact, cut at 4 KiB with a pointer to the app (spec 4.6). The change comes from the request, which holds only checked values.
func approvalText(r request) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	if r.AssetName != "" {
		line("On: %s", truncRunes(cleanLine(r.AssetName), 120))
	}
	line("Risk: %s. %d approver%s needed. Ends %s.", r.Risk, r.RequiresApprovals, plural(r.RequiresApprovals), r.ExpiresAt)
	for _, i := range r.recs {
		line("- %s (%s risk)", truncRunes(cleanLine(i.Title), 160), i.Risk)
		line("  Before: %s", truncRunes(cleanLine(i.Change.Before), 200))
		line("  After: %s", truncRunes(cleanLine(i.Change.After), 200))
		line("  Exact call: %s", truncRunes(cleanLine(callText(i.Change.Rest, i.Change.CLI)), 400))
	}
	out := b.String()
	const more = "\n...open Vedette for the full change."
	if len(out) > approvalWhatMax {
		out = strings.ToValidUTF8(out[:approvalWhatMax-len(more)], "") + more
	}
	return strings.TrimRight(out, "\n")
}

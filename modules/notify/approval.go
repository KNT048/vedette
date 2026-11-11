package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/modules/notify/channel"
)

// ApprovalRequest is one action waiting for approval (module response). Expires is when the request
// itself ends; a link never outlives it.
type ApprovalRequest struct {
	ID       string // 1 to 128 characters of A-Z a-z 0-9 _ . : @ + - (it goes into the signed token)
	Title    string
	What     string
	Action   string
	Severity Severity
	Risk     Risk
	Expires  time.Time
	// Channels are the channels the response module allows for this request; empty sends nothing (PRE-4, D-96). Only
	// a channel that is in the list and has approvals on receives a message.
	Channels []channel.Type
	// InAppOnly is a high-risk request from the AI (INV-16 of response): every channel only gets a message that says
	// to open Vedette. No approval link, no button, no reply code, and no token is made or recorded.
	InAppOnly bool
	// NoChatButtons: no chat channel gets Approve/Reject buttons, only a message that says to open Vedette (D-175: response decides, from
	// the risk and from whether the whole change fits one message; notify only obeys).
	NoChatButtons bool
}

const (
	approvalKeyPurpose = "approval.hmac_key"
	approvalKeyID      = "k1"
)

// SendApprovalRequest tells the approvers (PRE-4, S-RESP-2 transport for email). Every email approver gets
// their own message at their own address, never the alert list: with a signed one-time link when the risk
// allows a link and a token recorder is wired (spec approval-tokens.md 4; the record of the token, with the
// address, is stored by the TokenRecorder before the mail goes out), otherwise (high risk, D-57 item 20, or no
// recorder) a message that says to open Vedette. Other channels with approvals on get one message without a
// link that approves; on Telegram it carries Approve/Reject buttons (tglisten.go) unless the request is in-app only.
// Slack buttons and Zalo reply codes are not built yet.
//
// A message with a link is sent at most once: nothing here is retried, and the request ending (ctx) stops the
// messages not yet started. Each attempt that was made is recorded, also after ctx ended. It returns one
// SendView per message, each also written to the history. Without BaseURL the links would point nowhere, and a
// link that approves is a credential, so ErrApprovalUnavailable is returned and nothing is sent.
func (s *Service) SendApprovalRequest(ctx context.Context, req ApprovalRequest) ([]SendView, error) {
	if !s.on() {
		return nil, ErrModuleOff
	}
	now := s.now()
	if !idRE.MatchString(req.ID) {
		return nil, fmt.Errorf("%w: the request id is 1 to 128 characters of letters, digits and _ . : @ + -", ErrInvalidNotice)
	}
	if strings.TrimSpace(req.Title) == "" || !req.Expires.After(now) {
		return nil, fmt.Errorf("%w: an approval request needs a title and a future expiry", ErrInvalidNotice)
	}
	if !req.Severity.Valid() {
		req.Severity = Medium
	}
	if s.cfg.BaseURL == "" {
		return nil, ErrApprovalUnavailable
	}
	if len(req.Channels) == 0 {
		return nil, nil // response allows no channel: nothing is sent, nothing is made
	}
	all, err := s.ApprovalChannels(ctx)
	if err != nil {
		return nil, err
	}
	var chans []ApprovalChannel
	for _, ac := range all {
		if slices.Contains(req.Channels, ac.Type) {
			chans = append(chans, ac)
		}
	}
	if len(chans) == 0 {
		return nil, nil
	}
	appLink := s.link("/response")
	base := channel.Message{ID: req.ID, Kind: "approval", Severity: string(req.Severity), Title: req.Title, What: req.What, Action: req.Action, Link: appLink}
	if req.InAppOnly {
		base.Action = "Open Vedette and approve it in the app with your two-step code."
	}
	type outgoing struct {
		snd       channel.Sender
		msg       channel.Message // what is sent (may hold a token)
		recipient string          // the approver's address, for a message to one person
		buttons   bool            // Telegram with buttons: where the message is gets kept, so they can be removed later (tgbuttons.go)
	}
	var plan []outgoing
	type skipped struct{ user, reason string }
	var skips []skipped // approvers who no longer qualify: no link is minted and nothing is mailed to them
	linkOK := s.cfg.Tokens != nil && !req.InAppOnly && ApprovalViaChannelAllowed("email", req.Risk) == nil
	for _, ac := range chans {
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), ac.Type)
		if err != nil {
			return nil, err
		}
		if ac.Type != channel.Email {
			snd, err := s.savedSender(ctx, c, nil)
			if err != nil {
				return nil, fmt.Errorf("notify: approval request: %s", userText(err))
			}
			m := base
			if req.NoChatButtons && !req.InAppOnly {
				m.Action = "Open Vedette, review the whole change there, then approve or reject it. This message has no buttons."
			}
			if ac.Type == channel.Telegram && !req.NoChatButtons { // Approve/Reject buttons; their nonce is kept before the message goes out (spec 6)
				if m.Buttons, err = s.telegramButtons(ctx, req, c.Fields); err != nil {
					return nil, err
				}
			}
			plan = append(plan, outgoing{snd: snd, msg: m, buttons: len(m.Buttons) > 0})
			continue
		}
		var key []byte
		if linkOK && len(ac.Approvers) > 0 {
			if key, err = s.cfg.Secrets.OpenOrCreate(ctx, s.cfg.DB, approvalKeyPurpose, MinApprovalKeyLen); err != nil {
				return nil, fmt.Errorf("notify: approval key: %w", err)
			}
		}
		for _, a := range ac.Approvers {
			if why := s.approverProblem(ctx, ac.Type, a); why != "" {
				skips = append(skips, skipped{a.UserID, why})
				continue
			}
			m := base // high risk, or no recorder: this message only says to open Vedette
			if linkOK {
				b := Binding{RequestID: req.ID, UserID: a.UserID, Channel: "email", ExpiresAt: ApprovalExpiry(now, req.Expires)}
				token, id, err := MintApprovalToken(key, b, req.Risk, now)
				if err != nil {
					return nil, err
				}
				if err := s.cfg.Tokens.RecordToken(ctx, id, b, approvalKeyID, a.Address); err != nil {
					return nil, fmt.Errorf("notify: record approval token: %w", err)
				}
				m.Link = s.link("/approve/" + token)
			}
			snd, err := s.savedSender(ctx, c, []string{a.Address})
			if err != nil {
				return nil, fmt.Errorf("notify: approval request: %s", userText(err))
			}
			plan = append(plan, outgoing{snd: snd, msg: m, recipient: a.Address})
		}
	}
	var recs []SendRecord
	var to []string
	var withButtons []bool
	for _, p := range plan {
		if ctx.Err() != nil {
			break // not started: nothing was sent, so there is nothing to record
		}
		recs = append(recs, Deliver(ctx, store.NewID("sd"), p.snd, p.msg, s.now))
		to, withButtons = append(to, p.recipient), append(withButtons, p.buttons)
	}
	if len(recs) == 0 && len(skips) == 0 {
		return nil, ctx.Err()
	}
	wctx, stop := detached(ctx) // the messages went out (or failed): the records are written even if the request ended
	defer stop()
	var out []SendView
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		out = nil
		ob = &events.Outbox{}
		for _, k := range skips {
			if err := s.record(wctx, tx, systemUser, "notify.approval_skipped", clip(k.user, 128), clip(req.ID+": "+k.reason, 400)); err != nil {
				return err
			}
		}
		if len(recs) == 0 {
			return nil
		}
		for i, r := range recs {
			if err := insertSend(wctx, tx, r, "approval", req.ID, req.Title, "/response", to[i], base); err != nil { // base: no token is ever stored
				return err
			}
			if withButtons[i] && r.OK && r.MessageID > 0 && r.ChatID != "" { // the chat Telegram named, never the configured text (#198 M1)
				if err := buttonsShown(wctx, tx, req.ID, r.ChatID, r.MessageID); err != nil {
					return err
				}
			}
			out = append(out, SendView{ID: r.ID, Channel: r.Channel, To: r.To, At: store.FormatTS(r.At), OK: r.OK, Error: r.Error})
		}
		ob.Add(events.Event{Name: "notify.approval.requested", Data: map[string]string{"request_id": req.ID}})
		return s.record(wctx, tx, systemUser, "notify.approval_request", clip(req.Title, 400), fmt.Sprintf("%d message(s)", len(recs)))
	})
	if err != nil {
		return nil, err
	}
	s.flush(wctx, ob)
	for _, k := range skips {
		s.cfg.Log.WarnContext(ctx, "approval request: approver skipped", "user", k.user, "reason", k.reason)
	}
	return out, nil
}

// VerifyApprovalLink checks the format and the MAC of an approval link token against the binding stored with it and the key
// named by keyID (PRE-7, spec approval-tokens.md 4). It writes nothing and burns nothing: reading the confirmation page
// calls it, and the module response burns the token in the transaction of the decision. It never creates the key: a
// missing key is ErrApprovalKeyUnavailable, never a new key (a new key could not have signed any link). A token that
// is malformed (any length), a binding that differs in any field and an unknown keyID are ErrTokenInvalid, refused before
// the key store is read. Expiry is not checked here: the record knows it, and response answers expired, not unknown.
func (s *Service) VerifyApprovalLink(ctx context.Context, token string, b Binding, keyID string) (TokenID, error) {
	// Cheap checks first, so junk of any size never costs a database read.
	id, err := ParseApprovalToken(token)
	if err != nil || b.check() != nil || keyID != approvalKeyID {
		return id, ErrTokenInvalid
	}
	secretID, err := coredb.New(s.cfg.DB.Reader()).GetSecretIDByPurpose(ctx, approvalKeyPurpose)
	if errors.Is(err, sql.ErrNoRows) {
		return id, ErrApprovalKeyUnavailable
	}
	if err != nil {
		return id, fmt.Errorf("notify: find approval key: %w", err)
	}
	key, err := s.cfg.Secrets.Open(ctx, s.cfg.DB.Reader(), secretID, approvalKeyPurpose)
	if err != nil {
		return id, fmt.Errorf("%w: %w", ErrApprovalKeyUnavailable, err)
	}
	return verifyMAC(key, token, b)
}

// approverProblem re-checks an approver before a link is minted for them (the saved list may be old): the user must still
// exist, be active and be an operator or administrator, and the saved address must still be their sign-in email.
// With Config.ApproverLinks set, the address must also be linked by the user in My account (D-191); an error from it is a problem too.
// It returns why not, or "" when the approver is fine. A directory that cannot answer counts as not fine (fail closed).
func (s *Service) approverProblem(ctx context.Context, ch channel.Type, a Approver) string {
	u, found, err := s.cfg.Users.Lookup(ctx, a.UserID)
	switch {
	case err != nil:
		return "the user directory could not be read"
	case !found:
		return "the user no longer exists"
	case !u.Active:
		return "the user is disabled"
	case u.Role != "operator" && u.Role != "admin":
		return "the user is no longer an operator or administrator"
	case !strings.EqualFold(strings.TrimSpace(a.Address), u.Email):
		return "the saved address is no longer the sign-in email of the user"
	}
	if s.cfg.ApproverLinks == nil {
		return ""
	}
	linked, err := s.cfg.ApproverLinks.Linked(ctx, a.UserID, ch, a.Address)
	switch {
	case err != nil:
		s.cfg.Log.WarnContext(ctx, "approval request: approver link check failed", "user", a.UserID, "channel", string(ch), "err", err)
		return "the link could not be checked"
	case !linked:
		return "the approver has not linked this address in My account"
	}
	return ""
}

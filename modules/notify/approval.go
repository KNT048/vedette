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
// link that approves; on Telegram and Slack it carries Approve/Reject buttons (tglisten.go, slacklisten.go) unless the
// request is in-app only. On Zalo personal, when reply codes are allowed (replyCodesAllowed), every approver instead gets
// their own direct message with their own two codes, recorded before it goes out (replycode.go, spec 7.1); otherwise the
// configured recipient gets one message that says to open Vedette.
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
		// fallback and fbMsg: when the first send fails, this one goes out instead (Slack: the webhook, without buttons, when the bot
		// post fails: not_in_channel, a revoked token). nil = no second try.
		fallback channel.Sender
		fbMsg    channel.Message
	}
	var plan []outgoing
	type skipped struct{ user, reason string }
	var skips []skipped // approvers who no longer qualify: no link is minted and nothing is mailed to them
	linkOK := s.cfg.Tokens != nil && !req.InAppOnly && ApprovalViaChannelAllowed("email", req.Risk) == nil
	codesOK := s.replyCodesAllowed(req)
	for _, ac := range chans {
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), ac.Type)
		if err != nil {
			return nil, err
		}
		if ac.Type == channel.ZaloPersonal && codesOK && len(ac.Approvers) > 0 { // each approver gets their own codes, in their own chat
			snd, err := s.savedSender(ctx, c, nil) // the session of the channel, shared with its alerts
			if err != nil {
				return nil, fmt.Errorf("notify: approval request: %s", userText(err))
			}
			expires := ApprovalExpiry(now, req.Expires)
			planned := len(plan)
			for _, a := range ac.Approvers {
				if why := s.approverProblem(ctx, ac.Type, a); why != "" {
					skips = append(skips, skipped{a.UserID, why})
					continue
				}
				direct, err := s.zaloTo(snd, a.Address)
				if err != nil {
					skips = append(skips, skipped{a.UserID, "the saved address is not a Zalo user ID"})
					continue
				}
				m := base
				if m.ReplyCodes, err = s.recordReplyCodes(ctx, req, a, expires); err != nil {
					return nil, err
				}
				plan = append(plan, outgoing{snd: direct, msg: m, recipient: a.Address})
			}
			if len(plan) > planned {
				continue
			}
			// every approver was skipped (left, demoted, or an address saved before D-242): the channel still hears about the
			// request, with the message that says to open Vedette
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
			var fb channel.Sender
			var fbMsg channel.Message
			if ac.Type == channel.Slack && !req.NoChatButtons && channel.SlackFits(m) { // buttons through the bot; the posted message is kept (slacklisten.go)
				if bs, btns := s.slackApprovalSender(ctx, c, req); bs != nil {
					// the bot post can fail while the webhook works (not_in_channel, a revoked bot token; after a timeout the post may even have gone out, its buttons then refused: the text says so): then the request still reaches the
					// channel, through the webhook and without buttons, and says so
					fb, fbMsg = snd, m
					fbMsg.Action = "Open Vedette to approve. Approve and Reject buttons may have been posted to this channel; they are not active, so use Vedette."
					snd, m.Buttons = bs, btns
				}
			}
			plan = append(plan, outgoing{snd: snd, msg: m, buttons: len(m.Buttons) > 0, fallback: fb, fbMsg: fbMsg})
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
	var fellBack []string // why the bot post failed, for each approval message that went out through its fallback
	for _, p := range plan {
		if ctx.Err() != nil {
			break // not started: nothing was sent, so there is nothing to record
		}
		rec := Deliver(ctx, store.NewID("sd"), p.snd, p.msg, s.now)
		recs = append(recs, rec)
		to, withButtons = append(to, p.recipient), append(withButtons, p.buttons)
		if p.fallback != nil && !rec.OK && ctx.Err() == nil { // the failed attempt keeps its own history row; the fallback is a second one
			fellBack = append(fellBack, rec.Error)
			recs = append(recs, Deliver(ctx, store.NewID("sd"), p.fallback, p.fbMsg, s.now))
			to, withButtons = append(to, p.recipient), append(withButtons, false)
		}
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
			if withButtons[i] && r.OK && r.Channel == channel.Slack && r.TS != "" && r.ChatID != "" {
				if err := slackButtonShown(wctx, tx, req.ID, r.ChatID, r.TS, req.Expires); err != nil {
					return err
				}
			}
			if withButtons[i] && r.OK && r.MessageID > 0 && r.ChatID != "" { // the chat Telegram named, never the configured text (#198 M1)
				if err := buttonsShown(wctx, tx, req.ID, r.ChatID, r.MessageID); err != nil {
					return err
				}
			}
			out = append(out, SendView{ID: r.ID, Channel: r.Channel, To: r.To, At: store.FormatTS(r.At), OK: r.OK, Error: r.Error})
		}
		for _, why := range fellBack {
			if err := s.record(wctx, tx, systemUser, "notify.approval_fallback", clip(req.Title, 400), "the Slack bot post failed ("+clip(why, 200)+"); sent through the webhook without buttons"); err != nil {
				return err
			}
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
// exist, be active and be an operator or administrator, and on the email channel the saved address must still be their sign-in email.
// With Config.ApproverLinks set, the address must also be linked by the user in My account (D-191); an error from it is a problem too.
// It returns why not, or "" when the approver is fine. A directory that cannot answer counts as not fine (fail closed).
func (s *Service) approverProblem(ctx context.Context, ch channel.Type, a Approver) string {
	why, err := s.approverCheck(ctx, ch, a)
	if err != nil {
		return err.Error()
	}
	return why
}

// approverCheck is approverProblem with a check that could not be made (a user directory or link store that did not answer) apart
// from a "no": the caller that must not turn a transient failure into a refusal (a resend) gets the error.
func (s *Service) approverCheck(ctx context.Context, ch channel.Type, a Approver) (string, error) {
	u, found, err := s.cfg.Users.Lookup(ctx, a.UserID)
	switch {
	case err != nil:
		return "", errApproverDirectory
	case !found:
		return "the user no longer exists", nil
	case !u.Active:
		return "the user is disabled", nil
	case u.Role != "operator" && u.Role != "admin":
		return "the user is no longer an operator or administrator", nil
	case ch == channel.Email && !strings.EqualFold(strings.TrimSpace(a.Address), u.Email):
		return "the saved address is no longer the sign-in email of the user", nil
	}
	if s.cfg.ApproverLinks == nil {
		return "", nil
	}
	linked, err := s.cfg.ApproverLinks.Linked(ctx, a.UserID, ch, a.Address)
	switch {
	case err != nil:
		s.cfg.Log.WarnContext(ctx, "approval request: approver link check failed", "user", a.UserID, "channel", string(ch), "error", err.Error())
		return "", errApproverLinks
	case !linked:
		return "the approver has not linked this address in My account", nil
	}
	return "", nil
}

var (
	errApproverDirectory = errors.New("the user directory could not be read")
	errApproverLinks     = errors.New("whether the approver linked this address could not be checked")
)

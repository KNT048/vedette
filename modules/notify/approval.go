package notify

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
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
// link that approves: buttons and reply codes are the in-channel transport, not built yet.
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
	chans, err := s.ApprovalChannels(ctx)
	if err != nil || len(chans) == 0 {
		return nil, err
	}
	appLink := s.link("/response")
	base := channel.Message{ID: req.ID, Kind: "approval", Severity: string(req.Severity), Title: req.Title, What: req.What, Action: req.Action, Link: appLink}
	type outgoing struct {
		snd       channel.Sender
		msg       channel.Message // what is sent (may hold a token)
		recipient string          // the approver's address, for a message to one person
	}
	var plan []outgoing
	linkOK := s.cfg.Tokens != nil && ApprovalViaChannelAllowed("email", req.Risk) == nil
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
			plan = append(plan, outgoing{snd: snd, msg: base})
			continue
		}
		var key []byte
		if linkOK && len(ac.Approvers) > 0 {
			if key, err = s.cfg.Secrets.OpenOrCreate(ctx, s.cfg.DB, approvalKeyPurpose, MinApprovalKeyLen); err != nil {
				return nil, fmt.Errorf("notify: approval key: %w", err)
			}
		}
		for _, a := range ac.Approvers {
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
	for _, p := range plan {
		if ctx.Err() != nil {
			break // not started: nothing was sent, so there is nothing to record
		}
		recs = append(recs, Deliver(ctx, store.NewID("sd"), p.snd, p.msg, s.now))
		to = append(to, p.recipient)
	}
	if len(recs) == 0 {
		return nil, ctx.Err()
	}
	wctx, stop := detached(ctx) // the messages went out (or failed): the records are written even if the request ended
	defer stop()
	var out []SendView
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		out = nil
		ob = &events.Outbox{}
		for i, r := range recs {
			if err := insertSend(wctx, tx, r, "approval", req.ID, req.Title, "/response", to[i], base); err != nil { // base: no token is ever stored
				return err
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
	return out, nil
}

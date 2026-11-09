package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Reasons EmailReady gives (POST-5).
const (
	ReasonModuleOff       = "module_off"
	ReasonChannelNotReady = "channel_not_ready"
)

// ErrEmailNotReady is returned by SendCode when the email channel is off, missing or the module is off.
var ErrEmailNotReady = errors.New("notify: the email channel is not ready")

// EmailReady reports whether email can be sent now: the module is on and the email channel is
// configured and enabled (POST-5). The reason is one of ReasonModuleOff, ReasonChannelNotReady.
func (s *Service) EmailReady(ctx context.Context) (ok bool, reason string) {
	if !s.on() {
		return false, ReasonModuleOff
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Email)
	if err != nil || !c.Configured || !c.Enabled {
		return false, ReasonChannelNotReady
	}
	return true, ""
}

// CodeMailer is what core/auth wants (auth.CodeMailer): two-step sign-in codes over the email channel (D-35, INV-9).
type CodeMailer struct{ s *Service }

// CodeMailer returns the mailer of this service. Pass it as auth.Config.Mailer.
func (s *Service) CodeMailer() CodeMailer { return CodeMailer{s} }

// Available reports whether SendCode can work now.
func (m CodeMailer) Available(ctx context.Context) bool {
	ok, _ := m.s.EmailReady(ctx)
	return ok
}

const codeSendTimeout = 30 * time.Second

// SendCode mails the 6-digit code to one address through the saved SMTP settings. The code is not
// logged, not stored and not put into any error or history row; the answer of the SMTP server is
// reduced by the adapter to a short secret-free reason.
func (m CodeMailer) SendCode(ctx context.Context, to, code string) error {
	s := m.s
	if ok, _ := s.EmailReady(ctx); !ok {
		return ErrEmailNotReady
	}
	rcpt, err := channel.ParseRecipients(to)
	if err != nil || len(rcpt) != 1 {
		return fmt.Errorf("notify: send sign-in code: the address is not valid")
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Email)
	if err != nil {
		return err
	}
	snd, err := s.savedSender(ctx, c, rcpt)
	if err != nil {
		return fmt.Errorf("notify: send sign-in code: %s", userText(err))
	}
	cctx, cancel := context.WithTimeout(ctx, codeSendTimeout)
	defer cancel()
	_, err = snd.Send(cctx, channel.Message{ID: store.NewID("code"), Kind: "test", Severity: string(Info), Title: "Your Vedette sign-in code",
		What: "Your sign-in code is " + code + ". It expires in 10 minutes. If you did not try to sign in, tell your administrator.",
		Link: s.link("/login")})
	if err != nil {
		return fmt.Errorf("notify: send sign-in code: %s", userText(err))
	}
	return nil
}

// ApprovalChannel is a channel that takes approvals and the people who may approve on it.
type ApprovalChannel struct {
	Type      channel.Type
	Approvers []Approver
}

// ApprovalChannels lists the enabled channels with approvals on (IMPACT: other modules read the
// approval setup through this, never from the notify_ tables). Whether an approver is still an active
// operator or admin is for the caller to check again when a decision arrives (spec 3.5).
func (s *Service) ApprovalChannels(ctx context.Context) ([]ApprovalChannel, error) {
	db := s.cfg.DB.Reader()
	var out []ApprovalChannel
	for _, t := range channelTypes {
		c, err := loadChannel(ctx, db, t)
		if err != nil {
			return nil, err
		}
		if !c.Configured || !c.Enabled || !c.Approvals {
			continue
		}
		ap, err := loadApprovers(ctx, db, t)
		if err != nil {
			return nil, err
		}
		out = append(out, ApprovalChannel{Type: t, Approvers: ap})
	}
	return out, nil
}

// ApprovalRequest is one action waiting for approval (module response). Expires is when the request
// itself ends; a link never outlives it.
type ApprovalRequest struct {
	ID       string
	Title    string
	What     string
	Action   string
	Severity Severity
	Risk     Risk
	Expires  time.Time
}

const approvalKeyPurpose = "approval.hmac_key"
const approvalKeyID = "k1"

// SendApprovalRequest tells the approvers (PRE-4, S-RESP-2 transport for email). Email approvers each get
// a signed one-time link (spec approval-tokens.md 4; the record of the token is stored by the TokenRecorder
// before the mail goes out); a high-risk request gets no link on any channel, only a message that says
// to open Vedette (D-57 item 20). Other channels with approvals on get the same message without a link
// that approves: buttons and reply codes are the in-channel transport, not built yet. It returns one
// SendView per message, each also written to the history.
func (s *Service) SendApprovalRequest(ctx context.Context, req ApprovalRequest) ([]SendView, error) {
	now := s.now()
	if strings.TrimSpace(req.Title) == "" || !req.Expires.After(now) {
		return nil, fmt.Errorf("%w: an approval request needs a title and a future expiry", ErrInvalidNotice)
	}
	if !req.Severity.Valid() {
		req.Severity = Medium
	}
	if s.cfg.Tokens == nil {
		return nil, ErrApprovalUnavailable
	}
	chans, err := s.ApprovalChannels(ctx)
	if err != nil || len(chans) == 0 {
		return nil, err
	}
	appLink := s.link("/response")
	base := channel.Message{ID: req.ID, Kind: "approval", Severity: string(req.Severity), Title: req.Title, What: req.What, Action: req.Action, Link: appLink}
	type outgoing struct {
		t        channel.Type
		snd      channel.Sender
		msg      channel.Message // what is sent (may hold a token)
		approver string
	}
	var plan []outgoing
	for _, ac := range chans {
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), ac.Type)
		if err != nil {
			return nil, err
		}
		if ac.Type != channel.Email || ApprovalViaChannelAllowed("email", req.Risk) != nil {
			snd, err := s.savedSender(ctx, c, nil)
			if err != nil {
				return nil, fmt.Errorf("notify: approval request: %s", userText(err))
			}
			plan = append(plan, outgoing{t: ac.Type, snd: snd, msg: base})
			continue
		}
		key, err := s.cfg.Secrets.OpenOrCreate(ctx, s.cfg.DB, approvalKeyPurpose, MinApprovalKeyLen)
		if err != nil {
			return nil, fmt.Errorf("notify: approval key: %w", err)
		}
		for _, a := range ac.Approvers {
			b := Binding{RequestID: req.ID, UserID: a.UserID, Channel: "email", ExpiresAt: ApprovalExpiry(now, req.Expires)}
			token, id, err := MintApprovalToken(key, b, req.Risk, now)
			if err != nil {
				return nil, err
			}
			if err := s.cfg.Tokens.RecordToken(ctx, id, b, approvalKeyID); err != nil {
				return nil, fmt.Errorf("notify: record approval token: %w", err)
			}
			snd, err := s.savedSender(ctx, c, []string{a.Address})
			if err != nil {
				return nil, fmt.Errorf("notify: approval request: %s", userText(err))
			}
			m := base
			m.Link = s.link("/approve/" + token)
			plan = append(plan, outgoing{t: ac.Type, snd: snd, msg: m, approver: a.UserID})
		}
	}
	var out []SendView
	var recs []SendRecord
	for _, p := range plan {
		recs = append(recs, Deliver(ctx, store.NewID("sd"), p.snd, p.msg, s.now))
	}
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range recs {
			if err := insertSend(ctx, tx, r, "approval", req.ID, req.Title, "/response", base); err != nil { // base: no token is ever stored
				return err
			}
			out = append(out, SendView{ID: r.ID, Channel: r.Channel, To: r.To, At: store.FormatTS(r.At), OK: r.OK, Error: r.Error})
		}
		ob.Add(events.Event{Name: "notify.approval.requested", Data: map[string]string{"request_id": req.ID}})
		return s.record(ctx, tx, systemUser, "notify.approval_request", clip(req.Title, 400), fmt.Sprintf("%d message(s)", len(recs)))
	})
	if err != nil {
		return nil, err
	}
	s.flush(ctx, ob)
	return out, nil
}

func unmarshalMessage(raw string, m *channel.Message) error {
	if err := json.Unmarshal([]byte(raw), m); err != nil {
		return fmt.Errorf("notify: stored message: %w", err)
	}
	return nil
}

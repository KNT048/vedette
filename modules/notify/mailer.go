package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
// logged, not stored and not put into any error or history row. A failure is a fixed error that may carry
// the numeric SMTP status and nothing else: no server reply text (a banner can name internals) and no
// address (the caller may log the error, and an address is personal data).
func (m CodeMailer) SendCode(ctx context.Context, to, code string) error {
	s := m.s
	if ok, _ := s.EmailReady(ctx); !ok {
		return ErrEmailNotReady
	}
	rcpt, err := channel.ParseRecipients(to)
	if err != nil || len(rcpt) != 1 {
		return errCodeAddress
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Email)
	if err != nil {
		return errCodeSettings
	}
	snd, err := s.savedSender(ctx, c, rcpt)
	if err != nil {
		return errCodeSettings
	}
	return m.send(ctx, snd, channel.Message{ID: store.NewID("code"), Kind: "test", Severity: string(Info), Title: "Your Vedette sign-in code",
		What: "Your sign-in code is " + code + ". It expires in 10 minutes. If you did not try to sign in, tell your administrator.",
		Link: s.link("/login")})
}

// SendStepUpCode mails a step-up code (core/auth.StepUpMailer, D-98): the same SMTP path, the same availability and the same
// fixed errors as SendCode, but the message says what is being approved so it cannot be taken for a sign-in code.
// summary is one line built by the server; it still goes through the line cleaner of the channel package (control and bidi
// characters, line breaks). There is no link in the message and nothing in it but the code. The code is not logged or stored.
func (m CodeMailer) SendStepUpCode(ctx context.Context, to, code, summary string) error {
	s := m.s
	if ok, _ := s.EmailReady(ctx); !ok {
		return ErrEmailNotReady
	}
	rcpt, err := channel.ParseRecipients(to)
	if err != nil || len(rcpt) != 1 {
		return errCodeAddress
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Email)
	if err != nil {
		return errCodeSettings
	}
	snd, err := s.savedSender(ctx, c, rcpt)
	if err != nil {
		return errCodeSettings
	}
	what := channel.Line(summary, 300)
	if what == "" {
		what = "an action in Vedette"
	}
	return m.send(ctx, snd, channel.Message{ID: store.NewID("code"), Kind: "test", Severity: string(Info), Title: "Your Vedette approval code",
		What: "You are asked to approve: " + what + "\n\nYour approval code is " + code + ". It expires in 10 minutes.\nIf this was not you, do not share the code."})
}

func (m CodeMailer) send(ctx context.Context, snd channel.Sender, msg channel.Message) error {
	cctx, cancel := context.WithTimeout(ctx, codeSendTimeout)
	defer cancel()
	_, err := snd.Send(cctx, msg)
	if err != nil {
		var se *channel.StatusError
		if errors.As(err, &se) {
			return fmt.Errorf("notify: sign-in code: the mail server refused the message (SMTP status %d)", se.Code)
		}
		return errCodeSend
	}
	return nil
}

// Fixed errors of SendCode: none of them holds the address, the code or text from the server.
var (
	errCodeAddress  = errors.New("notify: sign-in code: the address is not valid")
	errCodeSettings = errors.New("notify: sign-in code: the email settings cannot be used")
	errCodeSend     = errors.New("notify: sign-in code: the message could not be sent")
)

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

func unmarshalMessage(raw string, m *channel.Message) error {
	if err := json.Unmarshal([]byte(raw), m); err != nil {
		return fmt.Errorf("notify: stored message: %w", err)
	}
	return nil
}

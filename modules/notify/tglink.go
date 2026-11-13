package notify

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Telegram approvers are linked by the confirm link of D-447, sent by the channel's bot (D-414). It replaced the private code answered to
// a press: a code shown in Telegram proves who holds the Telegram account, not which Vedette user they are. The token and the proof belong
// to module response (Config.LinkCodes); only the person, signed in to Vedette as themself, confirms the link (response INV-24). The
// state per approver is kept with Zalo's (zaloSetup.codes, codeKey).

const tgLinkSendWait = 30 * time.Second

func telegramLinkPath(token string) string { return "/link/telegram?c=" + url.QueryEscape(token) }

// TelegramApprovers is GET /notify/telegram/approvers: each saved approver of the Telegram channel and whether their Telegram is linked;
// who is the administrator asking (their own row is Self).
func (s *Service) TelegramApprovers(ctx context.Context, who string) ([]LinkApprover, error) {
	list, err := loadApprovers(ctx, s.cfg.DB.Reader(), channel.Telegram)
	if err != nil {
		return nil, err
	}
	out := make([]LinkApprover, 0, len(list))
	for _, a := range list {
		out = append(out, s.approverState(ctx, channel.Telegram, a, who, ""))
	}
	return out, nil
}

// SendTelegramLink is POST /notify/telegram/approvers/{user_id}/code: a new confirm link for that approver (the old one stops working),
// sent privately by the bot. An administrator's own row gets the message like everyone's; they confirm it in their session.
func (s *Service) SendTelegramLink(ctx context.Context, actor, userID string) (LinkApprover, error) {
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Telegram)
	if err != nil {
		return LinkApprover{}, err
	}
	if !approvalsReady(c) {
		return LinkApprover{}, apierr.New(http.StatusConflict, "channel_not_ready", `Save the Telegram channel turned on, with "Approve actions from this channel", first.`)
	}
	list, err := loadApprovers(ctx, s.cfg.DB.Reader(), channel.Telegram)
	if err != nil {
		return LinkApprover{}, err
	}
	i := slices.IndexFunc(list, func(a Approver) bool { return a.UserID == userID })
	if i < 0 {
		return LinkApprover{}, apierr.New(http.StatusNotFound, "not_listed", "This person is not an approver on the Telegram channel. Save the channel first.")
	}
	if err := s.sendTelegramLink(ctx, actor, c, list[i]); err != nil {
		return LinkApprover{}, err
	}
	return s.approverState(ctx, channel.Telegram, list[i], actor, ""), nil
}

// SendApproverLink sends the approver userID of a confirm-link channel a new confirm link: response's Send again in My account (D-414,
// response Config.LinkSender), where actor is that person. link is set when nothing was sent because the person confirms in their session
// (Zalo: their own row with the box's own account).
func (s *Service) SendApproverLink(ctx context.Context, actor string, t channel.Type, userID string) (link string, err error) {
	switch t {
	case channel.Telegram:
		_, err := s.SendTelegramLink(ctx, actor, userID)
		return "", err
	case channel.ZaloPersonal:
		v, err := s.SendZaloCode(ctx, actor, userID)
		return v.Link, err
	}
	return "", badRequest("chat_channel", "This channel is not linked by a confirm link.")
}

// sendTelegramLink asks response for a new token and sends the link privately: "<name>: open this link to link your Telegram account to
// Vedette". The link needs the address people open Vedette at (Config.BaseURL). The token goes only to the listed user ID, never into a
// shared chat (review of D-414): only that account can open it. A link that could not be delivered is dropped (response DropChatLink: no
// token waits that nobody received) and answered as 502 send_failed; the approver's state keeps why. The token is never logged nor audited.
func (s *Service) sendTelegramLink(ctx context.Context, actor string, c channelRow, a Approver) error {
	if s.cfg.LinkCodes == nil {
		return apierr.New(http.StatusServiceUnavailable, "link_unavailable", "Approvers cannot be linked now: the Response module is off.")
	}
	if s.baseURL() == "" {
		err := apierr.New(http.StatusServiceUnavailable, "no_base_url", "Vedette does not know the address people open it at, so no confirm link can be sent.")
		s.markCode(channel.Telegram, a, zaloCodeSent{address: a.Address, errText: err.Message})
		return err
	}
	s.markCode(channel.Telegram, a, zaloCodeSent{address: a.Address, sending: true})
	token, name, err := s.cfg.LinkCodes.ChatLinkToken(ctx, a.UserID, channel.Telegram, a.Address)
	if err != nil {
		s.markCode(channel.Telegram, a, zaloCodeSent{address: a.Address, errText: "No link was made: " + refusalText(err)})
		return err
	}
	sent, note := s.deliverTelegramLink(ctx, c, a, s.link(telegramLinkPath(token)), name)
	s.markCode(channel.Telegram, a, sent)
	detail := "a confirm link was sent privately to Telegram " + a.Address
	if sent.errText != "" {
		detail = "a confirm link could not be sent to Telegram " + a.Address + ": " + sent.errText
		if note {
			detail = "a confirm link could not be sent to Telegram " + a.Address + " (the bot may not write to it first); a note asking them to press Start was posted in the approval chat"
		}
		if derr := s.cfg.LinkCodes.DropChatLink(ctx, actor, a.UserID, channel.Telegram, a.Address); derr != nil {
			s.cfg.Log.WarnContext(ctx, "notify: telegram: an undelivered confirm link could not be dropped", "user", a.UserID, "error", derr.Error())
		}
	}
	if u, ok, uerr := s.cfg.Users.Lookup(ctx, a.UserID); uerr == nil && ok {
		detail += " (approver " + u.Email + ")"
	}
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		return s.record(ctx, tx, actor, "notify.telegram_link_code", string(channel.Telegram), clip(detail, 400))
	}); err != nil {
		return err
	}
	if sent.errText != "" {
		return apierr.New(http.StatusBadGateway, "send_failed", sent.errText)
	}
	return nil
}

// deliverTelegramLink sends the link privately to the approver's user ID. A bot cannot write first to someone who never wrote to it
// (Telegram answers 403, or 400 "chat not found"): then the approval chat gets a note WITHOUT the link, addressed to the person, asking them
// to open a private chat with the bot and press Start, then Send again (My account). note says that the note was posted.
func (s *Service) deliverTelegramLink(ctx context.Context, c channelRow, a Approver, link, name string) (out zaloCodeSent, note bool) {
	out = zaloCodeSent{address: a.Address, at: time.Now()}
	who := clip(name, 64)
	m := channel.Message{Kind: channel.KindReply, Severity: "info", Title: who + ": open this link to link your Telegram account to Vedette.",
		What: "Sign in to Vedette as " + who + ", then press Confirm. It works once, within 10 minutes. If you are not " + who + ", ignore this message.",
		Link: link}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tgLinkSendWait)
	defer cancel()
	snd, err := s.savedSender(sctx, c, []string{a.Address})
	if err == nil {
		_, err = snd.Send(sctx, m)
	}
	if err == nil {
		return out, false
	}
	var se *channel.StatusError
	if !errors.As(err, &se) || (se.Code != http.StatusForbidden && se.Code != http.StatusBadRequest) {
		out.errText = userText(err)
		return out, false
	}
	shown := shownName(who) // the chat sees a name, never a sign-in email
	out.errText = "The bot cannot write to " + shown + " yet: they must open a private chat with the bot and press Start, then press Send again. " +
		"If they did, check the Telegram user ID."
	ask := channel.Message{Kind: channel.KindReply, Severity: "info",
		Title: shown + ": to link your Telegram account to Vedette, open a private chat with this bot and press Start, then press Send again in Vedette (My account), or ask your administrator to.",
		Link:  s.link("/account#approver-identities")}
	gs, gerr := s.savedSender(sctx, c, nil)
	if gerr == nil {
		_, gerr = gs.Send(sctx, ask)
	}
	if gerr != nil {
		out.errText += " The note to the approval chat failed too: " + userText(gerr)
		return out, false
	}
	out.errText += " A note asking them to was posted in the approval chat."
	return out, true
}

// shownName is a name for a shared chat: an email (a user without a name) is masked to its first letter and domain.
func shownName(name string) string {
	local, domain, ok := strings.Cut(name, "@")
	if !ok || local == "" {
		return name
	}
	return string([]rune(local)[0]) + "•••@" + domain
}

// sendTelegramLinksLater sends the links of approvers a save added or gave a new Telegram ID, after the save, one after the other. The
// dialog shows them as sending until each is done.
func (s *Service) sendTelegramLinksLater(ctx context.Context, actor string, c channelRow, list []Approver) {
	if len(list) == 0 || s.cfg.LinkCodes == nil {
		return
	}
	for _, a := range list {
		s.markCode(channel.Telegram, a, zaloCodeSent{address: a.Address, sending: true})
	}
	bg := context.WithoutCancel(ctx)
	s.zalo.bg.Go(func() {
		for _, a := range list {
			if err := s.sendTelegramLink(bg, actor, c, a); err != nil {
				s.cfg.Log.DebugContext(bg, "notify: telegram: a confirm link was not sent", "error", err.Error())
			}
		}
	})
}

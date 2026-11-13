package notify

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/notify/channel"
)

// TelegramChats is POST /notify/telegram/chats (admin, D-491): the chats the bot has seen, for the Chat ID picker. The token is the one in
// the form, or, when the form has none (an edit), the saved one, which never goes back to the browser. Telegram is asked once, without an
// offset, so no update is confirmed and the approval buttons lose nothing. No chat yet is an empty list, not an error.
func (s *Service) TelegramChats(ctx context.Context, token string) (chats []channel.TelegramChat, fresh bool, err error) {
	saved, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Telegram)
	if err != nil {
		return nil, false, err
	}
	savedToken := func() (string, error) {
		if saved.SecretID == "" {
			return "", nil
		}
		return s.openSecret(ctx, s.cfg.DB.Reader(), saved.SecretID)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		t, err := savedToken()
		switch {
		case errors.Is(err, errSecretUnreadable):
			return nil, false, badRequest("bad_token", "The saved bot token cannot be read. Enter the token again.")
		case err != nil:
			return nil, false, err
		case t == "":
			return nil, false, badRequest("secret_required", "Enter the bot token first.")
		}
		token = t
	}
	bot, err := channel.NewTelegramBot(secrets.NewValue(token), s.cfg.HTTPClient)
	if err != nil {
		var ce *channel.ConfigError
		if errors.As(err, &ce) {
			return nil, false, badRequest(ce.Code, ce.Msg)
		}
		return nil, false, err
	}
	// While the box long-polls this bot for approval buttons it is the one reader (a second getUpdates would end its poll with 409).
	if s.cfg.Decisions != nil && saved.Configured && saved.Enabled && saved.Approvals && approvalChat(saved.Fields) {
		if t, err := savedToken(); err == nil && botOf(t) == botOf(token) {
			return nil, false, apierr.New(http.StatusConflict, "telegram_busy", "Approval buttons are on for this bot, so Vedette is already reading its messages. Switch approvals off and save, press Find my chat, then switch them on again; or type the Chat ID by hand.")
		}
	}
	chats, err = bot.FindChats(ctx)
	if err != nil {
		var se *channel.StatusError
		var rl *channel.RateLimitError
		var pe *channel.ProviderError
		switch {
		case errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusNotFound): // an unknown or revoked token is 401 (a malformed one 404)
			return nil, false, badRequest("bad_token", "The bot token is not valid. Copy it again from @BotFather.")
		case errors.As(err, &se) && se.Code == http.StatusConflict:
			return nil, false, apierr.New(http.StatusConflict, "telegram_busy", "Another program is already reading this bot's messages (a webhook is set, or other software uses the same token). Type the Chat ID by hand, or stop the other reader and try again.")
		case errors.As(err, &rl):
			return nil, false, apierr.New(http.StatusBadGateway, "telegram_failed", "Telegram asked to wait. Try again in a minute.")
		case errors.As(err, &pe):
			return nil, false, apierr.New(http.StatusBadGateway, "telegram_failed", "Telegram's answer could not be used. Try again, or type the Chat ID by hand.")
		}
		return nil, false, apierr.New(http.StatusBadGateway, "telegram_failed", "Telegram did not answer: "+userText(err))
	}
	if len(chats) == 0 {
		// The call just set the update filter (Telegram keeps the last one given): a message sent while approvals had it at button presses
		// only was never stored, so the first empty answer for a bot says to send the message again.
		id := botOf(token)
		s.tgFound.mu.Lock()
		if s.tgFound.seen == nil || len(s.tgFound.seen) >= 64 {
			s.tgFound.seen = map[string]bool{}
		}
		fresh = !s.tgFound.seen[id]
		s.tgFound.seen[id] = true
		s.tgFound.mu.Unlock()
	}
	return chats, fresh, nil
}

// botOf is the bot's id, the part of the token before the colon.
func botOf(token string) string {
	id, _, _ := strings.Cut(strings.TrimSpace(token), ":")
	return id
}

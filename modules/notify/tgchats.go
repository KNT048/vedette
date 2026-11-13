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
func (s *Service) TelegramChats(ctx context.Context, token string) ([]channel.TelegramChat, error) {
	saved, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Telegram)
	if err != nil {
		return nil, err
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
			return nil, badRequest("bad_token", "The saved bot token cannot be read. Enter the token again.")
		case err != nil:
			return nil, err
		case t == "":
			return nil, badRequest("secret_required", "Enter the bot token first.")
		}
		token = t
	}
	bot, err := channel.NewTelegramBot(secrets.NewValue(token), s.cfg.HTTPClient)
	if err != nil {
		var ce *channel.ConfigError
		if errors.As(err, &ce) {
			return nil, badRequest(ce.Code, ce.Msg)
		}
		return nil, err
	}
	// While the box long-polls this bot for approval buttons it is the one reader (a second getUpdates would end its poll with 409).
	if saved.Configured && saved.Enabled && saved.Approvals && approvalChat(saved.Fields) {
		if t, err := savedToken(); err == nil && botOf(t) == botOf(token) {
			return nil, apierr.New(http.StatusConflict, "telegram_busy", "Approval buttons are on for this bot, so Vedette is already reading its messages. Switch approvals off and save, press Find my chat, then switch them on again; or type the Chat ID by hand.")
		}
	}
	chats, err := bot.FindChats(ctx)
	if err != nil {
		var se *channel.StatusError
		if errors.As(err, &se) {
			switch se.Code {
			case http.StatusUnauthorized, http.StatusNotFound: // Telegram answers an unknown or revoked token with 401 (a malformed one with 404)
				return nil, badRequest("bad_token", "The bot token is not valid. Copy it again from @BotFather.")
			case http.StatusConflict:
				return nil, apierr.New(http.StatusConflict, "telegram_busy", "Another program is already reading this bot's messages (a webhook is set, or other software uses the same token). Type the Chat ID by hand, or stop the other reader and try again.")
			}
		}
		return nil, apierr.New(http.StatusBadGateway, "telegram_failed", "Telegram did not answer: "+userText(err))
	}
	return chats, nil
}

// botOf is the bot's id, the part of the token before the colon.
func botOf(token string) string {
	id, _, _ := strings.Cut(strings.TrimSpace(token), ":")
	return id
}

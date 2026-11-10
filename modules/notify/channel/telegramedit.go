package channel

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
)

// Removing the buttons of a sent approval message (slice 2, spec approval-tokens.md 6: "sửa tin để bỏ nút").

// maxMessageID bounds a Telegram message_id: Telegram documents ids as fitting a 53-bit integer.
const maxMessageID = 1 << 53

var messageIDRE = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)

// sentMessageID reads result.message_id of a sendMessage answer (untrusted): a plain positive JSON number up to 2^53, else 0
// (unknown: the message was still delivered, only its buttons cannot be removed later).
func sentMessageID(body []byte) int64 {
	var ans struct {
		Result struct {
			MessageID json.RawMessage `json:"message_id"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &ans) != nil || !messageIDRE.Match(ans.Result.MessageID) {
		return 0
	}
	var id int64
	if json.Unmarshal(ans.Result.MessageID, &id) != nil || id <= 0 || id > maxMessageID {
		return 0
	}
	return id
}

// RemoveButtons takes the inline keyboard off one message (editMessageReplyMarkup with an empty keyboard). A refusal is a
// *StatusError: 400 means Telegram will never take this edit (the buttons are gone already, the message was deleted, or it is
// too old to edit); other codes may pass later. Errors never carry the URL or the token.
func (b *TelegramBot) RemoveButtons(ctx context.Context, chatID string, messageID int64) error {
	if !telegramChatIDRE.MatchString(chatID) || messageID <= 0 || messageID > maxMessageID {
		return errors.New("notify: telegram: no message to edit")
	}
	args := map[string]any{"chat_id": chatID, "message_id": messageID, "reply_markup": map[string]any{"inline_keyboard": []any{}}}
	ans, err := b.call(ctx, "editMessageReplyMarkup", args, defaultTimeout, maxResponseBody)
	if err != nil {
		return err
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(ans, &ok) != nil || !ok.OK {
		return &ProviderError{Channel: Telegram, Reason: "the answer did not confirm the edit"}
	}
	return nil
}

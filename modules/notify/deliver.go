package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/notify/channel"
)

// SendRecord is one delivery attempt (contract.ts SendRecord, table notify_send).
type SendRecord struct {
	ID      string
	Channel channel.Type
	To      string
	At      time.Time
	OK      bool
	Error   string // for people: short, friendly, secret-free (see friendlyError); empty when OK
	// MessageID is the provider's id of the sent message (Telegram), 0 when unknown; kept only to remove approval buttons later.
	MessageID int64
	ChatID    string // the provider's chat of the sent message (Telegram, a checked number), "" when unknown
}

// Deliver makes one attempt through s and always returns its record (INV-6:
// there is no attempt without a record), even when the sender panics: that is
// recorded as a failure with the error "internal error". Now is the injected
// clock. Whether to try at all (min_severity, quiet hours, grouping) is decided
// before, by Decide and Group. The record's Error is friendlyError of what the
// adapter returned: the raw text of a provider or a server never reaches the GUI.
func Deliver(ctx context.Context, id string, s channel.Sender, m channel.Message, now func() time.Time) (rec SendRecord) {
	rec.ID = id
	defer func() {
		if p := recover(); p != nil {
			rec.At, rec.OK, rec.Error = now(), false, "internal error"
		}
	}()
	rec.Channel, rec.To = s.Type(), s.Dest()
	r, err := s.Send(ctx, m)
	rec.At = now()
	if r.To != "" {
		rec.To = r.To
	}
	if err != nil {
		rec.Error = friendlyError(err)
		return rec
	}
	rec.OK, rec.MessageID, rec.ChatID = true, r.MessageID, r.ChatID
	return rec
}

var channelName = map[channel.Type]string{
	channel.Telegram: "Telegram", channel.Slack: "Slack", channel.Zalo: "Zalo", channel.ZaloPersonal: "Zalo",
	channel.Email: "The mail server", channel.Webhook: "The webhook server",
}

// friendlyError is the text of a send failure for people: it says what happened and never repeats what the
// other side wrote (provider answers and server banners are untrusted and may carry internals). A status
// code is shown for Telegram, Slack and Zalo (HTTP) and for email (the SMTP code, never called HTTP); a
// webhook only says it answered with an error, so the test button cannot be used to probe internal servers.
func friendlyError(err error) string {
	var ce *channel.ConfigError
	var be *channel.BackoffError
	var se *channel.StatusError
	var pe *channel.ProviderError
	switch {
	case errors.As(err, &ce):
		return ce.Msg
	case errors.As(err, &be):
		return "Zalo is pausing sign-in attempts after a failure. It will try again later."
	case errors.As(err, &se):
		name := channelName[se.Channel]
		switch se.Channel {
		case channel.Email:
			return fmt.Sprintf("The mail server refused the message (SMTP code %d).", se.Code)
		case channel.Webhook:
			return name + " answered with an error, so it did not accept the message."
		}
		return fmt.Sprintf("%s refused the message (HTTP %d).", name, se.Code)
	case errors.As(err, &pe):
		if pe.Code == 0 {
			return channelName[pe.Channel] + " refused the message."
		}
		return fmt.Sprintf("%s refused the message (code %d).", channelName[pe.Channel], pe.Code)
	case errors.Is(err, errSecretUnreadable):
		return "The saved key cannot be read. Save the channel again with the key."
	case errors.Is(err, channel.ErrInvalidMessage):
		return "The message could not be built."
	}
	text := err.Error()
	switch {
	case errors.Is(err, channel.ErrBoxAddrsUnknown), strings.Contains(text, "addresses are not known yet"): // the dial error arrives as text
		return "Vedette does not know this box's own network addresses yet, so webhooks wait. Try again in a minute."
	case strings.Contains(text, "refusing to connect"):
		return "This address is not allowed: it points at this machine, a link-local, multicast or reserved address."
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "timed out"):
		return "The server did not answer in time."
	case errors.Is(err, context.Canceled), strings.Contains(text, "cancelled"):
		return "The send was cancelled before it finished."
	}
	return "The message could not be sent. The server could not be reached or answered something unexpected."
}

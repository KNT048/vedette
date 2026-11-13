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
	TS        string // Slack: the ts of the posted approval message, "" when unknown
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
	rec.OK, rec.MessageID, rec.ChatID, rec.TS = true, r.MessageID, r.ChatID, r.TS
	return rec
}

var channelName = map[channel.Type]string{
	channel.Telegram: "Telegram", channel.Slack: "Slack", channel.Zalo: "Zalo", channel.ZaloPersonal: "Zalo",
	channel.Email: "The mail server", channel.Webhook: "The webhook server",
}

// zaloOAHints says what to do for the Zalo OA errors a person can fix, from the OA API error list
// (https://stc-developers.zdn.vn/docs/v2/official-account/phu-luc/ma-loi/index.html); other codes keep the bare code.
var zaloOAHints = map[int]string{
	-216: zaloTokenHint, // Access token is invalid
	-220: zaloTokenHint, // access_token is expired or removed
	-213: "the recipient does not follow the OA. Ask them to follow it and send it a message, then try again.",
	-230: zaloWindowHint, // User has not interacted with the OA in the past 7 days
	-232: zaloWindowHint, // ... or the last interaction has expired
	-211: "the OA is out of message quota. Check the OA's service package in Zalo.",
	-32:  "the app or the OA called Zalo too often. Try again in a minute.",
	-209: "the Zalo app is not activated. Turn it on in Zalo Developers (Manage app > Settings).",
	-212: "the Zalo app has not registered the Official Account message API. Register it in Zalo Developers.",
	-223: "the OA has not granted the app permission to send. Ask the OA admin to approve the app's request.",
	-320: "paid messages need the Zalo app linked to a Zalo Cloud Account. Link one in Zalo Developers.",
	-321: "the Zalo Cloud Account linked to the app is out of money or cannot be charged. Top it up in Zalo.",
}

const (
	zaloTokenHint  = "the access token is invalid or expired (OA tokens last 25 hours). Get a new token in Zalo Developers and save it."
	zaloWindowHint = "Zalo delivers these messages only to people who interacted with the OA in the last 7 days. Ask the recipient to send the OA a message, then try again."
)

// friendlyError is the text of a send failure for people: it says what happened and never repeats what the
// other side wrote (provider answers and server banners are untrusted and may carry internals). A status
// code is shown for Telegram, Slack and Zalo (HTTP) and for email (the SMTP code, never called HTTP); a
// webhook only says it answered with an error, so the test button cannot be used to probe internal servers.
func friendlyError(err error) string {
	var ce *channel.ConfigError
	var be *channel.BackoffError
	var se *channel.StatusError
	var pe *channel.ProviderError
	var si *channel.SignInError
	switch {
	case errors.As(err, &ce):
		return ce.Msg
	case errors.As(err, &si): // before StatusError: a refused sign-in carries the SMTP code under our sentence (D-449)
		return si.Msg
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
		if hint, ok := zaloOAHints[pe.Code]; ok && pe.Channel == channel.Zalo {
			return fmt.Sprintf("Zalo refused the message (code %d): %s", pe.Code, hint)
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
	case strings.Contains(text, "refusing to connect to Vedette itself"):
		return channel.OwnText
	case strings.Contains(text, "refusing to connect"):
		return "This address is not allowed: it is a link-local, multicast, unspecified or cloud metadata address."
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "timed out"):
		return "The server did not answer in time."
	case errors.Is(err, context.Canceled), strings.Contains(text, "cancelled"):
		return "The send was cancelled before it finished."
	}
	return "The message could not be sent. The server could not be reached or answered something unexpected."
}

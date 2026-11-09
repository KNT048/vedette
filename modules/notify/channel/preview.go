package channel

import (
	"encoding/json"
	"fmt"
)

// Preview renders m the way the adapter of type t would send it, without sending anything: the email
// subject (empty for other types) and the body text (the JSON body for a webhook). It is what the
// incident page shows as "what was sent on each channel". Like Send, it rejects an unusable Message.
func Preview(t Type, m Message) (subject, text string, err error) {
	if err := m.check(); err != nil {
		return "", "", err
	}
	link, _ := safeLink(m.Link)
	n := m.norm()
	switch t {
	case Slack:
		return "", slackText(n, link), nil
	case Telegram:
		return "", telegramText(n, link), nil
	case Zalo, ZaloPersonal:
		return "", fit(n.mapText(defang).lines(link), zaloTextMax), nil
	case Email:
		return emailSubject(n), emailBody(n, link), nil
	case Webhook:
		b, err := json.MarshalIndent(newWebhookPayload(n, link), "", "  ")
		if err != nil {
			return "", "", fmt.Errorf("notify: preview: encode webhook payload: %w", err)
		}
		return "", string(b), nil
	}
	return "", "", fmt.Errorf("notify: preview: unknown channel type %q", t)
}

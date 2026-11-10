package notify

import (
	"context"

	"github.com/knt048/vedette/modules/notify/channel"
)

// WebhookTarget returns where the webhook channel posts and the key that signs its body, for the response module's
// webhook_call action (D-65: a neutral read for wiring; the caller applies its own address guard, and the values
// must never be logged or shown). ok is false when the webhook channel is not configured and enabled.
func (s *Service) WebhookTarget(ctx context.Context) (url, signingKey string, ok bool, err error) {
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Webhook)
	if err != nil || !c.Configured || !c.Enabled {
		return "", "", false, err
	}
	key, err := s.openSecret(ctx, s.cfg.DB.Reader(), c.SecretID)
	if err != nil {
		return "", "", false, err
	}
	return c.Fields["url"], key, true, nil
}

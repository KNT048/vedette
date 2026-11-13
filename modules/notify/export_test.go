package notify

import (
	"context"
	"net/http"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/notify/channel"
)

// SetWebhookClientForTest lets a test replace the guarded client of the webhook adapter; production code cannot.
func (s *Service) SetWebhookClientForTest(c *http.Client) { s.webhookClient = c }

// ApproverProblemForTest runs the approver re-check for one channel.
func (s *Service) ApproverProblemForTest(ctx context.Context, ch channel.Type, a Approver) string {
	return s.approverProblem(ctx, ch, a)
}

// SetZaloToForTest replaces how the direct Zalo sender of an approver is made (channel.ZaloPersonalTo in production).
func (s *Service) SetZaloToForTest(f func(channel.Sender, string) (channel.Sender, error)) {
	s.zaloTo = f
}

// ReplyCodeHashForTest is the code_hash of spec approval-tokens.md 7.1.
func ReplyCodeHashForTest(requestID, userID string, approve bool, code string) string {
	return replyCodeHash(requestID, userID, approve, code)
}

// NewReplyCodesForTest makes the two codes of one approver.
func NewReplyCodesForTest() (approve, reject string, err error) { return newReplyCodes() }

// ZaloInboxForTest is an open Zalo message connection, as the listener reads it.
type ZaloInboxForTest = zaloInbox

// SetZaloListenForTest replaces how the Zalo listener opens its connection (channel.ZaloListen in production).
func (s *Service) SetZaloListenForTest(f func(context.Context, channel.Sender) (ZaloInboxForTest, error)) {
	s.zaloListen = f
}

// RotateEmailSecretForTest saves a rotated email secret as a send would, and waits for the save.
func (s *Service) RotateEmailSecretForTest(old, next string) {
	_ = s.rotateEmailSecret(context.Background(), secrets.NewValue(old), secrets.NewValue(next))
	s.rotations.Wait()
}

// EmailSecretForTest opens the saved secret of the email channel.
func (s *Service) EmailSecretForTest(ctx context.Context) string {
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Email)
	if err != nil {
		return err.Error()
	}
	v, err := s.openSecret(ctx, s.cfg.DB.Reader(), c.SecretID)
	if err != nil {
		return err.Error()
	}
	return v
}

// ListenZaloForTest runs the job "zalo-listen" once.
func (s *Service) ListenZaloForTest(ctx context.Context) error { return s.listenZalo(ctx) }

// NormReplyCodeForTest is the normalisation of spec 7.1.
func NormReplyCodeForTest(s string) (string, bool, bool) { return normReplyCode(s) }

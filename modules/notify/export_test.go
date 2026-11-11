package notify

import (
	"context"
	"net/http"

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

// SetZaloRepliesForTest turns on sending Zalo reply codes, which waits for the listener (slice 4b) in production.
func (s *Service) SetZaloRepliesForTest() { s.zaloReplies = true }

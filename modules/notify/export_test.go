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

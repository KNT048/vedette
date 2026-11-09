package notify

import "net/http"

// SetWebhookClientForTest lets a test replace the guarded client of the webhook adapter; production code cannot.
func (s *Service) SetWebhookClientForTest(c *http.Client) { s.webhookClient = c }

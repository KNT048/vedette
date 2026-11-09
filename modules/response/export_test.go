package response

import "net/http"

// SetWebhookClientForTest lets a test replace the guarded client of webhook_call; production code cannot.
func (s *Service) SetWebhookClientForTest(c *http.Client) { s.webhookClient = c }

// AllowLoopbackForTest lets the guard accept 127.0.0.1 so a test can talk to an httptest server; production code cannot.
func (s *Service) AllowLoopbackForTest() { s.allowLoopback = true }

// LoopbackAllowedForTest reports the flag that AllowLoopbackForTest sets.
func (s *Service) LoopbackAllowedForTest() bool { return s.allowLoopback }

// GuardedClientForTest returns the client webhook_call uses.
func (s *Service) GuardedClientForTest() *http.Client { return s.guardedClient() }

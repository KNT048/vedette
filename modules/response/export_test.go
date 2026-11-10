package response

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"time"
)

// SetWebhookClientForTest lets a test replace the guarded client of webhook_call; production code cannot.
func (s *Service) SetWebhookClientForTest(c *http.Client) { s.webhookClient = c }

// AllowLoopbackForTest lets the guard accept 127.0.0.1 so a test can talk to an httptest server; production code cannot.
func (s *Service) AllowLoopbackForTest() { s.allowLoopback = true }

// LoopbackAllowedForTest reports the flag that AllowLoopbackForTest sets.
func (s *Service) LoopbackAllowedForTest() bool { return s.allowLoopback }

// GuardedClientForTest returns the client webhook_call uses.
func (s *Service) GuardedClientForTest() *http.Client { return s.guardedClient() }

// SetInterfacesForTest replaces the read of the box's network interfaces (a failing one proves the fail-closed paths).
func (s *Service) SetInterfacesForTest(f func() ([]netip.Addr, error)) { s.interfaceFn = f }

// SetBacklogForTest sets how many unprocessed trigger events are kept before the oldest are dropped.
func (s *Service) SetBacklogForTest(n int) { s.maxBacklog = n }

// FetchKeysForTest is how many sources the block list rate limit remembers.
func (s *Service) FetchKeysForTest() int {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	return len(s.fetchTimes)
}

// SweepStuckForTest runs the sweep that fails items an approved request left behind.
func (s *Service) SweepStuckForTest(ctx context.Context) error { return s.failStuck(ctx) }

// SetStepLimitForTest sets the time one item may take before its context ends.
func (s *Service) SetStepLimitForTest(d time.Duration) { s.stepLimit = d }

// HandleStaleForTest runs rule ruleID on ev as the evaluator does after it read the rule: inside a transaction, re-testing the
// stored rule. It reports whether the rule ran.
func (s *Service) HandleStaleForTest(ctx context.Context, ruleID string, ev Det, all []Det) (handled bool, err error) {
	var sum RunSummary
	var fx effects
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, handled, err = s.handleInTx(ctx, tx, ruleID, ev, all, &sum, &fx)
		return err
	})
	return handled, err
}

// ApproveViaForTest approves as who with the way of approval they came by (the public Approve is always the app; chat and email arrive in 13b-7).
func (s *Service) ApproveViaForTest(ctx context.Context, who Actor, id string, pick []string, code string) (ActionRequest, error) {
	return s.approve(ctx, who, id, pick, code, false, nil)
}

// CheckAIPausedForTest runs the pause gate 13b-10 puts among its proposal gates.
func CheckAIPausedForTest(st Settings) error { return checkAIPaused(st) }

// ApproveSummaryForTest returns the line sent with a two-step code for the request.
func (s *Service) ApproveSummaryForTest(ctx context.Context, id string, pick ...string) (string, error) {
	r, ok, err := loadReq(ctx, s.cfg.DB.Reader(), id)
	if err != nil || !ok {
		return "", err
	}
	return approveSummary(r, pick), nil
}

// WaitSendsForTest waits for the approval requests that are being sent in the background.
func (s *Service) WaitSendsForTest() { s.sendWG.Wait() }

// SetBeforeLockForTest sets a function that runs just before a decision through an approval link takes the service lock.
func (s *Service) SetBeforeLockForTest(f func()) { s.beforeLock = f }

// LinkKeysForTest is how many sources the approval link rate limit remembers.
func (s *Service) LinkKeysForTest() int {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	return len(s.linkTimes)
}

// SetSendBudgetForTest sets how long sending one approval request may take.
func (s *Service) SetSendBudgetForTest(d time.Duration) { s.budget = d }

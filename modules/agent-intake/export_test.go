package agentintake

import (
	"context"
	"crypto/x509"
	"time"
)

// SetWazuhForTest makes the Wazuh client trust roots as public authorities, call without pacing, and sleep through sleep (the 429
// waits), so the tests run in milliseconds against a fake on loopback.
func (s *Service) SetWazuhForTest(roots *x509.CertPool, sleep func(ctx context.Context, d time.Duration) error) {
	s.wazuhRoots, s.wazuhPace, s.wazuhSleep = roots, 0, sleep
}

// SetWazuhBudgetForTest replaces the time one pull may take with a context the test ends itself (nil: the real budget back).
func (s *Service) SetWazuhBudgetForTest(budget func(ctx context.Context) (context.Context, context.CancelFunc)) {
	if budget == nil {
		budget = func(ctx context.Context) (context.Context, context.CancelFunc) {
			return context.WithTimeout(ctx, wazuhPullBudget)
		}
	}
	s.wazuhBudget = budget
}

// SetMirrorWaitsForTest shortens the write deadline of one chunk of a package download and the time one download may take.
func (s *Service) SetMirrorWaitsForTest(chunk, total time.Duration) {
	s.chunkWait, s.maxDownload = chunk, total
}

// SetMirrorEventForTest reports each take and give-back of a package download slot, by source key, so a test waits on that state instead of the clock.
func (s *Service) SetMirrorEventForTest(f func(key string, held bool)) { s.mirrorEvent = f }

// AllowedWazuhCall is the allow-list of FORBID-4.
func AllowedWazuhCall(method, path string) bool { return allowedCall(method, path) }

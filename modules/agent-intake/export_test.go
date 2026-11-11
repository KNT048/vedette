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

// SetWazuhBudgetForTest shortens the time one pull may take.
func (s *Service) SetWazuhBudgetForTest(d time.Duration) { s.wazuhBudget = d }

// AllowedWazuhCall is the allow-list of FORBID-4.
func AllowedWazuhCall(method, path string) bool { return allowedCall(method, path) }

package conn

import (
	"crypto/x509"
	"time"

	"github.com/knt048/vedette/core/conn/internal/cred"
)

// VaultForTest hands a test the vault that only this package holds, to check what is stored.
func (s *Service) VaultForTest() *cred.Vault { return s.vault }

// SetTestBudgetForTest shortens the time a whole Test may take.
func (s *Service) SetTestBudgetForTest(d time.Duration) { s.testBudget = d }

// SetRootsForTest makes the certificates in pool "public": what the system roots would vouch for.
func (s *Service) SetRootsForTest(pool *x509.CertPool) { s.roots = pool }

// PinChangedForTest reports whether another pin value on c counts as a change of a security field.
func PinChangedForTest(c Connection, value string) bool {
	next := c
	next.Pin = &Pin{Kind: c.Pin.Kind, Value: value, FirstSeen: c.Pin.FirstSeen}
	return len(changedSecurityFields(c, next, false)) > 0
}

// BudgetOf is how long a whole Test of a kind may take.
func BudgetOf(kind string) time.Duration { return testBudget(kind) }

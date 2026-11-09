package conn

import "github.com/knt048/vedette/core/conn/internal/cred"

// VaultForTest hands a test the vault that only this package holds, to check what is stored.
func (s *Service) VaultForTest() *cred.Vault { return s.vault }

// PinChangedForTest reports whether another pin value on c counts as a change of a security field.
func PinChangedForTest(c Connection, value string) bool {
	next := c
	next.Pin = &Pin{Kind: c.Pin.Kind, Value: value, FirstSeen: c.Pin.FirstSeen}
	return len(changedSecurityFields(c, next, false)) > 0
}

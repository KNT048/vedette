// Package cred is the one place that decrypts the credential of a connection (D-93 (1)). Only the transports (slice 13b-5)
// and tests import it; Go's internal rule keeps everything outside core/conn away, and nothing in core/conn returns the
// value to an API, an audit row or a log: callers get a secrets.Value, which prints as a placeholder.
package cred

import (
	"context"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store/coredb"
)

// Purpose is the core_secret purpose of a connection's credential (conn.SecretPurpose).
const Purpose = "core_connection"

// Open decrypts the credential stored under secretID: a token, a password or an SSH private key in PEM.
func Open(ctx context.Context, s *secrets.Store, q coredb.DBTX, secretID string) (secrets.Value, error) {
	b, err := s.Open(ctx, q, secretID, Purpose)
	if err != nil {
		return secrets.Value{}, err
	}
	return secrets.NewValue(string(b)), nil
}

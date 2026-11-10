// Package cred is the one place that names the secret purpose of a connection credential, seals it and decrypts it (D-93 (1)).
// New restricts the purpose in core/secrets, so secrets.Store.Open refuses it for every other package: the only way to read a
// credential back is a Vault, and a Vault exists only inside core/conn (Go's internal rule). Only the transports (slice 13b-5)
// and tests call Open; nothing returns the value to an API, an audit row or a log: callers get a secrets.Value, which prints as
// a placeholder. TestOnlyCredNamesTheCredentialPurpose scans the source tree for anything else that names the purpose.
package cred

import (
	"context"
	"database/sql"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store/coredb"
)

const purpose = "core_connection"

// Key is the proof of being inside core/conn. It holds a pointer that must be the one unexported sentinel of this package: only Grant
// returns it, and Grant can be called only by packages under core/conn (Go's internal rule). A zero Key, new(Key), a Key made with
// reflect.Zero or any copy that did not come from Grant fails Valid, so code that merely holds a *conn.Service, or can name the type
// through a method signature, cannot make one. The methods of conn.Service that hand out a credential, the dialer or the connection
// lock check it at runtime and refuse with no secret.
type Key struct{ p *proof }

type proof struct{ _ byte } // not zero-size: every pointer to it is distinct

var sentinel = &proof{}

// Grant returns the one valid Key.
func Grant() Key { return Key{p: sentinel} }

// Valid reports whether k came from Grant.
func (k Key) Valid() bool { return k.p != nil && k.p == sentinel }

// Vault seals, replaces and decrypts the credentials of connections.
type Vault struct {
	s  *secrets.Store
	op *secrets.Opener
}

// New restricts the credential purpose of s and returns its only reader. It can be called once per Store.
func New(s *secrets.Store) (*Vault, error) {
	op, err := s.Restrict(purpose)
	if err != nil {
		return nil, err
	}
	return &Vault{s: s, op: op}, nil
}

// Seal stores a new credential in tx and returns its secret id. keepLast4 keeps the last 4 characters (a token or password).
func (v *Vault) Seal(ctx context.Context, tx *sql.Tx, plaintext []byte, keepLast4 bool) (string, error) {
	id, _, err := v.s.Seal(ctx, tx, purpose, plaintext, keepLast4)
	return id, err
}

// Replace encrypts a new value under an existing secret id.
func (v *Vault) Replace(ctx context.Context, tx *sql.Tx, id string, plaintext []byte, keepLast4 bool) error {
	_, err := v.s.Replace(ctx, tx, id, purpose, plaintext, keepLast4)
	return err
}

// Delete removes a credential in the transaction that deletes its owner.
func (v *Vault) Delete(ctx context.Context, tx *sql.Tx, id string) error {
	return v.s.Delete(ctx, tx, id)
}

// Open decrypts the credential stored under secretID: a token, a password or an SSH private key in PEM.
func (v *Vault) Open(ctx context.Context, q coredb.DBTX, secretID string) (secrets.Value, error) {
	b, err := v.op.Open(ctx, q, secretID)
	if err != nil {
		return secrets.Value{}, err
	}
	return secrets.NewValue(string(b)), nil
}

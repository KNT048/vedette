package conn

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/knt048/vedette/core/conn/internal/cred"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

// What core/conn/write needs from this package and nobody else may have (D-93, D-94, core INV-23). Each function asks for a
// cred.Key, which only a package under core/conn can make, so a package that merely holds the Service cannot read a credential
// or take the dialer.

// WriteAccess is the way out of the box for the writer: the dialer whose policy is the same as the one Test uses (asked at every
// dial, with the addresses of the box as they are then), and the roots that vouch for a server (nil: the system's).
type WriteAccess struct {
	Dialer *transport.Dialer
	Roots  *x509.CertPool
}

// WriteAccess returns it.
func (s *Service) WriteAccess(cred.Key) WriteAccess {
	return WriteAccess{Dialer: s.dialer(), Roots: s.roots}
}

// OpenCredential decrypts the credential of c: a token, a password or an SSH key. The value prints as a placeholder.
func (s *Service) OpenCredential(ctx context.Context, _ cred.Key, c Connection) (secrets.Value, error) {
	if c.secretID == nil {
		return secrets.Value{}, nil
	}
	v, err := s.vault.Open(ctx, s.cfg.DB.Reader(), *c.secretID)
	if err != nil {
		return secrets.Value{}, fmt.Errorf("conn: open credential: %w", err)
	}
	return v, nil
}

// AllowsURL says whether a request may be sent to raw through c (D-94 (1)): the address is under the target and under one entry of
// the allow-list, by the same rule as the save-time check (under): the same scheme, host and port, a path at or below, dot segments
// resolved first, and a backslash or an encoded slash, backslash or dot (%2F, %5C, %2E) refused. It never matches by string prefix.
func AllowsURL(c Connection, raw string) bool {
	if !under(raw, c.Target) {
		return false
	}
	for _, a := range c.Allow {
		if under(raw, a) {
			return true
		}
	}
	return false
}

// connLocks is one turn at a time per connection.
type connLocks struct {
	mu sync.Mutex
	m  map[string]chan struct{}
}

// LockConn takes the turn of connection id, or gives up when ctx ends (ok false). Whoever sends something to a device through the
// connection holds it for the whole call: the writer and the reader share it, so a read and a write never interleave on one session.
func (s *Service) LockConn(ctx context.Context, _ cred.Key, id string) (release func(), ok bool) {
	s.locks.mu.Lock()
	ch, found := s.locks.m[id]
	if !found {
		ch = make(chan struct{}, 1)
		s.locks.m[id] = ch
	}
	s.locks.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	case <-ctx.Done():
		return nil, false
	}
}

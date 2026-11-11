package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Retention of the sign-in tables (core CONTRACT INV-30). A session is deleted a day after it ended (expired, revoked, or idle that
// long: nothing reads an ended session, and the audit log keeps its sign-in and sign-out); a key the user never proved and an email
// code an hour past their 10 minutes; a code send a day after it was sent, past the hour that MaxSendsPerHour counts.
const (
	PruneEvery         = time.Hour
	sessionKeep        = 24 * time.Hour
	pendingKeep        = time.Hour
	emailCodeSendsKeep = 24 * time.Hour
)

// Pruned is how many rows one Prune deleted.
type Pruned struct{ Sessions, PendingTOTP, EmailCodes, EmailCodeSends int64 }

// Prune deletes the rows of the sign-in tables that can no longer be used, so they do not grow without end: sessions ended more than a
// day ago, authenticator keys never confirmed (with their sealed key in core_secret, like every other path that drops one), expired
// email codes and old code sends. None of them can sign anyone in, so no audit row is written (the session's own sign-in and
// sign-out rows stay in the audit log).
func (s *Service) Prune(ctx context.Context) (Pruned, error) {
	now := s.now()
	var p Pruned
	var keys []string
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		var err error
		if p.Sessions, err = q.PruneSessions(ctx, store.FormatTS(now.Add(-sessionKeep))); err != nil {
			return err
		}
		if keys, err = q.PrunePendingTotp(ctx, store.FormatTS(now.Add(-pendingTOTPTTL-pendingKeep))); err != nil {
			return err
		}
		for _, id := range keys {
			if err := s.secrets.Delete(ctx, tx, id); err != nil && !errors.Is(err, secrets.ErrNotFound) {
				return err
			}
		}
		p.PendingTOTP = int64(len(keys))
		if p.EmailCodes, err = q.PruneEmailCodes(ctx, store.FormatTS(now.Add(-pendingKeep))); err != nil {
			return err
		}
		p.EmailCodeSends, err = q.PruneOldEmailCodeSends(ctx, store.FormatTS(now.Add(-emailCodeSendsKeep)))
		return err
	})
	if err != nil {
		return Pruned{}, fmt.Errorf("auth: prune: %w", err)
	}
	for _, id := range keys {
		s.pendingTries.forget(id)
	}
	return p, nil
}

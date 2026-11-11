package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Retention of the sign-in tables (core CONTRACT INV-30). A session is kept 30 days after it ended (expired, revoked, or idle
// that long), for the record of where an account was used; a key the user never proved and an email code are kept an hour past
// their 10 minutes; a code send is kept a day, past the hour that MaxSendsPerHour counts.
const (
	PruneEvery         = time.Hour
	sessionKeep        = 30 * 24 * time.Hour
	pendingKeep        = time.Hour
	emailCodeSendsKeep = 24 * time.Hour
)

// Pruned is how many rows one Prune deleted.
type Pruned struct{ Sessions, PendingTOTP, EmailCodes, EmailCodeSends int64 }

// Prune deletes the rows of the sign-in tables that can no longer be used, so they do not grow without end: sessions ended more than 30
// days ago, authenticator keys never confirmed, expired email codes and old code sends. None of them can sign anyone in, so no
// audit row is written (the session's own sign-in and sign-out rows stay in the audit log).
func (s *Service) Prune(ctx context.Context) (Pruned, error) {
	now := s.now()
	var p Pruned
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		var err error
		if p.Sessions, err = q.PruneSessions(ctx, store.FormatTS(now.Add(-sessionKeep))); err != nil {
			return err
		}
		if p.PendingTOTP, err = q.PrunePendingTotp(ctx, store.FormatTS(now.Add(-pendingTOTPTTL-pendingKeep))); err != nil {
			return err
		}
		if p.EmailCodes, err = q.PruneEmailCodes(ctx, store.FormatTS(now.Add(-pendingKeep))); err != nil {
			return err
		}
		p.EmailCodeSends, err = q.PruneOldEmailCodeSends(ctx, store.FormatTS(now.Add(-emailCodeSendsKeep)))
		return err
	})
	if err != nil {
		return Pruned{}, fmt.Errorf("auth: prune: %w", err)
	}
	return p, nil
}

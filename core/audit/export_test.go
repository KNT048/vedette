package audit

import (
	"context"
	"database/sql"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/store"
)

// VerifyPaged exposes verify with a small page size and a per-page hook.
func VerifyPaged(ctx context.Context, db *sql.DB, page int64, afterPage func()) (chain.Result, error) {
	return verify(ctx, db, page, afterPage)
}

// PruneWith exposes the retention prune with a small window and ceiling.
func (l *Log) PruneWith(ctx context.Context, db *store.DB, days int, maxRows int64) (int64, error) {
	return l.prune(ctx, db, days, maxRows)
}

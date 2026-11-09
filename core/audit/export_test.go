package audit

import (
	"context"
	"database/sql"

	"github.com/knt048/vedette/core/chain"
)

// VerifyPaged exposes verify with a small page size and a per-page hook.
func VerifyPaged(ctx context.Context, db *sql.DB, page int64, afterPage func()) (chain.Result, error) {
	return verify(ctx, db, page, afterPage)
}

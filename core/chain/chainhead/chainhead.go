// Package chainhead reads and moves the recorded head of a hash chain (core_chain_head, issue #17). It is
// separate from package chain so that chain (the pure hash formula, D-57 (14)) has no database dependency.
package chainhead

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Load reads the head of the named chain (core_audit, ai_activity or resp_log); nil when none is recorded.
func Load(ctx context.Context, q coredb.DBTX, name string) (*chain.Head, error) {
	h, err := coredb.New(q).GetChainHead(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // nil means "no head recorded"
	}
	if err != nil {
		return nil, fmt.Errorf("chain: read head of %s: %w", name, err)
	}
	return &chain.Head{Hash: h.LastHash, Count: h.Count}, nil
}

// Advance records that a row with the given hash was appended to the chain. Call it inside the same
// transaction as the row insert (the audit, ai_activity and resp_log appends all do), so the head and the
// rows commit or roll back together.
func Advance(ctx context.Context, tx coredb.DBTX, name, hash string, now time.Time) error {
	err := coredb.New(tx).AdvanceChainHead(ctx, coredb.AdvanceChainHeadParams{Chain: name, LastHash: hash, UpdatedAt: store.FormatTS(now)})
	if err != nil {
		return fmt.Errorf("chain: advance head of %s: %w", name, err)
	}
	return nil
}

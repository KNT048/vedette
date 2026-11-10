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

// ErrPruneMismatch means a prune asked to remove more rows than the chain's head counts (or the chain has no
// head): the caller's transaction must roll back, because the head would no longer describe the table.
var ErrPruneMismatch = errors.New("chain: prune does not match the recorded head")

// Prune records that the oldest `removed` rows of the chain, up to and including lastPrunedID (whose stored hash
// is lastPrunedHash), were deleted in tx (issue #194): it upserts the chain's core_chain_anchor (where the chain
// now starts, read by verification and export) and lowers core_chain_head.count by removed. Call it in the same
// transaction as the DELETE, after it, so rows, anchor and head commit or roll back together. The newest row is
// never pruned through here: the head's hash stays as it is.
func Prune(ctx context.Context, tx coredb.DBTX, name, lastPrunedID, lastPrunedHash string, removed int64, now time.Time) error {
	if removed <= 0 || lastPrunedID == "" || len(lastPrunedHash) != 64 {
		return fmt.Errorf("chain: prune %s: need removed > 0, an id and a 64-hex hash", name)
	}
	res, err := tx.ExecContext(ctx, `UPDATE core_chain_head SET count = count - ?, updated_at = ? WHERE chain = ? AND count > ?`,
		removed, store.FormatTS(now), name, removed)
	if err != nil {
		return fmt.Errorf("chain: prune head of %s: %w", name, err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("%w: %s, removing %d rows", ErrPruneMismatch, name, removed)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO core_chain_anchor (chain, last_pruned_id, last_pruned_hash, pruned_at) VALUES (?, ?, ?, ?)
ON CONFLICT (chain) DO UPDATE SET last_pruned_id = excluded.last_pruned_id, last_pruned_hash = excluded.last_pruned_hash, pruned_at = excluded.pruned_at`,
		name, lastPrunedID, lastPrunedHash, store.FormatTS(now))
	if err != nil {
		return fmt.Errorf("chain: prune anchor of %s: %w", name, err)
	}
	return nil
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

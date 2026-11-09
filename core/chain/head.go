package chain

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Head is the newest row of a chain as recorded in core_chain_head (issue #17): its hash and the number of
// rows the chain holds now. Every append moves it in the same transaction (AdvanceHead); a retention prune
// must lower Count in its own transaction. Like the chain itself it is tamper-evident, not tamper-proof:
// someone who can rewrite the database file can rewrite the head too (DATA_MODEL 5.3).
type Head struct {
	Hash  string
	Count int64
}

// LoadHead reads the head of the named chain (core_audit, ai_activity or resp_log); nil when none is recorded.
func LoadHead(ctx context.Context, q coredb.DBTX, name string) (*Head, error) {
	h, err := coredb.New(q).GetChainHead(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // nil means "no head recorded"
	}
	if err != nil {
		return nil, fmt.Errorf("chain: read head of %s: %w", name, err)
	}
	return &Head{Hash: h.LastHash, Count: h.Count}, nil
}

// AdvanceHead records that a row with the given hash was appended to the chain. Call it inside the same
// transaction as the row insert (the audit, ai_activity and resp_log appends all do), so the head and the
// rows commit or roll back together.
func AdvanceHead(ctx context.Context, tx coredb.DBTX, name, hash string, now time.Time) error {
	err := coredb.New(tx).AdvanceChainHead(ctx, coredb.AdvanceChainHeadParams{Chain: name, LastHash: hash, UpdatedAt: store.FormatTS(now)})
	if err != nil {
		return fmt.Errorf("chain: advance head of %s: %w", name, err)
	}
	return nil
}

package chainhead_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/store/storetest"
)

const coreMigrations = "../../../modules/core/migrations/sqlite"

func TestHead(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	ctx := t.Context()
	now := time.Date(2026, 11, 9, 1, 2, 3, 0, time.UTC)

	if h, err := chainhead.Load(ctx, db.Reader(), "resp_log"); err != nil || h != nil {
		t.Fatalf("empty: %v, %v", h, err)
	}
	for i, hash := range []string{"a", "b", "c"} {
		hash = hash + "000000000000000000000000000000000000000000000000000000000000000"
		if err := db.Write(ctx, func(tx *sql.Tx) error { return chainhead.Advance(ctx, tx, "resp_log", hash, now) }); err != nil {
			t.Fatalf("advance %d: %v", i, err)
		}
	}
	h, err := chainhead.Load(ctx, db.Reader(), "resp_log")
	if err != nil || h == nil || h.Count != 3 || h.Hash[0] != 'c' || len(h.Hash) != 64 {
		t.Fatalf("head = %+v, %v", h, err)
	}
	if other, _ := chainhead.Load(ctx, db.Reader(), "ai_activity"); other != nil {
		t.Fatalf("chains share a head: %+v", other)
	}

	// The head rolls back with the caller's transaction.
	boom := errors.New("boom")
	err = db.Write(ctx, func(tx *sql.Tx) error {
		if err := chainhead.Advance(ctx, tx, "resp_log", "d"+h.Hash[1:], now); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if h2, _ := chainhead.Load(ctx, db.Reader(), "resp_log"); h2.Count != 3 || h2.Hash != h.Hash {
		t.Fatalf("head moved despite rollback: %+v", h2)
	}

	// Only the three chain names are accepted (the table has a CHECK).
	if err := db.Write(ctx, func(tx *sql.Tx) error { return chainhead.Advance(ctx, tx, "other_chain", h.Hash, now) }); err == nil {
		t.Fatal("unknown chain accepted")
	}
}

// Prune (issue #194) moves the anchor to the last pruned row and lowers the head count in the caller's transaction,
// so a verifier built from the anchor and the head accepts what is left; it refuses to prune the newest row.
func TestPrune(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	ctx := t.Context()
	now := time.Date(2026, 11, 10, 1, 2, 3, 0, time.UTC)
	h := func(c string) string { return strings.Repeat(c, 64) }
	for _, c := range []string{"a", "b", "c", "d"} {
		if err := db.Write(ctx, func(tx *sql.Tx) error { return chainhead.Advance(ctx, tx, "ai_activity", h(c), now) }); err != nil {
			t.Fatal(err)
		}
	}
	anchor := func() (id, hash string) {
		t.Helper()
		err := db.Reader().QueryRowContext(ctx, `SELECT last_pruned_id, last_pruned_hash FROM core_chain_anchor WHERE chain = 'ai_activity'`).Scan(&id, &hash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		return id, hash
	}
	prune := func(id, hash string, n int64) error {
		return db.Write(ctx, func(tx *sql.Tx) error { return chainhead.Prune(ctx, tx, "ai_activity", id, hash, n, now) })
	}

	// The two oldest rows (hashes a, b) go: the chain starts after b, two rows remain.
	if err := prune("r2", h("b"), 2); err != nil {
		t.Fatal(err)
	}
	if id, hash := anchor(); id != "r2" || hash != h("b") {
		t.Fatalf("anchor = %s %s", id, hash)
	}
	head, _ := chainhead.Load(ctx, db.Reader(), "ai_activity")
	if head.Count != 2 || head.Hash != h("d") {
		t.Fatalf("head = %+v", head)
	}
	v := chain.NewVerifierWithHead(h("b"), head)
	v.Add("r3", h("b"), h("c"), h("c"))
	v.Add("r4", h("c"), h("d"), h("d"))
	if r := v.Result(); !r.OK {
		t.Fatalf("remaining rows do not verify from the anchor: %+v", r)
	}

	// A second prune moves the anchor again (upsert, one row per chain).
	if err := prune("r3", h("c"), 1); err != nil {
		t.Fatal(err)
	}
	if id, _ := anchor(); id != "r3" {
		t.Fatalf("anchor not moved: %s", id)
	}

	// The newest row is never pruned: removing as many rows as the head counts (or more) is refused, and nothing moves.
	if err := prune("r4", h("d"), 1); !errors.Is(err, chainhead.ErrPruneMismatch) {
		t.Fatalf("pruning the newest row: %v", err)
	}
	if err := db.Write(ctx, func(tx *sql.Tx) error { return chainhead.Prune(ctx, tx, "resp_log", "x", h("e"), 1, now) }); !errors.Is(err, chainhead.ErrPruneMismatch) {
		t.Fatalf("a chain with no head: %v", err)
	}
	if id, _ := anchor(); id != "r3" {
		t.Fatalf("a refused prune moved the anchor: %s", id)
	}
	if head, _ := chainhead.Load(ctx, db.Reader(), "ai_activity"); head.Count != 1 {
		t.Fatalf("a refused prune moved the head: %+v", head)
	}
	for _, bad := range []struct {
		id, hash string
		n        int64
	}{{"", h("c"), 1}, {"r", "short", 1}, {"r", h("c"), 0}} {
		if err := prune(bad.id, bad.hash, bad.n); err == nil {
			t.Fatalf("bad input accepted: %+v", bad)
		}
	}

	// The anchor and head roll back with the caller's transaction.
	if err := db.Write(ctx, func(tx *sql.Tx) error { return chainhead.Advance(ctx, tx, "ai_activity", h("f"), now) }); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err := db.Write(ctx, func(tx *sql.Tx) error {
		if err := chainhead.Prune(ctx, tx, "ai_activity", "r4", h("d"), 1, now); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if id, _ := anchor(); id != "r3" {
		t.Fatalf("anchor moved despite rollback: %s", id)
	}
}

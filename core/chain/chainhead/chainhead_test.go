package chainhead_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

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

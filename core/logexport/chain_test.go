package logexport_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

const coreMigrations = "../../modules/core/migrations/sqlite"

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

// chainEnv is a core_audit with rows at the given times (a clock that can step back).
type chainEnv struct {
	t  *testing.T
	db *store.DB
	r  *logexport.Registry
}

func newChainEnv(t *testing.T, at ...time.Time) *chainEnv {
	t.Helper()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: os.DirFS(coreMigrations)})
	var now time.Time
	l := audit.New(func() time.Time { return now })
	for i, ts := range at {
		now = ts
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			return l.Append(t.Context(), tx, audit.Entry{User: "u@x.example", Action: "t.row", Target: "r" + strconv.Itoa(i)})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	e := &chainEnv{t: t, db: db, r: logexport.New()}
	e.r.Register("audit", func(ctx context.Context, from, to time.Time, w io.Writer) error {
		return logexport.ChainRows("core_audit", "core_audit", "id, prev_hash, hash, ts, user, action, target, detail", from, to).Write(ctx, db.Reader(), w)
	})
	return e
}

type fileRow map[string]any

func (e *chainEnv) export(from, to time.Time) (logexport.ChainInfo, []fileRow) {
	e.t.Helper()
	exp, err := e.r.Build(e.t.Context(), logexport.Request{Categories: []string{"audit"}, From: from, To: to, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: e.t.TempDir()})
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = exp.Close() }()
	body, err := io.ReadAll(exp)
	if err != nil {
		e.t.Fatal(err)
	}
	var f struct {
		Chains     map[string]logexport.ChainInfo
		Categories map[string][]fileRow
	}
	if err := json.Unmarshal(body, &f); err != nil {
		e.t.Fatal(err)
	}
	info, ok := f.Chains["audit"]
	if !ok {
		e.t.Fatalf("no chain info for audit: %s", body)
	}
	return info, f.Categories["audit"]
}

// verify checks the rows from the file alone, starting at anchor, with the shared formula.
func verify(t *testing.T, anchor string, rows []fileRow) chain.Result {
	t.Helper()
	v := chain.NewVerifier(anchor)
	for _, e := range rows {
		str := func(k string) string { s, _ := e[k].(string); return s }
		entry := map[string]any{"id": str("id"), "ts": str("ts"), "user": str("user"), "action": str("action"), "target": str("target"), "detail": nil}
		if d, ok := e["detail"].(string); ok {
			entry["detail"] = d
		}
		sum, err := chain.HashCanonical(str("prev_hash"), entry)
		if err != nil {
			t.Fatal(err)
		}
		v.Add(str("id"), str("prev_hash"), str("hash"), sum)
	}
	return v.Result()
}

func at(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }

func TestChainFromGenesisVerifiesFullyOffline(t *testing.T) {
	t.Parallel()
	e := newChainEnv(t, at(0), at(1), at(2), at(3))
	info, rows := e.export(time.Time{}, time.Time{})
	if len(rows) != 4 || info.Count != 4 || !info.Complete || info.AnchorKind != "genesis" || info.Anchor == nil || *info.Anchor != chain.Genesis {
		t.Fatalf("info = %+v rows = %d", info, len(rows))
	}
	if info.HeadHash == nil || *info.HeadHash != rows[3]["hash"] {
		t.Fatalf("head_hash = %v, want the newest row's hash", info.HeadHash)
	}
	if res := verify(t, *info.Anchor, rows); !res.OK || res.Count != 4 {
		t.Fatalf("verify = %+v", res)
	}
}

func TestARangedExportVerifiesFromItsStatedAnchor(t *testing.T) {
	t.Parallel()
	e := newChainEnv(t, at(0), at(1), at(2), at(3), at(4))
	info, rows := e.export(at(1), at(3)) // rows 2..4
	if len(rows) != 3 || info.Complete || info.AnchorKind != "row" || info.Count != 5 || info.Anchor == nil {
		t.Fatalf("info = %+v rows = %d", info, len(rows))
	}
	if *info.Anchor != rows[0]["prev_hash"] {
		t.Fatal("the anchor is the prev_hash of the first exported row")
	}
	if res := verify(t, *info.Anchor, rows); !res.OK || res.Count != 3 {
		t.Fatalf("from the stated anchor: %+v", res)
	}
	if res := verify(t, chain.Genesis, rows); res.OK {
		t.Fatal("a ranged export must not verify from Genesis: the anchor matters")
	}
	// A range that reaches the head but starts late, and one from the start that stops early, are not complete either.
	if info, _ := e.export(at(2), time.Time{}); info.Complete {
		t.Fatalf("late start is complete: %+v", info)
	}
	if info, _ := e.export(time.Time{}, at(2)); info.Complete || info.AnchorKind != "genesis" {
		t.Fatalf("early stop: %+v", info)
	}
	// An empty range has no anchor and says it is not complete.
	if info, rows := e.export(at(30), time.Time{}); len(rows) != 0 || info.Anchor != nil || info.Complete || info.AnchorKind != "none" {
		t.Fatalf("empty range: %+v", info)
	}
}

func TestAPrunedLogVerifiesFromLastPrunedHash(t *testing.T) {
	t.Parallel()
	e := newChainEnv(t, at(0), at(1), at(2), at(3))
	_, all := e.export(time.Time{}, time.Time{})
	pruned := all[1]["hash"].(string)
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			"DROP TRIGGER core_audit_no_delete",
			"DELETE FROM core_audit WHERE seq <= 2",
			"UPDATE core_chain_head SET count = count - 2 WHERE chain = 'core_audit'",
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(t.Context(), "INSERT INTO core_chain_anchor (chain, last_pruned_id, last_pruned_hash, pruned_at) VALUES ('core_audit', ?, ?, '2026-11-09T11:00:00.000Z')", all[1]["id"], pruned)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	info, rows := e.export(time.Time{}, time.Time{})
	if len(rows) != 2 || info.AnchorKind != "pruned" || !info.Complete || info.Count != 2 || *info.Anchor != pruned {
		t.Fatalf("info = %+v rows = %d", info, len(rows))
	}
	if res := verify(t, pruned, rows); !res.OK || res.Count != 2 {
		t.Fatalf("verify from last_pruned_hash: %+v", res)
	}
}

func TestDeletingTheNewestRowShowsInHeadHashAndCount(t *testing.T) {
	t.Parallel()
	e := newChainEnv(t, at(0), at(1), at(2), at(3))
	_, before := e.export(time.Time{}, time.Time{})
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{"DROP TRIGGER core_audit_no_delete", "DELETE FROM core_audit WHERE seq = 4"} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	info, rows := e.export(time.Time{}, time.Time{})
	if len(rows) != 3 || info.Complete {
		t.Fatalf("a log with its newest row removed is complete: %+v", info)
	}
	// What the file says: the head the box recorded is not the last row, and the count is one more than the rows.
	if info.Count != 4 || info.HeadHash == nil || *info.HeadHash != before[3]["hash"] || *info.HeadHash == rows[2]["hash"] {
		t.Fatalf("info = %+v", info)
	}
	// The remaining rows still verify on their own: only head_hash and count give the cut away.
	if res := verify(t, chain.Genesis, rows); !res.OK {
		t.Fatalf("verify = %+v", res)
	}
}

// The rows of a range are one run of seq: from the first row at or after from to the last at or before to. A row whose
// clock stepped back inside that run is kept, so the run still links.
func TestARangeIsOneRunOfSeqEvenWhenAClockSteppedBack(t *testing.T) {
	t.Parallel()
	e := newChainEnv(t, at(0), at(3), at(1), at(4)) // the third row is stamped before the second
	info, rows := e.export(at(2), at(3).Add(30*time.Second))
	var got []string
	for _, r := range rows {
		got = append(got, r["target"].(string))
	}
	if strings.Join(got, ",") != "r1,r2" {
		t.Fatalf("rows = %v, want r1,r2 (r2 is before from by its time, inside the run by its place)", got)
	}
	if res := verify(t, *info.Anchor, rows); !res.OK {
		t.Fatalf("verify = %+v", res)
	}
}

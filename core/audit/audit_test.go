package audit_test

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

const coreMigrations = "../../modules/core/migrations/sqlite"

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 9, 1, 2, 3, 456_000_000, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func appendAll(t *testing.T, db *store.DB, l *audit.Log, entries ...audit.Entry) {
	t.Helper()
	for _, e := range entries {
		if err := db.Write(t.Context(), func(tx *sql.Tx) error { return l.Append(t.Context(), tx, e) }); err != nil {
			t.Fatalf("Append(%+v): %v", e, err)
		}
	}
}

func TestAppendVerify(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(fixedClock())
	ctx := t.Context()

	if res, err := audit.Verify(ctx, db.Reader()); err != nil || !res.OK || res.Count != 0 {
		t.Fatalf("empty chain: %+v, %v", res, err)
	}
	appendAll(t, db, l,
		audit.Entry{User: "admin@acme.example", Action: "module.enable", Target: "feeds", Detail: "with dependencies <a&b> \u2028 \"quoted\" \\ Vietnamese: Máy chủ 😀"},
		audit.Entry{User: "system", Action: "auth.login", Target: "it@acme.example"},
		audit.Entry{User: "admin@acme.example", Action: "core.settings-change", Target: "general"},
	)

	rows, err := db.Reader().QueryContext(ctx, "SELECT seq, id, prev_hash, hash, ts, detail FROM core_audit ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	prev := chain.Genesis
	n := 0
	for rows.Next() {
		var seq int
		var id, p, h, ts string
		var detail sql.NullString
		if err := rows.Scan(&seq, &id, &p, &h, &ts, &detail); err != nil {
			t.Fatal(err)
		}
		n++
		if seq != n || p != prev || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h) {
			t.Errorf("row %d: seq=%d prev=%s hash=%s", n, seq, p, h)
		}
		if !regexp.MustCompile(`^au-[a-z2-7]{26}$`).MatchString(id) || !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`).MatchString(ts) {
			t.Errorf("row %d: id=%s ts=%s", n, id, ts)
		}
		if n == 2 && detail.Valid {
			t.Errorf("empty detail stored as %q, want NULL", detail.String)
		}
		prev = h
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("rows = %d", n)
	}
	if res, err := audit.Verify(ctx, db.Reader()); err != nil || res != (chain.Result{OK: true, Count: 3}) {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
}

// The preimage is fixed by D-57 (14): SHA-256(prev + "\n" + canon(row without hash/seq)), NULL as null.
func TestAppendHashMatchesSpec(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	appendAll(t, db, audit.New(fixedClock()),
		audit.Entry{User: "a@b.example", Action: "x.y", Target: "t", Detail: "d"},
		audit.Entry{User: "a@b.example", Action: "x.y", Target: "t"},
	)
	type row struct{ id, prev, hash, ts string }
	var rs []row
	rows, err := db.Reader().QueryContext(t.Context(), "SELECT id, prev_hash, hash, ts FROM core_audit ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.prev, &r.hash, &r.ts); err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	want0, _ := chain.HashCanonical(chain.Genesis, map[string]any{"id": rs[0].id, "ts": rs[0].ts, "user": "a@b.example", "action": "x.y", "target": "t", "detail": "d"})
	want1, _ := chain.HashCanonical(rs[0].hash, map[string]any{"id": rs[1].id, "ts": rs[1].ts, "user": "a@b.example", "action": "x.y", "target": "t", "detail": nil})
	if rs[0].hash != want0 || rs[1].hash != want1 || rs[1].prev != rs[0].hash {
		t.Fatalf("hashes do not match the spec preimage:\n%v\nwant %s %s", rs, want0, want1)
	}
	if rs[0].ts != "2026-11-09T01:02:04.456Z" {
		t.Errorf("ts = %s, want the injected clock", rs[0].ts)
	}
}

func TestAppendValidation(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(nil)
	ok := audit.Entry{User: "a@b.example", Action: "module.enable", Target: "feeds"}
	with := func(f func(*audit.Entry)) audit.Entry { e := ok; f(&e); return e }

	tests := []struct {
		name string
		e    audit.Entry
		ok   bool
	}{
		{"valid", ok, true},
		{"detail at max (2000 chars)", with(func(e *audit.Entry) { e.Detail = strings.Repeat("é", 2000) }), true},
		{"detail too long", with(func(e *audit.Entry) { e.Detail = strings.Repeat("é", 2001) }), false},
		{"detail NUL", with(func(e *audit.Entry) { e.Detail = "a\x00b" }), false},
		{"detail invalid UTF-8", with(func(e *audit.Entry) { e.Detail = "a\xffb" }), false},
		{"empty user", with(func(e *audit.Entry) { e.User = "" }), false},
		{"user NUL", with(func(e *audit.Entry) { e.User = "a\x00" }), false},
		{"empty target", with(func(e *audit.Entry) { e.Target = "" }), false},
		{"target NUL", with(func(e *audit.Entry) { e.Target = "a\x00" }), false},
		{"action without dot", with(func(e *audit.Entry) { e.Action = "enable" }), false},
		{"action uppercase", with(func(e *audit.Entry) { e.Action = "Module.enable" }), false},
		{"action with space", with(func(e *audit.Entry) { e.Action = "module.en able" }), false},
		{"action empty group", with(func(e *audit.Entry) { e.Action = ".enable" }), false},
		{"action dotted verb", with(func(e *audit.Entry) { e.Action = "update.os.reboot-cancel" }), true},
		{"action empty", with(func(e *audit.Entry) { e.Action = "" }), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Write(t.Context(), func(tx *sql.Tx) error { return l.Append(t.Context(), tx, tc.e) })
			if tc.ok && err != nil {
				t.Fatalf("err = %v", err)
			}
			if !tc.ok && !errors.Is(err, audit.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAppendRollsBackWithCaller(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(nil)
	sentinel := errors.New("caller failed after audit")
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		if err := l.Append(t.Context(), tx, audit.Entry{User: "system", Action: "a.b", Target: "t"}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	var n int
	if err := db.Reader().QueryRowContext(t.Context(), "SELECT count(*) FROM core_audit").Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows after rollback = %d, %v", n, err)
	}
}

// Tampering is only possible by bypassing the append-only triggers (what an attacker with the DB file can do).
func TestVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	seed := func(t *testing.T) *store.DB {
		db := storetest.NewMigrated(t, "core", coreMigrations)
		var es []audit.Entry
		for range 5 {
			es = append(es, audit.Entry{User: "system", Action: "a.b", Target: "t", Detail: "row"})
		}
		appendAll(t, db, audit.New(nil), es...)
		return db
	}
	// Run raw SQL with the triggers dropped, as someone editing the file directly would.
	tamper := func(t *testing.T, db *store.DB, stmts ...string) {
		t.Helper()
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			for _, s := range append([]string{"DROP TRIGGER core_audit_no_update", "DROP TRIGGER core_audit_no_delete"}, stmts...) {
				if _, err := tx.ExecContext(t.Context(), s); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		stmts []string
		want  chain.Result
	}{
		{"edited column", []string{"UPDATE core_audit SET target = 'other' WHERE seq = 3"}, chain.Result{Count: 5, BrokenAt: 3}},
		{"detail nulled", []string{"UPDATE core_audit SET detail = NULL WHERE seq = 2"}, chain.Result{Count: 5, BrokenAt: 2}},
		{"deleted middle row", []string{"DELETE FROM core_audit WHERE seq = 3"}, chain.Result{Count: 4, BrokenAt: 3}},
		{"deleted first row", []string{"DELETE FROM core_audit WHERE seq = 1"}, chain.Result{Count: 4, BrokenAt: 1}},
		{"hash rewritten but chain not", []string{"UPDATE core_audit SET hash = '" + strings.Repeat("a", 64) + "' WHERE seq = 4"}, chain.Result{Count: 5, BrokenAt: 4}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := seed(t)
			tamper(t, db, tc.stmts...)
			res, err := audit.Verify(t.Context(), db.Reader())
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || res.Count != tc.want.Count || res.BrokenAt != tc.want.BrokenAt || res.EntryID == "" {
				t.Fatalf("Verify = %+v, want %+v", res, tc.want)
			}
		})
	}
}

func TestAnchor(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(nil)
	anchorHash := strings.Repeat("ab", 32)
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "INSERT INTO core_chain_anchor (chain, last_pruned_id, last_pruned_hash, pruned_at) VALUES ('core_audit', 'au-x', ?, '2026-01-01T00:00:00.000Z')", anchorHash)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, db, l, audit.Entry{User: "system", Action: "a.b", Target: "t"}, audit.Entry{User: "system", Action: "a.b", Target: "t"})
	var prev string
	if err := db.Reader().QueryRowContext(t.Context(), "SELECT prev_hash FROM core_audit WHERE seq = 1").Scan(&prev); err != nil || prev != anchorHash {
		t.Fatalf("first prev = %q (%v), want the anchor hash", prev, err)
	}
	if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || !res.OK || res.Count != 2 {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
}

func TestVerifyPagination(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(nil)
	const n = 1203 // more than two pages
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		for range n {
			if err := l.Append(t.Context(), tx, audit.Entry{User: "system", Action: "a.b", Target: "t"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || !res.OK || res.Count != n {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
}

func TestConcurrentAppendsKeepOneChain(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(nil)
	done := make(chan error, 20)
	for range 20 {
		go func() {
			done <- db.Write(t.Context(), func(tx *sql.Tx) error {
				return l.Append(t.Context(), tx, audit.Entry{User: "system", Action: "a.b", Target: "t"})
			})
		}()
	}
	for range 20 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || !res.OK || res.Count != 20 {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
}

// One read transaction: rows appended while Verify is between pages are not seen.
func TestVerifyUsesOneSnapshot(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	l := audit.New(nil)
	ctx := t.Context()
	const n = 25
	err := db.Write(ctx, func(tx *sql.Tx) error {
		for range n {
			if err := l.Append(ctx, tx, audit.Entry{User: "system", Action: "a.b", Target: "t"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pages := 0
	res, err := audit.VerifyPaged(ctx, db.Reader(), 10, func() {
		pages++
		if pages == 1 { // a commit lands between page 1 and page 2
			appendAll(t, db, l, audit.Entry{User: "system", Action: "a.b", Target: "late"})
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != n {
		t.Fatalf("Verify = %+v, want ok with the %d rows of the snapshot", res, n)
	}
	// A fresh Verify sees the new row.
	if res, err := audit.Verify(ctx, db.Reader()); err != nil || !res.OK || res.Count != n+1 {
		t.Fatalf("later Verify = %+v, %v", res, err)
	}
}

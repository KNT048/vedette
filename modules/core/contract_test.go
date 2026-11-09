package core_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain"
	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// The test binary doubles as the helper process for the exec contract (the Runner clears the environment).
const helperArg = "__helper__"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperArg {
		if os.Args[2] == "echo" {
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[3:])
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func migrated(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	return db
}

func count(t *testing.T, db *store.DB, query string) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(t.Context(), query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// POST-3: the audit row is written in the caller's transaction; an audit error rolls the caller's change back,
// and a caller error rolls the audit row back.
func TestContract_POST3_AuditSharesCallerTransaction(t *testing.T) {
	t.Parallel()
	secretStore, err := secrets.New(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New(nil)
	good := audit.Entry{User: "admin@acme.example", Action: "core.secret-set", Target: "feeds_source"}

	t.Run("audit failure rolls back the caller's write", func(t *testing.T) {
		t.Parallel()
		db := migrated(t)
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			if _, _, err := secretStore.Seal(t.Context(), tx, "feeds_source.secret", []byte("a-business-change"), false); err != nil {
				return err
			}
			bad := good
			bad.Action = "NOT VALID"
			return log.Append(t.Context(), tx, bad)
		})
		if !errors.Is(err, audit.ErrInvalid) {
			t.Fatalf("err = %v, want audit.ErrInvalid", err)
		}
		if n := count(t, db, "SELECT count(*) FROM core_secret"); n != 0 {
			t.Fatalf("caller's write survived an audit failure: %d secret rows", n)
		}
	})
	t.Run("database-level audit failure rolls back the caller's write", func(t *testing.T) {
		t.Parallel()
		db := migrated(t)
		fixed := audit.New(nil)
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			if _, _, err := secretStore.Seal(t.Context(), tx, "feeds_source.secret", []byte("a-business-change"), false); err != nil {
				return err
			}
			if err := fixed.Append(t.Context(), tx, good); err != nil {
				return err
			}
			// Make the next insert fail inside the database itself (not in application validation).
			if _, err := tx.ExecContext(t.Context(), "CREATE TRIGGER core_audit_test_block BEFORE INSERT ON core_audit BEGIN SELECT RAISE(ABORT, 'blocked'); END"); err != nil {
				return err
			}
			return fixed.Append(t.Context(), tx, good)
		})
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("err = %v, want the database failure", err)
		}
		if n := count(t, db, "SELECT count(*) FROM core_secret") + count(t, db, "SELECT count(*) FROM core_audit"); n != 0 {
			t.Fatalf("rows survived the rollback: %d", n)
		}
	})
	t.Run("caller failure rolls back the audit row", func(t *testing.T) {
		t.Parallel()
		db := migrated(t)
		sentinel := errors.New("handler failed after auditing")
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			if err := log.Append(t.Context(), tx, good); err != nil {
				return err
			}
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
		if n := count(t, db, "SELECT count(*) FROM core_audit"); n != 0 {
			t.Fatalf("audit row survived a caller failure: %d", n)
		}
	})
	t.Run("both commit together", func(t *testing.T) {
		t.Parallel()
		db := migrated(t)
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			if _, _, err := secretStore.Seal(t.Context(), tx, "feeds_source.secret", []byte("a-business-change"), false); err != nil {
				return err
			}
			return log.Append(t.Context(), tx, good)
		})
		if err != nil {
			t.Fatal(err)
		}
		if a, s := count(t, db, "SELECT count(*) FROM core_audit"), count(t, db, "SELECT count(*) FROM core_secret"); a != 1 || s != 1 {
			t.Fatalf("audit rows %d, secret rows %d", a, s)
		}
		if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || !res.OK || res.Count != 1 {
			t.Fatalf("Verify = %+v, %v", res, err)
		}
	})
}

// INV-2 (partial): core_audit accepts inserts only. UPDATE and DELETE are refused by the database itself.
func TestContract_INV2_AuditIsAppendOnly(t *testing.T) {
	t.Parallel()
	db := migrated(t)
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		return audit.New(nil).Append(t.Context(), tx, audit.Entry{User: "system", Action: "core.test", Target: "t", Detail: "keep me"})
	})
	if err != nil {
		t.Fatal(err)
	}
	h64 := strings.Repeat("c", 64)
	for _, stmt := range []string{
		"UPDATE core_audit SET detail = 'changed'",
		"UPDATE core_audit SET hash = '" + strings.Repeat("0", 64) + "'",
		"UPDATE core_audit SET seq = seq + 10",
		"DELETE FROM core_audit",
		"DELETE FROM core_audit WHERE seq = 1",
		// REPLACE removes the conflicting row without firing DELETE triggers; UPSERT rewrites it.
		"REPLACE INTO core_audit (seq, id, prev_hash, hash, ts, user, action, target) VALUES (1, 'au-x', '" + h64 + "', '" + h64 + "', '2026-01-01T00:00:00.000Z', 'system', 'a.b', 't')",
		"INSERT OR REPLACE INTO core_audit (id, prev_hash, hash, ts, user, action, target) SELECT id, prev_hash, '" + h64 + "', ts, user, action, target FROM core_audit",
		"INSERT OR REPLACE INTO core_audit (id, prev_hash, hash, ts, user, action, target) SELECT 'au-other', prev_hash, hash, ts, user, action, target FROM core_audit",
		"INSERT OR REPLACE INTO core_audit (seq, id, prev_hash, hash, ts, user, action, target) SELECT seq, 'au-new', prev_hash, '" + h64 + "', ts, user, action, target FROM core_audit",
		"INSERT OR IGNORE INTO core_audit (id, prev_hash, hash, ts, user, action, target) SELECT id, prev_hash, hash, ts, user, action, target FROM core_audit",
		"INSERT INTO core_audit (id, prev_hash, hash, ts, user, action, target, detail) SELECT id, prev_hash, hash, ts, user, action, target, 'x' FROM core_audit WHERE true ON CONFLICT (id) DO UPDATE SET detail = 'upserted'",
		"INSERT INTO core_audit (id, prev_hash, hash, ts, user, action, target, detail) SELECT 'au-new2', prev_hash, hash, ts, user, action, target, 'x' FROM core_audit WHERE true ON CONFLICT (hash) DO UPDATE SET detail = 'upserted'",
		"INSERT INTO core_audit (id, prev_hash, hash, ts, user, action, target) SELECT id, prev_hash, hash, ts, user, action, target FROM core_audit WHERE true ON CONFLICT DO NOTHING",
	} {
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), stmt)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%q: err = %v, want an append-only refusal", stmt, err)
		}
	}
	if n := count(t, db, "SELECT count(*) FROM core_audit WHERE detail = 'keep me'"); n != 1 {
		t.Fatalf("row changed or vanished despite the refusals (%d)", n)
	}
	if n := count(t, db, "SELECT count(*) FROM core_audit"); n != 1 {
		t.Fatalf("row count = %d, want 1", n)
	}
	// Control: a normal append still works with the replace guard in place.
	err = db.Write(t.Context(), func(tx *sql.Tx) error {
		return audit.New(nil).Append(t.Context(), tx, audit.Entry{User: "system", Action: "core.test", Target: "t2"})
	})
	if err != nil {
		t.Fatalf("append after the guards: %v", err)
	}
	if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || !res.OK {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
	// Database level, not application level: the reader pool is read-only too.
	if _, err := db.Reader().ExecContext(t.Context(), "DELETE FROM core_audit"); err == nil {
		t.Error("reader pool accepted a DELETE")
	}
}

// PRE-4 / POST-4: allowlist, argv array without a shell, bounded output, mandatory timeout.
func TestContract_POST4_ExecIsBounded(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, err := vexec.NewRunner(slog.New(slog.DiscardHandler), vexec.Binary{
		Name: "helper", Path: self, MaxOutput: 64,
		Validate: func(args []string) error {
			if len(args) < 2 || args[0] != helperArg || args[1] != "echo" {
				return errors.New("only the echo helper is allowed")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	if _, err := r.Run(ctx, "sh", []string{"-c", "id"}, nil); !errors.Is(err, vexec.ErrNotAllowed) {
		t.Errorf("binary outside the allowlist: err = %v", err)
	}
	if _, err := r.Run(t.Context(), "helper", []string{helperArg, "echo"}, nil); !errors.Is(err, vexec.ErrNoDeadline) {
		t.Errorf("run without deadline: err = %v", err)
	}
	if _, err := r.Run(ctx, "helper", []string{"--anything"}, nil); !errors.Is(err, vexec.ErrBadArgs) {
		t.Errorf("argv the validator rejects: err = %v", err)
	}
	res, err := r.Run(ctx, "helper", []string{helperArg, "echo", "$(id); rm -rf /", "`id`"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := `["$(id); rm -rf /","` + "`id`" + `"]`; strings.TrimSpace(string(res.Stdout)) != want {
		t.Errorf("shell metacharacters were interpreted: %q", res.Stdout)
	}
	res, err = r.Run(ctx, "helper", []string{helperArg, "echo", strings.Repeat("y", 500)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 64 || !res.Truncated {
		t.Errorf("output not bounded: %d bytes, truncated=%v", len(res.Stdout), res.Truncated)
	}
}

// INV-6 (partial): no core column holds a plaintext secret. Allowed names are references and one-way
// values: secret_id, *_hash (token_hash, password_hash, code_hash), *_last4, *_id.
func TestContract_INV6_NoPlaintextSecretColumns(t *testing.T) {
	t.Parallel()
	db := migrated(t)
	rows, err := db.Reader().QueryContext(t.Context(),
		"SELECT m.name, p.name, p.type FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type = 'table' AND m.name LIKE 'core\\_%' ESCAPE '\\' ORDER BY 1, p.cid")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	risky := regexp.MustCompile(`(?i)password|secret|token|api_key|private_key`)
	safeSuffix := regexp.MustCompile(`(_hash|_last4|_id)$`)
	seen := 0
	for rows.Next() {
		var table, col, typ string
		if err := rows.Scan(&table, &col, &typ); err != nil {
			t.Fatal(err)
		}
		seen++
		if risky.MatchString(col) && !safeSuffix.MatchString(col) {
			t.Errorf("%s.%s (%s) looks like a plaintext secret column", table, col, typ)
		}
		if table == "core_secret" && col == "ciphertext" && !strings.EqualFold(typ, "BLOB") {
			t.Errorf("core_secret.ciphertext is %s, want BLOB", typ)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("no core tables found")
	}
	// The scan itself must be able to fail: a name like api_key is flagged.
	for _, bad := range []string{"password", "client_secret", "api_key", "private_key", "token"} {
		if !risky.MatchString(bad) || safeSuffix.MatchString(bad) {
			t.Errorf("scan would miss %q", bad)
		}
	}
	for _, ok := range []string{"secret_id", "token_hash", "password_hash", "last4", "key_last4", "code_hash"} {
		if risky.MatchString(ok) && !safeSuffix.MatchString(ok) {
			t.Errorf("scan would wrongly flag %q", ok)
		}
	}
}

// Migrations: core_ prefix only, forward-only, idempotent, and verified by effect.
func TestContract_Migrations(t *testing.T) {
	t.Parallel()
	t.Run("only core_ objects", func(t *testing.T) {
		t.Parallel()
		storetest.AssertMigrationsUsePrefix(t, "core", core.Migrations, "core_")
	})
	t.Run("forward-only", func(t *testing.T) {
		t.Parallel()
		down := regexp.MustCompile(`(?mi)^\s*--\s*\+goose\s+down\b`)
		n := 0
		err := fs.WalkDir(core.Migrations, ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			n++
			b, err := fs.ReadFile(core.Migrations, name)
			if err != nil {
				return err
			}
			if down.Match(b) {
				t.Errorf("%s has a Down section", name)
			}
			if !regexp.MustCompile(`^\d{4}_[a-z0-9_]+\.sql$`).MatchString(name) {
				t.Errorf("migration file name %q does not match NNNN_description.sql", name)
			}
			return nil
		})
		if err != nil || n == 0 {
			t.Fatalf("scan: %v (%d files)", err, n)
		}
	})
	t.Run("idempotent and effective", func(t *testing.T) {
		t.Parallel()
		db := storetest.New(t)
		snapshot := func() string {
			rows, err := db.Reader().QueryContext(t.Context(), "SELECT type, name, sql FROM sqlite_master ORDER BY 1, 2")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rows.Close() }()
			var b strings.Builder
			for rows.Next() {
				var typ, name string
				var s sql.NullString
				if err := rows.Scan(&typ, &name, &s); err != nil {
					t.Fatal(err)
				}
				b.WriteString(typ + "|" + name + "|" + s.String + "\n")
			}
			return b.String()
		}
		for range 2 {
			if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
				t.Fatal(err)
			}
		}
		after := snapshot()
		if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
			t.Fatal(err)
		}
		if snapshot() != after {
			t.Fatal("schema changed on a repeat run")
		}
		// Effects, not exit codes: objects exist and the version table records the file once.
		for _, want := range []string{
			"table|core_secret|", "table|core_audit|", "table|core_chain_anchor|", "index|core_audit_ts_idx|",
			"trigger|core_audit_no_update|", "trigger|core_audit_no_delete|", "table|core_migration_core|",
			"table|core_module|", "table|core_job_run|", "index|core_job_run_job_idx|",
		} {
			if !strings.Contains(after, want) {
				t.Errorf("schema lacks %s", want)
			}
		}
		for _, v := range []int{1, 2} {
			if n := count(t, db, fmt.Sprintf("SELECT count(*) FROM core_migration_core WHERE version_id = %d AND is_applied = 1", v)); n != 1 {
				t.Errorf("version rows for %04d = %d, want 1", v, n)
			}
		}
		if err := db.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// The chain primitives used by core_audit agree with the documented preimage (DATA_MODEL 5.3):
// hash = SHA-256(prev + canonical JSON of the row without hash/seq).
func TestContract_AuditHashPreimage(t *testing.T) {
	t.Parallel()
	db := migrated(t)
	clock := func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) }
	l := audit.New(clock)
	for _, e := range []audit.Entry{
		{User: "admin@acme.example", Action: "module.enable", Target: "feeds", Detail: "x"},
		{User: "system", Action: "auth.login", Target: "it@acme.example"}, // detail NULL: hashed as null
	} {
		err := db.Write(t.Context(), func(tx *sql.Tx) error { return l.Append(t.Context(), tx, e) })
		if err != nil {
			t.Fatal(err)
		}
	}
	prev := chain.Genesis
	rows, err := db.Reader().QueryContext(t.Context(), "SELECT id, prev_hash, hash, ts, user, action, target, detail FROM core_audit ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var id, p, hash, ts, user, action, target string
		var detail sql.NullString
		if err := rows.Scan(&id, &p, &hash, &ts, &user, &action, &target, &detail); err != nil {
			t.Fatal(err)
		}
		var d any
		if detail.Valid {
			d = detail.String
		}
		entry := map[string]any{"id": id, "ts": ts, "user": user, "action": action, "target": target, "detail": d, "prev_hash": p}
		canon, err := chain.Canon(entry)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(prev + "\n" + string(canon)))
		if p != prev || hash != hex.EncodeToString(h[:]) {
			t.Fatalf("row %d: hash %s does not match SHA-256(prev + \"\\n\" + canon(row)) over %s", n+1, hash, canon)
		}
		if n == 1 && !strings.Contains(string(canon), `"detail":null`) {
			t.Fatalf("NULL detail not hashed as null: %s", canon)
		}
		prev = hash
		n++
	}
	if err := rows.Err(); err != nil || n != 2 {
		t.Fatalf("rows = %d, %v", n, err)
	}
}

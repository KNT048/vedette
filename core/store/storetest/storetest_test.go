package storetest_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store/storetest"
)

// fakeTB records failures instead of failing the real test. Everything else (TempDir, Context,
// Cleanup) goes to the real test.
type fakeTB struct {
	testing.TB
	msgs []string
}

func (f *fakeTB) Helper()                        {}
func (f *fakeTB) Errorf(format string, a ...any) { f.msgs = append(f.msgs, fmt.Sprintf(format, a...)) }
func (f *fakeTB) Fatalf(format string, a ...any) { f.Errorf(format, a...); runtime.Goexit() }

// run returns what the assertion reported.
func run(t *testing.T, module, sql, prefix string, base ...storetest.Migration) string {
	t.Helper()
	f := &fakeTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		storetest.AssertMigrationsUsePrefix(f, module, fstest.MapFS{"0001_x.sql": {Data: []byte("-- +goose Up\n" + sql)}}, prefix, base...)
	}()
	<-done
	return strings.Join(f.msgs, "\n")
}

// A stand-in for core's migrations: tables other modules must not touch, with rows in them.
var core = storetest.Migration{Module: "core", FS: fstest.MapFS{"0001_core.sql": {Data: []byte(`-- +goose Up
CREATE TABLE core_user (id TEXT PRIMARY KEY, email TEXT);
CREATE TABLE core_secret (id TEXT PRIMARY KEY);
CREATE TABLE core_module (id TEXT PRIMARY KEY);
CREATE TABLE core_audit (id TEXT PRIMARY KEY);
INSERT INTO core_secret VALUES ('sec-1');
INSERT INTO core_module VALUES ('feeds');
`)}}}

func TestAssertMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		sql     string
		wantMsg string // "" = must pass; otherwise the failure must mention it
	}{
		{"all prefixed", "CREATE TABLE feeds_a (x TEXT);\nCREATE UNIQUE INDEX feeds_a_ix ON feeds_a(x);\nCREATE TRIGGER feeds_a_t BEFORE DELETE ON feeds_a BEGIN SELECT 1; END;\nCREATE VIEW feeds_v AS SELECT 1;", ""},
		{"own seed rows and own alter", "CREATE TABLE feeds_a (x TEXT);\nINSERT INTO feeds_a VALUES ('seed');\nALTER TABLE feeds_a ADD COLUMN y TEXT;", ""},
		{"if not exists and quotes", `CREATE TABLE IF NOT EXISTS "feeds_a" (x);`, ""},
		{"table without prefix", "CREATE TABLE other (x);", "other"},
		{"index without prefix", "CREATE TABLE feeds_a (x);\nCREATE INDEX ix ON feeds_a(x);", `"ix"`},
		{"trigger without prefix", "CREATE TABLE feeds_a (x);\nCREATE TRIGGER trg BEFORE DELETE ON feeds_a BEGIN SELECT 1; END;", `"trg"`},
		{"view without prefix", "CREATE VIEW v AS SELECT 1;", `"v"`},
		{"virtual table (fts5) with shadow tables", "CREATE VIRTUAL TABLE other_fts USING fts5(body);", "other_fts"},
		{"prefixed trigger on a core table whose body deletes from core_secret", "CREATE TABLE feeds_a (x);\nCREATE TRIGGER feeds_t AFTER INSERT ON core_audit BEGIN DELETE FROM core_secret; END;", `"core_audit"`},
		{"prefixed index on a core table", "CREATE INDEX feeds_ix ON core_user(email);", `"core_user"`},
		{"rename into core_ namespace", "CREATE TABLE feeds_a (x);\nALTER TABLE feeds_a RENAME TO core_extra;", "core_extra"},
		{"insert into another module's table", "CREATE TABLE feeds_a (x);\nINSERT INTO core_module VALUES ('evil');", `"core_module"`},
		{"delete from another module's table", "CREATE TABLE feeds_a (x);\nDELETE FROM core_secret;", `"core_secret"`},
		{"drop another module's table", "CREATE TABLE feeds_a (x);\nDROP TABLE core_user;", "core_user"},
		{"string literal that looks like a comment hides a statement", "CREATE TABLE feeds_a (x TEXT DEFAULT '--');\nCREATE TABLE evil (y);", "evil"},
		{"block comment lookalike in a literal", "CREATE TABLE feeds_a (x TEXT DEFAULT '/*');\nCREATE TABLE evil2 (y);\n-- */", "evil2"},
		{"no objects at all", "SELECT 1;", "created nothing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := run(t, "feeds", tc.sql, "feeds_", core)
			switch {
			case tc.wantMsg == "" && got != "":
				t.Fatalf("expected pass, got: %s", got)
			case tc.wantMsg != "" && !strings.Contains(got, tc.wantMsg):
				t.Fatalf("expected a failure mentioning %q, got: %q", tc.wantMsg, got)
			}
		})
	}
}

func TestAssertMigrationsUsePrefixForTheBaseModuleItself(t *testing.T) {
	t.Parallel()
	if got := run(t, "core", "CREATE TABLE core_a (x);\nCREATE INDEX core_a_ix ON core_a(x);", "core_"); got != "" {
		t.Fatalf("expected pass, got: %s", got)
	}
	if got := run(t, "core", "CREATE TABLE core_a (x);\nCREATE TABLE nope (x);", "core_"); !strings.Contains(got, "nope") {
		t.Fatalf("expected a failure naming nope, got: %q", got)
	}
}

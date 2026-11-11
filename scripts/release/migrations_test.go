package main

import (
	"os"
	"os/exec" //nolint:depguard // test of a release tool outside the product: fixed argv (git), no shell
	"path/filepath"
	"strings"
	"testing"
)

func up(body string) []byte {
	return []byte("-- +goose Up\n" + body + "\n-- +goose Down\nDROP TABLE nothing;\n")
}

// Each fixture is the Up section of a migration and what the guard must say.
func TestClassifyUp(t *testing.T) {
	t.Parallel()
	trig := "-- +goose StatementBegin\nCREATE TRIGGER %s AFTER INSERT ON %s BEGIN\n  UPDATE %s SET n = n + 1;\nEND;\n-- +goose StatementEnd\n"
	cases := []struct {
		name, sql string
		want      string // "" = add-only, else a substring of the first reason
	}{
		// add-only
		{"create table and index", "CREATE TABLE a (id INTEGER PRIMARY KEY, n INT NOT NULL DEFAULT 0);\nCREATE INDEX a_n ON a(n);", ""},
		{"if not exists, quoted names, schema", "CREATE TABLE IF NOT EXISTS main.\"a\" (id INT);\nCREATE INDEX IF NOT EXISTS \"a_i\" ON `a`(id);", ""},
		{"alter add column", "ALTER TABLE old ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;", ""},
		{"plain index on an old table, partial index, collation and order", "CREATE INDEX i1 ON old(a, b DESC);\nCREATE INDEX i2 ON old(a COLLATE NOCASE) WHERE a IS NOT NULL;", ""},
		{"foreign key to a table made here", "CREATE TABLE p (id INT PRIMARY KEY);\nCREATE TABLE c (id INT, p INT REFERENCES p(id));", ""},
		{"foreign key to itself", "CREATE TABLE t (id INT PRIMARY KEY, parent INT REFERENCES t(id));", ""},
		{"foreign key to an old table that cascades", "CREATE TABLE c (id INT, u TEXT REFERENCES core_user(id) ON UPDATE NO ACTION ON DELETE CASCADE, v INT);", ""},
		{"foreign key to an old table that nulls (table constraint)", "CREATE TABLE c (id INT, u TEXT, FOREIGN KEY (u) REFERENCES core_user(id) ON DELETE SET NULL);", ""},
		{"trigger first, seed of another new table", "CREATE TABLE a (id INT, n INT);\nCREATE TABLE b (id INT);\n" + strings.ReplaceAll(strings.Replace(trig, "%s", "a_t", 1), "%s", "a") + "INSERT INTO b VALUES (1);", ""},
		{"seed before the trigger exists", "CREATE TABLE a (id INT, n INT);\nINSERT INTO a VALUES (1, 0);\n" + strings.ReplaceAll(strings.Replace(trig, "%s", "a_t", 1), "%s", "a"), ""},
		{"unique index on a table made here", "CREATE TABLE a (id INT, k TEXT);\nCREATE UNIQUE INDEX a_k ON a(k);", ""},
		{"seed rows of a table made here", "CREATE TABLE a (id INT, v TEXT);\nINSERT INTO a (id, v) VALUES (1, 'x;y -- not a comment'), (2, 'it''s');", ""},
		{"insert select from an old table into a new one", "CREATE TABLE vol (id INT, b INT);\nINSERT INTO vol SELECT 1, sum(length(line)) FROM old_events;", ""},
		{"update and delete of a table made here", "CREATE TABLE a (id INT, n INT);\nUPDATE a SET n = 1;\nDELETE FROM a WHERE id = 3;", ""},
		{"view", "CREATE VIEW v AS SELECT 1 AS x;", ""},
		{"trigger on a table made here", "CREATE TABLE a (id INT, n INT);\n" + strings.ReplaceAll(strings.Replace(trig, "%s", "a_t", 1), "%s", "a"), ""},
		{"comments with semicolons, quotes, and goose-like text", "-- note; it's -- fine\n/* block; 'x */\nCREATE TABLE a (\n  c INT -- +1 on change; it's a comment\n);", ""},
		{"trigger body with CASE", "CREATE TABLE a (id INT, n INT);\n-- +goose StatementBegin\nCREATE TRIGGER t AFTER INSERT ON a BEGIN\n UPDATE a SET n = CASE WHEN n > 1 THEN 1 ELSE 0 END;\nEND;\n-- +goose StatementEnd", ""},
		{"no statements", "-- nothing to do", ""},
		{"notransaction", "-- +goose NO TRANSACTION\nCREATE TABLE a (id INT);", ""},
		// not add-only
		{"drop table", "DROP TABLE resp_tokens;", "cannot classify"},
		{"drop index", "DROP INDEX i;", "cannot classify"},
		{"drop then create", "DROP TABLE t;\nCREATE TABLE t (id INT);", "DROP TABLE"},
		{"rename table", "ALTER TABLE a RENAME TO b;", "cannot classify"},
		{"rename column", "ALTER TABLE a RENAME COLUMN x TO y;", "cannot classify"},
		{"drop column", "ALTER TABLE a DROP COLUMN x;", "cannot classify"},
		{"add without COLUMN keyword", "ALTER TABLE a ADD CONSTRAINT c CHECK (1);", "cannot classify"},
		{"update of an existing table", "UPDATE core_user SET admin = 0;", "UPDATE of a table"},
		{"delete from an existing table", "DELETE FROM core_user;", "DELETE of a table"},
		{"insert into an existing table", "INSERT INTO core_module (id) VALUES ('x');", "INSERT of a table"},
		{"insert into another schema's table of the same name", "CREATE TABLE a (id INT);\nINSERT INTO temp.a VALUES (1);", "INSERT of a table"},
		// M1: only a plain CREATE TABLE of the main schema proves a table is new
		{"IF NOT EXISTS does not make a table new: delete", "CREATE TABLE IF NOT EXISTS core_user (id INT);\nDELETE FROM core_user;", "DELETE of a table"},
		{"IF NOT EXISTS does not make a table new: update", "CREATE TABLE IF NOT EXISTS core_user (id INT);\nUPDATE core_user SET id = 1;", "UPDATE of a table"},
		{"IF NOT EXISTS does not make a table new: unique index", "CREATE TABLE IF NOT EXISTS core_user (email TEXT);\nCREATE UNIQUE INDEX u ON core_user(email);", "UNIQUE index"},
		{"IF NOT EXISTS does not make a table new: trigger", "CREATE TABLE IF NOT EXISTS core_user (id INT);\n" + strings.ReplaceAll(strings.Replace(trig, "%s", "t", 1), "%s", "core_user"), "trigger on a table"},
		{"IF NOT EXISTS does not make a table new: insert", "CREATE TABLE IF NOT EXISTS core_user (id INT);\nINSERT INTO core_user VALUES (1);", "INSERT of a table"},
		{"a TEMP table is another table: delete", "CREATE TEMP TABLE core_user (id INT);\nDELETE FROM core_user;", "DELETE of a table"},
		{"a TEMPORARY table is another table: unique index", "CREATE TEMPORARY TABLE core_user (id INT);\nCREATE UNIQUE INDEX u ON core_user(id);", "UNIQUE index"},
		{"a table of another schema is not new", "CREATE TABLE temp.core_user (id INT);\nDELETE FROM core_user;", "DELETE of a table"},
		{"two tables of another schema are not each other", "CREATE TABLE aux.a (id INT);\nINSERT INTO aux.b VALUES (1);", "INSERT of a table"},
		// M2: a seed write into a table that has this file's trigger fires the trigger
		{"seed into a table with a trigger of this file", "CREATE TABLE a (id INT, n INT);\n" + strings.ReplaceAll(strings.Replace(trig, "%s", "a_t", 1), "%s", "core_user") + "INSERT INTO a VALUES (1, 0);", "trigger on a table"},
		{"seed fires the trigger that rewrites old data", "CREATE TABLE a (id INT, n INT);\n-- +goose StatementBegin\nCREATE TRIGGER a_t AFTER INSERT ON a BEGIN UPDATE core_user SET admin = 1; END;\n-- +goose StatementEnd\nINSERT INTO a VALUES (1, 0);", "already has a trigger"},
		{"update of a table with a trigger of this file", "CREATE TABLE a (id INT, n INT);\n-- +goose StatementBegin\nCREATE TRIGGER a_t AFTER UPDATE ON a BEGIN SELECT 1; END;\n-- +goose StatementEnd\nUPDATE a SET n = 1;", "already has a trigger"},
		{"delete from a table with a trigger of this file", "CREATE TABLE a (id INT, n INT);\n-- +goose StatementBegin\nCREATE TRIGGER a_t AFTER DELETE ON a BEGIN SELECT 1; END;\n-- +goose StatementEnd\nDELETE FROM a;", "already has a trigger"},
		// M3: constraints that can refuse the older version's own writes
		{"foreign key to an old table without a cascade", "CREATE TABLE c (id INT, u TEXT REFERENCES core_user(id));", "foreign key"},
		{"foreign key to an old table with ON DELETE RESTRICT", "CREATE TABLE c (id INT, u TEXT REFERENCES core_user(id) ON DELETE RESTRICT);", "foreign key"},
		{"foreign key where the cascade belongs to the next column", "CREATE TABLE c (id INT, u TEXT REFERENCES core_user(id), v TEXT REFERENCES p(id) ON DELETE CASCADE);", "foreign key"},
		{"table-level foreign key without a cascade", "CREATE TABLE c (id INT, u TEXT, FOREIGN KEY (u) REFERENCES core_user(id));", "foreign key"},
		{"foreign key to another schema", "CREATE TABLE c (id INT, u TEXT REFERENCES aux.p(id));", "foreign key"},
		{"added column with REFERENCES", "ALTER TABLE old ADD COLUMN u TEXT REFERENCES core_user(id);", "REFERENCES or CHECK"},
		{"added column with CHECK", "ALTER TABLE old ADD COLUMN n INTEGER NOT NULL DEFAULT 1 CHECK (n >= 1);", "REFERENCES or CHECK"},
		{"expression index on a new table", "CREATE TABLE n (name TEXT);\nCREATE UNIQUE INDEX i ON n(lower(name));", ""},
		{"expression index", "CREATE INDEX i ON old(lower(name));", "expression index"},
		{"expression index among plain columns", "CREATE INDEX i ON old(a, a + b);", "expression index"},
		{"index with a string constant column", "CREATE INDEX i ON old('x');", "expression index"},
		{"unique index on an existing table", "CREATE UNIQUE INDEX u ON core_user(email);", "UNIQUE index"},
		{"trigger on an existing table", strings.ReplaceAll(strings.Replace(trig, "%s", "t", 1), "%s", "core_user"), "trigger on a table"},
		{"trigger without StatementBegin", "CREATE TABLE a (id INT);\nCREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; END;", "trigger outside"},
		{"virtual table", "CREATE VIRTUAL TABLE s USING fts5(x);", "cannot classify"},
		{"pragma", "PRAGMA foreign_keys = OFF;", "cannot classify"},
		{"vacuum", "VACUUM;", "cannot classify"},
		{"replace into", "CREATE TABLE a (id INT);\nREPLACE INTO a VALUES (1);", "cannot classify"},
		{"select", "SELECT 1;", "cannot classify"},
		{"begin transaction", "BEGIN; CREATE TABLE a (id INT); COMMIT;", "cannot classify"},
		{"attach", "ATTACH DATABASE 'x' AS x;", "cannot classify"},
		{"block that is not a trigger", "-- +goose StatementBegin\nDROP TABLE a;\n-- +goose StatementEnd", "not a CREATE TRIGGER"},
		{"drop smuggled after the trigger's END", "CREATE TABLE a (id INT, n INT);\n-- +goose StatementBegin\nCREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; END;\nDROP TABLE core_user;\n-- +goose StatementEnd", "more than the one trigger"},
		{"drop smuggled before a second trigger", "CREATE TABLE a (id INT);\n-- +goose StatementBegin\nCREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; END; DROP TABLE x; CREATE TRIGGER u AFTER INSERT ON a BEGIN SELECT 1; END;\n-- +goose StatementEnd", "more than the one trigger"},
		{"semicolon in a string does not hide a drop", "CREATE TABLE a (id INT);\nINSERT INTO a VALUES ('x'); DROP TABLE core_user;", "DROP TABLE"},
		{"comment does not hide a drop", "CREATE TABLE a (id INT); /* ; */ DROP TABLE core_user; -- x", "DROP TABLE"},
		{"unterminated string", "CREATE TABLE a (id INT DEFAULT 'x);", "never ends"},
		{"unterminated block comment", "CREATE TABLE a (id INT); /* x", "never ends"},
		{"unknown goose directive", "-- +goose ENVSUB on\nCREATE TABLE a (id INT);", "not understood"},
		{"StatementBegin never ends", "-- +goose StatementBegin\nCREATE TABLE a (id INT);", "without StatementEnd"},
		{"statement before Up", "CREATE TABLE a (id INT);\n-- +goose Up\nCREATE TABLE b (id INT);", "before the -- +goose Up"},
		{"two Up sections", "CREATE TABLE a (id INT);\n-- +goose Up\nCREATE TABLE b (id INT);", "exactly one"},
		{"empty garbage", "garbage", "cannot classify"},
	}
	for _, c := range cases {
		src := up(c.sql)
		switch c.name {
		case "statement before Up":
			src = []byte("CREATE TABLE a (id INT);\n-- +goose Up\nCREATE TABLE b (id INT);\n")
		case "two Up sections":
			src = []byte("-- +goose Up\nCREATE TABLE a (id INT);\n-- +goose Up\nCREATE TABLE b (id INT);\n")
		}
		got := classifyUp(src)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: want add-only, got %v", c.name, got)
			}
			continue
		}
		if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), c.want) {
			t.Errorf("%s: want a reason containing %q, got %v", c.name, c.want, got)
		}
	}
	if got := classifyUp([]byte("CREATE TABLE a (id INT);\n")); len(got) == 0 {
		t.Error("a file with no Up section must be refused")
	}
	if got := classifyUp(nil); len(got) == 0 {
		t.Error("an empty file must be refused")
	}
}

func mig(n, name, body string) (string, []byte) {
	return "modules/" + name + "/migrations/sqlite/" + n, up(body)
}

func tree(kv ...any) Tree {
	t := Tree{}
	for i := 0; i < len(kv); i += 2 {
		t[kv[i].(string)] = kv[i+1].([]byte) //nolint:gosec // pairs: the loop steps by two and the callers pass an even count
	}
	return t
}

func TestCheckMigrations(t *testing.T) {
	t.Parallel()
	p1, b1 := mig("0001_a.sql", "a", "CREATE TABLE a (id INT);")
	p2, b2 := mig("0002_a.sql", "a", "ALTER TABLE a ADD COLUMN x INT;")
	q1, c1 := mig("0001_b.sql", "b", "CREATE TABLE b (id INT);")
	prev := tree(p1, b1, q1, c1) // db_schema 2
	cases := []struct {
		name string
		cur  Tree
		prev Tree
		want string // "" = clean
	}{
		{"nothing new", tree(p1, b1, q1, c1), prev, ""},
		{"an add-only migration", tree(p1, b1, p2, b2, q1, c1), prev, ""},
		{"a new module's first migration", tree(p1, b1, q1, c1, "modules/c/migrations/sqlite/0001_c.sql", up("CREATE TABLE c (id INT);")), prev, ""},
		{"a non-additive new migration", tree(p1, b1, q1, c1, p2, up("DROP TABLE a;")), prev, "0002_a.sql: cannot classify"},
		{"a migration removed", tree(p1, b1), prev, "q"}, // placeholder replaced below
		{"a migration edited", tree(p1, up("CREATE TABLE a (id INT, extra INT);"), q1, c1), prev, "was edited"},
		{"a new migration below an applied number", tree(p1, b1, q1, c1, "modules/a/migrations/sqlite/0000_late.sql", up("CREATE TABLE late (id INT);")), prev, "not above the highest"},
		{"a new migration at an applied number", tree(p1, b1, q1, c1, "modules/a/migrations/sqlite/0001_other.sql", up("CREATE TABLE o (id INT);")), prev, "not above the highest"},
		{"two new with one number", tree(p1, b1, q1, c1, "modules/a/migrations/sqlite/0002_x.sql", up("CREATE TABLE x (id INT);"), "modules/a/migrations/sqlite/0002_y.sql", up("CREATE TABLE y (id INT);")), prev, "same number"},
		{"a stray file", tree(p1, b1, q1, c1, "modules/a/migrations/sqlite/README.md", []byte("x")), prev, "cannot be classified"},
		{"a go migration", tree(p1, b1, q1, c1, "modules/a/migrations/sqlite/0002_x.go", []byte("package x")), prev, "cannot be classified"},
		{"an empty baseline is a wrong ref", tree(p1, b1), Tree{}, "wrong ref"},
		{"the number of migrations went down", tree(p1, b1), tree(p1, b1, q1, c1), "went down"},
	}
	for _, c := range cases {
		got := CheckMigrations(c.prev, c.cur)
		joined := ""
		for _, f := range got {
			joined += f.String() + "\n"
		}
		switch {
		case c.name == "a migration removed":
			if !strings.Contains(joined, "was removed") || !strings.Contains(joined, "went down") {
				t.Errorf("%s: %q", c.name, joined)
			}
		case c.want == "":
			if len(got) != 0 {
				t.Errorf("%s: want clean, got %q", c.name, joined)
			}
		case !strings.Contains(joined, c.want):
			t.Errorf("%s: want %q in %q", c.name, c.want, joined)
		}
	}
}

func TestDirTreeReadsOnlyMigrationFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("modules/a/migrations/sqlite/0001_a.sql", "x")
	write("modules/a/migrations/sqlite/notes.md", "y")
	write("modules/a/other/0001_a.sql", "z")
	write("modules/a/migrations/0001_flat.sql", "w")
	write("core/store/queries/q.sql", "v")
	got, err := DirTree(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got.Count() != 1 {
		t.Fatalf("%v", got)
	}
	if empty, err := DirTree(os.DirFS(t.TempDir())); err != nil || len(empty) != 0 {
		t.Fatal(empty, err)
	}
}

// The repository's own migrations: the guard parses every one and flags the one real history has that is not add-only
// (response 0003 drops a table), so it has teeth on real input, not only on fixtures.
func TestGuardOnTheRealMigrations(t *testing.T) {
	t.Parallel()
	cur, err := DirTree(os.DirFS("../.."))
	if err != nil {
		t.Fatal(err)
	}
	if cur.Count() < 30 {
		t.Fatalf("found only %d migrations; is the path right?", cur.Count())
	}
	bad := map[string]bool{}
	for p, b := range cur {
		if r := classifyUp(b); len(r) > 0 {
			bad[p] = true
		}
	}
	if !bad["modules/response/migrations/sqlite/0003_response_tokens.sql"] {
		t.Error("DROP TABLE resp_tokens was not flagged")
	}
	// ADD COLUMN with a CHECK is not add-only (M3): these two are flagged even though they only add a column.
	for _, p := range []string{"modules/honeypot/migrations/sqlite/0002_hit_count.sql", "modules/core/migrations/sqlite/0009_core_user_temp_password.sql"} {
		if !bad[p] {
			t.Errorf("%s adds a column with a CHECK and must be flagged", p)
		}
	}
	// A seed into a new table, a trigger and expression indexes on new tables, a plain table: add-only.
	for _, p := range []string{"modules/logs/migrations/volume/0002_logs_volume_bytes.sql", "modules/inventory/migrations/sqlite/0001_inventory.sql",
		"modules/core/migrations/sqlite/0004_core_chain_head.sql", "modules/exposure/migrations/sqlite/0001_exposure.sql"} {
		if bad[p] {
			t.Errorf("%s is add-only and was flagged", p)
		}
	}
}

func TestGitTree(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append( //nolint:gosec // fixed git argv in a test repository
			[]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	dir := filepath.Join(repo, "modules/a/migrations/sqlite")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0001_a.sql"), up("CREATE TABLE a (id INT);"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "one")
	git("tag", "v0.1.0")
	if err := os.WriteFile(filepath.Join(dir, "0002_a.sql"), up("DROP TABLE a;"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, err := GitTree(t.Context(), repo, "v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	cur, err := DirTree(os.DirFS(repo))
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 1 || len(cur) != 2 {
		t.Fatalf("%d %d", len(prev), len(cur))
	}
	if f := CheckMigrations(prev, cur); len(f) != 1 || !strings.Contains(f[0].String(), "0002_a.sql") {
		t.Fatalf("%v", f)
	}
	for _, ref := range []string{"", "-x", "--output=/tmp/x", "a..b", "v0.1.0; rm -rf /", "nope"} {
		if _, err := GitTree(t.Context(), repo, ref); err == nil {
			t.Errorf("ref %q accepted", ref)
		}
	}
}

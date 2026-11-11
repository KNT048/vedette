package logs

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// D-151: logs.db is not in the backup, and a restore or a rollback leaves it alone, so an OLDER binary can be started
// against a NEWER logs.db. For that to be safe the migrations of the volume (migrations/volume) must be add-only: new
// tables, new indexes, new nullable or defaulted columns, and nothing else. No DROP, no RENAME, no DELETE or UPDATE of
// existing rows, nothing that changes what an existing column means. An incompatible change is a new file (logs-v2.db)
// and a new decision, not a migration here. The migrations of the main database (migrations/config) are not held to this:
// they travel with the backup and the binary together.

var (
	forbidden = []struct {
		re  *regexp.Regexp
		why string
	}{
		{regexp.MustCompile(`(?i)\bdrop\b`), "DROP removes something an older binary still reads"},
		{regexp.MustCompile(`(?i)\brename\b`), "RENAME makes the old name disappear for an older binary"},
		{regexp.MustCompile(`(?i)\bdelete\b`), "DELETE removes rows an older binary expects"},
		{regexp.MustCompile(`(?i)\bupdate\b`), "UPDATE rewrites what an older binary reads"},
		{regexp.MustCompile(`(?i)\breplace\s+into\b`), "REPLACE INTO overwrites rows"},
		{regexp.MustCompile(`(?i)\binsert\s+or\s+replace\b`), "INSERT OR REPLACE overwrites rows"},
		{regexp.MustCompile(`(?i)\bcreate\s+(temp\w*\s+)?trigger\b`), "a trigger changes what an older binary's statements do"},
		{regexp.MustCompile(`(?i)\bcreate\s+unique\s+index\b`), "a unique index makes an older binary's inserts fail"},
		{regexp.MustCompile(`(?i)\bif\s+not\s+exists\b`), "IF NOT EXISTS may find an older shape of the table and carry on: a migration creates what is not there"},
		{regexp.MustCompile(`(?i)\b(attach|detach)\b`), "ATTACH reaches outside logs.db"},
	}
	pragma     = regexp.MustCompile(`(?i)\bpragma\b`)
	checkWord  = regexp.MustCompile(`(?i)\bcheck\b`)
	createTab  = regexp.MustCompile(`(?i)\bcreate\s+(?:temp\w*\s+)?table\s+([A-Za-z_]\w*)`)
	insertInto = regexp.MustCompile(`(?i)\binsert\s+(?:or\s+\w+\s+)?into\s+(\S+)`)
	createIdx  = regexp.MustCompile(`(?is)^\s*create\s+index\s+[^(]*?\bon\s+[^(]*\((.*)\)\s*(?:where\b.*)?$`)
	plainCol   = regexp.MustCompile(`(?i)^\s*(?:[A-Za-z_]\w*|""|\[\])(?:\s+collate\s+\w+)?(?:\s+(?:asc|desc))?\s*$`)
	references = regexp.MustCompile(`(?i)\breferences\b`)
	alterAdd   = regexp.MustCompile(`(?i)^\s*alter\s+table\s+\S+\s+add\s+column\s`)
)

// stripLiterals removes string literals, quoted identifiers and comments in one left-to-right pass, so that each is
// recognised by what precedes it and not by what another removal left: a '--' inside a string or a "quoted name" is not a
// comment, and a quote inside a comment or another quoted span starts nothing. A '...' string becomes ”, a "..." or `...`
// identifier "" and a [...] identifier [], a comment a space.
func stripLiterals(sql string) string {
	var b strings.Builder
	for i := 0; i < len(sql); {
		switch c := sql[i]; {
		case c == '\'' || c == '"' || c == '`':
			i++
			for i < len(sql) {
				if sql[i] == c {
					if i+1 < len(sql) && sql[i+1] == c { // a doubled quote is a quote inside
						i += 2
						continue
					}
					break
				}
				i++
			}
			i++ // the closing quote (an unterminated span runs to the end)
			b.WriteString(strings.Repeat(string(c), 2))
		case c == '[':
			end := strings.IndexByte(sql[i:], ']')
			if end < 0 {
				i = len(sql)
			} else {
				i += end + 1
			}
			b.WriteString("[]")
		case strings.HasPrefix(sql[i:], "--"):
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				i = len(sql)
			} else {
				i += end + 4
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// addOnlyViolations returns what in a migration is not add-only (empty: it is).
func addOnlyViolations(sql string) []string {
	s := stripLiterals(sql)
	var out []string
	for _, f := range forbidden {
		if m := f.re.FindString(s); m != "" {
			out = append(out, f.why)
		}
	}
	if pragma.MatchString(s) {
		out = append(out, "PRAGMA changes the database itself (writable_schema, foreign keys, ...)")
	}
	created := map[string]bool{} // tables this migration creates: the only ones it may insert into
	for _, m := range createTab.FindAllStringSubmatch(s, -1) {
		created[strings.ToLower(m[1])] = true
	}
	for _, m := range insertInto.FindAllStringSubmatch(s, -1) {
		if !created[strings.ToLower(strings.Trim(m[1], "(;"))] {
			out = append(out, "INSERT INTO a table that already exists changes what an older binary reads: "+m[1])
		}
	}
	for _, stmt := range strings.Split(s, ";") {
		if t := strings.TrimSpace(stmt); strings.HasPrefix(strings.ToLower(t), "alter") {
			if !alterAdd.MatchString(stmt) {
				out = append(out, "ALTER TABLE may only ADD COLUMN: "+t)
			} else if checkWord.MatchString(stmt) {
				out = append(out, "a CHECK on an added column fails an older binary's writes: "+t)
			} else if references.MatchString(stmt) {
				out = append(out, "a REFERENCES on an added column ties the table to another: "+t)
			}
		}
		if m := createIdx.FindStringSubmatch(stmt); m != nil {
			for _, col := range splitTop(m[1]) {
				if !plainCol.MatchString(col) {
					out = append(out, "an index on an expression is not a column of the table an older binary reads: "+strings.TrimSpace(stmt))
					break
				}
			}
		}
	}
	return out
}

// splitTop splits an index's column list at the commas that are not inside parentheses.
func splitTop(list string) []string {
	var out []string
	depth, from := 0, 0
	for i, c := range list {
		switch {
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, list[from:i])
			from = i + 1
		}
	}
	return append(out, list[from:])
}

func TestAddOnlyCheckerJudgesStatements(t *testing.T) {
	t.Parallel()
	for sql, want := range map[string]bool{ // true: add-only
		`CREATE TABLE logs_x (id INTEGER PRIMARY KEY, a TEXT);`:                   true,
		`CREATE INDEX logs_x_a ON logs_x (a);`:                                    true,
		`ALTER TABLE logs_events ADD COLUMN src_ip TEXT;`:                         true,
		`alter table logs_events add column n INTEGER NOT NULL DEFAULT 0;`:        true,
		"-- DROP TABLE in a comment is fine\nCREATE TABLE logs_y (id INTEGER);":   true,
		`/* rename later */ CREATE TABLE logs_z (a TEXT CHECK (a <> 'drop'));`:    true,
		`CREATE TABLE logs_x (a TEXT); INSERT INTO logs_x (a) VALUES ('update');`: true,
		`DROP TABLE logs_source_seen;`:                                            false,
		`drop index logs_events_ts;`:                                              false,
		`ALTER TABLE logs_events RENAME COLUMN line TO text;`:                     false,
		`ALTER TABLE logs_events RENAME TO logs_lines;`:                           false,
		`ALTER TABLE logs_events DROP COLUMN line;`:                               false,
		`ALTER TABLE logs_events ALTER COLUMN line SET NOT NULL;`:                 false,
		`DELETE FROM logs_events;`:                                                false,
		`UPDATE logs_events SET line = lower(line);`:                              false,
		"CREATE TABLE logs_ok (a TEXT);\nDROP\nTABLE logs_source_buckets;":        false,
		// the two ways round the old order of removal (comments first, then strings)
		"SELECT '--'; DROP TABLE logs_events;":                                                                         false, // '--' in a string is not a comment
		"SELECT '/*'; DROP TABLE logs_events; SELECT '*/';":                                                            false, // two strings are not a comment
		`CREATE TABLE logs_x (a TEXT); INSERT INTO logs_x (a) VALUES ('it''s -- fine'); CREATE TABLE logs_w (a TEXT);`: true,
		// quoted identifiers (review of fe9b026)
		`CREATE TABLE "x'" (a); DROP TABLE logs_events; CREATE TABLE "y'" (b);`:                      false,
		`CREATE TABLE "a--b" (x); DROP TABLE logs_events;`:                                           false,
		`CREATE TABLE "/*" (x); DROP TABLE logs_events; CREATE TABLE "*/" (y);`:                      false,
		"CREATE TABLE `x'` (a); DROP TABLE logs_events; CREATE TABLE `y'` (b);":                      false,
		`CREATE TABLE [x'] (a); DROP TABLE logs_events; CREATE TABLE [y'] (b);`:                      false,
		`CREATE TABLE "logs_ok" (a TEXT);`:                                                           true,
		`ALTER TABLE logs_events ADD COLUMN n INTEGER CHECK (n > 5);`:                                false,
		`PRAGMA writable_schema = 1;`:                                                                false,
		`INSERT INTO logs_events (ts, source_id, line) SELECT ts, source_id, line FROM logs_events;`: false,
		`INSERT INTO "logs_events" (line) VALUES ('x');`:                                             false,
		`REPLACE INTO logs_source_seen (source_id, last_received) VALUES ('a', 'b');`:                false,
		`INSERT OR REPLACE INTO logs_source_seen (source_id) VALUES ('a');`:                          false,
		`CREATE TRIGGER logs_t AFTER INSERT ON logs_events BEGIN SELECT 1; END;`:                     false,
		`CREATE UNIQUE INDEX logs_u ON logs_events (source_id, ts);`:                                 false,
		// L-1 remainder (re-review of 4911f0e)
		`CREATE TABLE IF NOT EXISTS logs_events (id INTEGER); INSERT INTO logs_events (id) VALUES (1);`: false,
		`CREATE TABLE IF NOT EXISTS logs_q (a TEXT);`:                                                   false,
		`CREATE INDEX IF NOT EXISTS logs_i ON logs_events (ts);`:                                        false,
		`CREATE INDEX logs_j ON logs_events (json_extract(line, '$.a'));`:                               false,
		`CREATE INDEX logs_k ON logs_events (lower(source_id));`:                                        false,
		`CREATE INDEX logs_l ON logs_events (ts + 1);`:                                                  false,
		`CREATE INDEX logs_m ON logs_events (source_id, ts DESC);`:                                      true,
		`CREATE INDEX logs_n ON logs_events (source_id COLLATE NOCASE);`:                                true,
		`ALTER TABLE logs_events ADD COLUMN s TEXT REFERENCES logs_sources (id);`:                       false,
		`ATTACH DATABASE 'x.db' AS x;`:                                                                  false,
		`attach 'x.db' as x; CREATE TABLE x.logs_t (a);`:                                                false,
	} {
		if got := len(addOnlyViolations(sql)) == 0; got != want {
			t.Errorf("%q: add-only = %t, want %t (%v)", sql, got, want, addOnlyViolations(sql))
		}
	}
}

// Every migration of logs.db, now and in the future, is add-only (D-151).
func TestVolumeMigrationsAreAddOnly(t *testing.T) {
	t.Parallel()
	n := 0
	err := fs.WalkDir(VolumeMigrations, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(name, ".sql") {
			return err
		}
		b, err := fs.ReadFile(VolumeMigrations, name)
		if err != nil {
			return err
		}
		n++
		for _, v := range addOnlyViolations(string(b)) {
			t.Errorf("migrations/volume/%s is not add-only (D-151: an older binary may run against a newer logs.db): %s", name, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no migration found: the check would pass without checking anything")
	}
}

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
	}
	alterAdd = regexp.MustCompile(`(?i)^\s*alter\s+table\s+\S+\s+add\s+column\s`)
)

// stripLiterals removes string literals and comments in one left-to-right pass, so that each is recognised by what
// precedes it and not by what another removal left: a '--' inside a string is not a comment, and a comment marker cannot
// be made by joining two strings. A string becomes ” (two quotes), a comment a space.
func stripLiterals(sql string) string {
	var b strings.Builder
	for i := 0; i < len(sql); {
		switch {
		case sql[i] == '\'':
			i++
			for i < len(sql) {
				if sql[i] == '\'' {
					if i+1 < len(sql) && sql[i+1] == '\'' {
						i += 2
						continue
					}
					break
				}
				i++
			}
			i++ // the closing quote (an unterminated string runs to the end)
			b.WriteString("''")
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
			b.WriteByte(sql[i])
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
	for _, stmt := range strings.Split(s, ";") {
		if t := strings.TrimSpace(stmt); strings.HasPrefix(strings.ToLower(t), "alter") && !alterAdd.MatchString(stmt) {
			out = append(out, "ALTER TABLE may only ADD COLUMN: "+t)
		}
	}
	return out
}

func TestAddOnlyCheckerJudgesStatements(t *testing.T) {
	t.Parallel()
	for sql, want := range map[string]bool{ // true: add-only
		`CREATE TABLE logs_x (id INTEGER PRIMARY KEY, a TEXT);`:                 true,
		`CREATE INDEX logs_x_a ON logs_x (a);`:                                  true,
		`ALTER TABLE logs_events ADD COLUMN src_ip TEXT;`:                       true,
		`alter table logs_events add column n INTEGER NOT NULL DEFAULT 0;`:      true,
		"-- DROP TABLE in a comment is fine\nCREATE TABLE logs_y (id INTEGER);": true,
		`/* rename later */ CREATE TABLE logs_z (a TEXT CHECK (a <> 'drop'));`:  true,
		`INSERT INTO logs_x (a) VALUES ('update');`:                             true,
		`DROP TABLE logs_source_seen;`:                                          false,
		`drop index logs_events_ts;`:                                            false,
		`ALTER TABLE logs_events RENAME COLUMN line TO text;`:                   false,
		`ALTER TABLE logs_events RENAME TO logs_lines;`:                         false,
		`ALTER TABLE logs_events DROP COLUMN line;`:                             false,
		`ALTER TABLE logs_events ALTER COLUMN line SET NOT NULL;`:               false,
		`DELETE FROM logs_events;`:                                              false,
		`UPDATE logs_events SET line = lower(line);`:                            false,
		"CREATE TABLE logs_ok (a TEXT);\nDROP\nTABLE logs_source_buckets;":      false,
		// the two ways round the old order of removal (comments first, then strings)
		"SELECT '--'; DROP TABLE logs_events;":                                           false, // '--' in a string is not a comment
		"SELECT '/*'; DROP TABLE logs_events; SELECT '*/';":                              false, // two strings are not a comment
		`INSERT INTO logs_x (a) VALUES ('it''s -- fine'); CREATE TABLE logs_w (a TEXT);`: true,
		`REPLACE INTO logs_source_seen (source_id, last_received) VALUES ('a', 'b');`:    false,
		`INSERT OR REPLACE INTO logs_source_seen (source_id) VALUES ('a');`:              false,
		`CREATE TRIGGER logs_t AFTER INSERT ON logs_events BEGIN SELECT 1; END;`:         false,
		`CREATE UNIQUE INDEX logs_u ON logs_events (source_id, ts);`:                     false,
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

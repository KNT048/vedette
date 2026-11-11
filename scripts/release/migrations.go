package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec" //nolint:depguard // release helper outside the product: fixed argv (git), no shell
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The D-183 guard. goose does not refuse a database newer than the binary (D-151, D-138), so the only thing that makes
// "the previous version runs on the new database" true is that every migration since the previous release is add-only. A
// release may declare rollback.safe=true only when the guard below finds nothing; anything it cannot classify counts as
// not add-only (fail closed).
//
// What is add-only (a binary that has never heard of the change keeps working on the changed database):
//   - CREATE TABLE, CREATE INDEX, CREATE VIEW (also IF NOT EXISTS);
//   - ALTER TABLE ... ADD COLUMN (SQLite insists on a default for a NOT NULL column; the old binary names its columns);
//   - CREATE UNIQUE INDEX, CREATE TRIGGER, INSERT, UPDATE and DELETE, but only on a table that the same file created: the old
//     binary never writes such a table, so nothing it does can hit the constraint, the trigger or the seed.
//
// Everything else is not add-only: DROP, RENAME, DROP COLUMN, UPDATE/DELETE/INSERT of an existing table (they change data the
// old binary reads), a unique index or trigger on an existing table (they can refuse the old binary's writes), CREATE VIRTUAL
// TABLE, PRAGMA, VACUUM, ATTACH, transactions, a statement that is not recognised, a file with no Up section, a goose
// directive that is not understood, a quote or comment that never ends, a file that is not an NNNN_name.sql, and a trigger
// outside -- +goose StatementBegin/StatementEnd. Between releases a migration file must also not be removed, edited or
// inserted below an applied number of its directory, and the number of migrations (db_schema) must not go down.

// maxMigFile and maxMigFiles bound what the guard reads (a repository is not trusted to be small).
const (
	maxMigFile  = 1 << 20
	maxMigFiles = 2000
)

// Tree is the migration files of one revision: path (slash form, "modules/<m>/migrations/<dir>/<file>") to contents.
type Tree map[string][]byte

var migPathRE = regexp.MustCompile(`^modules/[^/]+/migrations/[^/]+/[^/]+$`)
var migNameRE = regexp.MustCompile(`^([0-9]{1,6})_[A-Za-z0-9_.-]+\.sql$`)

// DirTree reads the migration files under root (the repository root) from fsys.
func DirTree(fsys fs.FS) (Tree, error) {
	t := Tree{}
	err := fs.WalkDir(fsys, "modules", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == "modules" {
				return fs.SkipAll
			}
			return err
		}
		if d.IsDir() || !migPathRE.MatchString(p) {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		if len(t) >= maxMigFiles {
			return fmt.Errorf("more than %d migration files", maxMigFiles)
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if len(b) > maxMigFile {
			return fmt.Errorf("%s is larger than %d bytes", p, maxMigFile)
		}
		t[p] = b
		return nil
	})
	return t, err
}

var gitRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)

// GitTree reads the migration files of revision ref in the repository at repo, with git (fixed argv, no shell).
func GitTree(ctx context.Context, repo, ref string) (Tree, error) {
	if !gitRefRE.MatchString(ref) || strings.Contains(ref, "..") {
		return nil, fmt.Errorf("git ref %q is not a plain tag, branch or commit name", ref)
	}
	git := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...) //nolint:gosec // fixed git argv; ref and paths validated
		cmd.Env = []string{"LC_ALL=C", "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "HOME=" + os.Getenv("HOME")}
		out, err := cmd.Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(ee.Stderr)))
			}
			return nil, fmt.Errorf("git %s: %w", args[0], err)
		}
		return out, nil
	}
	list, err := git("ls-tree", "-r", "-z", "--name-only", ref, "--", "modules")
	if err != nil {
		return nil, err
	}
	t := Tree{}
	for _, p := range strings.Split(string(list), "\x00") {
		if p == "" || !migPathRE.MatchString(p) {
			continue
		}
		if len(t) >= maxMigFiles {
			return nil, fmt.Errorf("more than %d migration files", maxMigFiles)
		}
		b, err := git("show", ref+":"+p)
		if err != nil {
			return nil, err
		}
		if len(b) > maxMigFile {
			return nil, fmt.Errorf("%s is larger than %d bytes", p, maxMigFile)
		}
		t[p] = b
	}
	return t, nil
}

// Count is the number of SQL migrations of the tree: the db_schema of the manifest.
func (t Tree) Count() int {
	n := 0
	for p := range t {
		if strings.HasSuffix(p, ".sql") {
			n++
		}
	}
	return n
}

// Finding is one reason a release is not add-only.
type Finding struct{ File, Reason string }

func (f Finding) String() string { return f.File + ": " + f.Reason }

// CheckMigrations compares the migrations of the previous release with the current tree and returns every reason the change is
// not add-only. prevSchema is the previous manifest's db_schema (it must equal the number of migrations of prev: a wrong git
// ref is caught here). No findings means rollback.safe=true may be declared as far as the database goes.
func CheckMigrations(prev, cur Tree, prevSchema int) []Finding {
	var out []Finding
	add := func(file, format string, a ...any) { out = append(out, Finding{file, fmt.Sprintf(format, a...)}) }
	if prev.Count() != prevSchema {
		add("(previous release)", "its manifest says db_schema %d but the previous revision holds %d migrations: wrong previous ref?", prevSchema, prev.Count())
	}
	if cur.Count() < prevSchema {
		add("(db_schema)", "the number of migrations went down from %d to %d", prevSchema, cur.Count())
	}
	maxPrev := map[string]int{} // directory -> highest applied number
	for p, b := range prev {
		if n, ok := migNumber(p); ok && n > maxPrev[path.Dir(p)] {
			maxPrev[path.Dir(p)] = n
		}
		c, there := cur[p]
		switch {
		case !there:
			add(p, "was removed since the previous release")
		case string(c) != string(b):
			add(p, "was edited since the previous release (goose has applied it already)")
		}
	}
	seen := map[string]string{} // directory + number -> file
	paths := make([]string, 0, len(cur))
	for p := range cur {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		n, ok := migNumber(p)
		if !ok {
			if _, old := prev[p]; !old {
				add(p, "is not an NNNN_name.sql goose migration, so it cannot be classified")
			}
			continue
		}
		key := path.Dir(p) + "#" + strconv.Itoa(n)
		if other, dup := seen[key]; dup {
			add(p, "has the same number as %s", path.Base(other))
		}
		seen[key] = p
		if _, old := prev[p]; old {
			continue
		}
		if n <= maxPrev[path.Dir(p)] {
			add(p, "is numbered %d, not above the highest migration of the previous release (%d)", n, maxPrev[path.Dir(p)])
		}
		for _, r := range classifyUp(cur[p]) {
			add(p, "%s", r)
		}
	}
	return out
}

func migNumber(p string) (int, bool) {
	m := migNameRE.FindStringSubmatch(path.Base(p))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// classifyUp returns the reasons the Up section of a goose migration is not add-only.
func classifyUp(src []byte) []string {
	var reasons []string
	fail := func(format string, a ...any) { reasons = append(reasons, fmt.Sprintf(format, a...)) }
	type stmt struct {
		text  string
		block bool // came from StatementBegin..StatementEnd
	}
	var stmts []stmt
	section, ups := "", 0
	inBlock := false
	var buf strings.Builder
	flush := func(block bool) {
		text := buf.String()
		buf.Reset()
		if section != "up" {
			if strings.TrimSpace(text) != "" && section == "" {
				// anything before "-- +goose Up" that is not a comment
				if cleaned, err := stripSQL(text); err != nil || strings.TrimSpace(cleaned) != "" {
					fail("SQL before the -- +goose Up line")
				}
			}
			return
		}
		if block {
			stmts = append(stmts, stmt{text, true})
			return
		}
		parts, err := splitSQL(text)
		if err != nil {
			fail("%v", err)
			return
		}
		for _, p := range parts {
			stmts = append(stmts, stmt{p, false})
		}
	}
	for _, line := range strings.Split(string(src), "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "-- +goose"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			f := strings.Fields(strings.ToLower(rest))
			if len(f) == 0 {
				fail("empty -- +goose directive")
				continue
			}
			switch f[0] {
			case "up":
				flush(inBlock)
				section = "up"
				ups++
			case "down":
				flush(inBlock)
				section = "down"
			case "statementbegin":
				flush(false)
				if inBlock {
					fail("nested StatementBegin")
				}
				inBlock = true
			case "statementend":
				if !inBlock {
					fail("StatementEnd without StatementBegin")
				}
				flush(true)
				inBlock = false
			case "no":
				if len(f) != 2 || f[1] != "transaction" {
					fail("goose directive %q is not understood", strings.Join(f, " "))
				}
			default:
				fail("goose directive %q is not understood", f[0])
			}
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	if inBlock {
		fail("StatementBegin without StatementEnd")
	}
	flush(false)
	if ups != 1 {
		fail("needs exactly one -- +goose Up section, has %d", ups)
	}
	created := map[string]bool{}
	for _, s := range stmts {
		clean, err := stripSQL(s.text)
		if err != nil {
			fail("%v", err)
			continue
		}
		clean = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(clean), ";"))
		if clean == "" {
			continue
		}
		if r := classifyStmt(clean, s.block, created); r != "" {
			fail("%s", r)
		}
	}
	return reasons
}

const ident = "(\"[^\"]+\"|`[^`]+`|\\[[^\\]]+\\]|[A-Za-z_][A-Za-z0-9_$]*)(?:\\.(\"[^\"]+\"|`[^`]+`|\\[[^\\]]+\\]|[A-Za-z_][A-Za-z0-9_$]*))?"

var (
	createTableRE = regexp.MustCompile(`(?is)^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident + `(?:[\s(]|$)`)
	createIndexRE = regexp.MustCompile(`(?is)^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident + `\s+ON\s+` + ident + `(?:[\s(]|$)`)
	createViewRE  = regexp.MustCompile(`(?is)^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident + `\s`)
	createTrigRE  = regexp.MustCompile(`(?is)^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident +
		`\s+(?:BEFORE\s+|AFTER\s+|INSTEAD\s+OF\s+)?(?:INSERT|DELETE|UPDATE(?:\s+OF\s+[^\s,]+(?:\s*,\s*[^\s,]+)*)?)\s+ON\s+` + ident + `\s`)
	alterAddRE = regexp.MustCompile(`(?is)^ALTER\s+TABLE\s+` + ident + `\s+ADD\s+COLUMN\s+[A-Za-z_"` + "`" + `\[]`)
	insertRE   = regexp.MustCompile(`(?is)^INSERT\s+(?:OR\s+[A-Za-z]+\s+)?INTO\s+` + ident + `(?:[\s(]|$)`)
	updateRE   = regexp.MustCompile(`(?is)^UPDATE\s+(?:OR\s+[A-Za-z]+\s+)?` + ident + `\s+SET\s`)
	deleteRE   = regexp.MustCompile(`(?is)^DELETE\s+FROM\s+` + ident + `(?:\s|$)`)
)

// tableName normalises the one or two identifier groups of a match (schema.name) to the lower-case table name.
func tableName(name, schema string) string {
	n := name
	if schema != "" {
		if !strings.EqualFold(unquote(name), "main") {
			return "\x00other-schema:" + strings.ToLower(unquote(name))
		}
		n = schema
	}
	return strings.ToLower(unquote(n))
}

func unquote(s string) string {
	if len(s) >= 2 {
		switch s[0] {
		case '"', '`':
			return s[1 : len(s)-1]
		case '[':
			return s[1 : len(s)-1]
		}
	}
	return s
}

// classifyStmt returns "" for an add-only statement, else the reason. created collects the tables the file made.
func classifyStmt(s string, block bool, created map[string]bool) string {
	head := s
	if len(head) > 60 {
		head = head[:60] + "..."
	}
	head = strings.Join(strings.Fields(head), " ")
	if block && !createTrigRE.MatchString(s) {
		return fmt.Sprintf("a StatementBegin block that is not a CREATE TRIGGER (%q)", head)
	}
	switch {
	case createTableRE.MatchString(s):
		m := createTableRE.FindStringSubmatch(s)
		created[tableName(m[1], m[2])] = true
		return ""
	case createIndexRE.MatchString(s):
		m := createIndexRE.FindStringSubmatch(s)
		if m[1] != "" && !created[tableName(m[4], m[5])] {
			return fmt.Sprintf("a UNIQUE index on a table this migration did not create can refuse writes of the older version (%q)", head)
		}
		return ""
	case createViewRE.MatchString(s):
		return ""
	case createTrigRE.MatchString(s):
		if !block {
			return fmt.Sprintf("a trigger outside -- +goose StatementBegin/StatementEnd (%q)", head)
		}
		if !triggerBlockOK(s) {
			return fmt.Sprintf("a StatementBegin block holds more than the one trigger it starts with (%q)", head)
		}
		m := createTrigRE.FindStringSubmatch(s)
		if !created[tableName(m[3], m[4])] {
			return fmt.Sprintf("a trigger on a table this migration did not create can refuse writes of the older version (%q)", head)
		}
		return ""
	case alterAddRE.MatchString(s):
		return ""
	case insertRE.MatchString(s):
		m := insertRE.FindStringSubmatch(s)
		if !created[tableName(m[1], m[2])] {
			return fmt.Sprintf("INSERT into a table this migration did not create changes data the older version reads (%q)", head)
		}
		return ""
	case updateRE.MatchString(s):
		m := updateRE.FindStringSubmatch(s)
		if !created[tableName(m[1], m[2])] {
			return fmt.Sprintf("UPDATE of a table this migration did not create changes data the older version reads (%q)", head)
		}
		return ""
	case deleteRE.MatchString(s):
		m := deleteRE.FindStringSubmatch(s)
		if !created[tableName(m[1], m[2])] {
			return fmt.Sprintf("DELETE from a table this migration did not create changes data the older version reads (%q)", head)
		}
		return ""
	}
	return fmt.Sprintf("cannot classify as add-only: %q", head)
}

// triggerBlockOK reports whether s (comments already removed) is exactly one trigger: after BEGIN, the first END that is not
// closing a CASE ends it, and nothing but whitespace and semicolons follows. Otherwise a block could smuggle a DROP in after the
// trigger's own END, past a check that only looks at how the block starts.
func triggerBlockOK(s string) bool {
	depth, begun := 0, false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'' || c == '"' || c == '`' || c == '[':
			closer := c
			if c == '[' {
				closer = ']'
			}
			j := i + 1
			for {
				k := strings.IndexByte(s[j:], closer)
				if k < 0 {
					return false
				}
				j += k + 1
				if c != '[' && j < len(s) && s[j] == closer {
					j++
					continue
				}
				break
			}
			i = j
		case c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z'):
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '$' || (s[j]|0x20 >= 'a' && s[j]|0x20 <= 'z') || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			switch strings.ToUpper(s[i:j]) {
			case "BEGIN":
				begun = true
			case "CASE":
				if begun {
					depth++
				}
			case "END":
				if begun && depth == 0 {
					return strings.Trim(s[j:], " \t\r\n;") == ""
				}
				if begun {
					depth--
				}
			}
			i = j
		default:
			i++
		}
	}
	return false
}

// scanSQL walks SQL text once, quote and comment aware: it drops comments (a space stays), keeps quoted text intact and, when
// split is set, cuts at the semicolons outside quotes. It is an error for a quote or a block comment never to end.
func scanSQL(s string, split bool) ([]string, error) {
	var out []string
	var cur strings.Builder
	cut := func() {
		if strings.TrimSpace(cur.String()) != "" {
			out = append(out, cur.String())
		}
		cur.Reset()
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			cur.WriteByte(' ')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return nil, errors.New("a /* comment never ends")
			}
			i += 2 + end + 2
			cur.WriteByte(' ')
		case c == '\'' || c == '"' || c == '`' || c == '[':
			closer := c
			if c == '[' {
				closer = ']'
			}
			j := i + 1
			for {
				k := strings.IndexByte(s[j:], closer)
				if k < 0 {
					return nil, fmt.Errorf("a %c quote never ends", c)
				}
				j += k + 1
				if c != '[' && j < len(s) && s[j] == closer { // doubled quote is an escaped quote
					j++
					continue
				}
				break
			}
			cur.WriteString(s[i:j])
			i = j
		case c == ';' && split:
			cur.WriteByte(';')
			cut()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	cut()
	return out, nil
}

func stripSQL(s string) (string, error) {
	parts, err := scanSQL(s, false)
	return strings.Join(parts, " "), err
}

func splitSQL(s string) ([]string, error) { return scanSQL(s, true) }

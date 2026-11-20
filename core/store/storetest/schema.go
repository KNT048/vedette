package storetest

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// SchemaTable is one table of a migrated database as the schema rules see it.
type SchemaTable struct {
	Name string
	SQL  string
	// ForeignKeys lists the tables this table's foreign keys point at.
	ForeignKeys []string
}

// Schema returns every ordinary table of db, sorted by name. FTS shadow tables and SQLite's own tables are left out.
func Schema(t testing.TB, db *store.DB) []SchemaTable {
	t.Helper()
	rows, err := db.Reader().QueryContext(t.Context(), `SELECT name, coalesce(sql, '') FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatalf("storetest: list tables: %v", err)
	}
	var out []SchemaTable
	for rows.Next() {
		var tb SchemaTable
		if err := rows.Scan(&tb.Name, &tb.SQL); err != nil {
			t.Fatalf("storetest: scan table: %v", err)
		}
		if tb.SQL == "" || strings.HasPrefix(tb.Name, "sqlite_") {
			continue
		}
		out = append(out, tb)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("storetest: list tables: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("storetest: list tables: %v", err)
	}
	for i := range out {
		fk, err := db.Reader().QueryContext(t.Context(), `SELECT DISTINCT "table" FROM pragma_foreign_key_list(?) ORDER BY 1`, out[i].Name)
		if err != nil {
			t.Fatalf("storetest: foreign keys of %s: %v", out[i].Name, err)
		}
		for fk.Next() {
			var to string
			if err := fk.Scan(&to); err != nil {
				t.Fatalf("storetest: scan foreign key: %v", err)
			}
			out[i].ForeignKeys = append(out[i].ForeignKeys, to)
		}
		if err := fk.Err(); err != nil {
			t.Fatalf("storetest: foreign keys of %s: %v", out[i].Name, err)
		}
		_ = fk.Close()
	}
	return out
}

var jsonValid = regexp.MustCompile(`(?i)json_valid\(\s*"?([a-z_][a-z0-9_]*)"?\s*\)`)

// JSONColumns returns the columns of a CREATE TABLE statement that are declared as JSON with a json_valid check, sorted.
func JSONColumns(createSQL string) []string {
	var out []string
	for _, m := range jsonValid.FindAllStringSubmatch(createSQL, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return out
}

var (
	inList  = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s+IN\s*\(\s*('(?:[^']|'')*'(?:\s*,\s*'(?:[^']|'')*')*)\s*\)`)
	literal = regexp.MustCompile(`'(?:[^']|'')*'`)
)

// LongValueLists returns the columns of a CREATE TABLE statement that a CHECK restricts to a list of more than max text
// values (col IN ('a', 'b', ...)), sorted.
func LongValueLists(createSQL string, max int) []string {
	var out []string
	for _, m := range inList.FindAllStringSubmatch(createSQL, -1) {
		if len(literal.FindAllString(m[2], -1)) > max && !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return out
}

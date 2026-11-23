package main

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// planter writes rows into any table of the real schema without knowing its columns: every column it is not given holds a value
// of its declared type (a number, "plant", a byte), and every foreign key is made to hold by writing the row it references first,
// with the referenced value (the planted default when the referencing column was not given). CHECK constraints are ignored for
// the planted rows (they need not look like real rows), so a test can put data in every table, or one row that breaks one rule.
type planter struct {
	t      *testing.T
	tables map[string][][2]string // table -> columns (name, declared type)
	refs   map[string]map[string]plantRef
	pks    map[string]string // table -> its single primary key column
}

type plantRef struct{ table, column string }

func newPlanter(t *testing.T, db *store.DB) *planter {
	t.Helper()
	ctx := t.Context()
	p := &planter{t: t, tables: tableColumns(t, db), refs: map[string]map[string]plantRef{}, pks: map[string]string{}}
	for tbl := range p.tables {
		rows, err := db.Reader().QueryContext(ctx, `SELECT name FROM pragma_table_info(?) WHERE pk > 0`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		var pk []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			pk = append(pk, c)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if len(pk) == 1 {
			p.pks[tbl] = pk[0]
		}
	}
	for tbl := range p.tables {
		rows, err := db.Reader().QueryContext(ctx, `SELECT "table", "from", ifnull("to", '') FROM pragma_foreign_key_list(?)`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var r plantRef
			var from string
			if err := rows.Scan(&r.table, &from, &r.column); err != nil {
				t.Fatal(err)
			}
			if r.column == "" {
				r.column = p.pks[r.table]
			}
			if p.refs[tbl] == nil {
				p.refs[tbl] = map[string]plantRef{}
			}
			p.refs[tbl][from] = r
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// value is the planted default of a column: a reference holds the default of the column it references, so both ends agree.
func (p *planter) value(tbl, col string) any {
	for depth := 0; depth < 8; depth++ {
		r, ok := p.refs[tbl][col]
		if !ok || r.column == "" {
			break
		}
		tbl, col = r.table, r.column
	}
	typ := ""
	for _, c := range p.tables[tbl] {
		if c[0] == col {
			typ = strings.ToUpper(c[1])
		}
	}
	switch {
	case strings.Contains(typ, "INT"):
		return int64(900001)
	case strings.Contains(typ, "REAL"), strings.Contains(typ, "FLOA"), strings.Contains(typ, "DOUBLE"):
		return 0.5
	case strings.Contains(typ, "BLOB"):
		return []byte{0x01}
	default:
		return "plant"
	}
}

// begin readies tx for planted rows: foreign keys are checked at the commit, CHECK constraints not at all.
func (p *planter) begin(ctx context.Context, tx *sql.Tx) error {
	for _, q := range []string{"PRAGMA defer_foreign_keys = ON", "PRAGMA ignore_check_constraints = ON"} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// end turns CHECK constraints on again (the setting belongs to the connection, not the transaction).
func (p *planter) end(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, "PRAGMA ignore_check_constraints = OFF")
	return err
}

// write writes one row of tbl with verb (INSERT, INSERT OR IGNORE): the columns of set as given (nil is NULL), every other column
// its planted default. The rows its foreign keys reference are written first when they are not there.
func (p *planter) write(ctx context.Context, tx *sql.Tx, tbl string, set map[string]any, verb string, depth int) error {
	if _, ok := p.tables[tbl]; !ok {
		return fmt.Errorf("no table %s", tbl)
	}
	for c := range set {
		if !slices.ContainsFunc(p.tables[tbl], func(col [2]string) bool { return col[0] == c }) {
			return fmt.Errorf("table %s has no column %s", tbl, c)
		}
	}
	xrows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_xinfo(?) WHERE hidden = 0 ORDER BY cid`, tbl) // not a generated column
	if err != nil {
		return err
	}
	var names []string
	for xrows.Next() {
		var c string
		if err := xrows.Scan(&c); err != nil {
			return err
		}
		names = append(names, c)
	}
	if err := xrows.Close(); err != nil {
		return err
	}
	vals := map[string]any{}
	var cols, marks []string
	var args []any
	for _, c := range names {
		v, given := set[c]
		if !given {
			v = p.value(tbl, c)
		}
		vals[c] = v
		cols, marks, args = append(cols, `"`+c+`"`), append(marks, "?"), append(args, v)
	}
	if depth < 8 {
		for c, r := range p.refs[tbl] {
			v := vals[c]
			if v == nil || r.column == "" || (r.table == tbl && v == vals[r.column]) { // NULL, or a row that references itself
				continue
			}
			if err := p.write(ctx, tx, r.table, map[string]any{r.column: v}, "INSERT OR IGNORE", depth+1); err != nil {
				return err
			}
		}
	}
	q := verb + ` INTO "` + tbl + `" (` + strings.Join(cols, ", ") + `) VALUES (` + strings.Join(marks, ", ") + `)` //nolint:gosec // names read from sqlite_master, quoted
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("plant a row in %s: %w", tbl, err)
	}
	return nil
}

// plantEveryTable writes one row into every data table of db, in one transaction, so that a test over "every table of every
// module" has data in each. It returns the names of the tables, sorted.
func plantEveryTable(t *testing.T, db *store.DB) []string {
	t.Helper()
	ctx := t.Context()
	p := newPlanter(t, db)
	names := make([]string, 0, len(p.tables))
	for tbl := range p.tables {
		names = append(names, tbl)
	}
	slices.Sort(names)
	err := db.Write(ctx, func(tx *sql.Tx) error {
		if err := p.begin(ctx, tx); err != nil {
			return err
		}
		for _, tbl := range names {
			if err := p.write(ctx, tx, tbl, nil, "INSERT OR IGNORE", 0); err != nil { // a referenced row may be there already
				return err
			}
		}
		return p.end(ctx, tx)
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

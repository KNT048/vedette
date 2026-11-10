package logexport

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Rows is a query a module hands to Write to make its Source: every row becomes one JSON line, the columns in
// the order of the SELECT, named as the SELECT names them. The query runs in one read transaction, so the
// rows are a snapshot, and the driver streams them: no more than one row is held. Write the SELECT with the
// columns of the hash chain unchanged (id, ts, ..., prev_hash, hash) and without seq, secrets or anything
// the module does not want in a download; Build scrubs the rest again.
type Rows struct {
	SQL  string
	Args []any
	JSON []string // columns that hold JSON text: embedded as JSON, not as a string
}

// Write runs the query on db (the read pool) and writes the rows to w.
func (q Rows) Write(ctx context.Context, db *sql.DB, w io.Writer) error {
	tx, err := db.BeginTx(ctx, nil) // the read pool is query_only
	if err != nil {
		return fmt.Errorf("logexport: begin read: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only: nothing to commit
	rows, err := tx.QueryContext(ctx, q.SQL, q.Args...)
	if err != nil {
		return fmt.Errorf("logexport: query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	isJSON := make([]bool, len(cols))
	for i, c := range cols {
		for _, j := range q.JSON {
			isJSON[i] = isJSON[i] || j == c
		}
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var line bytes.Buffer
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("logexport: scan: %w", err)
		}
		o := &object{keys: cols, vals: make([]any, len(cols))}
		for i, v := range vals {
			if o.vals[i], err = jsonValue(v, isJSON[i]); err != nil {
				return fmt.Errorf("logexport: column %s: %w", cols[i], err)
			}
		}
		line.Reset()
		writeValue(&line, o)
		line.WriteByte('\n')
		if _, err := w.Write(line.Bytes()); err != nil {
			return err
		}
	}
	return rows.Err()
}

func jsonValue(v any, asJSON bool) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case int64:
		return json.Number(strconv.FormatInt(x, 10)), nil
	case float64:
		return json.Number(strconv.FormatFloat(x, 'g', -1, 64)), nil
	case bool:
		return x, nil
	case time.Time:
		return x.UTC().Format("2006-01-02T15:04:05.000Z"), nil
	case []byte:
		return jsonValue(string(x), asJSON)
	case string:
		if !asJSON {
			return x, nil
		}
		return decodeLine([]byte(x))
	}
	return nil, fmt.Errorf("unsupported type %T", v)
}

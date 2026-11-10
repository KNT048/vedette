package logexport

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/store"
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
	// Chain is the name of the hash chain (core_chain_head.chain: core_audit, ai_activity, resp_log) when the rows are
	// that chain: Write then reads the anchor and the head in the same transaction and calls ReportChain. The SELECT
	// must return prev_hash and hash.
	Chain string
}

// ChainRows is the Rows of a chained table in a date range: from the first row with ts >= from to the last row with
// ts <= to, as one run of seq (a row whose clock stepped back inside that run is kept, so the run still links). The
// table must have seq, ts, prev_hash and hash; table, chain and cols are constants of the module, never user input.
func ChainRows(table, chain, cols string, from, to time.Time) Rows {
	lo, hi := "", ""
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	return Rows{SQL: `SELECT ` + cols + ` FROM ` + table + ` WHERE (? = '' OR seq >= (SELECT min(seq) FROM ` + table + ` WHERE ts >= ?))
		AND (? = '' OR seq <= (SELECT max(seq) FROM ` + table + ` WHERE ts <= ?)) ORDER BY seq`,
		Args: []any{lo, lo, hi, hi}, Chain: chain}
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
	prevAt, hashAt := slices.Index(cols, "prev_hash"), slices.Index(cols, "hash")
	if q.Chain != "" && (prevAt < 0 || hashAt < 0) {
		return errors.New("logexport: a chained SELECT must return prev_hash and hash")
	}
	var line bytes.Buffer
	n, firstPrev, lastHash := 0, "", ""
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
		if q.Chain != "" {
			if n == 0 {
				firstPrev, _ = o.vals[prevAt].(string)
			}
			lastHash, _ = o.vals[hashAt].(string)
		}
		n++
		line.Reset()
		writeValue(&line, o)
		line.WriteByte('\n')
		if _, err := w.Write(line.Bytes()); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_ = rows.Close()
	if q.Chain == "" {
		return nil
	}
	info, err := chainInfo(ctx, tx, q.Chain, n, firstPrev, lastHash)
	if err != nil {
		return err
	}
	ReportChain(ctx, info)
	return nil
}

// chainInfo reads the anchor and the head of the chain in tx and compares them with what was exported.
func chainInfo(ctx context.Context, tx *sql.Tx, name string, n int, firstPrev, lastHash string) (ChainInfo, error) {
	pruned := ""
	err := tx.QueryRowContext(ctx, `SELECT last_pruned_hash FROM core_chain_anchor WHERE chain = ?`, name).Scan(&pruned)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ChainInfo{}, fmt.Errorf("logexport: read anchor of %s: %w", name, err)
	}
	head, err := chainhead.Load(ctx, tx, name)
	if err != nil {
		return ChainInfo{}, err
	}
	start := chain.Genesis
	if pruned != "" {
		start = pruned
	}
	info := ChainInfo{AnchorKind: "none"}
	if head != nil {
		h := head.Hash
		info.HeadHash, info.Count = &h, head.Count
	}
	if n == 0 {
		info.Complete = head == nil || head.Count == 0
		return info, nil
	}
	info.Anchor = &firstPrev
	switch {
	case pruned != "" && firstPrev == pruned:
		info.AnchorKind = "pruned"
	case firstPrev == chain.Genesis:
		info.AnchorKind = "genesis"
	default:
		info.AnchorKind = "row"
	}
	info.Complete = firstPrev == start && head != nil && lastHash == head.Hash && int64(n) == head.Count
	return info, nil
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
		return decodeLine([]byte(x), false)
	}
	return nil, fmt.Errorf("unsupported type %T", v)
}

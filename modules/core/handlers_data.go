package core

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store/coredb"
)

// GET /core/data/export (S-CORE-1, D-154): everything the box stores about the organization as one JSON file, except what
// is secret. core cannot read the tables of other modules by name (MODULES rule), so the file is a dump of every table of the
// database, filtered by the explicit, fail-closed policy of export_policy.go: every column of every table is classified there
// (export, json with secret keys dropped, url cut to scheme and host, skip), and what is not listed is not exported.
// cmd/vedette's TestExport_PolicyClassifiesEveryColumn fails until a new table or column is classified.
const (
	exportFormat        = "vedette-export/1"
	exportMaxBytes      = 256 << 20 // the largest file: over it the file ends early and says so ("truncated")
	exportChunkDeadline = 60 * time.Second
)

// exportCell turns one stored value into the JSON text of the export, by the class of its column. Bytes are never exported.
func exportCell(class exportClass, v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return []byte("null"), nil
	case string:
		switch class {
		case classJSON, classJSONURL:
			clean, err := logexport.Scrub([]byte(x))
			if err != nil || !json.Valid(clean) {
				return []byte("null"), nil //nolint:nilerr // text that is not JSON in a JSON column is not exported: fail closed
			}
			if class == classJSONURL {
				return cutURLKeys(clean), nil
			}
			return clean, nil
		case classURL:
			v = cutURL(x)
		}
	case nil:
	default:
		if class == classJSON || class == classJSONURL {
			return []byte("null"), nil // a number in a JSON column: not the shape the schema promises
		}
	}
	return json.Marshal(v) //nolint:wrapcheck // values from database/sql always marshal
}

// cutURL keeps scheme and host of an http(s) URL: the userinfo, path and query of a webhook, feed or provider address can be
// the secret. Text that is not such a URL is returned as it is; a URL that does not parse becomes "".
func cutURL(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(t), "http://") && !strings.HasPrefix(strings.ToLower(t), "https://") {
		return s
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// cutURLKeys cuts every string value under a key named "url", at any depth, to scheme and host.
func cutURLKeys(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte("null")
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				if s, ok := e.(string); ok && strings.EqualFold(k, "url") {
					t[k] = cutURL(s)
				} else {
					t[k] = walk(e)
				}
			}
		case []any:
			for i, e := range t {
				t[i] = walk(e)
			}
		}
		return x
	}
	out, err := json.Marshal(walk(v))
	if err != nil {
		return []byte("null")
	}
	return out
}

// column is one column of a table as the schema declares it.
type column struct{ Name, Type string }

// quoteIdent quotes an SQL identifier read from sqlite_master.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// dataTables lists the tables that hold data, sorted by name: not SQLite's own and not the migration records, which are the
// schema and stay in every reset. Each comes with its columns.
func dataTables(ctx context.Context, q querier) (map[string][]column, []string, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB 'core_migration_*' ORDER BY name`)
	if err != nil {
		return nil, nil, fmt.Errorf("core: list tables: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("core: list tables: %w", err)
		}
		names = append(names, n)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("core: list tables: %w", err)
	}
	out := make(map[string][]column, len(names))
	for _, n := range names {
		crows, err := q.QueryContext(ctx, `SELECT name, type FROM pragma_table_info(?) ORDER BY cid`, n)
		if err != nil {
			return nil, nil, fmt.Errorf("core: list columns of %s: %w", n, err)
		}
		for crows.Next() {
			var c column
			if err := crows.Scan(&c.Name, &c.Type); err != nil {
				_ = crows.Close()
				return nil, nil, fmt.Errorf("core: list columns of %s: %w", n, err)
			}
			out[n] = append(out[n], c)
		}
		if err := errors.Join(crows.Err(), crows.Close()); err != nil {
			return nil, nil, fmt.Errorf("core: list columns of %s: %w", n, err)
		}
	}
	return out, names, nil
}

// CoreGetCoreDataExport implements GET /core/data/export (admin). The file is written row by row into a pipe while one read
// transaction holds a consistent view, so memory stays at one row whatever the size of the database. At most exportMaxBytes
// are written: the file then ends cleanly (valid JSON) with "truncated": true and the table it stopped in. One export runs
// at a time (409 busy). The row of core_audit is written before the first byte, with the administrator's name (SYS-3).
func (h *APIHandlers) CoreGetCoreDataExport(ctx context.Context) (oas.CoreGetCoreDataExportOK, error) {
	none := oas.CoreGetCoreDataExportOK{}
	c, err := h.caller(ctx)
	if err != nil {
		return none, err
	}
	if !h.exporting.CompareAndSwap(false, true) {
		return none, apierr.New(409, "busy", "Another export is being prepared. Wait for it to finish, then try again.")
	}
	started := false // the body owns the slot (and releases it on Close) once this is true
	defer func() {
		if !started {
			h.exporting.Store(false)
		}
	}()
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "data.export", Target: "JSON export", Detail: fmt.Sprintf("secrets left out; at most %d MiB", h.exportLimit()>>20)})
	})
	if err != nil {
		return none, err
	}
	pr, pw := io.Pipe()
	go func() {
		err := h.writeExport(ctx, pw, h.exportLimit())
		if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, context.Canceled) {
			h.log.ErrorContext(ctx, "data export failed", "error", err)
		}
		pw.CloseWithError(err)
	}()
	b := &exportBody{pr: pr, release: func() { h.exporting.Store(false) }}
	started = true
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", fmt.Sprintf("attachment; filename=vedette-export-%s.json", h.now().UTC().Format(dateLayout)))
		hd.Set("Cache-Control", "no-store")
		x.SetContentType("application/json") // L3: the generated file encoder says octet-stream; this puts the right type back
		b.rc = http.NewResponseController(x.W)
	}
	return oas.CoreGetCoreDataExportOK{Data: b}, nil
}

func (h *APIHandlers) exportLimit() int64 {
	if h.exportCap > 0 {
		return h.exportCap
	}
	return exportMaxBytes
}

// exportBody is the response body: the read side of the pipe, with a write deadline for each chunk so a client that stops
// reading cannot hold the export slot (and the read transaction) for ever.
type exportBody struct {
	pr      *io.PipeReader
	release func()
	rc      *http.ResponseController
	sent    bool
	closed  atomic.Bool
}

func (b *exportBody) Read(p []byte) (int, error) {
	if b.rc != nil {
		_ = b.rc.SetWriteDeadline(time.Now().Add(exportChunkDeadline)) // not every writer supports it: then there is no deadline
	}
	n, err := b.pr.Read(p)
	if n > 0 {
		b.sent = true
	}
	if err != nil && !errors.Is(err, io.EOF) && b.sent {
		panic(http.ErrAbortHandler) // part of the file is out: a clean end would look like a whole file
	}
	return n, err
}

// Close stops the writer and gives the slot back; calling it twice is harmless.
func (b *exportBody) Close() error {
	if b.closed.CompareAndSwap(false, true) {
		defer b.release()
	}
	return b.pr.Close()
}

// capWriter counts what it passes on and refuses what would go over the limit.
type capWriter struct {
	w     *bufio.Writer
	n     int64
	limit int64
}

var errExportFull = errors.New("core: export is over its size cap")

// end writes the closing text of an array or of the file: the 256 bytes kept back from the cap are for it, so it never fails for size.
func (c *capWriter) end(s string) error {
	c.n += int64(len(s))
	_, err := c.w.WriteString(s)
	return err //nolint:wrapcheck // the pipe's own error, the caller returns it as is
}

func (c *capWriter) write(b []byte) error {
	if c.n+int64(len(b)) > c.limit {
		return errExportFull
	}
	c.n += int64(len(b))
	_, err := c.w.Write(b)
	return err //nolint:wrapcheck // the pipe's own error, the caller returns it as is
}

// writeExport writes the whole file to w. A write error (the client left) is returned as is; reaching the limit is not an error.
func (h *APIHandlers) writeExport(ctx context.Context, w io.Writer, limit int64) error {
	tx, err := h.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("core: export: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	org, err := coredb.New(tx).GetOrg(ctx)
	if err != nil && !isNoRows(err) {
		return fmt.Errorf("core: export: read org: %w", err)
	}
	tables, names, err := dataTables(ctx, tx)
	if err != nil {
		return err
	}
	cw := &capWriter{w: bufio.NewWriterSize(w, 64<<10), limit: limit - 256} // 256 bytes are kept for the closing text
	head, err := json.Marshal(map[string]string{"format": exportFormat, "exported_at": h.now().UTC().Format(time.RFC3339), "org": org.Name})
	if err != nil {
		return fmt.Errorf("core: export: head: %w", err)
	}
	if err := cw.write(append(head[:len(head)-1], `,"tables":{`...)); err != nil {
		return err
	}
	stoppedIn := ""
	first := true
	for _, name := range names {
		var cols []string
		var classes []exportClass
		for _, col := range tables[name] {
			if cl := exportClass(ExportColumnClass(name, col.Name)); cl != "" && cl != classSkip && !strings.Contains(strings.ToUpper(col.Type), "BLOB") {
				cols, classes = append(cols, col.Name), append(classes, cl)
			}
		}
		if len(cols) == 0 { // a table or column the policy does not list is not exported (fail closed)
			continue
		}
		stopped, err := h.exportTable(ctx, tx, cw, name, cols, classes, first)
		if err != nil {
			return err
		}
		first = false
		if stopped {
			stoppedIn = name
			break
		}
	}
	tail := `},"truncated":false}`
	if stoppedIn != "" {
		t, _ := json.Marshal(stoppedIn)
		tail = `},"truncated":true,"truncated_in":` + string(t) + `}`
	}
	if err := cw.end(tail); err != nil {
		return err
	}
	return cw.w.Flush()
}

// exportTable writes `"name":[row,...]`. stopped is true when the next row would not fit: the array is closed and the caller ends the file.
func (h *APIHandlers) exportTable(ctx context.Context, tx *sql.Tx, cw *capWriter, name string, cols []string, classes []exportClass, first bool) (stopped bool, err error) {
	quoted := make([]string, len(cols))
	keys := make([][]byte, len(cols))
	for i, c := range cols {
		quoted[i] = quoteIdent(c)
		k, _ := json.Marshal(c)
		keys[i] = k
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(quoted, ", ")+" FROM "+quoteIdent(name)) //nolint:gosec // names come from sqlite_master and are quoted
	if err != nil {
		return false, fmt.Errorf("core: export %s: %w", name, err)
	}
	defer func() { _ = rows.Close() }()
	nameJSON, _ := json.Marshal(name)
	open := `"` + string(nameJSON[1:len(nameJSON)-1]) + `":[`
	if !first {
		open = "," + open
	}
	if err := cw.write([]byte(open)); err != nil {
		if errors.Is(err, errExportFull) { // not even the name of the table fits: the file ends before it
			return true, nil
		}
		return false, err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var buf []byte
	for n := 0; rows.Next(); n++ {
		if err := rows.Scan(ptrs...); err != nil {
			return false, fmt.Errorf("core: export %s: %w", name, err)
		}
		buf = buf[:0]
		if n > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '{')
		for i, v := range vals {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, keys[i]...)
			buf = append(buf, ':')
			j, err := exportCell(classes[i], v)
			if err != nil {
				return false, fmt.Errorf("core: export %s: %w", name, err)
			}
			buf = append(buf, j...)
		}
		buf = append(buf, '}')
		if err := cw.write(buf); err != nil {
			if errors.Is(err, errExportFull) {
				return true, cw.end("]")
			}
			return false, err
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("core: export %s: %w", name, err)
	}
	return false, cw.end("]")
}

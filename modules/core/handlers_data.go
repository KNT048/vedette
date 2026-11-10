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
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store/coredb"
)

// GET /core/data/export (S-CORE-1, D-154): everything the box stores about the organization as one JSON file, except what
// is secret. core cannot read the tables of other modules by name (MODULES rule), so the file is a dump of every table of the
// database, with a policy that is safe by default: whole tables that only hold secrets or sign-in state are left out, and so is
// every column whose name looks like a secret (ExportColumnSkipped) or that holds bytes. A new module's table is exported;
// a new column that looks like a secret is not. cmd/vedette's TestExport_PolicyCoversEverySchemaColumn lists what is left out.
const (
	exportFormat        = "vedette-export/1"
	exportMaxBytes      = 256 << 20 // the largest file: over it the file ends early and says so ("truncated")
	exportChunkDeadline = 60 * time.Second
)

// exportSkipTables hold only secrets (ciphertext), sign-in state (token and code hashes) or protocol nonces; none is "my data".
var exportSkipTables = map[string]bool{
	"core_secret":          true, // the ciphertext of every secret, with its nonce
	"core_session":         true, // token and CSRF hashes of the signed-in sessions
	"core_user_totp":       true, // the TOTP seed (as a reference to core_secret) and the last accepted step
	"core_email_code":      true, // hashes of the one-time email codes
	"core_email_code_send": true, // their send log, used for rate limits only
	"core_sensor_cert":     true, // serials of issued sensor certificates: link state, not data
	"notify_tg_button":     true, // nonce hashes of Telegram approval buttons
	"resp_tokens":          true, // token hashes of approval links
}

var (
	exportSecretColumnRE = regexp.MustCompile(`(?i)secret|passw|token|nonce|cipher|totp|csrf|salt|credential|private|api_?key|_hash$`)
	// exportKeepColumns look like secrets by name but are public: the hash chain of the audit logs (so the file verifies offline),
	// a reference to a honeytoken row, and the last four characters of a secret, which the interface shows too.
	exportKeepColumns = map[string]bool{"hash": true, "prev_hash": true, "last_hash": true, "last_pruned_hash": true, "token_id": true}
)

// ExportTableSkipped reports whether a whole table stays out of the export. Exported so the binary's test can check the policy against
// the schema of every module.
func ExportTableSkipped(name string) bool { return exportSkipTables[name] }

// ExportColumnSkipped reports whether a column stays out of the export: bytes (a nonce, a ciphertext) and every name that
// looks like a secret, except the public ones above and "*_last4".
func ExportColumnSkipped(name, declType string) bool {
	if strings.Contains(strings.ToUpper(declType), "BLOB") {
		return true
	}
	if strings.HasSuffix(name, "_last4") || exportKeepColumns[name] {
		return false
	}
	return exportSecretColumnRE.MatchString(name)
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
	go func() { pw.CloseWithError(h.writeExport(ctx, pw, h.exportLimit())) }()
	b := &exportBody{pr: pr, release: func() { h.exporting.Store(false) }}
	started = true
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", fmt.Sprintf("attachment; filename=vedette-export-%s.json", h.now().UTC().Format(dateLayout)))
		hd.Set("Cache-Control", "no-store")
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
		for _, col := range tables[name] {
			if !ExportColumnSkipped(col.Name, col.Type) {
				cols = append(cols, col.Name)
			}
		}
		if ExportTableSkipped(name) || len(cols) == 0 {
			continue
		}
		stopped, err := h.exportTable(ctx, tx, cw, name, cols, first)
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
	cw.limit += 256
	if err := cw.write([]byte(tail)); err != nil {
		return err
	}
	return cw.w.Flush()
}

// exportTable writes `"name":[row,...]`. stopped is true when the next row would not fit: the array is closed and the caller ends the file.
func (h *APIHandlers) exportTable(ctx context.Context, tx *sql.Tx, cw *capWriter, name string, cols []string, first bool) (stopped bool, err error) {
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
			if _, ok := v.([]byte); ok { // bytes in a column the schema did not declare as a blob: never exported
				v = nil
			}
			j, err := json.Marshal(v)
			if err != nil {
				return false, fmt.Errorf("core: export %s: %w", name, err)
			}
			buf = append(buf, j...)
		}
		buf = append(buf, '}')
		if err := cw.write(buf); err != nil {
			if errors.Is(err, errExportFull) {
				return true, cw.write([]byte("]"))
			}
			return false, err
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("core: export %s: %w", name, err)
	}
	return false, cw.write([]byte("]"))
}

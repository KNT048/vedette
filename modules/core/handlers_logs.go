package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/server"
)

// Error codes of GET /core/logs/export, the ones of the mock (web/src/features/core/logExport.ts).
const (
	CodeInvalidCategories = "invalid_categories"
	CodeInvalidFormat     = "invalid_format"
	CodeInvalidRange      = "invalid_range"
	CodeLogsTooLarge      = "logs_too_large" // not too_large: that code means "the request body is over the limit" (API_CONVENTIONS 3.2 rule 5)
)

// logExportMaxBytes caps the scrubbed rows of one export (INV-13). Over it the answer is 413 too_large and
// nothing is sent or audited: the admin narrows the dates or picks fewer categories. The rows are spooled
// to disk while they are read, so memory stays at one row whatever the size of the logs.
const logExportMaxBytes = 128 << 20

const (
	logExportGap           = time.Minute      // at most one export starts per minute (INV-19, like the backup download)
	logExportChunkDeadline = 60 * time.Second // a client that takes longer than this for one chunk is cut off
)

// CoreGetCoreLogsExport implements GET /core/logs/export (admin, S-CORE-6, D-48): the chosen log categories
// as one JSON or CSV file. Each category comes from the source its module registered (core/logexport); one
// without a source is empty and listed as missing. The download is itself a row of core_audit (D-72).
func (h *APIHandlers) CoreGetCoreLogsExport(ctx context.Context, params oas.CoreGetCoreLogsExportParams) (oas.CoreGetCoreLogsExportOK, error) {
	none := oas.CoreGetCoreLogsExportOK{}
	c, err := h.caller(ctx)
	if err != nil {
		return none, err
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range strings.Split(params.Categories.Or(""), ",") {
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			if !logexport.Valid(id) {
				return none, apierr.New(400, CodeInvalidCategories, fmt.Sprintf("Unknown log category %q.", cutAtRune(id, 40)))
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return none, apierr.New(400, CodeInvalidCategories, "Pick at least one log category to download.")
	}
	format := logexport.Format(params.Format.Or("json"))
	if format != logexport.JSON && format != logexport.CSV {
		return none, apierr.New(400, CodeInvalidFormat, "Choose JSON or CSV.")
	}
	fromDay, toDay := strings.TrimSpace(params.From.Or("")), strings.TrimSpace(params.To.Or(""))
	loc, err := h.orgLocation(ctx)
	if err != nil {
		return none, err
	}
	req := logexport.Request{Dir: h.logsDir, TimeZone: loc.String(), Categories: ids, FromDay: fromDay, ToDay: toDay, Format: format, MaxBytes: h.logsCap, ExportedAt: h.now()}
	if req.MaxBytes == 0 {
		req.MaxBytes = logExportMaxBytes
	}
	if fromDay != "" {
		if req.From, err = parseDay(fromDay, loc, false); err != nil {
			return none, err
		}
	}
	if toDay != "" {
		if req.To, err = parseDay(toDay, loc, true); err != nil {
			return none, err
		}
	}
	if fromDay != "" && toDay != "" && fromDay > toDay {
		return none, apierr.New(400, CodeInvalidRange, "The start date is after the end date.")
	}

	retry, ok := h.startLogExport()
	if !ok {
		code, status, msg := "busy", 409, "Another log download is being prepared. Wait for it to finish, then try again."
		if retry > 0 {
			code, status, msg = "rate_limited", 429, "Log downloads are limited to one a minute. Wait a moment, then try again."
		}
		if err := h.logsRefused(ctx, c, ids, string(format), code); err != nil {
			return none, err
		}
		e := apierr.New(status, code, msg)
		if retry > 0 {
			e = e.With("retry_after", retry)
		}
		return none, e
	}
	released := false
	release := func() {
		if !released {
			released = true
			h.logsMu.Lock()
			h.logsBusy = false
			h.logsMu.Unlock()
		}
	}
	handedOver := false // the response owns the slot (and releases it on Close) once this is true
	defer func() {
		if !handedOver {
			release()
		}
	}()

	exp, err := h.logs.Build(ctx, req)
	if errors.Is(err, logexport.ErrTooLarge) {
		if aerr := h.logsRefused(ctx, c, ids, string(format), "too_large: over 128 MiB"); aerr != nil {
			return none, aerr
		}
		return none, apierr.New(413, CodeLogsTooLarge, "These logs are over 128 MB. Choose a shorter date range or fewer categories.")
	}
	if err != nil {
		return none, err
	}
	detail := fmt.Sprintf("%s; %d rows", format, exp.Rows)
	if fromDay != "" {
		detail += "; from " + fromDay
	}
	if toDay != "" {
		detail += "; to " + toDay
	}
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "logs.export", Target: strings.Join(ids, ","), Detail: cutAtRune(detail, auditMaxDetail)})
	})
	if err != nil {
		_ = exp.Close()
		return none, err
	}
	d := &download{exp: exp, release: release}
	handedOver = true
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", fmt.Sprintf("attachment; filename=vedette-logs-%s.%s", h.now().UTC().Format(dateLayout), format))
		hd.Set("Cache-Control", "no-store")
		d.rc = http.NewResponseController(x.W)
	}
	// The response encoder closes Data when it is done (or when the client is gone), which removes the spool.
	return oas.CoreGetCoreLogsExportOK{Data: d}, nil
}

// startLogExport takes the one export slot. ok is false when another export is running (retry 0) or the last one
// started less than a minute ago (retry = seconds to wait).
func (h *APIHandlers) startLogExport() (retry int, ok bool) {
	h.logsMu.Lock()
	defer h.logsMu.Unlock()
	if h.logsBusy {
		return 0, false
	}
	gap := h.logsGap
	if gap == 0 {
		gap = logExportGap
	}
	now := h.now()
	if gap > 0 && !h.logsLast.IsZero() && now.Sub(h.logsLast) < gap {
		return int((gap - now.Sub(h.logsLast)).Seconds()) + 1, false
	}
	h.logsBusy, h.logsLast = true, now
	return 0, true
}

// logsRefused records an export that was asked for and refused (busy, rate limited, over the cap), so a refusal
// leaves a trace like a download does (D-72). It re-checks the caller as every admin write does.
func (h *APIHandlers) logsRefused(ctx context.Context, c caller, ids []string, format, reason string) error {
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "logs.export_refused", Target: strings.Join(ids, ","), Detail: cutAtRune(format+"; "+reason, auditMaxDetail)})
	})
}

// download is the body of the response: the finished file, read with a write deadline of its own for each chunk so a
// client that stops reading cannot hold the export slot (and the spool) for ever. Close frees both.
type download struct {
	exp     *logexport.Export
	release func()
	rc      *http.ResponseController
	sent    bool
}

func (d *download) Read(p []byte) (int, error) {
	if d.rc != nil {
		_ = d.rc.SetWriteDeadline(time.Now().Add(logExportChunkDeadline)) // not supported by every writer: then there is no deadline
	}
	n, err := d.exp.Read(p)
	if n > 0 {
		d.sent = true
	}
	if err != nil && !errors.Is(err, io.EOF) && d.sent {
		// The 200 and part of the file are out: a clean end would look like a whole file. Abort the connection.
		panic(http.ErrAbortHandler)
	}
	return n, err
}

// Close removes the spool and gives the export slot back.
func (d *download) Close() error {
	err := d.exp.Close()
	d.release()
	return err
}

// prepareSpoolDir creates the spool directory (0700) and removes what an earlier run left in it.
func prepareSpoolDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("core: log export spool dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory: owner only
		return fmt.Errorf("core: log export spool dir: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("core: log export spool dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), logexport.SpoolPrefix) {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("core: log export spool dir: %w", err)
			}
		}
	}
	return nil
}

// parseDay reads a YYYY-MM-DD day of the organization: the start of it, or with end the last millisecond.
func parseDay(s string, loc *time.Location, end bool) (time.Time, error) {
	if !dateOnlyRE.MatchString(s) {
		return time.Time{}, apierr.New(400, CodeInvalidRange, "Dates are written YYYY-MM-DD, for example 2026-11-09, between 2000 and 2100.")
	}
	t, err := time.ParseInLocation(dateLayout, s, loc)
	if err != nil || t.Year() < 2000 || t.Year() > 2100 {
		return time.Time{}, apierr.New(400, CodeInvalidRange, "Dates are written YYYY-MM-DD, for example 2026-11-09, between 2000 and 2100.")
	}
	if end {
		t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
	}
	return t, nil
}

// exportAudit is the source of the "audit" category: core_audit in order, with its chain fields as stored
// (id, prev_hash, hash and the columns the hash covers), so the file verifies offline (core INV-2, INV-13), and
// the anchor and head of the chain read in the same transaction (logexport.ChainInfo).
func (h *APIHandlers) exportAudit(ctx context.Context, from, to time.Time, w io.Writer) error {
	return logexport.ChainRows("core_audit", "core_audit", "id, prev_hash, hash, ts, user, action, target, detail", from, to).Write(ctx, h.db.Reader(), w)
}

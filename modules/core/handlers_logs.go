package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
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
	req := logexport.Request{Categories: ids, FromDay: fromDay, ToDay: toDay, Format: format, MaxBytes: h.logsCap, ExportedAt: h.now()}
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

	exp, err := h.logs.Build(ctx, req)
	if errors.Is(err, logexport.ErrTooLarge) {
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
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", fmt.Sprintf("attachment; filename=vedette-logs-%s.%s", h.now().UTC().Format(dateLayout), format))
		hd.Set("Cache-Control", "no-store")
	}
	// The response encoder closes Data when it is done, which removes the spool.
	return oas.CoreGetCoreLogsExportOK{Data: exp}, nil
}

// parseDay reads a YYYY-MM-DD day of the organization: the start of it, or with end the last millisecond.
func parseDay(s string, loc *time.Location, end bool) (time.Time, error) {
	if !dateOnlyRE.MatchString(s) {
		return time.Time{}, apierr.New(400, CodeInvalidRange, "Dates are written YYYY-MM-DD, for example 2026-11-09.")
	}
	t, err := time.ParseInLocation(dateLayout, s, loc)
	if err != nil {
		return time.Time{}, apierr.New(400, CodeInvalidRange, "Dates are written YYYY-MM-DD, for example 2026-11-09.")
	}
	if end {
		t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
	}
	return t, nil
}

// exportAudit is the source of the "audit" category: core_audit in order, with its chain fields as stored
// (id, prev_hash, hash and the columns the hash covers), so the file verifies offline (core INV-2, INV-13).
func (h *APIHandlers) exportAudit(ctx context.Context, from, to time.Time, w io.Writer) error {
	lo, hi := "", ""
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	return logexport.Rows{SQL: `SELECT id, prev_hash, hash, ts, user, action, target, detail FROM core_audit
		WHERE (? = '' OR ts >= ?) AND (? = '' OR ts <= ?) ORDER BY seq`, Args: []any{lo, lo, hi, hi}}.Write(ctx, h.db.Reader(), w)
}

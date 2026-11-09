package core

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Error codes of the general settings and the audit filters. The audit ones are invalid_from and invalid_to
// (not bad_from and bad_to): API_CONVENTIONS 3.2 rule 5 gives one meaning to a code, and bad_from/bad_to
// already mean "the sender/recipient email is not valid" in notify.
const (
	CodeInvalidTimezone = "invalid_timezone"
	CodeInvalidFrom     = "invalid_from"
	CodeInvalidTo       = "invalid_to"
)

const (
	auditPageRows    = 200  // GET /core/audit returns at most this many rows
	auditExportPage  = 1000 // rows the export reads per query
	auditMaxNeedle   = 200  // longest text filter
	tsLayout         = "2006-01-02T15:04:05.000Z"
	dateLayout       = "2006-01-02"
	auditExportBOM   = "\ufeff"
	auditExportTitle = "time,user,action,target,detail"
)

var dateOnlyRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// auditFilter is the SQL form of the query of GET /core/audit and /core/audit/export: nil or a string each.
type auditFilter struct {
	from, to, who, grp, needle any
	text                       string // the filters as typed, for the audit row of an export
}

// orgLocation is the time zone of the organization (a date in a filter is a day there).
func (h *APIHandlers) orgLocation(ctx context.Context) (*time.Location, error) {
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if isNoRows(err) {
		return time.UTC, nil
	}
	if err != nil {
		return nil, fmt.Errorf("core: read org: %w", err)
	}
	loc, err := time.LoadLocation(org.Timezone)
	if err != nil {
		return time.UTC, nil // a zone stored by an older build that this one does not know
	}
	return loc, nil
}

// parseAuditBound reads one end of the date range: a day (YYYY-MM-DD, in the organization's zone; the
// start of the day for from, the last millisecond of it for to) or a timestamp in UTC written with a Z.
// An offset (+07:00) is refused: the stored timestamps are UTC and a client that means another zone should
// say a day or convert.
func parseAuditBound(s string, loc *time.Location, end bool) (string, bool) {
	if dateOnlyRE.MatchString(s) {
		t, err := time.ParseInLocation(dateLayout, s, loc)
		if err != nil {
			return "", false
		}
		if end {
			t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
		}
		return store.FormatTS(t), true
	}
	if !strings.HasSuffix(s, "Z") {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return "", false
	}
	return store.FormatTS(t), true
}

func (h *APIHandlers) auditFilter(ctx context.Context, q, user, group, from, to oas.OptString) (auditFilter, error) {
	var f auditFilter
	var parts []string
	set := func(name string, v oas.OptString) string {
		s := strings.TrimSpace(v.Or(""))
		if s != "" {
			parts = append(parts, name+"="+s)
		}
		return s
	}
	if s := set("q", q); s != "" {
		if len(s) > auditMaxNeedle {
			return f, apierr.Invalid("The search text is too long (at most 200 characters).")
		}
		f.needle = strings.ToLower(s)
	}
	if s := set("user", user); s != "" {
		f.who = s
	}
	if s := set("group", group); s != "" {
		f.grp = s
	}
	fromS, toS := set("from", from), set("to", to)
	if fromS != "" || toS != "" {
		loc, err := h.orgLocation(ctx)
		if err != nil {
			return f, err
		}
		if fromS != "" {
			v, ok := parseAuditBound(fromS, loc, false)
			if !ok {
				return f, apierr.New(400, CodeInvalidFrom, "The start of the range must be a date like 2026-11-09 or a UTC time ending in Z, like 2026-11-09T00:00:00Z.")
			}
			f.from = v
		}
		if toS != "" {
			v, ok := parseAuditBound(toS, loc, true)
			if !ok {
				return f, apierr.New(400, CodeInvalidTo, "The end of the range must be a date like 2026-11-09 or a UTC time ending in Z, like 2026-11-09T23:59:59Z.")
			}
			f.to = v
		}
	}
	f.text = strings.Join(parts, " ")
	return f, nil
}

func (f auditFilter) list(ctx context.Context, q *coredb.Queries, before, limit int64) ([]coredb.ListAuditFilteredRow, error) {
	return q.ListAuditFiltered(ctx, coredb.ListAuditFilteredParams{BeforeSeq: before, FromTs: f.from, ToTs: f.to, Who: f.who, Grp: f.grp, Needle: f.needle, MaxRows: limit})
}

// CoreGetCoreAudit implements GET /core/audit (admin): the newest rows that match, at most 200, with the
// total number of matches and the users and groups present in the log (for the filter lists).
func (h *APIHandlers) CoreGetCoreAudit(ctx context.Context, params oas.CoreGetCoreAuditParams) (*oas.CoreGetCoreAuditOK, error) {
	f, err := h.auditFilter(ctx, params.Q, params.User, params.Group, params.From, params.To)
	if err != nil {
		return nil, err
	}
	// One read transaction so the rows, the total and the lists describe the same moment.
	tx, err := h.db.Reader().BeginTx(ctx, nil) // the reader pool is query_only already
	if err != nil {
		return nil, fmt.Errorf("core: begin read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := coredb.New(tx)
	top, err := q.MaxAuditSeq(ctx)
	if err != nil {
		return nil, fmt.Errorf("core: audit head: %w", err)
	}
	rows, err := f.list(ctx, q, top+1, auditPageRows)
	if err != nil {
		return nil, fmt.Errorf("core: list audit: %w", err)
	}
	total, err := q.CountAuditFiltered(ctx, coredb.CountAuditFilteredParams{UptoSeq: top, FromTs: f.from, ToTs: f.to, Who: f.who, Grp: f.grp, Needle: f.needle})
	if err != nil {
		return nil, fmt.Errorf("core: count audit: %w", err)
	}
	users, err := q.ListAuditUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("core: audit users: %w", err)
	}
	groups, err := q.ListAuditGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("core: audit groups: %w", err)
	}
	out := &oas.CoreGetCoreAuditOK{Items: make([]oas.CoreGetCoreAuditOKItemsItem, 0, len(rows)), Total: float64(total), Users: users, Groups: groups}
	for _, r := range rows {
		ts, perr := time.Parse(tsLayout, r.Ts)
		if perr != nil {
			return nil, fmt.Errorf("core: audit row %s has a bad timestamp: %w", r.ID, perr)
		}
		it := oas.CoreGetCoreAuditOKItemsItem{ID: r.ID, Ts: ts, User: r.User, Action: r.Action, Target: r.Target}
		if r.Detail != nil {
			it.Detail = oas.NewOptString(*r.Detail)
		}
		out.Items = append(out.Items, it)
	}
	return out, nil
}

// CoreGetCoreAuditExport implements GET /core/audit/export (admin): the matching rows as CSV, newest first,
// no 200-row limit. The download is itself a row of core_audit (INV-2, D-48), written before the file is
// read, so the file is a snapshot that ends at that row. The rows are read page by page while the response
// is written, so a large log is never held in memory.
func (h *APIHandlers) CoreGetCoreAuditExport(ctx context.Context, params oas.CoreGetCoreAuditExportParams) (oas.CoreGetCoreAuditExportOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return oas.CoreGetCoreAuditExportOK{}, err
	}
	f, err := h.auditFilter(ctx, params.Q, params.User, params.Group, params.From, params.To)
	if err != nil {
		return oas.CoreGetCoreAuditExportOK{}, err
	}
	detail := "csv"
	if f.text != "" {
		detail += "; filters " + f.text
	}
	if len(detail) > 1000 {
		detail = detail[:1000]
	}
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "audit.export", Target: "core_audit", Detail: detail})
	})
	if err != nil {
		return oas.CoreGetCoreAuditExportOK{}, err
	}
	top, err := coredb.New(h.db.Reader()).MaxAuditSeq(ctx)
	if err != nil {
		return oas.CoreGetCoreAuditExportOK{}, fmt.Errorf("core: audit head: %w", err)
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		x.W.Header().Set("Content-Disposition", `attachment; filename="vedette-audit.csv"`)
	}
	return oas.CoreGetCoreAuditExportOK{Data: &auditCSV{ctx: ctx, q: coredb.New(h.db.Reader()), f: f, next: top + 1, buf: *bytes.NewBufferString(auditExportBOM + auditExportTitle + "\r\n")}}, nil
}

// auditCSV is an io.Reader over the matching audit rows: each time its buffer runs dry it reads the next
// page below the last seq it has seen.
type auditCSV struct {
	ctx  context.Context
	q    *coredb.Queries
	f    auditFilter
	next int64 // the next page holds rows with seq below this
	done bool
	buf  bytes.Buffer
}

func (a *auditCSV) Read(p []byte) (int, error) {
	for a.buf.Len() == 0 {
		if a.done {
			return 0, io.EOF
		}
		rows, err := a.f.list(a.ctx, a.q, a.next, auditExportPage)
		if err != nil {
			return 0, fmt.Errorf("core: read audit page: %w", err)
		}
		for _, r := range rows {
			d := ""
			if r.Detail != nil {
				d = *r.Detail
			}
			a.buf.WriteString(strings.Join([]string{csvCell(r.Ts), csvCell(r.User), csvCell(r.Action), csvCell(r.Target), csvCell(d)}, ","))
			a.buf.WriteString("\r\n")
			a.next = r.Seq
		}
		if len(rows) < auditExportPage {
			a.done = true
		}
	}
	return a.buf.Read(p)
}

// csvCell quotes a CSV field and defuses spreadsheet formulas: a cell that starts with = + - @ tab or CR is
// read as a formula by Excel and friends, so it gets a leading apostrophe and stays text.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		v = "'" + v
	}
	if strings.ContainsAny(v, ",\"\r\n") {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

// CoreGetCoreGeneral implements GET /core/general (viewer).
func (h *APIHandlers) CoreGetCoreGeneral(ctx context.Context) (*oas.CoreGetCoreGeneralOK, error) {
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if isNoRows(err) {
		return &oas.CoreGetCoreGeneralOK{Name: "", Timezone: defaultTimezone}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("core: read org: %w", err)
	}
	return &oas.CoreGetCoreGeneralOK{Name: org.Name, Timezone: org.Timezone}, nil
}

// validTimezone accepts an IANA zone name this box knows (the compiled-in list of time/tzdata).
func validTimezone(s string) bool {
	if s == "" || len(s) > 64 || s == "Local" {
		return false
	}
	_, err := time.LoadLocation(s)
	return err == nil
}

// CorePutCoreGeneral implements PUT /core/general (admin): organization name and time zone.
func (h *APIHandlers) CorePutCoreGeneral(ctx context.Context, req *oas.CorePutCoreGeneralReq) (*oas.CorePutCoreGeneralOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if !validOrgName(name) {
		return nil, apierr.New(400, CodeInvalidOrg, "The organization name is 2 to 80 characters.")
	}
	if !validTimezone(req.Timezone) {
		return nil, apierr.New(400, CodeInvalidTimezone, "The time zone is not a known name, for example Asia/Ho_Chi_Minh or UTC.")
	}
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		n, err := coredb.New(tx).UpdateOrgGeneral(ctx, coredb.UpdateOrgGeneralParams{Name: name, Timezone: req.Timezone})
		if err != nil {
			return fmt.Errorf("core: update org: %w", err)
		}
		if n == 0 {
			return apierr.NotFound() // setup has not run: nothing to change
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "core.general", Target: name, Detail: "time zone " + req.Timezone})
	})
	if err != nil {
		return nil, err
	}
	return &oas.CorePutCoreGeneralOK{Name: name, Timezone: req.Timezone}, nil
}

package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// ---- settings ----

// defaultSettings keeps the execution switch OFF (INV-7).
func defaultSettings() Settings {
	return Settings{
		MaxPerHour: 3, ExpiryMin: 15, ApprovalChannels: []string{}, BreakerMaxPerHour: 20, BreakerNotified: []string{}, MultiTargetMax: 5, Maintenance: []Window{},
		AI: AiGates{Triggers: []string{"ioc_connection", "finding"}, BudgetHour: 2, BudgetDay: 5},
	}
}

func loadSettings(ctx context.Context, q dbq) (Settings, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT value FROM resp_settings WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultSettings(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("response: read settings: %w", err)
	}
	s := defaultSettings()
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return Settings{}, fmt.Errorf("response: parse settings: %w", err)
	}
	if s.ApprovalChannels == nil {
		s.ApprovalChannels = []string{}
	}
	if s.BreakerNotified == nil {
		s.BreakerNotified = []string{}
	}
	if s.Maintenance == nil {
		s.Maintenance = []Window{}
	}
	if s.AI.Triggers == nil {
		s.AI.Triggers = []string{}
	}
	return s, nil
}

func (s *Service) saveSettings(ctx context.Context, tx *sql.Tx, st Settings) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO resp_settings (id, value, updated_at) VALUES (1, ?, ?) ON CONFLICT (id) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		mustJSON(st), s.ts())
	if err != nil {
		return fmt.Errorf("response: save settings: %w", err)
	}
	return nil
}

// ---- allow list ----

func loadAllow(ctx context.Context, q dbq) ([]AllowEntry, error) {
	rows, err := q.QueryContext(ctx, `SELECT value, label FROM resp_allowlist ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("response: read the never-touch list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []AllowEntry{}
	for rows.Next() {
		var e AllowEntry
		if err := rows.Scan(&e.Value, &e.Label); err != nil {
			return nil, fmt.Errorf("response: read the never-touch list: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// errNeverTouchUnread is what neverTouch returns when part of the list cannot be built. The callers refuse the action (fail
// closed) rather than go on with a shorter list.
var errNeverTouchUnread = errors.New("response: the never-touch list could not be read in full")

// neverTouchGateways are the inventory kinds whose devices count as never-touch without being listed: in practice they are
// the gateways (INV-10). The gateway and DNS addresses read from the host's network state come with WP-07b part 3.
var neverTouchGateways = []string{"router", "firewall"}

// neverTouch is the declared list, the box's own addresses and every inventory router and firewall (INV-10). The box's
// addresses and the inventory are read at every call. When either cannot be read the error wraps errNeverTouchUnread.
func (s *Service) neverTouch(ctx context.Context, q dbq) ([]AllowEntry, error) {
	l, err := loadAllow(ctx, q)
	if err != nil {
		return nil, err
	}
	box, err := s.boxAddrs()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNeverTouchUnread, err)
	}
	l = append(l, boxEntries(box)...)
	if s.cfg.Directory == nil {
		return l, nil
	}
	gws, err := s.cfg.Directory.DevicesOfKind(ctx, neverTouchGateways...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNeverTouchUnread, err)
	}
	for _, d := range gws {
		label := "Router or firewall " + truncRunes(cleanLine(d.Name), 60)
		if ip, ok := CheckValue(PIP, d.IP); ok {
			l = append(l, AllowEntry{Value: ip, Label: label})
		}
		if mac, ok := CheckValue(PMAC, d.MAC); ok {
			l = append(l, AllowEntry{Value: mac, Label: label})
		}
	}
	return l, nil
}

// neverTouchOrRefusal is neverTouch for the callers that refuse an action: an unreadable list is a refusal with a plain
// reason (409 never_touch, nothing is requested or run), any other failure is an error.
func (s *Service) neverTouchOrRefusal(ctx context.Context, q dbq) ([]AllowEntry, *apierr.Error, error) {
	l, err := s.neverTouch(ctx, q)
	if errors.Is(err, errNeverTouchUnread) {
		return nil, fail(http.StatusConflict, "never_touch", "The never-touch list could not be read in full (this box's own addresses or the inventory are not available), so nothing was changed."), nil
	}
	return l, nil, err
}

// ---- catalog ----

// catRow is a stored catalog action.
type catRow struct {
	ID             string
	Builtin        bool
	Pack           string
	Kind           string
	Name           string
	Description    string
	ConnectionID   string
	Tool           string
	RollbackTool   string
	Run            Tpl
	Rollback       Tpl
	Verify         Tpl
	Precheck       Tpl      // D-95: a read-only template that runs right before Run
	PrecheckRefuse []string // D-95: texts that make the check refuse; never nil
	PrecheckExpect string   // D-95: text the output of the check must contain; empty = none
	Risk           Risk
	Enabled        bool
	AIMayPropose   bool
}

func (c catRow) params() []ParamType { return tplParams(c.Run, c.Rollback, c.Verify, c.Precheck) }
func (c catRow) reversible() bool    { return !c.Rollback.Empty() }
func (c catRow) device() bool        { return c.Kind == "device" }

const catCols = `id, builtin, pack, kind, name, description, connection_id, tool, rollback_tool, run, rollback, verify, precheck, precheck_refuse, precheck_expect, risk, enabled, ai_may_propose`

type scanner interface{ Scan(dest ...any) error }

func scanCat(r scanner) (catRow, error) {
	var c catRow
	var conn, tool, rtool sql.NullString
	var run, rb, vf, pre, refuse, expect, risk string
	if err := r.Scan(&c.ID, &c.Builtin, &c.Pack, &c.Kind, &c.Name, &c.Description, &conn, &tool, &rtool, &run, &rb, &vf, &pre, &refuse, &expect, &risk, &c.Enabled, &c.AIMayPropose); err != nil {
		return catRow{}, err
	}
	c.ConnectionID, c.Tool, c.RollbackTool, c.Risk = conn.String, tool.String, rtool.String, Risk(risk)
	if err := json.Unmarshal([]byte(run), &c.Run); err != nil {
		return catRow{}, err
	}
	if err := json.Unmarshal([]byte(rb), &c.Rollback); err != nil {
		return catRow{}, err
	}
	if err := json.Unmarshal([]byte(vf), &c.Verify); err != nil {
		return catRow{}, err
	}
	c.PrecheckExpect = expect
	if err := json.Unmarshal([]byte(pre), &c.Precheck); err != nil {
		return catRow{}, err
	}
	if err := json.Unmarshal([]byte(refuse), &c.PrecheckRefuse); err != nil {
		return catRow{}, err
	}
	if c.PrecheckRefuse == nil {
		c.PrecheckRefuse = []string{}
	}
	return c, nil
}

func loadCatalog(ctx context.Context, q dbq) ([]catRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+catCols+` FROM resp_catalog ORDER BY position, rowid`)
	if err != nil {
		return nil, fmt.Errorf("response: read the catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []catRow
	for rows.Next() {
		c, err := scanCat(rows)
		if err != nil {
			return nil, fmt.Errorf("response: read the catalog: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func loadCat(ctx context.Context, q dbq, id string) (catRow, bool, error) {
	c, err := scanCat(q.QueryRowContext(ctx, `SELECT `+catCols+` FROM resp_catalog WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return catRow{}, false, nil
	}
	if err != nil {
		return catRow{}, false, fmt.Errorf("response: read an action: %w", err)
	}
	return c, true, nil
}

func saveCat(ctx context.Context, tx *sql.Tx, c catRow, position int) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO resp_catalog (`+catCols+`, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET name = excluded.name, description = excluded.description, connection_id = excluded.connection_id, tool = excluded.tool, rollback_tool = excluded.rollback_tool,
  run = excluded.run, rollback = excluded.rollback, verify = excluded.verify, precheck = excluded.precheck, precheck_refuse = excluded.precheck_refuse, precheck_expect = excluded.precheck_expect, risk = excluded.risk, enabled = excluded.enabled, ai_may_propose = excluded.ai_may_propose`,
		c.ID, boolInt(c.Builtin), c.Pack, c.Kind, c.Name, c.Description, nullable(c.ConnectionID), nullable(c.Tool), nullable(c.RollbackTool),
		mustJSON(c.Run), mustJSON(c.Rollback), mustJSON(c.Verify), mustJSON(c.Precheck), mustJSON(nonNilStrings(c.PrecheckRefuse)), c.PrecheckExpect, string(c.Risk), boolInt(c.Enabled), boolInt(c.AIMayPropose), position)
	if err != nil {
		return fmt.Errorf("response: save an action: %w", err)
	}
	return nil
}

// ---- rules ----

func scanRule(r scanner) (Rule, error) {
	var x Rule
	var conds, acts, trig, match string
	var sched sql.NullInt64
	var tpl, last sql.NullString
	if err := r.Scan(&x.ID, &x.Name, &x.Enabled, &x.Live, &trig, &match, &conds, &acts, &x.PreApproved, &x.MaxPerHour, &sched, &tpl, &last); err != nil {
		return Rule{}, err
	}
	x.Trigger, x.Match = trig, match
	if err := json.Unmarshal([]byte(conds), &x.Conditions); err != nil {
		return Rule{}, err
	}
	if err := json.Unmarshal([]byte(acts), &x.Actions); err != nil {
		return Rule{}, err
	}
	if x.Conditions == nil {
		x.Conditions = []Condition{}
	}
	if sched.Valid {
		n := int(sched.Int64)
		x.ScheduleMin = &n
	}
	x.TemplateID, x.LastFired = ptrOrNilNS(tpl), ptrOrNilNS(last)
	return x, nil
}

func ptrOrNilNS(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

const ruleCols = `id, name, enabled, live, trigger, match, conditions, actions, pre_approved, max_per_hour, schedule_min, template_id, last_fired`

func loadRules(ctx context.Context, q dbq) ([]Rule, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+ruleCols+` FROM resp_rules ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("response: read the rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Rule{}
	for rows.Next() {
		x, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("response: read the rules: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func loadRule(ctx context.Context, q dbq, id string) (Rule, bool, error) {
	x, err := scanRule(q.QueryRowContext(ctx, `SELECT `+ruleCols+` FROM resp_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, false, nil
	}
	if err != nil {
		return Rule{}, false, fmt.Errorf("response: read a rule: %w", err)
	}
	return x, true, nil
}

func ruleArgs(r Rule) []any {
	var sched any
	if r.ScheduleMin != nil {
		sched = *r.ScheduleMin
	}
	return []any{r.Name, boolInt(r.Enabled), boolInt(r.Live), r.Trigger, r.Match, mustJSON(r.Conditions), mustJSON(r.Actions), boolInt(r.PreApproved), r.MaxPerHour, sched}
}

// ---- requests ----

const reqCols = `id, source, proposal_id, rule_id, rule_name, trigger, trigger_summary, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, decided_at, requires_approvals, two_because, approvals, sent_to, note, pre_approved, ai, items`

func scanReq(r scanner) (request, error) {
	var q request
	a := &q.ActionRequest
	var ruleID, ruleName, trig, tsum, fid, cve, aid, decided, two, note, ai sql.NullString
	var source, risk, status, approvals, sentTo, items string
	if err := r.Scan(&a.ID, &source, &a.ProposalID, &ruleID, &ruleName, &trig, &tsum, &fid, &cve, &aid, &a.AssetName, &a.Title, &risk, &status, &a.RequestedAt, &a.ExpiresAt, &decided,
		&a.RequiresApprovals, &two, &approvals, &sentTo, &note, &a.PreApproved, &ai, &items); err != nil {
		return request{}, err
	}
	a.Source, a.Risk, a.Status = source, Risk(risk), Status(status)
	a.RuleID, a.RuleName, a.Trigger, a.TriggerSummary = ptrOrNilNS(ruleID), ptrOrNilNS(ruleName), ptrOrNilNS(trig), ptrOrNilNS(tsum)
	a.FindingID, a.CVE, a.AssetID, a.DecidedAt, a.TwoBecause, a.Note = ptrOrNilNS(fid), ptrOrNilNS(cve), ptrOrNilNS(aid), ptrOrNilNS(decided), ptrOrNilNS(two), ptrOrNilNS(note)
	if err := json.Unmarshal([]byte(approvals), &a.Approvals); err != nil {
		return request{}, err
	}
	if err := json.Unmarshal([]byte(sentTo), &a.SentTo); err != nil {
		return request{}, err
	}
	if ai.Valid {
		a.AI = new(AiMeta)
		if err := json.Unmarshal([]byte(ai.String), a.AI); err != nil {
			return request{}, err
		}
	}
	if err := json.Unmarshal([]byte(items), &q.recs); err != nil {
		return request{}, err
	}
	return q, nil
}

func loadReq(ctx context.Context, q dbq, id string) (request, bool, error) {
	r, err := scanReq(q.QueryRowContext(ctx, `SELECT `+reqCols+` FROM resp_actions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return request{}, false, nil
	}
	if err != nil {
		return request{}, false, fmt.Errorf("response: read a request: %w", err)
	}
	return r, true, nil
}

func loadReqs(ctx context.Context, q dbq, where string, args ...any) ([]request, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+reqCols+` FROM resp_actions `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("response: read the requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []request
	for rows.Next() {
		r, err := scanReq(rows)
		if err != nil {
			return nil, fmt.Errorf("response: read the requests: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func insertReq(ctx context.Context, tx *sql.Tx, r request) error {
	a := r.ActionRequest
	var ai any
	if a.AI != nil {
		ai = mustJSON(a.AI)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO resp_actions (`+reqCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Source, a.ProposalID, deref(a.RuleID), deref(a.RuleName), deref(a.Trigger), deref(a.TriggerSummary), deref(a.FindingID), deref(a.CVE), deref(a.AssetID), a.AssetName, a.Title,
		string(a.Risk), string(a.Status), a.RequestedAt, a.ExpiresAt, deref(a.DecidedAt), a.RequiresApprovals, deref(a.TwoBecause), mustJSON(nonNil(a.Approvals)), mustJSON(nonNilS(a.SentTo)),
		deref(a.Note), boolInt(a.PreApproved), ai, mustJSON(r.recs))
	if err != nil {
		return fmt.Errorf("response: save a request: %w", err)
	}
	return nil
}

// updateReq writes back the parts of a request that change after it was created.
func updateReq(ctx context.Context, tx *sql.Tx, r request) error {
	a := r.ActionRequest
	_, err := tx.ExecContext(ctx, `UPDATE resp_actions SET risk = ?, status = ?, decided_at = ?, requires_approvals = ?, two_because = ?, approvals = ?, note = ?, pre_approved = ?, items = ? WHERE id = ?`,
		string(a.Risk), string(a.Status), deref(a.DecidedAt), a.RequiresApprovals, deref(a.TwoBecause), mustJSON(nonNil(a.Approvals)), deref(a.Note), boolInt(a.PreApproved), mustJSON(r.recs), a.ID)
	if err != nil {
		return fmt.Errorf("response: update a request: %w", err)
	}
	return nil
}

func deref(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func nonNil(a []Approval) []Approval {
	if a == nil {
		return []Approval{}
	}
	return a
}

func nonNilS(a []string) []string {
	if a == nil {
		return []string{}
	}
	return a
}

// ---- events and the done set ----

// Det is an event a trigger watches for.
type Det struct {
	ID         string
	Trigger    string
	TS         string
	Summary    string
	Fields     map[string]string
	DeviceKind string
	AssetID    string
	FindingID  string
	CVE        string
}

const evCols = `id, trigger, ts, summary, fields, device_kind, asset_id, finding_id, cve`

func scanEv(r scanner) (Det, error) {
	var d Det
	var fields string
	var kind, aid, fid, cve sql.NullString
	if err := r.Scan(&d.ID, &d.Trigger, &d.TS, &d.Summary, &fields, &kind, &aid, &fid, &cve); err != nil {
		return Det{}, err
	}
	if err := json.Unmarshal([]byte(fields), &d.Fields); err != nil {
		return Det{}, err
	}
	if d.Fields == nil {
		d.Fields = map[string]string{}
	}
	d.DeviceKind, d.AssetID, d.FindingID, d.CVE = kind.String, aid.String, fid.String, cve.String
	return d, nil
}

func loadEvents(ctx context.Context, q dbq, where string, limit int, args ...any) ([]Det, error) {
	rows, err := q.QueryContext(ctx, fmt.Sprintf(`SELECT %s FROM resp_events %s ORDER BY ts DESC, seq DESC LIMIT %d`, evCols, where, limit), args...)
	if err != nil {
		return nil, fmt.Errorf("response: read the events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Det
	for rows.Next() {
		d, err := scanEv(rows)
		if err != nil {
			return nil, fmt.Errorf("response: read the events: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Bounds of resp_events: the newest processed events are kept for the conditions that count (a window of events and the
// "first time" test); events no rule has seen yet are never trimmed to make room, only dropped (and counted, logged) when the
// backlog itself passes maxEventBacklog.
const (
	maxEvents       = 500
	maxEventBacklog = 2000
)

// insertEvent records an event. Only processed events are trimmed. When the unprocessed events pass backlog, the oldest of
// them are deleted and their number is returned: the caller must log that loss (never silent).
func insertEvent(ctx context.Context, tx *sql.Tx, d Det, backlog int) (inserted bool, dropped int, err error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO resp_events (id, trigger, ts, summary, fields, device_kind, asset_id, finding_id, cve) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
		d.ID, d.Trigger, d.TS, d.Summary, mustJSON(d.Fields), nullable(d.DeviceKind), nullable(d.AssetID), nullable(d.FindingID), nullable(d.CVE))
	if err != nil {
		return false, 0, fmt.Errorf("response: save an event: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `DELETE FROM resp_events WHERE processed = 1 AND seq NOT IN (SELECT seq FROM resp_events WHERE processed = 1 ORDER BY seq DESC LIMIT ?)`, maxEvents); err != nil {
		return false, 0, fmt.Errorf("response: trim the events: %w", err)
	}
	if n == 0 {
		return false, 0, nil
	}
	var open int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM resp_events WHERE processed = 0`).Scan(&open); err != nil {
		return false, 0, fmt.Errorf("response: count the events: %w", err)
	}
	if open <= backlog {
		return true, 0, nil
	}
	res, err = tx.ExecContext(ctx, `DELETE FROM resp_events WHERE seq IN (SELECT seq FROM resp_events WHERE processed = 0 ORDER BY seq LIMIT ?)`, open-backlog)
	if err != nil {
		return false, 0, fmt.Errorf("response: bound the event backlog: %w", err)
	}
	k, _ := res.RowsAffected()
	return true, int(k), nil
}

func doneKeys(ctx context.Context, q dbq) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT rule_id, event_id FROM resp_done`)
	if err != nil {
		return nil, fmt.Errorf("response: read the handled events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r, e string
		if err := rows.Scan(&r, &e); err != nil {
			return nil, err
		}
		out = append(out, r+"\x00"+e)
	}
	return out, rows.Err()
}

// ---- helpers ----

func parseTS(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func newID(prefix string) string { return store.NewID(prefix) }

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// nonNilStrings makes a nil list an empty one, so it is stored and sent as [] and never as null.
func nonNilStrings(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

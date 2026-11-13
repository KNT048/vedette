package scan

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// RetentionDays is how long the probe log is kept (INV-7: at least 90 days; the GUI says 90).
const RetentionDays = 90

// maxProbeList caps GET /scans/probes; the CSV has every row.
const maxProbeList = 5000

const runColumns = `id, trigger, trigger_note, started_at, started_by, ended_at, status, total, done, current, results, matched, stop_reason, identification`

func scanRun(row interface{ Scan(...any) error }) (RunView, error) {
	var v RunView
	var cur sql.NullString
	var results, idents string
	err := row.Scan(&v.ID, &v.Trigger, &v.TriggerNote, &v.StartedAt, &v.StartedBy, &v.EndedAt, &v.Status, &v.Total, &v.Done, &cur, &results, &v.Matched, &v.StopReason, &idents)
	if err != nil {
		return RunView{}, err
	}
	if cur.Valid {
		v.Current = &Current{}
		if err := json.Unmarshal([]byte(cur.String), v.Current); err != nil {
			return RunView{}, fmt.Errorf("scan: reading the current device: %w", err)
		}
	}
	if err := json.Unmarshal([]byte(results), &v.Results); err != nil {
		return RunView{}, fmt.Errorf("scan: reading the results: %w", err)
	}
	if v.Results == nil {
		v.Results = []RunRow{}
	}
	if err := json.Unmarshal([]byte(idents), &v.Identification); err != nil {
		return RunView{}, fmt.Errorf("scan: reading the identification: %w", err)
	}
	if v.Identification == nil {
		v.Identification = []IdentRow{}
	}
	return v, nil
}

// Run returns one run.
func (s *Service) Run(ctx context.Context, id string) (RunView, error) {
	v, err := scanRun(s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT `+runColumns+` FROM scan_run WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return RunView{}, errNoRun
	}
	if err != nil {
		return RunView{}, fmt.Errorf("scan: reading run %s: %w", id, err)
	}
	return v, nil
}

// Runs returns the newest runs, newest first, with their per-device results (S-SCAN-3).
func (s *Service) Runs(ctx context.Context) ([]RunView, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT `+runColumns+` FROM scan_run ORDER BY started_at DESC, rowid DESC LIMIT ?`, keepRuns)
	if err != nil {
		return nil, fmt.Errorf("scan: listing runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []RunView{}
	for rows.Next() {
		v, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: listing runs: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ProbeView is contract.ts ProbeEntry.
type ProbeView struct {
	ID       string  `json:"id"`
	TS       string  `json:"ts"`
	RunID    *string `json:"run_id"`
	IP       string  `json:"ip"`
	Label    string  `json:"label"`
	Template string  `json:"template"`
	Request  string  `json:"request"`
	Result   string  `json:"result"`
}

// Probes returns the probe log, newest first (INV-7). Requests still on their way have no result yet and are left
// out here; the CSV lists them as in_progress.
func (s *Service) Probes(ctx context.Context) ([]ProbeView, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, run_id, ip, label, template, request, result FROM scan_probe
WHERE result IS NOT NULL ORDER BY ts DESC, rowid DESC LIMIT ?`, maxProbeList)
	if err != nil {
		return nil, fmt.Errorf("scan: reading the probe log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ProbeView{}
	for rows.Next() {
		var p ProbeView
		if err := rows.Scan(&p.ID, &p.TS, &p.RunID, &p.IP, &p.Label, &p.Template, &p.Request, &p.Result); err != nil {
			return nil, fmt.Errorf("scan: reading the probe log: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// csvCell keeps a spreadsheet from reading a cell as a formula (names come from the network: DHCP, mDNS).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ProbesCSV is the whole probe log as CSV, newest first: time, target, name, template, request, result.
func (s *Service) ProbesCSV(ctx context.Context) (io.Reader, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT ts, ip, label, template, request, coalesce(result, 'in_progress') FROM scan_probe ORDER BY ts DESC, rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("scan: reading the probe log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"time", "target", "name", "template", "request", "result"}); err != nil {
		return nil, err
	}
	for rows.Next() {
		rec := make([]string, 6)
		if err := rows.Scan(&rec[0], &rec[1], &rec[2], &rec[3], &rec[4], &rec[5]); err != nil {
			return nil, fmt.Errorf("scan: reading the probe log: %w", err)
		}
		for i := range rec {
			rec[i] = csvCell(rec[i])
		}
		if err := w.Write(rec); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	w.Flush()
	return &buf, w.Error()
}

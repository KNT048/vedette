package scan

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// RetentionDays is how long the probe log is kept (INV-7: at least 90 days; the GUI says 90).
const RetentionDays = 90

// maxProbeList caps GET /scans/probes; the CSV has every row.
const maxProbeList = 5000

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

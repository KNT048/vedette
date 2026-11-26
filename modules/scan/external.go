package scan

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/knt048/vedette/core/store"
)

// ExternalProbe is one probe of the external-surface scan (INV-12) in the probe log: the same table, retention (90 days)
// and CSV as the probes of a run (INV-7), with no run id. Template names the kind ("exposure: tcp", "exposure: https"…).
type ExternalProbe struct {
	ID       string // from the scanner; the second write with the same ID completes the row
	IP       string
	Label    string
	Template string
	Request  string
	Answered bool
	// Result, when set, is the result of a template probe of exposure's safe checks: matched or not_matched (a
	// probe that got no usable answer stays no_response), ProbeNotRun (handed to nuclei, which did not run it) or ProbeRefused (the
	// scan worker refused the job: nothing was sent; kf-scan item 5). It wins over Answered; any other value is not written.
	Result string
	// RunID is the core_run of the exposure scan that sends the probe, so a run's probes can be listed; "" for none. A later write of
	// the same row never takes its run away.
	RunID string
}

// Probe-log results of a template probe that never reached the target (migration 0007).
const (
	ProbeNotRun  = "not_run"
	ProbeRefused = "refused"
)

// RecordExternalProbes writes probes of the external-surface scan: before they go out (result no_response, "sent, no answer
// yet": a box that stops mid-scan leaves that), and again with the same IDs after, when something answered (banner) and with
// the request completed (the open ports). The time of a row is the first write. Texts are cut to the table's limits.
func (s *Service) RecordExternalProbes(ctx context.Context, ps []ExternalProbe) error {
	now := store.FormatTS(s.now())
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, p := range ps {
			result := "no_response"
			switch {
			case p.Result == "matched" || p.Result == "not_matched" || p.Result == ProbeNotRun || p.Result == ProbeRefused:
				result = p.Result
			case p.Answered:
				result = "banner"
			}
			var runID any
			if p.RunID != "" {
				runID = clip(p.RunID, 96)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO scan_probe (id, ts, run_id, ip, label, template, request, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET request = excluded.request, result = excluded.result, run_id = coalesce(scan_probe.run_id, excluded.run_id)`,
				clip(p.ID, 96), now, runID, clip(p.IP, 253), clip(p.Label, 300), clip(p.Template, 300), clip(p.Request, 300), result); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan: writing the probe log of an external scan: %w", err)
	}
	return nil
}

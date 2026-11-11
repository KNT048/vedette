package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/store"
)

// ExportDeviceLogs is the source of the "device_logs" category of GET /core/logs/export (core INV-13, D-132): one JSON
// object per received line, oldest first, {id, ts, source_id, line}. A module that is off keeps its lines, so the
// source stays registered. The range is both ends inclusive, a zero time open. The lines are device text, untrusted;
// they are exported as the text they are.
//
// The category has a cap of its own (ExportMaxBytes): core refuses the whole export, every category, when the rows pass
// its total cap, so a large log must not be able to do that. Over the cap the newest lines are kept, and the last line of
// the category is a marker {id: "cut", ts, source_id: "", line: "..."} that says older lines were left out.
func (s *Service) ExportDeviceLogs(ctx context.Context, from, to time.Time, w io.Writer) error {
	lo, hi := "0000-01-01T00:00:00.000Z", "9999-12-31T23:59:59.999Z"
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	vol := s.cfg.Volume.Reader()
	// The oldest id that still fits: the running cost of the lines from the newest back, as far as it stays within the cap.
	var first sql.NullInt64
	err := vol.QueryRowContext(ctx, `SELECT min(id) FROM (SELECT id, sum(2 * length(CAST(line AS BLOB)) + 128) OVER (ORDER BY id DESC) AS run
		FROM logs_events WHERE ts >= ? AND ts <= ?) WHERE run <= ?`, lo, hi, s.exportBytes).Scan(&first)
	if err != nil {
		return fmt.Errorf("logs: sizing the export: %w", err)
	}
	if !first.Valid {
		first.Int64 = math.MaxInt64 // nothing fits, or nothing is there: no line, and a marker only if something was left out
	}
	if err := (logexport.Rows{
		SQL:  `SELECT 'le-' || id AS id, ts, source_id, line FROM logs_events WHERE ts >= ? AND ts <= ? AND id >= ? ORDER BY id`,
		Args: []any{lo, hi, first.Int64},
	}).Write(ctx, vol, w); err != nil {
		return err
	}
	var older int
	if err := vol.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM logs_events WHERE ts >= ? AND ts <= ? AND id < ? LIMIT 1)`, lo, hi, first.Int64).Scan(&older); err != nil {
		return fmt.Errorf("logs: sizing the export: %w", err)
	}
	if older == 0 {
		return nil
	}
	marker, err := json.Marshal(map[string]string{"id": "cut", "ts": store.FormatTS(s.now()), "source_id": "",
		"line": fmt.Sprintf("[device_logs cut: older lines are left out, this category holds at most about %d MiB; export a shorter date range to get them]", s.exportBytes>>20)})
	if err != nil {
		return err
	}
	_, err = w.Write(append(marker, '\n'))
	return err
}

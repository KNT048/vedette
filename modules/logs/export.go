package logs

import (
	"context"
	"io"
	"time"

	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/store"
)

// ExportDeviceLogs is the source of the "device_logs" category of GET /core/logs/export (core INV-13, D-132): one JSON
// object per received line, oldest first, {id, ts, source_id, line}. A module that is off keeps its lines, so the
// source stays registered. The range is both ends inclusive, a zero time open. The lines are device text, untrusted;
// they are exported as the text they are.
func (s *Service) ExportDeviceLogs(ctx context.Context, from, to time.Time, w io.Writer) error {
	lo, hi := "0000-01-01T00:00:00.000Z", "9999-12-31T23:59:59.999Z"
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	return logexport.Rows{
		SQL:  `SELECT 'le-' || id AS id, ts, source_id, line FROM logs_events WHERE ts >= ? AND ts <= ? ORDER BY id`,
		Args: []any{lo, hi},
	}.Write(ctx, s.cfg.Volume.Reader(), w)
}

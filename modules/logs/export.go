package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// Walk the range from the newest line back, adding up what each costs, and stop at the first line that does not fit: the
	// lines before it (older) are left out. newest is the first id seen: the rows below are read up to it, so a line that
	// arrives during the export is not half in.
	var first, newest int64
	cutOff := false
	rows, err := vol.QueryContext(ctx, `SELECT id, octet_length(line) FROM logs_events WHERE ts >= ? AND ts <= ? ORDER BY id DESC`, lo, hi)
	if err != nil {
		return fmt.Errorf("logs: sizing the export: %w", err)
	}
	var used int64
	for rows.Next() {
		var id, n int64
		if err := rows.Scan(&id, &n); err != nil {
			_ = rows.Close()
			return fmt.Errorf("logs: sizing the export: %w", err)
		}
		if newest == 0 {
			newest = id
		}
		if used += 2*n + 128; used > s.exportBytes {
			cutOff = true
			break
		}
		first = id
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("logs: sizing the export: %w", err)
	}
	if newest == 0 {
		return nil // no line in the range
	}
	if first > 0 {
		if err := (logexport.Rows{
			SQL:  `SELECT 'le-' || id AS id, ts, source_id, line FROM logs_events WHERE ts >= ? AND ts <= ? AND id >= ? AND id <= ? ORDER BY id`,
			Args: []any{lo, hi, first, newest},
		}).Write(ctx, vol, w); err != nil {
			return err
		}
	}
	if !cutOff {
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

// ExportKnownBad is the "known_bad" source of GET /core/logs/export (core INV-13): the connections to listed destinations from through to,
// oldest first, one JSON object per hit with the stored columns {id, ts, src_ip, dest, dest_kind, seen_via, feeds (an array), confidence,
// blocked, listed_as (empty unless dest matched as a subdomain of it, D-425), source_id}. The device is not looked up (a download carries what was stored, INV-7 resolves it at read for the page only). The table
// holds at most MaxIocRows hits, so the category is bounded by that and needs no cap of its own. A zero time is open; a module that is off
// keeps its rows, so the source stays registered.
func (s *Service) ExportKnownBad(ctx context.Context, from, to time.Time, w io.Writer) error {
	lo, hi := "", ""
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	return logexport.Rows{SQL: `SELECT ` + iocColumns + `, source_id FROM logs_ioc_hits WHERE (? = '' OR ts >= ?) AND (? = '' OR ts <= ?) ORDER BY ts, rowid`,
		Args: []any{lo, lo, hi, hi}, JSON: []string{"feeds"}}.Write(ctx, s.cfg.Volume.Reader(), w)
}

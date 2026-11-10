package main

import (
	"context"
	"io"
	"time"

	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// registerLogSources adds the log sources of the modules to the registry of GET /core/logs/export (core INV-13).
// Each module owns its rows and writes them (JSON lines, chain fields unchanged); core reads no other module's
// table. A module that is off keeps its rows, so its source stays registered and its log is still in the file.
// "audit" is registered by core itself. Not registered, so they export as missing:
//   - ai_activity: the ai module registers its ExportActivity here when it has it (issue #114).
//   - alerts: notify has no read of its delivery log by date yet (.ai/deferred/feat-logs-export.md).
//   - device_logs, known_bad: the logs module has no code yet.
func registerLogSources(d *deps) {
	d.Logs.Register("response", d.Response.ExportLog)
	d.Logs.Register("honeypot", d.Honeypot.ExportHits)
	d.Logs.Register("scan_probes", func(ctx context.Context, from, to time.Time, w io.Writer) error {
		return sensoractive.ExportProbes(ctx, d.DB, from, to, w)
	})
}

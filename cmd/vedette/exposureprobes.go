package main

import (
	"context"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
)

// exposureProbeLog is exposure's ProbeLog (cfg.Probes, exposure INV-23): the scan module's probe log (scan INV-7, INV-12; 90 days,
// Scans -> Probe log), the same table as the surface scan's rows. exposure writes its planned template rows through it before it
// calls the TemplateScanner; nothing is sent when it fails.
type exposureProbeLog struct{ d deps }

func (l exposureProbeLog) RecordTemplateProbes(ctx context.Context, ps []exposure.TemplateProbe) error {
	rows := make([]scan.ExternalProbe, len(ps))
	for i, p := range ps {
		rows[i] = scan.ExternalProbe{ID: p.ID, IP: p.IP, Label: p.Label, Template: p.Template, Request: p.Request}
	}
	return scanService(l.d).RecordExternalProbes(ctx, rows)
}

package main

import (
	"context"
	"fmt"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
)

// exposureProbeLog is exposure's probe log over the scan module's (scan INV-7, INV-12; 90 days, Scans -> Probe log). Slice b
// (cmd/vedette/exposureprobes.go, D-520) declares this type with RecordTemplateProbes and wires it as cfg.Probes; the type line below
// is here only until b is on main (when the branches meet, keep b's declaration and drop this one). RecordWebProbe makes the same
// value exposure's WebProbeLog (INV-24, LEGAL §3): one row per page before ZAP starts on it.
type exposureProbeLog struct{ d deps }

// RecordWebProbe writes the row of one page before zap.baseline is asked (exposure INV-24): the address and port ZAP is pinned to,
// the tool and its options, the URL. It returns only once the row is written; exposure scans nothing when it fails.
func (l exposureProbeLog) RecordWebProbe(ctx context.Context, p exposure.WebProbe) error {
	return scanService(l.d).RecordExternalProbes(ctx, []scan.ExternalProbe{{
		ID: p.ID, IP: p.IP, Label: fmt.Sprintf("%s:%d", p.IP, p.Port), Template: "exposure: " + p.Tool,
		Request: fmt.Sprintf("planned: passive web scan of %s, ZAP pinned to %s:%d (no other address, no DNS)", p.URL, p.IP, p.Port),
	}})
}

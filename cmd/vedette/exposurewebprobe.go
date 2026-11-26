package main

import (
	"context"
	"fmt"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
)

// exposureProbeLog (exposureprobes.go, cfg.Probes) is exposure's WebProbeLog too (INV-24, LEGAL §3): one row per page before
// ZAP starts on it.
var _ exposure.WebProbeLog = exposureProbeLog{}

// exposureProbeLog is exposure's GreenboneProbeLog too (INV-25, LEGAL §3): one row per OpenVAS scan before its task starts.
var _ exposure.GreenboneProbeLog = exposureProbeLog{}

// RecordGreenboneProbe writes the row of one OpenVAS (Greenbone) scan before gvmd's task starts: the address, the port list, the scan
// config and the note that its probes are not logged one by one. It returns only once the row is written; nothing is started when it
// fails.
func (l exposureProbeLog) RecordGreenboneProbe(ctx context.Context, p exposure.GreenboneProbe) error {
	return scanService(l.d).RecordExternalProbes(ctx, []scan.ExternalProbe{{
		ID: p.ID, IP: p.IP, Label: p.IP, Template: "exposure: OpenVAS (Greenbone CE), config " + p.Config, Request: greenboneProbeRequest(p), RunID: exposure.RunIDOf(ctx),
	}})
}

// greenboneProbeRequest is the probe row's text: the domain fence note first, then the port list (exposure clips it, with the count),
// then the note on OpenVAS's many probes. The scan module clips the text at 300 characters, so the fence note (LEGAL §3: why a
// non-box address was probed) is never the part that is cut.
func greenboneProbeRequest(p exposure.GreenboneProbe) string {
	return fmt.Sprintf("planned: OpenVAS scan of %s. %sPort list %s. %s", p.IP, p.Fence, p.PortList, p.Note)
}

// RecordWebProbe writes the row of one page before zap.baseline is asked (exposure INV-24): the address and port ZAP is pinned to,
// the tool and its options, the URL. It returns only once the row is written; exposure scans nothing when it fails.
func (l exposureProbeLog) RecordWebProbe(ctx context.Context, p exposure.WebProbe) error {
	return scanService(l.d).RecordExternalProbes(ctx, []scan.ExternalProbe{{
		ID: p.ID, IP: p.IP, Label: fmt.Sprintf("%s:%d", p.IP, p.Port), Template: "exposure: " + p.Tool,
		Request: fmt.Sprintf("planned: passive web scan of %s, ZAP pinned to %s:%d (no other address, no DNS)", p.URL, p.IP, p.Port), RunID: exposure.RunIDOf(ctx),
	}})
}

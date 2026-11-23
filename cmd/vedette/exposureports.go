package main

import (
	"cmp"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/response"
)

// maxPortsPerScan bounds the exposure.port.opened events one scan publishes: each one is a write to response's event
// backlog (the rules run later, in its evaluate job). A first scan after a long gap or a big change can open many; the rest are on
// the Exposure page (each service's first seen), and the box log says how many were left out.
const maxPortsPerScan = 20

// portsOpenedTimeout bounds the bridge's writes. exposure publishes under a 5-second deadline, too short for twenty writes while
// another writer holds the database; a port not announced now is never announced (the next scan finds it open already), so the
// bridge detaches from that deadline, as the baseline re-match does (rematchTimeout).
const portsOpenedTimeout = 30 * time.Second

// exposurePortsOpened bridges exposure.scan.written to response's new_port trigger: the scan writer says which services are open now
// and were not before that scan (new, or open again after a scan closed them), and this publishes one exposure.port.opened per
// service. The first scan of a target is the baseline: it opens nothing (Shodan Monitor's new_service behaves the same). Nothing is
// sent while exposure is off; the subscription itself is wired for response (subscribe), so nothing runs while response is off, and a
// port that opened then is not announced later (SYS-5).
func exposurePortsOpened(d deps) func(ctx context.Context, data any) error {
	return func(ctx context.Context, data any) error {
		ev, ok := data.(exposure.ScanWrittenEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		if ev.First || (d.Reg != nil && !d.Reg.Enabled(exposure.ModuleID)) {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), portsOpenedTimeout)
		defer cancel()
		day := ev.At[:min(len(ev.At), len(time.DateOnly))] // the scan's day, the key of response's event
		for i, r := range ev.Opened {
			if i == maxPortsPerScan {
				d.Log.WarnContext(ctx, "exposure: more new open ports than one scan announces; the rest are on the Exposure page only",
					"target", ev.TargetID, "new_ports", len(ev.Opened), "announced", maxPortsPerScan)
				break
			}
			// rules compare nmap's name (service); the summary reads the person's name, "probably SIP" for a port-number guess
			// the target that holds the port now: a port the scan of a domain found on a name its child target took over is the child's
			p := response.PortOpenedEvent{TargetID: cmp.Or(r.TargetID, ev.TargetID), Date: day, IP: r.IP, Port: r.Port, Service: r.Service,
				Label: shortLabel(exposure.ServiceLabel(r.PortRow)), Identified: r.Ident}
			if err := d.Bus.Publish(ctx, events.Event{Name: response.EventPortOpened, Data: p}); err != nil {
				return err
			}
		}
		return nil
	}
}

// shortLabel drops the page's bracketed hint for the alert's own brackets: "Cisco SCCP (IP phones)" → "Cisco SCCP".
func shortLabel(s string) string {
	s, _, _ = strings.Cut(s, " (")
	return s
}

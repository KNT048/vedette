package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/response"
)

// maxPortsPerScan bounds the exposure.port.opened events one scan publishes (D-384): each one is a write to response's event
// backlog (the rules run later, in its evaluate job). A first scan after a long gap or a big change can open many; the rest are on
// the Exposure page (its diff), and the box log says how many were left out. ponytail: a flat cap; upgrade path: one summary event.
const maxPortsPerScan = 20

// portsOpenedTimeout bounds the bridge's reads and writes. exposure publishes under a 5-second deadline, too short for three reads
// and twenty writes while another writer holds the database; a port not stored now is never announced (the next day compares with a
// snapshot that already has it), so the bridge detaches from that deadline, as the baseline re-match does (rematchTimeout).
const portsOpenedTimeout = 30 * time.Second

// exposurePortsOpened bridges exposure.snapshot.created to response's new_port trigger (D-384): exposure publishes only the counts
// of a scan, so on each snapshot this compares it with the previous scan day of the same target through exposure's own Diff and
// publishes one exposure.port.opened per port that is open now and was not then. The first scan day of a target is the baseline:
// it has nothing to compare with, so it opens nothing (Shodan Monitor's new_service behaves the same). Nothing is read while
// exposure is off; the subscription itself is wired for response (subscribe), so nothing runs while response is off, and a port
// that opened then is not announced later (SYS-5).
func exposurePortsOpened(d deps) func(ctx context.Context, data any) error {
	return func(ctx context.Context, data any) error {
		ev, ok := data.(exposure.SnapshotCreatedEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		if d.Reg != nil && !d.Reg.Enabled(exposure.ModuleID) {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), portsOpenedTimeout)
		defer cancel()
		opened, err := openedPorts(ctx, exposureService(d), ev.TargetID, ev.Date)
		if err != nil {
			return err
		}
		for i, p := range opened {
			if i == maxPortsPerScan {
				d.Log.WarnContext(ctx, "exposure: more new open ports than one scan announces; the rest are on the Exposure page only",
					"target", ev.TargetID, "new_ports", len(opened), "announced", maxPortsPerScan)
				break
			}
			if err := d.Bus.Publish(ctx, events.Event{Name: response.EventPortOpened, Data: p}); err != nil {
				return err
			}
		}
		return nil
	}
}

// openedPorts lists the ports that the scan day `date` of a target shows and its previous scan day does not, from exposure's Diff.
// The address, port and service guess come from that day's own rows (the diff keeps them only as display text); response checks
// them again at its edge. The diff compares the scanner's text, so a port whose address is only spelled differently from the day
// before (an IPv4-mapped form) is not new.
func openedPorts(ctx context.Context, svc *exposure.Service, targetID, date string) ([]response.PortOpenedEvent, error) {
	days, err := svc.Snapshots(ctx, targetID) // newest first
	if err != nil {
		return nil, err
	}
	prev := ""
	for _, m := range days {
		if m.Date < date {
			prev = m.Date
			break
		}
	}
	if prev == "" { // the first scan day: the baseline
		return nil, nil
	}
	diff, err := svc.Diff(ctx, targetID, prev, date)
	if err != nil {
		return nil, err
	}
	before, err := svc.SnapshotOf(ctx, targetID, prev)
	if err != nil {
		return nil, err
	}
	snap, err := svc.SnapshotOf(ctx, targetID, date)
	if err != nil {
		return nil, err
	}
	added := map[string]bool{}
	for _, it := range diff.Added {
		if it.Kind == "port" {
			added[it.Label] = true
		}
	}
	type key struct {
		ip   netip.Addr
		port int
	}
	canon := func(r exposure.PortRow) key {
		a, _ := netip.ParseAddr(r.IP)
		return key{a.Unmap(), r.Port}
	}
	seen := map[key]bool{}
	for _, r := range before.Ports {
		seen[canon(r)] = true
	}
	var out []response.PortOpenedEvent
	for _, r := range snap.Ports {
		label := fmt.Sprintf("%s:%d", r.IP, r.Port) // the label exposure's diff gives a port row (TestExposureSnapshotOpensNewPorts)
		if k := canon(r); added[label] && !seen[k] {
			seen[k] = true // a row listed twice is one port
			out = append(out, response.PortOpenedEvent{TargetID: targetID, Date: date, IP: r.IP, Port: r.Port, Service: r.Service})
		}
	}
	return out, nil
}

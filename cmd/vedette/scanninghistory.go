package main

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// historyRead is how many rows each source gives GET /scanning/history (core keeps the newest 200 of all of them).
const historyRead = 200

// history is Settings › Scanning › History of the runs that are not vulnerability checks: every sa_job of the LAN
// (discovery sweeps, device identifications, SNMP reads) and every stored scan of a public target, each with its outcome in words
// from what it stored. The vulnerability checks keep their own list (GET /scans/runs). A source that is not built or not readable
// gives nothing; it never fails the page.
//
// With asset (the device page's Last checks): only the LAN jobs that reached that device's address now, its
// identifications and the SNMP reads that asked it, at most historyRead of each kind; no sweep, no public scan. The jobs record
// addresses, not devices: an unknown device, or one without an address, has none.
func (e scanningEngines) history(ctx context.Context, asset string) ([]core.HistoryRun, error) {
	var out []core.HistoryRun
	if e.d.DB != nil && e.d.SensorDispatcher != nil {
		if svc, err := sensorActiveService(ctx, e.d); err == nil {
			var jobs []sensoractive.JobRow
			if asset == "" {
				jobs, err = svc.Jobs(ctx, historyRead)
			} else {
				var at netip.Addr
				if at, err = e.deviceAddr(ctx, asset); err == nil && at.IsValid() {
					jobs, err = svc.JobsAt(ctx, at, historyRead)
				}
			}
			if err != nil {
				return nil, err
			}
			for _, j := range jobs {
				if r, ok := jobHistory(j); ok {
					out = append(out, r)
				}
			}
		}
	}
	if asset != "" {
		return out, nil
	}
	if e.d.DB != nil && e.d.Reg != nil && e.d.Reg.Enabled("exposure") {
		scans, err := exposureService(e.d).RecentScans(ctx, historyRead)
		if err != nil {
			return nil, err
		}
		for _, s := range scans {
			if r, ok := exposureHistory(s); ok {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// deviceAddr is the address of device id now; the zero Addr when the device is unknown or has none.
func (e scanningEngines) deviceAddr(ctx context.Context, id string) (netip.Addr, error) {
	if e.d.Inventory == nil {
		return netip.Addr{}, nil
	}
	refs, err := e.d.Inventory.DeviceRefs(ctx, []string{id})
	if err != nil {
		return netip.Addr{}, err
	}
	at, err := netip.ParseAddr(refs[id].IP) // "—" or "" when it has none
	if err != nil {
		return netip.Addr{}, nil //nolint:nilerr // no address: no run reached it
	}
	return at, nil
}

// probeUp reads nmap's one-line result of a probe ("ok: 1 hosts up"); snmpAnswered an SNMP read's ("ok: 2 of 3 answered").
var (
	probeUp      = regexp.MustCompile(`^ok: (\d+) hosts? up`)
	snmpAnswered = regexp.MustCompile(`^ok: (\d+) of (\d+) answered`)
)

// jobHistory is an sa_job row as a History row. Its words come from what it stored (#940 review r1 H1, M3): the hosts that answered
// each sweep batch, the devices that answered each SNMP read, the row's own status and error; never the targets it only meant to reach.
func jobHistory(j sensoractive.JobRow) (core.HistoryRun, bool) {
	start, ok := parseTS(j.StartedAt)
	if !ok {
		return core.HistoryRun{}, false
	}
	r := core.HistoryRun{ID: j.ID, Kind: j.Kind, StartedAt: start, Outcome: map[string]string{sensoractive.StatusDone: "ok", sensoractive.StatusStopped: "stopped", sensoractive.StatusFailed: "failed", sensoractive.StatusRunning: "running"}[j.Status]}
	if r.Outcome == "" {
		r.Outcome = "failed"
	}
	if j.FinishedAt != nil {
		if at, ok := parseTS(*j.FinishedAt); ok {
			r.EndedAt = &at
		}
	}
	failedProbes, probeErr := 0, ""
	for _, p := range j.Probes {
		if strings.HasPrefix(p.Result, "failed") {
			failedProbes++
			if probeErr == "" {
				probeErr = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(p.Result, "failed"), ":"))
			}
		}
	}
	var found string // what the stored probes say it did, "" when it sent none
	switch j.Kind {
	case sensoractive.KindSweep:
		r.Engine, r.Trigger, r.Label = "nmap-discovery", "sweep", "LAN sweep"
		up, okBatches := 0, 0
		for _, p := range j.Probes {
			if m := probeUp.FindStringSubmatch(p.Result); m != nil {
				n, _ := strconv.Atoi(m[1])
				up += n
				okBatches++
			}
		}
		switch {
		case len(j.Probes) == 0:
		case j.Status == sensoractive.StatusRunning:
			// j.Targets is the planned size while it runs; only the finished batches are stored
			r.Label = "LAN sweep of " + j.Probes[0].Targets
			if len(j.Probes) > 1 {
				r.Label = fmt.Sprintf("LAN sweep in %d batches so far", len(j.Probes))
			}
			if okBatches > 0 {
				found = fmt.Sprintf("%s finished: %s answered", count(okBatches, "batch", "batches"), count(up, "host", "hosts"))
			}
		case okBatches == 0: // every batch failed: nothing it found is stored
			r.Label = "LAN sweep of " + j.Probes[0].Targets
		case len(j.Probes) == 1:
			r.Label = "LAN sweep of " + j.Probes[0].Targets
			found = fmt.Sprintf("swept %d addresses: %s answered, %d new %s", j.Targets, count(up, "host", "hosts"), j.NewDevices, plural(j.NewDevices, "device", "devices"))
		default:
			r.Label = fmt.Sprintf("LAN sweep in %d batches", len(j.Probes))
			found = fmt.Sprintf("swept %d addresses in %d batches: %s answered, %d new %s", j.Targets, len(j.Probes), count(up, "host", "hosts"), j.NewDevices, plural(j.NewDevices, "device", "devices"))
		}
	case sensoractive.KindDevice:
		r.Engine, r.Label = "nmap-versions", "A device"
		switch j.Reason {
		case "check_now":
			r.Trigger = "person"
		case "scan_now":
			r.Trigger = "scan_now"
		default:
			r.Trigger = "automatic"
		}
		if len(j.Probes) > 0 {
			addr := j.Probes[0].Targets
			r.Label = addr
			switch m := probeUp.FindStringSubmatch(j.Probes[0].Result); {
			case m != nil && m[1] == "0":
				found = "scanned " + addr + ": it did not answer"
			case m != nil:
				found = "scanned " + addr + ": it answered; what it runs is on its device page"
			case strings.HasPrefix(j.Probes[0].Result, "failed"): // the failed reason is the text; nothing was found
			default:
				found = "scanned " + addr
			}
		}
	case sensoractive.KindSNMP:
		r.Engine, r.Label = "snmp", "SNMP read"
		switch j.Reason {
		case "snmp_test":
			r.Trigger, r.Label = "test", "SNMP test"
		case "window":
			r.Trigger = "automatic"
		default:
			r.Trigger = "person"
		}
		answered, asked, read := 0, 0, false
		for _, p := range j.Probes {
			if m := snmpAnswered.FindStringSubmatch(p.Result); m != nil {
				a, _ := strconv.Atoi(m[1])
				b, _ := strconv.Atoi(m[2])
				answered, asked, read = answered+a, asked+b, true
			}
		}
		if read {
			found = fmt.Sprintf("%d of %s answered over SNMP", answered, count(asked, "device", "devices"))
			if r.Outcome == "ok" && answered < asked {
				r.Outcome = "partial"
			}
		}
	default:
		return core.HistoryRun{}, false
	}
	switch {
	case failedProbes > 0 && found != "":
		found += fmt.Sprintf("; %s failed", count(failedProbes, "part", "parts"))
		if r.Outcome == "ok" {
			r.Outcome = "partial"
		}
	case failedProbes > 0 && r.Outcome == "ok": // it sent something and every part failed: nothing it found is stored
		r.Outcome = "failed"
	}
	// what it did, from the probes; "" when it sent something but nothing usable was stored
	did := found
	if did == "" && len(j.Probes) == 0 {
		did = "nothing was sent"
		if r.Outcome == "ok" { // a green badge says it checked something
			r.Outcome = "partial"
		}
	}
	switch r.Outcome {
	case "running":
		r.Text = "Running"
		if found != "" {
			r.Text += ": " + found + " so far"
		} else if len(j.Probes) == 0 && j.Kind == sensoractive.KindSweep {
			r.Text += ": sweeping"
		}
	case "failed", "stopped":
		why := orDefault(j.Error, orDefault(probeErr, map[string]string{"failed": "the box did not record why", "stopped": "stopped before the end"}[r.Outcome]))
		r.Text = upper(r.Outcome) + ": " + strings.TrimSuffix(why, ".") + "."
		if did != "" {
			r.Text += " " + upper(did)
			if found != "" {
				r.Text += " before it ended"
			}
		}
	default:
		r.Text = upper(orDefault(did, "nothing usable was recorded"))
	}
	r.Text = clipText(r.Text, 300)
	return r, true
}

// exposureHistory is a stored scan of a public target as a History row (one per target and day). Public scans run only when a person
// presses Scan now (exposure INV-30), so the trigger is a person; who is in the audit log, not in the snapshot. A scan that failed
// before it stored its snapshot is not kept anywhere and cannot be listed (the History tab says so).
func exposureHistory(s exposure.ScanRecord) (core.HistoryRun, bool) {
	at, ok := parseTS(s.ScannedAt)
	if !ok {
		return core.HistoryRun{}, false
	}
	c := s.Counts
	parts := []string{count(c.Ports, "open port", "open ports")}
	if c.AdminPanels > 0 {
		parts = append(parts, count(c.AdminPanels, "admin page", "admin pages"))
	}
	if c.CertsExpiring > 0 {
		parts = append(parts, count(c.CertsExpiring, "certificate expiring", "certificates expiring"))
	}
	if c.Subdomains > 0 {
		parts = append(parts, count(c.Subdomains, "subdomain", "subdomains"))
	}
	outcome, text := "ok", "Scanned "+s.Target+": "+strings.Join(parts, ", ")
	if g := map[string]string{"partial": "OpenVAS scanned part of it", "failed": "OpenVAS failed", "stopped": "OpenVAS was stopped"}[s.Greenbone]; g != "" {
		outcome, text = "partial", text+"; "+g
	}
	if s.NotChecked > 0 {
		outcome, text = "partial", text+"; "+count(s.NotChecked, "step", "steps")+" not checked (see the target)"
	}
	end := at
	return core.HistoryRun{ID: "exp-" + s.TargetID + "-" + at.Format(time.DateOnly), Kind: "external", Engine: "nuclei", Trigger: "person", Label: s.Target, TargetID: s.TargetID,
		StartedAt: at, EndedAt: &end, Outcome: outcome, Text: text}, true
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func count(n int, one, many string) string { return strconv.Itoa(n) + " " + plural(n, one, many) }

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

package main

import (
	"context"
	"fmt"
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

// history is Settings › Scanning › History of the runs that are not vulnerability checks (kien G7a): every sa_job of the LAN
// (discovery sweeps, device identifications, SNMP reads) and every stored scan of a public target, each with its outcome in words
// from what it stored. The vulnerability checks keep their own list (GET /scans/runs). A source that is not built or not readable
// gives nothing; it never fails the page.
func (e scanningEngines) history(ctx context.Context) ([]core.HistoryRun, error) {
	var out []core.HistoryRun
	if e.d.DB != nil && e.d.SensorDispatcher != nil {
		if svc, err := sensorActiveService(ctx, e.d); err == nil {
			jobs, err := svc.Jobs(ctx, historyRead)
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

// probeUp reads nmap's one-line result of a probe ("ok: 1 hosts up").
var probeUp = regexp.MustCompile(`^ok: (\d+) hosts? up`)

// jobHistory is an sa_job row as a History row.
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
	switch j.Kind {
	case sensoractive.KindSweep:
		r.Engine, r.Trigger, r.Label = "nmap-discovery", "sweep", "LAN"
		if j.Address != "" {
			r.Label = "LAN " + j.Address
		}
		r.Text = fmt.Sprintf("Swept %d addresses, %d new %s", j.Targets, j.NewDevices, plural(j.NewDevices, "device", "devices"))
	case sensoractive.KindDevice:
		r.Engine, r.Label = "nmap-versions", j.Address
		if r.Label == "" {
			r.Label = "A device"
		}
		switch j.Reason {
		case "check_now":
			r.Trigger = "person"
		case "scan_now":
			r.Trigger = "scan_now"
		default:
			r.Trigger = "automatic"
		}
		switch m := probeUp.FindStringSubmatch(j.Result); {
		case j.Address == "":
			r.Text = "Nothing was sent to the device"
		case m != nil && m[1] == "0":
			r.Text = "Scanned " + j.Address + ": it did not answer"
		case m != nil:
			r.Text = "Scanned " + j.Address + ": it answered; what it runs is on its device page"
		default:
			r.Text = "Scanned " + j.Address
		}
	case sensoractive.KindSNMP:
		r.Engine = "snmp"
		r.Label = fmt.Sprintf("SNMP read of %d %s", j.Targets, plural(j.Targets, "device", "devices"))
		switch j.Reason {
		case "snmp_test":
			r.Trigger, r.Label = "test", "SNMP test"
		case "window":
			r.Trigger = "automatic"
		default:
			r.Trigger = "person"
		}
		r.Text = fmt.Sprintf("Read %d %s over SNMP", j.Targets, plural(j.Targets, "device", "devices"))
	default:
		return core.HistoryRun{}, false
	}
	switch r.Outcome {
	case "running":
		r.Text = "Running"
	case "failed":
		r.Text = "Failed: " + orDefault(j.Error, "the box did not record why")
	case "stopped":
		r.Text = "Stopped: " + orDefault(j.Error, "stopped before the end")
	}
	r.Text = clipText(r.Text, 300)
	return r, true
}

// exposureHistory is a stored scan of a public target as a History row (one per target and day).
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
	end := at
	return core.HistoryRun{ID: "exp-" + s.TargetID + "-" + at.Format(time.DateOnly), Kind: "external", Engine: "nuclei", Trigger: "person", Label: s.Target, TargetID: s.TargetID,
		StartedAt: at, EndedAt: &end, Outcome: "ok", Text: "Scanned " + s.Target + ": " + strings.Join(parts, ", ")}, true
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

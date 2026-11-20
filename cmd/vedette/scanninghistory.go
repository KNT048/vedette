package main

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
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
// With asset (the device page's Last checks): only that device's LAN jobs, at most historyRead of each kind: its identifications
// (the jobs that name it, and those stored before jobs named their device that reached its address now) and the SNMP reads of its
// SNMP read address while it has SNMP set up; no sweep, no public scan.
func (e scanningEngines) history(ctx context.Context, asset string) ([]core.HistoryRun, error) {
	var out []core.HistoryRun
	if e.d.DB != nil && e.d.SensorDispatcher != nil {
		if svc, err := sensorActiveService(ctx, e.d); err == nil {
			var jobs []sensoractive.JobRow
			if asset == "" {
				jobs, err = svc.Jobs(ctx, historyRead)
			} else {
				var at netip.Addr
				if at, err = e.deviceAddr(ctx, asset); err == nil {
					jobs, err = svc.JobsOf(ctx, asset, at, historyRead)
				}
			}
			if err != nil {
				return nil, err
			}
			shown := e.osShown(ctx, jobs)
			for _, j := range jobs {
				if r, ok := jobHistory(j, shown); ok {
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

// osShown is the OS the device page shows now for each device whose checks recorded an OS (the inventory's ranking, INV-44), so a
// check's words never put another OS beside the one the page shows. Nil without an inventory: the checks' words are kept. A failed
// read is logged and leaves out the OS words of those checks: the list still answers, and never names an OS the page may not show.
func (e scanningEngines) osShown(ctx context.Context, jobs []sensoractive.JobRow) map[string]shownOS {
	if e.d.Inventory == nil {
		return nil
	}
	var ids []string
	for _, j := range jobs {
		if j.Found != nil && j.Found.OS != "" && j.AssetID != "" && !slices.Contains(ids, j.AssetID) {
			ids = append(ids, j.AssetID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]shownOS, len(ids))
	refs, err := e.d.Inventory.DeviceRefs(ctx, ids)
	if err != nil {
		if e.d.Log != nil {
			e.d.Log.ErrorContext(ctx, "scanning history: the OS the device pages show could not be read; checks are listed without their OS", "error", err)
		}
		for _, id := range ids {
			out[id] = shownOS{Unread: true}
		}
		return out
	}
	for id, r := range refs {
		out[id] = shownOS{Value: r.OS, Basis: r.OSBasis}
	}
	return out
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
// shownOS is the OS a device's page shows now: the value the inventory's ranking chose and its basis (inventory DeviceRef: "guess"
// for nmap's fingerprint, "stated", or ""), or Unread when it could not be read.
type shownOS struct {
	Value, Basis string
	Unread       bool
}

func jobHistory(j sensoractive.JobRow, shown map[string]shownOS) (core.HistoryRun, bool) {
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
	var found string    // what the stored probes say it did, "" when it sent none
	var noAnswer string // why an SNMP read that ended found nothing: nothing answered
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
		case "check_now", "check_wait":
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
			case j.Found != nil: // what it recorded on the device (sa_job.found)
				var page *shownOS
				if o, ok := shown[j.AssetID]; ok {
					page = &o
				}
				found = foundText(addr, *j.Found, page)
			case m != nil && m[1] == "0":
				found = "scanned " + addr + ": it did not answer"
			case m != nil:
				found = "scanned " + addr + ": it answered (a check from before checks kept what they found)"
				switch {
				case j.AssetID == "": // a check stored before checks named their device
				case j.Status == sensoractive.StatusRunning: // what it found is stored when it ends
					found = "scanned " + addr + ": it answered; what it found is shown when the check ends"
				case j.Status == sensoractive.StatusDone: // it finished, but storing its result failed
					found = "scanned " + addr + ": it answered, but what it found could not be recorded"
				default: // stopped or failed: the reason is the sentence; it recorded nothing
					found = "scanned " + addr + ": it answered"
				}
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
		round := ""
		if asked > 1 {
			round = fmt.Sprintf(" (a round of %d devices: %d answered)", asked, answered)
		}
		switch {
		case !read:
		case j.Own != "" && r.Outcome == "ok": // the device page: how this device's own read went
			if j.Own == "ok" {
				found = "this device answered over SNMP" + round
			} else {
				r.Outcome, noAnswer = "failed", orDefault(snmpOwnWhy[j.Own], "the SNMP read of this device failed")+round
			}
		case answered == 0 && r.Outcome == "ok": // it asked and nothing came back: no model, no firmware read
			r.Outcome, noAnswer = "failed", "no device answered over SNMP"
			if asked == 1 {
				noAnswer = "the device did not answer over SNMP"
			}
		case asked == 1 && answered == 1:
			found = "the device answered over SNMP"
		default:
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
		switch {
		case found != "" && j.Kind == sensoractive.KindDevice: // one device: its sentence says what is still to come
			r.Text += ": " + found
		case found != "":
			r.Text += ": " + found + " so far"
		case len(j.Probes) == 0 && j.Kind == sensoractive.KindSweep:
			r.Text += ": sweeping"
		}
	case "failed", "stopped":
		why := orDefault(j.Error, orDefault(noAnswer, orDefault(probeErr, map[string]string{"failed": "the box did not record why", "stopped": "stopped before the end"}[r.Outcome])))
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
	r.Text = clipText(r.Text, 600)
	return r, true
}

// snmpOwnWhy is why a device's own SNMP read found nothing, by sa_snmp_device.last_status.
var snmpOwnWhy = map[string]string{
	"no_answer":    "this device did not answer over SNMP",
	"auth_failed":  "this device refused the SNMP community or password",
	"unknown_user": "this device does not know the SNMP v3 user",
}

// shownPorts is how many open ports a device check names before "and n more".
const shownPorts = 8

// foundText is what a device check found, in words, from what it stored (sensoractive.DeviceFound): the open ports with nmap's
// service names, its OS guess, and what changed since the previous check of the same reach ("nothing changed" when the ports and
// the OS guess are the same). The OS it recorded, and its change, are said only when it is the OS the device page shows now (page;
// nil: no page to compare with, said as recorded): otherwise "scan guess not used now", never a second OS value (INV-44 of
// inventory). A change is said without the old value. Lower case first: the caller makes the sentence.
func foundText(addr string, f sensoractive.DeviceFound, page *shownOS) string {
	var b strings.Builder
	switch f.Reach {
	case "top100":
		b.WriteString("gentle scan of " + addr + " (its 100 most used ports)")
	case "all":
		b.WriteString("scanned every port of " + addr)
	case "extra":
		b.WriteString("scanned " + addr + ": only the scan of the extra ports saw it")
	default:
		b.WriteString("scanned " + addr)
	}
	sep := ": "
	if f.Reach == "extra" {
		sep = "; "
	}
	if f.TimedOut {
		b.WriteString(sep + "it answered, but nmap reached its time limit before it listed the ports; the ports known before are kept")
	} else {
		b.WriteString(sep + portsText(f))
	}
	osChanged := false
	switch {
	case f.OS == "", page != nil && page.Unread: // nothing recorded, or the page's OS unknown: no OS words
	case page != nil && page.Value != f.OS: // the page shows another OS (a better source, or a newer scan's guess): one OS on the page
		b.WriteString("; OS: scan guess not used now")
	default: // the OS the page shows (or no page to compare with): a guess is called one, the device's own answer is not
		label := "OS guess "
		if page != nil && page.Basis != "guess" {
			label = "OS "
		}
		if f.OSWas != "" {
			b.WriteString("; " + label + "now " + f.OS + " (changed since the previous check)")
			osChanged = true
		} else {
			b.WriteString("; " + label + f.OS)
		}
	}
	if f.ExtraFailed {
		b.WriteString("; the scan of the extra ports did not finish")
	}
	if f.Compared && !f.TimedOut {
		since := "since the previous check"
		if f.ComparedPart { // one of the two checks did not cover the extra ports
			since += " (outside the extra ports)"
		}
		var ch []string
		if len(f.New) > 0 {
			ch = append(ch, portList(f.New)+" newly open")
		}
		if len(f.Gone) > 0 {
			ch = append(ch, portList(f.Gone)+" no longer open")
		}
		switch {
		case len(ch) > 0:
			b.WriteString("; " + since + ": " + strings.Join(ch, ", "))
		case !osChanged:
			b.WriteString("; nothing changed " + since)
		}
	}
	return b.String()
}

// portsText is "3 open ports (22 ssh, 80 http, 161/udp snmp)", "no open port", or the first shownPorts and "and n more".
func portsText(f sensoractive.DeviceFound) string {
	if f.Open == 0 {
		return "no open port"
	}
	var names []string
	for _, p := range f.Ports[:min(len(f.Ports), shownPorts)] {
		n := strconv.Itoa(p.Port)
		if p.Proto == "udp" {
			n += "/udp"
		}
		if p.Name != "" {
			n += " " + p.Name
		}
		names = append(names, n)
	}
	if more := f.Open - len(names); more > 0 {
		names = append(names, fmt.Sprintf("and %d more", more))
	}
	return count(f.Open, "open port", "open ports") + " (" + strings.Join(names, ", ") + ")"
}

// portList is "port 23" or "ports 23, 8080".
func portList(ps []int) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = strconv.Itoa(p)
	}
	return plural(len(ps), "port ", "ports ") + strings.Join(out, ", ")
}

// exposureHistory is a stored scan of a public target as a History row (one per target and day). Public scans run only when a person
// presses Scan now (exposure INV-30), so the trigger is a person; who is in the audit log, not in the snapshot. A scan that failed
// before it stored its snapshot is not kept anywhere and cannot be listed (the History tab says so).
func exposureHistory(s exposure.ScanRecord) (core.HistoryRun, bool) {
	at, ok := parseTS(s.StartedAt) // a scan is named by its start, as on the target's page
	if !ok {
		if at, ok = parseTS(s.ScannedAt); !ok {
			return core.HistoryRun{}, false
		}
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
	var end *time.Time // nil while OpenVAS still runs: the scan has not ended
	if s.FinishedAt != nil {
		if e, ok := parseTS(*s.FinishedAt); ok {
			end = &e
		}
	}
	if s.Greenbone == "running" {
		outcome, text = "running", text+"; OpenVAS is still scanning"
	} else if end == nil { // a scan stored before its end was kept
		end = &at
	}
	id := s.RunID // the scan's shared run
	return core.HistoryRun{ID: id, Kind: "external", Engine: "nuclei", Trigger: "person", Label: s.Target, TargetID: s.TargetID,
		StartedAt: at, EndedAt: end, Outcome: outcome, Text: text}, true
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

package main

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// Every run of the LAN engines and every public scan has a History row whose outcome comes from what it stored.
func TestJobHistory_OutcomeInWords(t *testing.T) {
	end := "2026-11-17T03:19:00.000Z"
	p := func(targets, result string) sensoractive.JobProbe {
		return sensoractive.JobProbe{Targets: targets, Result: result}
	}
	job := func(kind, status, reason, errText string, targets, newDevices int, probes ...sensoractive.JobProbe) sensoractive.JobRow {
		return sensoractive.JobRow{JobHead: sensoractive.JobHead{ID: "j", Kind: kind, Status: status, Reason: reason, StartedAt: "2026-11-17T03:18:00.000Z", FinishedAt: &end, Targets: targets, NewDevices: newDevices, Error: errText}, Probes: probes}
	}
	for _, c := range []struct {
		name                          string
		j                             sensoractive.JobRow
		trigger, label, outcome, text string
	}{
		{"sweep, one batch", job("sweep", "done", "", "", 254, 2, p("10.142.0.0/24", "ok: 12 hosts up")), "sweep", "LAN sweep of 10.142.0.0/24", "ok", "Swept 254 addresses: 12 hosts answered, 2 new devices"},
		// #940 review r1 M3: every batch counts, and a stopped sweep says what it did before it stopped
		{"sweep, batches", job("sweep", "done", "", "", 128, 1, p("10.142.0.0/26", "ok: 3 hosts up"), p("10.142.0.64/26", "ok: 2 hosts up")), "sweep", "LAN sweep in 2 batches", "ok", "Swept 128 addresses in 2 batches: 5 hosts answered, 1 new device"},
		{"sweep stopped", job("sweep", "stopped", "", "outside the window", 64, 0, p("10.142.0.0/26", "ok: 3 hosts up")), "sweep", "LAN sweep of 10.142.0.0/26", "stopped", "Stopped: outside the window. Swept 64 addresses: 3 hosts answered, 0 new devices before it ended"},
		{"sweep stopped at once", job("sweep", "stopped", "", "outside the window", 0, 0), "sweep", "LAN sweep", "stopped", "Stopped: outside the window. Nothing was sent"},
		{"check now", job("device", "done", "check_now", "", 1, 0, p("10.142.0.20", "ok: 1 hosts up")), "person", "10.142.0.20", "ok", "Scanned 10.142.0.20: it answered (a check from before checks kept what they found)"},
		{"no answer", job("device", "done", "discovered", "", 1, 0, p("10.142.0.21", "ok: 0 hosts up")), "automatic", "10.142.0.21", "ok", "Scanned 10.142.0.21: it did not answer"},
		{"scan now failed", job("device", "failed", "scan_now", "nmap exited 1", 1, 0), "scan_now", "A device", "failed", "Failed: nmap exited 1. Nothing was sent"},
		// #940 review r2: only what is stored; a running sweep has not swept its planned size, a failed probe found nothing
		{"sweep running", job("sweep", "running", "", "", 1024, 0, p("10.142.0.0/24", "ok: 4 hosts up")), "sweep", "LAN sweep of 10.142.0.0/24", "running", "Running: 1 batch finished: 4 hosts answered so far"},
		{"sweep running, no batch yet", job("sweep", "running", "", "", 1024, 0), "sweep", "LAN sweep", "running", "Running: sweeping"},
		{"sweep, only batch failed", job("sweep", "done", "", "", 254, 0, p("10.142.0.0/24", "failed: nmap exited 1")), "sweep", "LAN sweep of 10.142.0.0/24", "failed", "Failed: nmap exited 1."},
		{"device probe failed", job("device", "done", "check_now", "", 1, 0, p("10.0.0.5", "failed: nmap gave up")), "person", "10.0.0.5", "failed", "Failed: nmap gave up."},
		{"done, nothing sent", job("sweep", "done", "", "", 0, 0), "sweep", "LAN sweep", "partial", "Nothing was sent"},
		// #940 review r1 H1: an SNMP read says how many answered, from its probes, never only how many it asked
		{"snmp, none answered", job("snmp", "done", "window", "", 3, 0, p("10.142.0.1,10.142.0.2,10.142.0.3", "ok: 0 of 3 answered")), "automatic", "SNMP read", "failed", "Failed: no device answered over SNMP."},
		// a test of one device that got no answer read nothing: failed, never "partly done"
		{"snmp test, no answer", job("snmp", "done", "snmp_test", "", 1, 0, p("10.142.0.1", "ok: 0 of 1 answered")), "test", "SNMP test", "failed", "Failed: the device did not answer over SNMP."},
		{"snmp check, answered", job("snmp", "done", "snmp_test", "", 1, 0, p("10.142.0.1", "ok: 1 of 1 answered")), "test", "SNMP test", "ok", "The device answered over SNMP"},
		{"snmp, some answered", job("snmp", "done", "window", "", 3, 0, p("10.142.0.1-10.142.0.3", "ok: 2 of 3 answered")), "automatic", "SNMP read", "partial", "2 of 3 devices answered over SNMP"},
		{"snmp, all answered", job("snmp", "done", "snmp_read", "", 2, 0, p("10.142.0.1", "ok: 1 of 1 answered"), p("10.142.0.2", "ok: 1 of 1 answered")), "person", "SNMP read", "ok", "2 of 2 devices answered over SNMP"},
		{"snmp test, read failed", job("snmp", "done", "snmp_test", "", 1, 0, p("10.142.0.30", "failed: the read did not finish")), "test", "SNMP test", "failed", "Failed: the read did not finish."},
		{"snmp, one batch failed", job("snmp", "done", "window", "", 4, 0, p("a", "ok: 2 of 2 answered"), p("b", "failed: the read did not finish")), "automatic", "SNMP read", "partial", "2 of 2 devices answered over SNMP; 1 part failed"},
	} {
		r, ok := jobHistory(c.j, nil)
		if !ok || r.Trigger != c.trigger || r.Label != c.label || r.Outcome != c.outcome || r.Text != c.text || r.EndedAt == nil {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	// a check made since checks name their device whose result could not be recorded says so, never that it is an old check
	rec := job("device", "done", "check_now", "", 1, 0, p("192.168.10.20", "ok: 1 hosts up"))
	rec.AssetID = "a-1"
	if r, _ := jobHistory(rec, nil); r.Text != "Scanned 192.168.10.20: it answered, but what it found could not be recorded" {
		t.Errorf("unrecorded check: %q", r.Text)
	}
	// only a finished check says that; one still running says when its result comes, a stopped or failed one gives its reason
	for _, c := range []struct{ status, errText, outcome, text string }{
		{"running", "", "running", "Running: scanned 192.168.10.20: it answered; what it found is shown when the check ends"},
		{"failed", "nmap exited 1", "failed", "Failed: nmap exited 1. Scanned 192.168.10.20: it answered before it ended"},
		{"stopped", "outside the window", "stopped", "Stopped: outside the window. Scanned 192.168.10.20: it answered before it ended"},
	} {
		j := job("device", c.status, "check_now", c.errText, 1, 0, p("192.168.10.20", "ok: 1 hosts up"))
		j.AssetID = "a-1"
		if c.status == "running" {
			j.FinishedAt = nil
		}
		if r, _ := jobHistory(j, nil); r.Outcome != c.outcome || r.Text != c.text {
			t.Errorf("%s check: %s %q", c.status, r.Outcome, r.Text)
		}
	}
	// the device page: in a round of several devices, its own read decides the outcome and the words
	for _, c := range []struct{ own, outcome, text string }{
		{"ok", "ok", "This device answered over SNMP (a round of 2 devices: 1 answered)"},
		{"no_answer", "failed", "Failed: this device did not answer over SNMP (a round of 2 devices: 1 answered)."},
		{"auth_failed", "failed", "Failed: this device refused the SNMP community or password (a round of 2 devices: 1 answered)."},
		{"error", "failed", "Failed: the SNMP read of this device failed (a round of 2 devices: 1 answered)."},
	} {
		j := job("snmp", "done", "window", "", 2, 0, p("192.168.10.1,192.168.10.9", "ok: 1 of 2 answered"))
		j.Own = c.own
		if r, _ := jobHistory(j, nil); r.Outcome != c.outcome || r.Text != c.text {
			t.Errorf("own %s: %s %q", c.own, r.Outcome, r.Text)
		}
	}
	if _, ok := jobHistory(job("external", "done", "exposure", "", 1, 0), nil); ok {
		t.Errorf("an external sa_job is exposure's to list")
	}
}

func TestExposureHistory_CountsInWords(t *testing.T) {
	r, ok := exposureHistory(exposure.ScanRecord{TargetID: "xt-1", Target: "203.0.113.10", ScannedAt: "2026-11-16T06:00:00.000Z", Counts: exposure.Counts{Ports: 1, AdminPanels: 2}})
	if !ok || r.Kind != "external" || r.TargetID != "xt-1" || r.Trigger != "person" || r.Outcome != "ok" || r.Text != "Scanned 203.0.113.10: 1 open port, 2 admin pages" {
		t.Errorf("exposure: %+v", r)
	}
	// #940 review r1 M2: what the snapshot stored as not checked, or an OpenVAS run that failed, makes it partial and says so
	r, _ = exposureHistory(exposure.ScanRecord{TargetID: "xt-1", Target: "203.0.113.10", ScannedAt: "2026-11-16T06:00:00.000Z", NotChecked: 2, Greenbone: "failed"})
	if r.Outcome != "partial" || r.Text != "Scanned 203.0.113.10: 0 open ports; OpenVAS failed; 2 steps not checked (see the target)" {
		t.Errorf("exposure partial: %+v", r)
	}
}

// A device check says what it found and what changed, from what it stored (sa_job.found), for every reach of a check: open ports
// with nmap's names, the OS guess (and the one before when it changed), the ports opened and closed since the previous check of the
// same reach, "nothing changed" when the ports and the guess are the same; a check that timed out says the ports were not listed.
func TestJobHistory_DeviceCheckSaysWhatItFound(t *testing.T) {
	end := "2026-11-17T03:19:00.000Z"
	job := func(f sensoractive.DeviceFound, result string) sensoractive.JobRow {
		return sensoractive.JobRow{JobHead: sensoractive.JobHead{ID: "j", Kind: "device", Status: "done", Reason: "check_now", StartedAt: "2026-11-17T03:18:00.000Z", FinishedAt: &end, Targets: 1},
			Probes: []sensoractive.JobProbe{{Targets: "192.168.10.47", Result: result}}, Found: &f}
	}
	ports := []sensoractive.FoundPort{{Port: 22, Proto: "tcp", Name: "ssh"}, {Port: 80, Proto: "tcp", Name: "http"}, {Port: 161, Proto: "udp", Name: "snmp"}}
	many := make([]sensoractive.FoundPort, 0, 12)
	for i := range 12 {
		many = append(many, sensoractive.FoundPort{Port: 8000 + i, Proto: "tcp"})
	}
	for _, c := range []struct {
		name    string
		f       sensoractive.DeviceFound
		result  string
		outcome string
		text    string
	}{
		{"first check", sensoractive.DeviceFound{Reach: "top1000", Open: 3, Ports: ports, OS: "Cisco Catalyst switch (IOS 15)"}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: 3 open ports (22 ssh, 80 http, 161/udp snmp); OS guess Cisco Catalyst switch (IOS 15)"},
		{"nothing changed", sensoractive.DeviceFound{Reach: "top1000", Open: 3, Ports: ports, OS: "Cisco Catalyst switch (IOS 15)", Compared: true}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: 3 open ports (22 ssh, 80 http, 161/udp snmp); OS guess Cisco Catalyst switch (IOS 15); nothing changed since the previous check"},
		{"OS changed", sensoractive.DeviceFound{Reach: "top1000", Open: 3, Ports: ports, OS: "Cisco Catalyst switch (IOS 15)", OSWas: "Cisco ISR router", Compared: true}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: 3 open ports (22 ssh, 80 http, 161/udp snmp); OS guess now Cisco Catalyst switch (IOS 15) (changed since the previous check)"},
		{"ports changed", sensoractive.DeviceFound{Reach: "top1000", Open: 3, Ports: ports, Compared: true, New: []int{80}, Gone: []int{23, 443}}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: 3 open ports (22 ssh, 80 http, 161/udp snmp); since the previous check: port 80 newly open, ports 23, 443 no longer open"},
		{"no open port", sensoractive.DeviceFound{Reach: "top1000"}, "ok: 1 hosts up", "ok", "Scanned 192.168.10.47: no open port"},
		{"many ports", sensoractive.DeviceFound{Reach: "all", Open: 70, Ports: many}, "ok: 1 hosts up", "ok",
			"Scanned every port of 192.168.10.47: 70 open ports (8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, and 62 more)"},
		{"gentle", sensoractive.DeviceFound{Reach: "top100", Open: 1, Ports: ports[:1]}, "ok: 1 hosts up", "ok", "Gentle scan of 192.168.10.47 (its 100 most used ports): 1 open port (22 ssh)"},
		{"only the extra ports", sensoractive.DeviceFound{Reach: "extra", Open: 1, Ports: []sensoractive.FoundPort{{Port: 22222, Proto: "tcp", Name: "ssh"}}}, "ok: 0 hosts up", "ok",
			"Scanned 192.168.10.47: only the scan of the extra ports saw it; 1 open port (22222 ssh)"},
		{"extra ports did not finish", sensoractive.DeviceFound{Reach: "top1000", Open: 1, Ports: ports[:1], ExtraFailed: true, Compared: true, ComparedPart: true, New: []int{40000}}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: 1 open port (22 ssh); the scan of the extra ports did not finish; since the previous check (outside the extra ports): port 40000 newly open"},
		{"compared outside the extra ports, no change", sensoractive.DeviceFound{Reach: "top1000", Open: 1, Ports: ports[:1], Compared: true, ComparedPart: true}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: 1 open port (22 ssh); nothing changed since the previous check (outside the extra ports)"},
		{"timed out", sensoractive.DeviceFound{Reach: "top1000", TimedOut: true, Compared: true}, "ok: 1 hosts up", "ok",
			"Scanned 192.168.10.47: it answered, but nmap reached its time limit before it listed the ports; the ports known before are kept"},
	} {
		r, ok := jobHistory(job(c.f, c.result), nil)
		if !ok || r.Outcome != c.outcome || r.Text != c.text || r.Label != "192.168.10.47" {
			t.Errorf("%s:\n got %q (%s)\nwant %q", c.name, r.Text, r.Outcome, c.text)
		}
	}
}

// A device check names the OS it recorded only when it is the OS the device page shows now (the inventory's ranking): a better
// source (a person, an agent, SNMP, LLDP) or a newer scan's guess makes it "scan guess not used now", never a second OS value; a
// change is said without the old value; the device's own NTLM answer is not called a guess; an unread page drops the OS words.
func TestJobHistory_TheScanGuessOnlyWhenThePageShowsIt(t *testing.T) {
	end := "2026-11-17T03:19:00.000Z"
	j := sensoractive.JobRow{JobHead: sensoractive.JobHead{ID: "j", Kind: "device", Status: "done", Reason: "check_now", StartedAt: "2026-11-17T03:18:00.000Z", FinishedAt: &end, Targets: 1},
		AssetID: "a-sw", Probes: []sensoractive.JobProbe{{Targets: "192.168.10.47", Result: "ok: 1 hosts up"}},
		Found: &sensoractive.DeviceFound{Reach: "top1000", Open: 1, Ports: []sensoractive.FoundPort{{Port: 22, Proto: "tcp", Name: "ssh"}},
			OS: "Network switch OS (8.5 - 11.2)", OSWas: "Network switch OS (12)", Compared: true}}
	const ports = "Scanned 192.168.10.47: 1 open port (22 ssh)"
	const notUsed = ports + "; OS: scan guess not used now; nothing changed since the previous check"
	for _, c := range []struct {
		name  string
		shown map[string]shownOS
		text  string
	}{
		{"stated over LLDP", map[string]shownOS{"a-sw": {Value: "NetOS 15.1R7.9", Basis: "stated"}}, notUsed},
		{"SNMP", map[string]shownOS{"a-sw": {Value: "NetOS 15.1R7.9"}}, notUsed},
		{"a newer scan's guess", map[string]shownOS{"a-sw": {Value: "Network switch OS (12)", Basis: "guess"}}, notUsed},
		{"no OS on the page", map[string]shownOS{"a-sw": {}}, notUsed},
		{"the page shows this guess", map[string]shownOS{"a-sw": {Value: "Network switch OS (8.5 - 11.2)", Basis: "guess"}},
			ports + "; OS guess now Network switch OS (8.5 - 11.2) (changed since the previous check)"},
		{"the page's OS could not be read", map[string]shownOS{"a-sw": {Unread: true}}, ports + "; nothing changed since the previous check"},
		{"no page to compare with", nil, ports + "; OS guess now Network switch OS (8.5 - 11.2) (changed since the previous check)"},
	} {
		r, ok := jobHistory(j, c.shown)
		if !ok || r.Text != c.text {
			t.Errorf("%s:\n got %q\nwant %q", c.name, r.Text, c.text)
		}
		if strings.Contains(r.Text, "Network switch OS (12)") || strings.Contains(r.Text, "NetOS") {
			t.Errorf("%s: a second OS value in %q", c.name, r.Text)
		}
	}
	// the device's own NTLM answer, shown on the page (basis not a guess), is named without "guess"
	ntlm := j
	f := *j.Found
	f.OS, f.OSWas = "Windows 11 (build 26100)", ""
	ntlm.Found = &f
	if r, _ := jobHistory(ntlm, map[string]shownOS{"a-sw": {Value: "Windows 11 (build 26100)"}}); r.Text != ports+"; OS Windows 11 (build 26100); nothing changed since the previous check" {
		t.Errorf("NTLM answer: %q", r.Text)
	}
}

package main

import (
	"testing"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// kien G7a: every run of the LAN engines and every public scan has a History row whose outcome comes from what it stored.
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
		{"sweep, one batch", job("sweep", "done", "", "", 254, 2, p("192.168.18.0/24", "ok: 12 hosts up")), "sweep", "LAN sweep of 192.168.18.0/24", "ok", "Swept 254 addresses: 12 hosts answered, 2 new devices"},
		// #940 review r1 M3: every batch counts, and a stopped sweep says what it did before it stopped
		{"sweep, batches", job("sweep", "done", "", "", 128, 1, p("192.168.18.0/26", "ok: 3 hosts up"), p("192.168.18.64/26", "ok: 2 hosts up")), "sweep", "LAN sweep in 2 batches", "ok", "Swept 128 addresses in 2 batches: 5 hosts answered, 1 new device"},
		{"sweep stopped", job("sweep", "stopped", "", "outside the window", 64, 0, p("192.168.18.0/26", "ok: 3 hosts up")), "sweep", "LAN sweep of 192.168.18.0/26", "stopped", "Stopped: outside the window. Swept 64 addresses: 3 hosts answered, 0 new devices before it ended"},
		{"sweep stopped at once", job("sweep", "stopped", "", "outside the window", 0, 0), "sweep", "LAN sweep", "stopped", "Stopped: outside the window. Nothing was sent"},
		{"check now", job("device", "done", "check_now", "", 1, 0, p("192.168.18.20", "ok: 1 hosts up")), "person", "192.168.18.20", "ok", "Scanned 192.168.18.20: it answered; what it runs is on its device page"},
		{"no answer", job("device", "done", "discovered", "", 1, 0, p("192.168.18.21", "ok: 0 hosts up")), "automatic", "192.168.18.21", "ok", "Scanned 192.168.18.21: it did not answer"},
		{"scan now failed", job("device", "failed", "scan_now", "nmap exited 1", 1, 0), "scan_now", "A device", "failed", "Failed: nmap exited 1. Nothing was sent"},
		// #940 review r1 H1: an SNMP read says how many answered, from its probes, never only how many it asked
		{"snmp, none answered", job("snmp", "done", "window", "", 3, 0, p("192.168.18.1,192.168.18.2,192.168.18.3", "ok: 0 of 3 answered")), "automatic", "SNMP read", "partial", "0 of 3 devices answered over SNMP"},
		{"snmp, all answered", job("snmp", "done", "snmp_read", "", 2, 0, p("192.168.18.1", "ok: 1 of 1 answered"), p("192.168.18.2", "ok: 1 of 1 answered")), "person", "SNMP read", "ok", "2 of 2 devices answered over SNMP"},
		{"snmp test, read failed", job("snmp", "done", "snmp_test", "", 1, 0, p("192.168.18.30", "failed: the read did not finish")), "test", "SNMP test", "failed", "Failed: the read did not finish."},
		{"snmp, one batch failed", job("snmp", "done", "window", "", 4, 0, p("a", "ok: 2 of 2 answered"), p("b", "failed: the read did not finish")), "automatic", "SNMP read", "partial", "2 of 2 devices answered over SNMP; 1 part failed"},
	} {
		r, ok := jobHistory(c.j)
		if !ok || r.Trigger != c.trigger || r.Label != c.label || r.Outcome != c.outcome || r.Text != c.text || r.EndedAt == nil {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	if _, ok := jobHistory(job("external", "done", "exposure", "", 1, 0)); ok {
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

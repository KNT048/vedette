package main

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// kien G7a: every run of the LAN engines and every public scan has a History row whose outcome comes from what it stored.
func TestJobHistory_OutcomeInWords(t *testing.T) {
	end := "2026-11-17T03:19:00.000Z"
	job := func(kind, status, reason, addr, result, errText string, targets, newDevices int) sensoractive.JobRow {
		return sensoractive.JobRow{JobHead: sensoractive.JobHead{ID: "j", Kind: kind, Status: status, Reason: reason, StartedAt: "2026-11-17T03:18:00.000Z", FinishedAt: &end, Targets: targets, NewDevices: newDevices, Error: errText}, Address: addr, Result: result}
	}
	for _, c := range []struct {
		name                          string
		j                             sensoractive.JobRow
		trigger, label, outcome, text string
	}{
		{"sweep", job("sweep", "done", "", "192.168.18.0/24", "ok: 12 hosts up", "", 254, 2), "sweep", "LAN 192.168.18.0/24", "ok", "Swept 254 addresses, 2 new devices"},
		{"check now", job("device", "done", "check_now", "192.168.18.20", "ok: 1 hosts up", "", 1, 0), "person", "192.168.18.20", "ok", "Scanned 192.168.18.20: it answered; what it runs is on its device page"},
		{"no answer", job("device", "done", "discovered", "192.168.18.21", "ok: 0 hosts up", "", 1, 0), "automatic", "192.168.18.21", "ok", "Scanned 192.168.18.21: it did not answer"},
		{"scan now failed", job("device", "failed", "scan_now", "192.168.18.22", "", "nmap exited 1", 1, 0), "scan_now", "192.168.18.22", "failed", "Failed: nmap exited 1"},
		{"stopped", job("sweep", "stopped", "", "", "", "outside the window", 254, 0), "sweep", "LAN", "stopped", "Stopped: outside the window"},
		{"snmp test", job("snmp", "done", "snmp_test", "192.168.18.30", "", "", 1, 0), "test", "SNMP test", "ok", "Read 1 device over SNMP"},
	} {
		r, ok := jobHistory(c.j)
		if !ok || r.Trigger != c.trigger || r.Label != c.label || r.Outcome != c.outcome || r.Text != c.text || r.EndedAt == nil {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	if _, ok := jobHistory(job("external", "done", "exposure", "", "", "", 1, 0)); ok {
		t.Errorf("an external sa_job is exposure's to list")
	}
}

func TestExposureHistory_CountsInWords(t *testing.T) {
	r, ok := exposureHistory(exposure.ScanRecord{TargetID: "xt-1", Target: "203.0.113.10", ScannedAt: "2026-11-16T06:00:00.000Z", Counts: exposure.Counts{Ports: 1, AdminPanels: 2}})
	if !ok || r.Kind != "external" || r.TargetID != "xt-1" || r.Trigger != "person" || !strings.HasPrefix(r.Text, "Scanned 203.0.113.10: 1 open port, 2 admin pages") {
		t.Errorf("exposure: %+v", r)
	}
}

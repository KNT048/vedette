package agentintake_test

import (
	"testing"
	"time"
)

// W-2 (D-548, TUNE-5b walk): a machine whose system_info answer has not reached the inventory is named by the host name osquery gave at
// enrolment, not by its network card's maker; the system_info answer then replaces it.
func TestContract_D548_EnrolmentHostNameNamesTheDevice(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("lab", 7)
	key := w.enroll(secret, "WIN-LAB", peerA)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)),
		snap("os_version", map[string]string{"name": "Microsoft Windows Server 2025 Standard Evaluation", "version": "10.0.26100", "build": "26100", "platform": "windows"})))
	if d, ok := w.device(peerA); !ok || d.Hostname == nil || *d.Hostname != "WIN-LAB" {
		t.Fatalf("before system_info: %+v", d.AssetCore)
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("system_info", map[string]string{"hostname": "win-lab.corp", "hardware_vendor": "QEMU", "hardware_model": "Standard PC"})))
	if d, _ := w.device(peerA); d.Hostname == nil || *d.Hostname != "win-lab.corp" {
		t.Fatalf("after system_info: %+v", d.AssetCore)
	}
}

// Review r1 #8: after the first-report window the enrolment's name is not written again (the device keeps it; system_info renames it).
func TestContract_D548_EnrolmentHostNameOnlyInTheFirstHour(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("lab", 7)
	key := w.enroll(secret, "WIN-LAB", peerA)
	w.clock.Advance(61 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)),
		snap("os_version", map[string]string{"name": "Microsoft Windows Server 2025 Standard Evaluation", "version": "10.0.26100", "build": "26100", "platform": "windows"})))
	if n := w.count(`SELECT count(*) FROM inv_observation WHERE field = 'hostname'`); n != 0 {
		t.Fatalf("hostname observations after the window: %d", n)
	}
}

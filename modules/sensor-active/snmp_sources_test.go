package sensoractive_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// A device whose SNMP a person set up is read outside the LAN ranges (those bind discovery and nmap
// only); the exclusions still win, at the device's address and at its read address; SNMP turned off for a device, or a device added
// by hand whose SNMP is not on, gets nothing and the check says why.
func TestSNMPSourcesAndScope(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ip := netip.MustParseAddr
	w.inv.mu.Lock()
	for id, a := range map[string]string{"a-forti": "100.66.254.1", "a-excl": "100.66.255.9", "a-off": "192.168.10.30", "a-hand": "192.168.10.31", "a-late": "100.66.255.10"} {
		w.inv.assets[id], w.inv.addrs[ip(a)], w.inv.approved[id] = ip(a), id, true
	}
	w.inv.st.Exclusions = []string{"100.66.255.9"}
	// What the inventory's SNMPPolicy answers (its rules are the inventory's tests): the FortiGate is outside lan_ranges and read;
	// a-excl is excluded; a-off has SNMP off; a-hand was added by hand.
	w.inv.snmpDecision = map[string]sa.Decision{
		"a-forti": {Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true},
		"a-excl":  {Reason: "excluded"},
		"a-off":   {Reason: "snmp_off"},
		"a-hand":  {Reason: "declared_by_hand"},
		// a-late: the policy is read before the exclusion is saved; the batch's own check against the settings stops it
		"a-late": {Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true},
	}
	w.inv.mu.Unlock()
	forti := v2c("s3cret-community")
	forti.ReadFrom = "100.66.253.1"
	w.set("a-forti", forti)
	for _, id := range []string{"a-excl", "a-off", "a-hand", "a-late"} {
		w.set(id, v2c("s3cret-community"))
	}
	res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", "a-forti")
	if err != nil || !res.OK {
		t.Fatalf("a device outside lan_ranges is read at its read address: %v %+v", err, res)
	}
	if jobs := r.sent(); len(jobs) != 1 || jobs[0].Targets[0].IP != "100.66.253.1" {
		t.Fatalf("jobs %+v", jobs)
	}
	for _, c := range []struct{ id, reason, words string }{
		{"a-excl", "excluded", "never touches it, not even with SNMP"},
		{"a-off", "snmp_off", "SNMP is turned off for this device"},
		{"a-hand", "declared_by_hand", "save its SNMP settings, or turn SNMP on"},
	} {
		res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", c.id)
		if err != nil || res.OK || res.Reason != c.reason || !strings.Contains(res.Message, c.words) {
			t.Errorf("%s: %v %+v", c.id, err, res)
		}
	}
	// The exclusion saved after the check read the policy: the batch stops before anything is sent.
	sa.SetBeforeSNMPBatch(w.svc, func() { w.inv.set(func(s *sa.Settings) { s.Exclusions = append(s.Exclusions, "100.66.255.10") }) })
	if res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", "a-late"); err == nil && res.OK {
		t.Fatalf("an excluded target the policy let through was read: %+v", res)
	}
	sa.SetBeforeSNMPBatch(w.svc, nil)
	// A read address that is excluded is never read, whatever the device's own address.
	w.inv.set(func(s *sa.Settings) { s.Exclusions = append(s.Exclusions, "100.66.253.1") })
	if res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", "a-forti"); err != nil || res.Reason != "excluded" || !strings.Contains(res.Message, "100.66.253.1") {
		t.Fatalf("an excluded read address: %v %+v", err, res)
	}
	if n := len(r.sent()); n != 1 {
		t.Fatalf("a refused check sent %d jobs", n)
	}
}

// Turning a device's network scan off while the sweep's batch probes its address stops the batch (nmap cannot drop one host mid-run);
// the pass reads the protected list again and sweeps the batch again from its cursor without that address, and its log says why.
func TestSweepStopsWhenADeviceItProbesIsTurnedOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1})
	ctx, cancel := context.WithCancel(e.ctx())
	defer cancel()
	go func() { _, _ = e.svc.DiscoverRanges(ctx) }()
	waitFor(t, "the fake nmap to start", func() bool { return len(e.nm.calls(t)) > 0 })
	if err := e.svc.AssetChanged(e.ctx(), "a-far"); err != nil { // outside the batch: nothing stops
		t.Fatal(err)
	}
	e.inv.mu.Lock()
	e.inv.protected = append(e.inv.protected, netip.MustParseAddr("192.168.10.20"))
	e.inv.mu.Unlock()
	if err := e.svc.AssetChanged(e.ctx(), "a-web"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the batch to be swept again", func() bool { return len(e.nm.calls(t)) > 1 })
	calls := e.nm.calls(t)
	if !slices.Contains(targetsOf(calls[0]), "192.168.10.20") || slices.Contains(targetsOf(calls[1]), "192.168.10.20") {
		t.Fatalf("nmap ran %q, want the batch again without the device turned off", calls)
	}
	runs := sweepRuns(e)
	if len(runs) != 1 || !strings.Contains(logOf(t, e, runs[0].ID), "A batch was stopped because a device in the batch may no longer be scanned; it is swept again") {
		t.Fatalf("the pass does not say why its batch stopped: %+v", runs)
	}
}

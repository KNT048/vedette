package sensoractive_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// D-601 (kien, FortiGate at 100.65.255.1): an address a person listed in a credential's "Send only to" is read by SNMP outside the
// LAN ranges (those bind discovery and nmap only); the exclusions still win; SNMP turned off for a device, or a device added by hand
// whose SNMP nobody turned on, gets nothing and the Test says why; a public address can never be listed.
func TestSNMPSourcesAndScope(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ip := netip.MustParseAddr
	w.inv.mu.Lock()
	for id, a := range map[string]string{"a-forti": "100.65.255.1", "a-excl": "100.65.255.9", "a-off": "192.168.10.30", "a-hand": "192.168.10.31", "a-late": "100.65.255.10"} {
		w.inv.assets[id], w.inv.addrs[ip(a)], w.inv.approved[id] = ip(a), id, true
	}
	w.inv.st.Exclusions = []string{"100.65.255.9", "100.65.255.10"}
	// What the inventory's SNMPPolicy answers (its rules are the inventory's tests): the FortiGate is outside lan_ranges and still read;
	// a-excl is excluded; a-off has SNMP off; a-hand was added by hand.
	w.inv.snmpDecision = map[string]sa.Decision{
		"a-forti": {Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true},
		"a-excl":  {Reason: "excluded"},
		"a-off":   {Reason: "snmp_off"},
		"a-hand":  {Reason: "declared_by_hand"},
		// a-late: the policy was read before the exclusion was saved; the batch's own check against the settings stops it (review r1 L5)
		"a-late": {Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true},
	}
	w.inv.mu.Unlock()
	forti := w.add(v2cInput("fortiBeyond", "s3cret-community", "100.65.255.1", "100.65.255.9", "100.65.255.10"))
	lan := w.add(v2cInput("lan", "s3cret-community"))

	res, err := w.svc.TestSNMP(t.Context(), "admin@example.com", forti.ID, "100.65.255.1")
	if err != nil || !res.OK || res.DeviceID != "a-forti" {
		t.Fatalf("a listed address outside lan_ranges is read: %v %+v", err, res)
	}
	if jobs := r.sent(); len(jobs) != 1 || jobs[0].Targets[0].IP != "100.65.255.1" {
		t.Fatalf("jobs %+v", jobs)
	}
	for _, c := range []struct{ cred, ip, reason, words string }{
		{forti.ID, "100.65.255.9", "excluded", "never touches it, not even with SNMP"},
		{lan.ID, "192.168.10.30", "snmp_off", "SNMP is turned off for this device"},
		{lan.ID, "192.168.10.31", "declared_by_hand", "only once you turn SNMP on"},
		{lan.ID, "100.65.255.1", "not_for_this_credential", "outside the scope of this credential"}, // not listed: refused as before
	} {
		res, err := w.svc.TestSNMP(t.Context(), "admin@example.com", c.cred, c.ip)
		if err != nil || res.OK || res.Reason != c.reason || !strings.Contains(res.Message, c.words) {
			t.Errorf("%s: %v %+v", c.ip, err, res)
		}
	}
	if _, err := w.svc.TestSNMP(t.Context(), "admin@example.com", forti.ID, "100.65.255.10"); apiCode(err) != "stopped" {
		t.Fatalf("an excluded target the policy let through: %v, want stopped", err)
	}
	if n := len(r.sent()); n != 1 {
		t.Fatalf("a refused Test sent %d jobs", n)
	}
	if _, err := w.svc.AddSNMP(t.Context(), "admin@example.com", v2cInput("public", "s3cret-community", "8.8.8.8")); apiCode(err) != "bad_scope" {
		t.Fatalf("a public address in Send only to: %v", err)
	}
}

// D-601 review r1 M2: turning a device's network scan off while the sweep's batch probes its address stops the batch (nmap cannot drop
// one host mid-run); the next pass reads the protected list again.
func TestSweepStopsWhenADeviceItProbesIsTurnedOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1})
	done := make(chan error, 1)
	go func() { _, err := e.svc.DiscoverRanges(e.ctx()); done <- err }()
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
	select {
	case err := <-done:
		if !errors.Is(err, sa.ErrStopped) {
			t.Fatalf("err = %v, want ErrStopped", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the sweep went on probing a device whose scan was turned off")
	}
}

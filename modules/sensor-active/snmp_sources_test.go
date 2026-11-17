package sensoractive_test

import (
	"net/netip"
	"strings"
	"testing"

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
	for id, a := range map[string]string{"a-forti": "100.65.255.1", "a-excl": "100.65.255.9", "a-off": "192.168.10.30", "a-hand": "192.168.10.31"} {
		w.inv.assets[id], w.inv.addrs[ip(a)], w.inv.approved[id] = ip(a), id, true
	}
	w.inv.st.Exclusions = []string{"100.65.255.9"}
	// What the inventory's SNMPPolicy answers (its rules are the inventory's tests): the FortiGate is outside lan_ranges and still read;
	// a-excl is excluded; a-off has SNMP off; a-hand was added by hand.
	w.inv.snmpDecision = map[string]sa.Decision{
		"a-forti": {Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true},
		"a-excl":  {Reason: "excluded"},
		"a-off":   {Reason: "snmp_off"},
		"a-hand":  {Reason: "declared_by_hand"},
	}
	w.inv.mu.Unlock()
	forti := w.add(v2cInput("fortiBeyond", "s3cret-community", "100.65.255.1", "100.65.255.9"))
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
	if n := len(r.sent()); n != 1 {
		t.Fatalf("a refused Test sent %d jobs", n)
	}
	if _, err := w.svc.AddSNMP(t.Context(), "admin@example.com", v2cInput("public", "s3cret-community", "8.8.8.8")); apiCode(err) != "bad_scope" {
		t.Fatalf("a public address in Send only to: %v", err)
	}
}

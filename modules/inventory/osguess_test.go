package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// W86-1 (BN340, n86): nmap's OS fingerprint guesses (source nmap, an OS CPE, no version: D-501) are left out of a device's software and
// of matching once a stronger source states the device's OS (INV-1: manual > agent > snmp > nmap). The rows stay stored, and with nmap
// alone they are listed as before.
func TestW861_NmapOSGuessesGoWhenSNMPStatesTheOS(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx()
	h := observe.AssetHint{IP: netip.MustParseAddr("192.168.18.1"), MAC: "00:0c:29:aa:bb:01"}
	e.record(observe.Observation{AssetHint: h, Field: observe.OS, Value: "Android 9 - 10 (Linux 4.9 - 4.14)", Source: observe.Nmap, Confidence: 0.6})
	id := e.idOf("192.168.18.1")
	if err := e.svc.ReplaceSoftware(ctx, observe.AssetHint{IP: h.IP}, observe.Nmap, []observe.Software{
		{Display: "Android 9 - 10 (Linux 4.9 - 4.14)", Vendor: "google", Product: "android", CPE: "cpe:/o:google:android", Confidence: 0.6, Guess: true},
		{Display: "Android 9 - 10 (Linux 4.9 - 4.14)", Vendor: "linux", Product: "linux kernel", CPE: "cpe:/o:linux:linux_kernel", Confidence: 0.6, Guess: true},
		{Display: "OpenSSH 9.6", Vendor: "openbsd", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", Confidence: 0.8},
	}); err != nil {
		t.Fatal(err)
	}
	names := func() (list, match []string) {
		t.Helper()
		d, err := e.svc.Device(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range d.Software {
			list = append(list, s.Product)
		}
		m, ok, err := e.svc.MatchInput(ctx, id)
		if err != nil || !ok {
			t.Fatalf("match input: %v %v", ok, err)
		}
		for _, s := range m.Software {
			match = append(match, s.Product)
		}
		return list, match
	}
	if list, match := names(); len(list) != 3 || len(match) != 3 {
		t.Fatalf("with nmap alone: software %v, matching %v; want the guesses listed as before", list, match)
	}
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: h.IP}, Field: observe.OS, Value: "Alpine Linux", Source: observe.SNMP, Confidence: 0.9})
	list, match := names()
	for _, l := range [][]string{list, match} {
		if len(l) != 1 || l[0] != "openssh" {
			t.Errorf("after SNMP stated Alpine: %v, want only openssh", l)
		}
	}
	if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND source = 'nmap'`, id); n != 3 {
		t.Errorf("%d nmap rows stored, want the 3 kept (a read-path rule, not a delete)", n)
	}
}

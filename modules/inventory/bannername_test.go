package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// A network scan names a line by its banner, product and version together ("OpenSSH 9.6"), while the version is a column of its
// own: the device page and the questions showed it twice ("OpenSSH 9.6 9.6"). A scan's line is named by its product alone; a name
// that does not repeat the version is kept, and so is a person's.
func TestBannerName_TheVersionIsShownOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	h := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.67"), MAC: "aa:bb:cc:00:02:01"}
	e.record(observe.Observation{AssetHint: h, Field: observe.MAC, Value: h.MAC, Source: observe.Nmap, Confidence: 0.9})
	rows := []observe.Software{
		{Display: "OpenSSH 9.6", Vendor: "openbsd", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", Confidence: 0.8},
		{Display: "Embedthis-Appweb 3.2.3", Vendor: "embedthis", Product: "appweb", Version: "3.2.3", CPE: "cpe:/a:embedthis:appweb:3.2.3", Confidence: 0.8},
		{Display: "VMware Authentication Daemon 1.10", Vendor: "VMware Authentication Daemon", Product: "VMware Authentication Daemon", Version: "1.10", Confidence: 0.6},
		{Display: "Juniper Junos OS", Vendor: "juniper", Product: "junos", Version: "15.1R7.9", Confidence: 0.8},
	}
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: h.IP}, observe.Nmap, nil, rows); err != nil {
		t.Fatal(err)
	}
	id := e.idOf("192.0.2.67")
	got := map[string]string{}
	d, err := e.svc.Detail(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range d.Asset.Software {
		got[l.Display] = deref(l.Version)
	}
	want := map[string]string{"OpenSSH": "9.6", "Embedthis-Appweb": "3.2.3", "VMware Authentication Daemon": "1.10", "Juniper Junos OS": "15.1R7.9"}
	if len(got) != len(want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("line %q: version %q, want %q (all: %v)", n, got[n], v, got)
		}
	}

	// the lines a scan stored before keep their version once too (renamed at start), a person's line is left as typed
	e.exec(`UPDATE inv_software SET display = display || ' ' || version WHERE asset_id = ? AND display IN ('OpenSSH', 'Embedthis-Appweb')`, id)
	e.exec(`UPDATE inv_software_reading SET display = display || ' ' || version WHERE source = 'nmap' AND display IN ('OpenSSH', 'Embedthis-Appweb')`)
	hand := e.addDevice(inventory.AddInput{Vendor: "Contoso", Product: "Gizmo 2", Version: "2", IP: "192.0.2.68"})
	for range 2 { // idempotent: the second run changes nothing
		if err := e.svc.ReidentifyLines(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range []struct{ id, display string }{{id, "OpenSSH"}, {id, "Embedthis-Appweb"}, {hand, "Contoso Gizmo 2"}} {
		if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND display = ?`, x.id, x.display); n != 1 {
			t.Errorf("%s: %d lines named %q", x.id, n, x.display)
		}
	}
	if n := e.count(`SELECT count(*) FROM inv_software_reading WHERE source = 'nmap' AND display LIKE '% ' || version`); n != 0 {
		t.Errorf("%d scan readings still repeat their version", n)
	}
}

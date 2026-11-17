package inventory_test

import (
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

func identityOf(t *testing.T, e *env, id string) (vendor, model, os *inventory.Observed) {
	t.Helper()
	d := e.detail(id)
	return d.Asset.Vendor, d.Asset.Model, d.Asset.OS
}

func wantIdentity(t *testing.T, what string, o *inventory.Observed, value, source string) {
	t.Helper()
	switch {
	case value == "" && o != nil:
		t.Errorf("%s %+v, want not known", what, o)
	case value != "" && (o == nil || o.Value != value || o.Source != source):
		t.Errorf("%s %+v, want %q from %s", what, o, value, source)
	}
}

// INV-45: a device added by hand as an OS or firmware product with its version is that OS, and the catalog's hardware line is its
// model, on the detail, the list and the export alike; the name stays the naming rule's.
func TestDeclaredOSRowGivesTheDeviceItsOSAndModel(t *testing.T) {
	for _, c := range []struct {
		name string
		in   inventory.AddInput
		os   string
	}{
		{"picked from the catalog", inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "100.65.254.1"}, "FortiOS 7.2.13"},
		{"typed vendor and product", inventory.AddInput{Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.13", IP: "100.65.254.1"}, "FortiOS 7.2.13"},
		{"no version", inventory.AddInput{CatalogID: "fortigate", IP: "100.65.254.1"}, "FortiOS"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			id := e.addDevice(c.in)
			v, m, os := identityOf(t, e, id)
			wantIdentity(t, "maker", v, "Fortinet", "manual")
			wantIdentity(t, "model", m, "FortiGate", "manual")
			wantIdentity(t, "OS", os, c.os, "manual")
			if os == nil || os.SoftwareID == "" || os.Confidence != 1 {
				t.Errorf("OS %+v, want the declared row named, full confidence", os)
			}
			l, err := e.svc.Devices(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range l.Items {
				if d.ID == id && (d.OS == nil || d.OS.Value != c.os || d.Model == nil || d.Model.Value != "FortiGate") {
					t.Errorf("list row OS %+v model %+v, want the detail's", d.OS, d.Model)
				}
			}
			names, err := e.svc.Names(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			if d, _ := e.svc.Device(e.ctx(), id); d.Name() != names[id] {
				t.Errorf("name %q on the page, %q elsewhere: want one naming rule", d.Name(), names[id])
			}
		})
	}
}

// A product that is not an OS gives the device no OS or model; a row the person said is not installed, or removed, gives nothing.
func TestDeclaredRowThatIsNoOSGivesNoOS(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{CatalogID: "openvpn-access-server", Version: "2.11", IP: "192.168.1.30"})
	_, m, os := identityOf(t, e, id)
	wantIdentity(t, "model", m, "", "")
	wantIdentity(t, "OS", os, "", "")
}

// A person's declared OS row ranks first among the sources (a scan guess, an SNMP answer), as the matcher reads it; the OS a person
// types in the OS field ranks above it. A model a sensor reads stays: it is more exact than the catalog's line. Removing the row
// gives the sources back.
func TestDeclaredOSRowRanksAboveTheSensors(t *testing.T) {
	e := newEnv(t)
	scanSwitch(e, vmwareMAC, "Fortinet FortiOS 6.0 - 7.0")
	id := e.idOf(switchIP)
	e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "FortiOS v7.2.12", Source: observe.SNMP, Confidence: 0.9},
		observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.Model, Value: "FGT60F", Source: observe.SNMP, Confidence: 0.9})
	if _, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13"}); err != nil {
		t.Fatal(err)
	}
	_, m, os := identityOf(t, e, id)
	wantIdentity(t, "OS", os, "FortiOS 7.2.13", "manual")
	wantIdentity(t, "model", m, "FGT60F", "snmp")

	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{OS: ptr("FortiOS 7.4.1")}); err != nil {
		t.Fatal(err)
	}
	if _, _, os = identityOf(t, e, id); os == nil || os.Value != "FortiOS 7.4.1" || os.SoftwareID != "" {
		t.Errorf("OS %+v, want the OS the person typed", os)
	}
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{OS: ptr("")}); err != nil {
		t.Fatal(err)
	}
	var sid string
	for _, sw := range e.detail(id).Asset.Software {
		if sw.Source == "manual" {
			sid = sw.ID
		}
	}
	if err := e.svc.RemoveSoftware(e.ctx(), "it@acme.example", id, sid); err != nil {
		t.Fatal(err)
	}
	_, _, os = identityOf(t, e, id)
	wantIdentity(t, "OS after the row is removed", os, "FortiOS v7.2.12", "snmp")
}

package inventory_test

import (
	"errors"
	"strings"
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

// matcher is a stand-in for the matcher's choice (Config.DeclaredOS; the real one, findings.DeclaredOSRow, is exercised through the
// wiring in cmd/vedette): it keeps the first candidate with the version it is given, or none. It records what it was asked.
type matcher struct {
	keep    bool
	version string
	fail    map[string]bool // devices it fails for
	asked   [][]string
}

func (m *matcher) choose(d inventory.MatchDevice, candidates []string) (string, string, error) {
	m.asked = append(m.asked, candidates)
	if m.fail[d.ID] {
		return "", "", errors.New("the matcher failed")
	}
	if !m.keep || len(candidates) == 0 {
		return "", "", nil
	}
	return candidates[0], m.version, nil
}

// withMatcher wires the stand-in, and a version reader that drops a leading "v" as findings.OSVersion does.
func withMatcher(m *matcher) opt {
	return func(c *inventory.Config) {
		c.DeclaredOS = m.choose
		c.OSVersion = func(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }
	}
}

// INV-45: a device added by hand as an OS or firmware product is that OS, and the catalog's hardware line is its model, on the
// detail and the list alike; the name stays one (the observations' maker and model on every path).
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
			m := &matcher{keep: true, version: "7.2.13"}
			if c.in.Version == "" {
				m.version = ""
			}
			e := newEnv(t, withMatcher(m))
			id := e.addDevice(c.in)
			v, mo, os := identityOf(t, e, id)
			wantIdentity(t, "maker", v, "Fortinet", "manual")
			wantIdentity(t, "model", mo, "FortiGate", "manual")
			wantIdentity(t, "OS", os, c.os, "manual")
			if os == nil || os.SoftwareID == "" {
				t.Errorf("OS %+v, want the declared row named", os)
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
		})
	}
}

// The matcher decides: a row it does not keep (the device's SNMP answer decides) leaves the OS the sources read; a row it keeps
// shows the version as it reads it; a row without a version never hides a version a source read; the OS a person typed stays.
func TestDeclaredOSRowIsTheMatchersChoice(t *testing.T) {
	setup := func(t *testing.T, m *matcher, version string) (*env, string) {
		e := newEnv(t, withMatcher(m))
		id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: version, IP: "100.65.254.1"})
		e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "FortiOS 7.2.12", Source: observe.SNMP, Confidence: 0.9},
			observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.Model, Value: "FGT60F", Source: observe.SNMP, Confidence: 0.9})
		return e, id
	}
	t.Run("not kept", func(t *testing.T) {
		e, id := setup(t, &matcher{}, "v7.2.13")
		_, m, os := identityOf(t, e, id)
		wantIdentity(t, "OS", os, "FortiOS 7.2.12", "snmp")
		wantIdentity(t, "model", m, "FGT60F", "snmp")
	})
	t.Run("kept", func(t *testing.T) {
		e, id := setup(t, &matcher{keep: true, version: "7.2.13"}, "v7.2.13")
		_, m, os := identityOf(t, e, id)
		wantIdentity(t, "OS", os, "FortiOS 7.2.13", "manual")
		wantIdentity(t, "model", m, "FGT60F", "snmp") // a sensor's model is more exact than the catalog's line
	})
	t.Run("kept without a version", func(t *testing.T) {
		e, id := setup(t, &matcher{keep: true}, "")
		_, _, os := identityOf(t, e, id)
		wantIdentity(t, "OS", os, "FortiOS 7.2.12", "snmp")
	})
	t.Run("typed OS", func(t *testing.T) {
		m := &matcher{keep: true, version: "7.2.13"}
		e, id := setup(t, m, "v7.2.13")
		if err := e.svc.PatchDevice(e.ctx(), "op@example.com", id, inventory.Patch{OS: ptr("FortiOS 7.4.1")}); err != nil {
			t.Fatal(err)
		}
		_, _, os := identityOf(t, e, id)
		wantIdentity(t, "OS", os, "FortiOS 7.4.1", "manual")
		if os != nil && os.SoftwareID != "" {
			t.Errorf("OS %+v, want the typed one, not the row", os)
		}
	})
}

// Without the matcher a declared row only fills an OS no source gives.
func TestDeclaredOSRowWithoutTheMatcherOnlyFills(t *testing.T) {
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.2.13", IP: "100.65.254.1"})
	_, _, os := identityOf(t, e, id)
	wantIdentity(t, "OS", os, "FortiOS 7.2.13", "manual")
	e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "FortiOS 7.2.12", Source: observe.SNMP, Confidence: 0.9})
	_, _, os = identityOf(t, e, id)
	wantIdentity(t, "OS", os, "FortiOS 7.2.12", "snmp")
}

// Only a product the catalog marks as a whole OS is a candidate: a kernel row, an entry that stands for several products, or an
// application gives no OS or model and the matcher is not asked.
func TestDeclaredRowThatIsNoWholeOSGivesNoOS(t *testing.T) {
	for _, in := range []inventory.AddInput{
		{Vendor: "Linux", Product: "Kernel", Version: "6.8.0-45", IP: "192.168.1.40"},
		{CatalogID: "windows-7-server-2008-unsupported", Version: "6.1.7601", IP: "192.168.1.41"},
		{CatalogID: "openvpn-access-server", Version: "2.11", IP: "192.168.1.42"},
	} {
		m := &matcher{keep: true, version: "x"}
		e := newEnv(t, withMatcher(m))
		id := e.addDevice(in)
		_, mo, os := identityOf(t, e, id)
		wantIdentity(t, "model", mo, "", "")
		wantIdentity(t, "OS", os, "", "")
		if len(m.asked) != 0 {
			t.Errorf("%+v: the matcher was asked %v", in, m.asked)
		}
	}
}

// One device, one name: a discovered device whose maker and model only a declared row gives is named as Names names it; and the
// Devices search finds a device by the model its declared row gives it.
func TestDeclaredIdentityKeepsOneNameAndIsSearchable(t *testing.T) {
	e := newEnv(t, withMatcher(&matcher{keep: true, version: "7.2.13"}))
	scanSwitch(e, vmwareMAC, "Fortinet FortiOS 6.0 - 7.0")
	id := e.idOf(switchIP)
	if _, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13"}); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Device(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	names, err := e.svc.Names(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if d.Model == nil || d.Model.Value != "FortiGate" || d.Name() != names[id] {
		t.Errorf("model %+v, name %q on the page and %q elsewhere: want FortiGate and one name", d.Model, d.Name(), names[id])
	}
	typed := e.addDevice(inventory.AddInput{Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.13", IP: "100.65.254.1"})
	f := false
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{Q: "fortigate", Ignored: &f})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range l.Items {
		found[r.ID] = true
	}
	if !found[id] || !found[typed] {
		t.Errorf("q=fortigate found %v, want both devices whose declared row names a FortiGate", found)
	}
}

// The matcher is asked only when a source it may prefer reads the device (SNMP, a passive frame, the agent); a device with nothing
// that outranks its declared row takes it at once. A device whose matcher read fails keeps what its sources read, and the list still
// loads.
func TestDeclaredOSAsksTheMatcherOnlyWhenASourceMayOutrankAndNeverFailsTheList(t *testing.T) {
	m := &matcher{keep: true, version: "7.2.13", fail: map[string]bool{}}
	e := newEnv(t, withMatcher(m))
	alone := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "100.65.254.1"})
	ok := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "100.65.254.2"})
	broken := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "100.65.254.3"})
	for _, id := range []string{ok, broken} {
		e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "FortiOS 7.2.12", Source: observe.SNMP, Confidence: 0.9})
	}
	m.fail[broken] = true
	m.asked = nil
	l, err := e.svc.Devices(e.ctx())
	if err != nil {
		t.Fatalf("the list failed: %v", err)
	}
	want := map[string]string{alone: "FortiOS 7.2.13", ok: "FortiOS 7.2.13", broken: "FortiOS 7.2.12"}
	for _, d := range l.Items {
		if w, in := want[d.ID]; in && (d.OS == nil || d.OS.Value != w) {
			t.Errorf("device %s OS %+v, want %q", d.ID, d.OS, w)
		}
	}
	if len(m.asked) != 2 {
		t.Errorf("the matcher was asked %d times, want 2 (only the devices SNMP reads)", len(m.asked))
	}
}

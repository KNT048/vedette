package inventory_test

import (
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			wantIdentity(t, "model", mo, "FortiGate", "declared")
			wantIdentity(t, "OS", os, c.os, "declared")
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
		wantIdentity(t, "OS", os, "FortiOS 7.2.13", "declared")
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
	wantIdentity(t, "OS", os, "FortiOS 7.2.13", "declared")
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

// The matcher is asked, when a source writes, only when a source it may prefer reads the device (SNMP, a passive frame, the agent);
// a device with nothing that outranks its declared row takes it at once. A device whose matcher fails keeps what its sources read,
// and the write still goes through. Reading the list asks nobody: the decision is stored.
func TestDeclaredOSAsksTheMatcherOnlyWhenASourceMayOutrankAndNeverFailsTheWrite(t *testing.T) {
	m := &matcher{keep: true, version: "7.2.13", fail: map[string]bool{}}
	e := newEnv(t, withMatcher(m))
	alone := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "192.0.2.1"})
	ok := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "192.0.2.2"})
	broken := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "192.0.2.3"})
	m.fail[broken] = true
	m.asked = nil
	for _, id := range []string{ok, broken} {
		e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "FortiOS 7.2.12", Source: observe.SNMP, Confidence: 0.9})
	}
	if len(m.asked) != 2 {
		t.Errorf("the matcher was asked %d times while SNMP wrote, want 2 (only the devices SNMP reads)", len(m.asked))
	}
	asked := len(m.asked)
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
	if len(m.asked) != asked {
		t.Errorf("reading the list asked the matcher %d more times, want 0", len(m.asked)-asked)
	}
}

// The declared OS is one stored decision: a device whose declared row differs from what a scan guesses shows the declared OS on the
// device page, in the list, in the matcher's input and in the export alike, and inv_asset holds it.
func TestDeclaredOSIsStoredAndEveryReaderShowsIt(t *testing.T) {
	m := &matcher{keep: true, version: "7.2.13"}
	e := newEnv(t, withMatcher(m))
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "192.0.2.1"})
	e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "Linux 4.15", Source: observe.SNMP, Confidence: 0.9})
	const want = "FortiOS 7.2.13"
	var stored, obsID string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT os, os_obs_id FROM inv_asset WHERE id = ?`, id).Scan(&stored, &obsID); err != nil {
		t.Fatal(err)
	}
	if stored != want || obsID == "" {
		t.Fatalf("inv_asset holds os %q (obs %q), want %q and an observation", stored, obsID, want)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE id = ? AND asset_id = ?`, obsID, id); n != 1 {
		t.Errorf("os_obs_id names %d observations of the device, want 1", n)
	}
	if _, _, os := identityOf(t, e, id); os == nil || os.Value != want || os.SoftwareID == "" {
		t.Errorf("device page OS %+v, want %q from the declared row", os, want)
	}
	l, err := e.svc.Devices(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.ID == id && (d.OS == nil || d.OS.Value != want) {
			t.Errorf("list OS %+v, want %q", d.OS, want)
		}
	}
	md, ok, err := e.svc.MatchInput(e.ctx(), id)
	if err != nil || !ok || md.OS != want {
		t.Errorf("matcher input OS %q (ok %v, err %v), want %q", md.OS, ok, err, want)
	}
	r, err := e.svc.ExportCSV(e.ctx(), "it@acme.example", inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), want) || strings.Contains(string(out), "Linux 4.15") {
		t.Errorf("export does not show %q alone:\n%s", want, out)
	}
	if got := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'declared'`, id); got != 1 {
		t.Errorf("%d stored OS decisions, want 1", got)
	}
	// Removing the row hands the OS back to the sources in the same transaction; a person's own OS beats the row.
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{OS: ptrTo("Alpine Linux 3.23")}); err != nil {
		t.Fatal(err)
	}
	if _, _, os := identityOf(t, e, id); os == nil || os.Value != "Alpine Linux 3.23" || os.SoftwareID != "" {
		t.Errorf("after a person set the OS, device page OS %+v, want theirs", os)
	}
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{OS: ptrTo("")}); err != nil {
		t.Fatal(err)
	}
	if _, _, os := identityOf(t, e, id); os == nil || os.Value != want {
		t.Errorf("after the person's OS was cleared, device page OS %+v, want the declared %q back", os, want)
	}
}

func ptrTo(s string) *string { return &s }

// The first run after an upgrade stores the decision of a device that was declared before it was stored.
func TestReconcileDeclaredOSStoresWhatAnOlderBoxLacks(t *testing.T) {
	m := &matcher{keep: true, version: "7.2.13"}
	e := newEnv(t, withMatcher(m))
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13", IP: "192.0.2.1"})
	e.exec(`DELETE FROM inv_observation WHERE asset_id = ? AND field = 'os'`, id)
	e.exec(`UPDATE inv_asset SET os = NULL, os_obs_id = NULL WHERE id = ?`, id)
	if err := e.svc.ReconcileDeclaredOS(e.ctx()); err != nil {
		t.Fatal(err)
	}
	var stored sql.NullString
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT os FROM inv_asset WHERE id = ?`, id).Scan(&stored); err != nil || stored.String != "FortiOS 7.2.13" {
		t.Errorf("after the reconcile os is %q (err %v), want FortiOS 7.2.13", stored.String, err)
	}
}

// Count test: the readers that decide the declared OS at read time. No file of the module outside the write path may name the
// function that did (before the stored decision: 1, reads.go; after: 0).
func TestNoReaderAppliesTheDeclaredOSAtReadTime(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var readers []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := fs.ReadFile(os.DirFS("."), f)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"applyDeclared(", "declaredCandidates(", "declaredChoice(", "storeDeclared(", "s.declared("} {
			if strings.Contains(string(b), name) && f != "declared.go" && (f != "observe.go" || name != "storeDeclared(") { // recomputeColumns is the one writer
				readers = append(readers, f+":"+name)
			}
		}
	}
	if len(readers) != 0 {
		t.Errorf("readers that apply the declared OS at read time: %d %v, want 0", len(readers), readers)
	}
}

// A network OS a person types is copied into a software line (the stated OS); clearing the OS removes the copy, and the device must
// not keep the OS the person just cleared as if it were a declared row.
func TestClearedTypedNetworkOSIsNotADeclaredRow(t *testing.T) {
	m := &matcher{keep: true, version: "7.4.1"}
	e := newEnv(t, withMatcher(m))
	e.record(obsv(macA, observe.Hostname, "fw1", observe.Passive, 0.6))
	id := e.idByMAC(macA)
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{OS: ptrTo("FortiOS 7.4.1")}); err != nil {
		t.Fatal(err)
	}
	if _, _, os := identityOf(t, e, id); os == nil || os.Value != "FortiOS 7.4.1" || os.SoftwareID != "" {
		t.Fatalf("typed OS %+v, want the person's", os)
	}
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{OS: ptrTo("")}); err != nil {
		t.Fatal(err)
	}
	if _, _, os := identityOf(t, e, id); os != nil {
		t.Errorf("after the OS was cleared the device shows %+v, want not known", os)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'os'`, id); n != 0 {
		t.Errorf("%d OS observations after the clear, want 0", n)
	}
}

// A typed OS that SNMP outgrows lapses; the device then shows what SNMP reads, not the copy of the typed OS.
func TestLapsedTypedNetworkOSIsNotADeclaredRow(t *testing.T) {
	e := newEnv(t, func(c *inventory.Config) {
		c.DeclaredOS = func(d inventory.MatchDevice, cands []string) (string, string, error) {
			for _, s := range d.Software {
				if len(cands) > 0 && s.ID == cands[0] {
					return s.ID, s.Version, nil
				}
			}
			return "", "", nil
		}
		c.OSVersion = func(v string) string { return v }
	})
	e.record(obsv(macA, observe.Hostname, "fw1", observe.Passive, 0.6))
	id := e.idByMAC(macA)
	if err := e.svc.PatchDevice(e.ctx(), "op@acme.example", id, inventory.Patch{OS: ptrTo("FortiOS 7.2.0")}); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	e.record(observe.Observation{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: "FortiOS 7.4.1", Source: observe.SNMP, Confidence: 0.9})
	if _, _, os := identityOf(t, e, id); os == nil || os.Value != "FortiOS 7.4.1" || os.Source != "snmp" {
		t.Errorf("after SNMP read a newer OS the device shows %+v, want SNMP's FortiOS 7.4.1", os)
	}
}

// Merging a device whose OS a person typed into a declared device with the same OS text keeps the person's OS and who set it.
func TestMergeKeepsAPersonsTypedOSAgainstADeclaredRow(t *testing.T) {
	m := &matcher{keep: true, version: "7.4.1"}
	e := newEnv(t, withMatcher(m))
	into := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.4.1", IP: "10.0.0.9"})
	e.record(obsv(macA, observe.Hostname, "fw1", observe.Passive, 0.6))
	from := e.idByMAC(macA)
	if err := e.svc.PatchDevice(e.ctx(), "op@acme.example", from, inventory.Patch{OS: ptrTo("FortiOS 7.4.1")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), "op@acme.example", into, from); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Detail(e.ctx(), into)
	if err != nil {
		t.Fatal(err)
	}
	if d.Asset.OSCorrection == nil || d.Asset.OSCorrection.Value != "FortiOS 7.4.1" {
		t.Fatalf("OS correction after the merge: %+v, want the person's FortiOS 7.4.1", d.Asset.OSCorrection)
	}
	if _, _, os := identityOf(t, e, into); os == nil || os.SoftwareID != "" {
		t.Errorf("device OS %+v, want the person's, not a declared row's", os)
	}
	var by string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT ifnull(evidence, '') FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, into).Scan(&by); err != nil || by != "op@acme.example" {
		t.Errorf("who set the OS: %q (err %v), want op@acme.example", by, err)
	}
}

// The stored decision of a declared row is its own source: no manual OS observation exists for it, so a person's typed OS and the
// decision never share a key, whichever device a merge keeps.
func TestDeclaredOSIsItsOwnSourceAndAMergeNeverMixesItWithATypedOS(t *testing.T) {
	m := &matcher{keep: true, version: "7.4.1"}
	e := newEnv(t, withMatcher(m))
	declared := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.4.1", IP: "10.0.0.9"})
	row := `SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = ?`
	if got := e.count(row, declared, "declared"); got != 1 {
		t.Fatalf("%d declared OS rows, want 1", got)
	}
	if got := e.count(row, declared, "manual"); got != 0 {
		t.Errorf("%d manual OS rows on a device nobody typed an OS on, want 0", got)
	}
	// The kept device is the declared one; the other has the person's own OS with the same text.
	e.record(obsv(macA, observe.Hostname, "fw1", observe.Passive, 0.6))
	typed := e.idByMAC(macA)
	if err := e.svc.PatchDevice(e.ctx(), "op@acme.example", typed, inventory.Patch{OS: ptrTo("FortiOS 7.0.1")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), "op@acme.example", declared, typed); err != nil {
		t.Fatal(err)
	}
	if got := e.count(row, declared, "manual"); got != 1 {
		t.Errorf("%d manual OS rows after the merge, want the person's one", got)
	}
	if got := e.count(row, declared, "declared"); got != 0 {
		t.Errorf("%d declared OS rows next to the person's OS, want 0", got)
	}
	d, err := e.svc.Detail(e.ctx(), declared)
	if err != nil {
		t.Fatal(err)
	}
	if d.Asset.OSCorrection == nil || d.Asset.OSCorrection.Value != "FortiOS 7.0.1" {
		t.Errorf("OS correction after the merge: %+v, want the person's FortiOS 7.0.1", d.Asset.OSCorrection)
	}
	if _, _, os := identityOf(t, e, declared); os == nil || os.Value != "FortiOS 7.0.1" || os.Source != "manual" {
		t.Errorf("device OS after the merge %+v, want the person's", os)
	}
	var by string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT ifnull(evidence, '') FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, declared).Scan(&by); err != nil || by != "op@acme.example" {
		t.Errorf("who set the OS: %q (err %v), want op@acme.example", by, err)
	}
	// The reverse: a declared device merged into one whose OS a person typed leaves the typed OS alone.
	e.record(obsv(macB, observe.Hostname, "fw2", observe.Passive, 0.6))
	other := e.idByMAC(macB)
	if err := e.svc.PatchDevice(e.ctx(), "op@acme.example", other, inventory.Patch{OS: ptrTo("FortiOS 7.0.1")}); err != nil {
		t.Fatal(err)
	}
	gone := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.4.1", IP: "10.0.0.10"})
	if err := e.svc.Merge(e.ctx(), "op@acme.example", other, gone); err != nil {
		t.Fatal(err)
	}
	if got := e.count(row, other, "manual"); got != 1 {
		t.Errorf("%d manual OS rows after the reverse merge, want 1", got)
	}
	if got := e.count(row, other, "declared"); got != 0 {
		t.Errorf("%d declared OS rows next to the person's OS, want 0", got)
	}
	if d, err := e.svc.Detail(e.ctx(), other); err != nil || d.Asset.OSCorrection == nil || d.Asset.OSCorrection.Value != "FortiOS 7.0.1" {
		t.Errorf("OS correction after the reverse merge: %+v (err %v), want the person's FortiOS 7.0.1", d.Asset.OSCorrection, err)
	}
	if _, _, os := identityOf(t, e, other); os == nil || os.Value != "FortiOS 7.0.1" || os.Source != "manual" {
		t.Errorf("device OS after the reverse merge %+v, want the person's", os)
	}
}

// No query matches the old marker (source manual with evidence "declared:<id>"): the stored decision is found by its source alone.
func TestNoQueryMatchesTheOldDeclaredMarker(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := fs.ReadFile(os.DirFS("."), f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "'declared:'") || strings.Contains(string(b), `"declared:"`) || strings.Contains(string(b), "AND NOT `+declaredObsSQL") {
			hits = append(hits, f)
		}
	}
	if len(hits) != 0 {
		t.Errorf("files that match the old declared marker: %d %v, want 0", len(hits), hits)
	}
}

package inventory_test

import (
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// INV-47: a value a person entered wins; a trusted source that reads another value makes the device say so.

type differsEnv struct {
	*env
	ip  netip.Addr
	dev string
}

func newDiffersEnv(t *testing.T) *differsEnv {
	t.Helper()
	e := &differsEnv{env: newEnv(t), ip: netip.MustParseAddr("10.142.0.7")}
	e.read(observe.Passive, observe.MAC, "02:aa:bb:cc:dd:ee") // a device to hang values on
	addrs, err := e.svc.AddressMap(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	e.dev = addrs[e.ip.String()]
	return e
}

func (e *differsEnv) read(src observe.Source, f observe.Field, v string) {
	e.t.Helper()
	e.tick(time.Minute)
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: e.ip}, Field: f, Value: v, Source: src, Confidence: 0.9}}); err != nil {
		e.t.Fatal(err)
	}
}

// enter is a person's value, as when a device is added by hand (a manual observation).
func (e *differsEnv) enter(field, v string) {
	e.t.Helper()
	e.tick(time.Minute)
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES (?, ?, ?, ?, 'manual', 1, ?)`,
			"o-m-"+field+v, e.dev, field, v, e.now.UTC().Format("2006-01-02T15:04:05.000Z")); err != nil {
			return err
		}
		_, err := e.svc.RecomputeAsset(e.ctx(), tx, e.dev)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *differsEnv) detail() inventory.Detail {
	e.t.Helper()
	d, err := e.svc.Detail(e.ctx(), e.dev)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *differsEnv) differs(field string) *inventory.Differs {
	for _, d := range e.detail().DetectedDiffers {
		if d.Field == field {
			return &d
		}
	}
	return nil
}

func fieldShown(d inventory.Detail, field string) string {
	var o *inventory.Observed
	switch field {
	case "vendor":
		o = d.Asset.Vendor
	case "model":
		o = d.Asset.Model
	case "os":
		o = d.Asset.OS
	case "hostname":
		if d.Asset.Hostname != nil {
			return *d.Asset.Hostname
		}
	case "kind":
		return d.Asset.Kind
	}
	if o == nil {
		return ""
	}
	return o.Value
}

var fieldOf = map[string]observe.Field{"hostname": observe.Hostname, "vendor": observe.Vendor, "model": observe.Model, "os": observe.OS, "kind": observe.Kind}

func TestINV47_EachFieldAgainstEachSource(t *testing.T) {
	t.Parallel()
	entered := map[string]string{"hostname": "front-fw", "vendor": "Acme", "model": "Box 1", "os": "Windows", "kind": "router"}
	detected := map[string]string{"hostname": "fw-edge-01", "vendor": "Fortinet", "model": "FortiGate-500E", "os": "Windows Server 2022", "kind": "firewall"}
	trust := map[observe.Source]bool{observe.Agent: true, observe.SNMP: true, observe.Nmap: false, observe.Passive: false, observe.Scan: false}
	for field := range entered {
		for src, trusted := range trust {
			t.Run(field+"/"+string(src), func(t *testing.T) {
				t.Parallel()
				e := newDiffersEnv(t)
				e.enter(field, entered[field])
				e.read(src, fieldOf[field], detected[field])
				d := e.differs(field)
				if !trusted {
					if d != nil {
						t.Fatalf("a %s reading is a guess or a hint and must not raise a notice: %+v", src, d)
					}
					return
				}
				if d == nil || d.Entered != entered[field] || d.Detected != detected[field] || d.Source != string(src) || d.SeenAt == "" {
					t.Fatalf("difference = %+v", d)
				}
				if got := fieldShown(e.detail(), field); got != entered[field] {
					t.Fatalf("the entered value must still win: shown %q", got)
				}
			})
		}
	}
}

func TestINV47_AnNTLMAnswerIsTheDevicesOwnWord(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	e.enter("os", "Windows")
	e.read(observe.Nmap, observe.OS, "Microsoft Windows Server 2019 - 2022") // a fingerprint guess
	if d := e.differs("os"); d != nil {
		t.Fatalf("a guess raised a notice: %+v", d)
	}
	e.read(observe.Nmap, observe.OS, "Microsoft Windows Server 2022 (build 20348)") // the device's own NTLM answer
	if d := e.differs("os"); d == nil || d.Detected != "Microsoft Windows Server 2022 (build 20348)" {
		t.Fatalf("difference = %+v", d)
	}
	// The next scan's guess is newer and wins the OS once the entered one is gone: the notice would promise a value the page does not show.
	e.read(observe.Nmap, observe.OS, "Microsoft Windows Server 2016 - 2019")
	if d := e.differs("os"); d != nil {
		t.Fatalf("a newer guess outranks the NTLM answer, so Use detected would show the guess: %+v", d)
	}
}

func TestINV47_NotADifference(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, field, entered, detected string }{
		{"host name case and spaces", "hostname", " Switch-01 ", "switch-01"},
		{"host name with its domain", "hostname", "switch-01", "switch-01.corp.example"},
		{"host name that is only an identifier", "hostname", "front-desk", "fbaf5191-cc17-4626-a85b-812bc3d7b83b"},
		{"maker legal suffix", "vendor", "Fortinet", "Fortinet, Inc."},
		{"maker legal suffix on the entered side", "vendor", "Cisco Systems, Inc.", "cisco"},
		{"maker generic word", "vendor", "Juniper", "Juniper Networks"},
		{"model dash and space", "model", "FortiGate 500E", "FortiGate-500E"},
		{"model case", "model", "ex4200-48t", "EX4200-48T"},
		{"OS the reading only adds a version to", "os", "Alpine Linux", "Alpine Linux 3.23"},
		{"OS with a v-version added", "os", "Cisco IOS", "Cisco IOS v15.2"},
		{"OS with a build added", "os", "Windows 10", "Microsoft Windows 10 (build 19045)"},
		{"OS contradicted: the entered OS has its own block", "os", "Ubuntu", "Alpine Linux"},
		{"model with the maker in front", "model", "Catalyst 9300", "Cisco Catalyst 9300"},
		{"OS with a version where the reading has none", "os", "Alpine Linux 3.23", "Alpine Linux"},
		{"OS with Microsoft in front", "os", "Windows 11", "Microsoft Windows 11 22H2"},
		{"type spelled the same", "kind", "router", "router"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newDiffersEnv(t)
			if c.name == "model with the maker in front" {
				e.read(observe.SNMP, observe.Vendor, "Cisco Systems, Inc.") // the device's maker is known
			}
			e.enter(c.field, c.entered)
			e.read(observe.SNMP, fieldOf[c.field], c.detected)
			if d := e.differs(c.field); d != nil {
				t.Fatalf("noise raised a notice: %+v", d)
			}
		})
	}
	// and the look-alikes that are different
	for _, c := range []struct{ field, entered, detected string }{
		{"vendor", "Hewlett Packard", "Hewlett Packard Enterprise"},
		{"hostname", "gateway", "gateway2"},
		{"os", "Windows", "Windows Server 2022"},
		{"os", "Linux", "Linux Mint"},
		{"model", "FortiGate-500E", "FortiGate-60F"},
	} {
		e := newDiffersEnv(t)
		e.enter(c.field, c.entered)
		e.read(observe.SNMP, fieldOf[c.field], c.detected)
		if e.differs(c.field) == nil {
			t.Errorf("%s %q vs %q must differ", c.field, c.entered, c.detected)
		}
	}
}

func TestINV47_NothingEnteredNothingToSay(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	e.read(observe.SNMP, observe.Hostname, "sw-1")
	e.read(observe.Agent, observe.Hostname, "sw-1.local")
	if got := e.detail().DetectedDiffers; got == nil || len(got) != 0 {
		t.Fatalf("differs = %#v, want an empty list", got)
	}
}

func TestINV47_KeepMineHidesUntilTheDetectedValueChanges(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	e.enter("hostname", "edge-fw")
	e.read(observe.SNMP, observe.Hostname, "fw-edge-01")
	before := e.detail()
	if err := e.svc.KeepEntered(e.ctx(), "op@example.com", e.dev, "hostname", "fw-edge-01"); err != nil {
		t.Fatal(err)
	}
	after := e.detail()
	if len(after.DetectedDiffers) != 0 || fieldShown(after, "hostname") != "edge-fw" || fieldShown(before, "hostname") != "edge-fw" {
		t.Fatalf("keep must hide the notice and change nothing else: %+v", after.DetectedDiffers)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'manual' AND field = 'hostname'`, e.dev); n != 1 {
		t.Fatalf("the entered value stays: %d", n)
	}
	if got := e.auditBy("inventory.keep_entered"); len(got) != 1 || !contains(got[0], "op@example.com") {
		t.Fatalf("audit = %v", got)
	}
	// the same value read again: still hidden
	e.read(observe.SNMP, observe.Hostname, "fw-edge-01")
	if e.differs("hostname") != nil {
		t.Fatal("the same detected value must stay hidden")
	}
	// another value: the notice is back, with the new value
	e.read(observe.SNMP, observe.Hostname, "fw-edge-02")
	if d := e.differs("hostname"); d == nil || d.Detected != "fw-edge-02" {
		t.Fatalf("a changed detected value must show again: %+v", d)
	}
	// keep is per field: another field's difference is not hidden by it
	e.enter("model", "Box")
	e.read(observe.SNMP, observe.Model, "FortiGate-500E")
	if e.differs("model") == nil {
		t.Fatal("keep on the host name must not hide the model")
	}
}

func TestINV47_UseDetectedSwitchesTheShownValueAndIsAudited(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	e.enter("hostname", "edge-fw")
	e.read(observe.SNMP, observe.Hostname, "fw-edge-01")
	e.enter("os", "Windows")
	e.read(observe.SNMP, observe.OS, "Windows Server 2022")
	e.ev.reset()
	if err := e.svc.UseDetected(e.ctx(), "op@example.com", e.dev, "hostname", "fw-edge-01"); err != nil {
		t.Fatal(err)
	}
	d := e.detail()
	if fieldShown(d, "hostname") != "fw-edge-01" || e.differs("hostname") != nil {
		t.Fatalf("host name must now be the detected one: %q", fieldShown(d, "hostname"))
	}
	if fieldShown(d, "os") != "Windows" || e.differs("os") == nil {
		t.Fatal("the other field's entered value must stay")
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'manual' AND field = 'hostname'`, e.dev); n != 0 {
		t.Fatalf("the entered host name must be removed: %d", n)
	}
	if got := e.auditBy("inventory.use_detected"); len(got) != 1 || !contains(got[0], "op@example.com") || !contains(got[0], "edge-fw → fw-edge-01") {
		t.Fatalf("audit = %v", got)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || !ev[0].Data.(inventory.AssetEvent).Match {
		t.Fatalf("matching must run again: %+v", ev)
	}
	if err := e.svc.UseDetected(e.ctx(), "op@example.com", e.dev, "os", "Windows Server 2022"); err != nil {
		t.Fatal(err)
	}
	if got := fieldShown(e.detail(), "os"); got != "Windows Server 2022" {
		t.Fatalf("OS = %q", got)
	}
	// the type goes back to what the sources read, too
	e.enter("kind", "router")
	e.read(observe.Agent, observe.Kind, "firewall")
	if err := e.svc.UseDetected(e.ctx(), "op@example.com", e.dev, "kind", "firewall"); err != nil {
		t.Fatal(err)
	}
	if got := fieldShown(e.detail(), "kind"); got != "firewall" {
		t.Fatalf("type = %q", got)
	}
}

func TestINV47_ActionsRefuseAStaleOrUnknownChoice(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	e.enter("hostname", "edge-fw")
	e.read(observe.SNMP, observe.Hostname, "fw-edge-01")
	e.read(observe.SNMP, observe.Hostname, "fw-edge-02") // what the person saw is already old
	wantAPIError(t, e.svc.UseDetected(e.ctx(), "op", e.dev, "hostname", "fw-edge-01"), 409, "detected_changed")
	wantAPIError(t, e.svc.KeepEntered(e.ctx(), "op", e.dev, "hostname", "fw-edge-01"), 409, "detected_changed")
	wantAPIError(t, e.svc.UseDetected(e.ctx(), "op", e.dev, "model", "x"), 409, "detected_changed")
	wantAPIError(t, e.svc.UseDetected(e.ctx(), "op", e.dev, "mac", "x"), 400, "bad_field")
	wantAPIError(t, e.svc.KeepEntered(e.ctx(), "op", "a-nope", "hostname", "x"), 404, "not_found")
	if fieldShown(e.detail(), "hostname") != "edge-fw" {
		t.Fatal("a refused action must change nothing")
	}
}

// A person's OS that the sources contradict already has the "You set X; the scan reads Y" block (INV-41): no second prompt.
func TestINV47_AContradictedOSHasItsOwnBlockNotASecondNotice(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", e.dev, inventory.Patch{OS: ptr("Ubuntu")}); err != nil {
		t.Fatal(err)
	}
	e.read(observe.SNMP, observe.OS, "Alpine Linux")
	d := e.detail()
	if c := d.Asset.OSCorrection; c == nil || !c.Disagrees {
		t.Fatalf("the OS block must say the sources disagree: %+v", c)
	}
	if e.differs("os") != nil {
		t.Fatal("the OS must be asked about once")
	}
}

// After Use detected the page shows what the notice named, also when a higher-ranked reading that is not trusted exists.
func TestINV47_NoticeOnlyNamesWhatThePageWillShow(t *testing.T) {
	t.Parallel()
	e := newDiffersEnv(t)
	e.enter("model", "Box")
	e.read(observe.Scan, observe.Model, "Appliance X")  // not trusted, and it outranks a passive model
	e.read(observe.Passive, observe.Model, "Gateway Z") // not trusted either
	if d := e.differs("model"); d != nil {
		t.Fatalf("untrusted readings raised a notice: %+v", d)
	}
	e.read(observe.SNMP, observe.Model, "Gateway Y")
	d := e.differs("model")
	if d == nil || d.Detected != "Gateway Y" {
		t.Fatalf("difference = %+v", d)
	}
	if err := e.svc.UseDetected(e.ctx(), "op", e.dev, "model", d.Detected); err != nil {
		t.Fatal(err)
	}
	if got := fieldShown(e.detail(), "model"); got != "Gateway Y" {
		t.Fatalf("the page shows %q, not what the notice named", got)
	}
}

// Merging two devices moves the kept choices of the one that goes: a notice a person dismissed does not come back.
func TestINV47_AMergeKeepsTheChoicesOfTheDeviceThatGoes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old, newer := phonePair(e)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO inv_detected_keep (asset_id, field, detected, kept_at, kept_by) VALUES (?, 'hostname', 'fw-edge-01', '2026-11-09T10:00:00.000Z', 'op')`, newer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), admin, old, newer); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_detected_keep WHERE asset_id = ?`, old); n != 1 {
		t.Fatalf("kept rows on the device that stays: %d", n)
	}
}

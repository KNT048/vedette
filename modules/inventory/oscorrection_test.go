package inventory_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

func deviceAt(t *testing.T, e *env, ip netip.Addr) string {
	t.Helper()
	addrs, err := e.svc.AddressMap(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	return addrs[ip.String()]
}

func matchRows(t *testing.T, e *env, dev string) []inventory.MatchSoftware {
	t.Helper()
	m, ok, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	return m.Software
}

// swViews is the device detail's first line read by a source and the first line whose value is a person's (the last of each).
func swViews(t *testing.T, e *env, dev string) (scanned, mine inventory.SoftwareView) {
	t.Helper()
	d, err := e.svc.Detail(e.ctx(), dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Asset.Software {
		if s.Source == "manual" {
			mine = s
		} else {
			scanned = s
		}
	}
	return scanned, mine
}

func countOf(list []string, v string) int {
	n := 0
	for _, x := range list {
		if x == v {
			n++
		}
	}
	return n
}

// nmap's fingerprint guesses "Android 9 - 10 (Linux 4.9 - 4.14)"; the device's SNMP answer (net-snmp's uname layout) says
// Alpine Linux and wins over the guess (INV-1); a person's correction wins over both, drives matching, survives later reads, says when
// the sources disagree, and can be cleared (INV-41).
func TestINV41_CorrectedOSWinsDrivesMatchingAndClears(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.0.2.1")
	rec := func(v string, src observe.Source) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: v, Source: src, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	rec("Android 9 - 10 (Linux 4.9 - 4.14)", observe.Nmap)
	rec("Alpine Linux", observe.SNMP)
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 1 {
		t.Fatalf("%d devices", n)
	}
	dev := deviceAt(t, e, ip)
	detail := func() inventory.Detail {
		t.Helper()
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := detail(); d.Asset.OS == nil || d.Asset.OS.Value != "Alpine Linux" || d.Asset.OS.Source != "snmp" || d.Asset.OSCorrection != nil {
		t.Fatalf("SNMP's OS must beat nmap's guess: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}

	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine <b>")}), 400, "bad_os")
	e.ev.reset()
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("  Alpine Linux 3.23 ")}); err != nil {
		t.Fatal(err)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || !ev[0].Data.(inventory.AssetEvent).Match {
		t.Fatalf("a corrected OS must match the device again: %+v", ev)
	}
	d := detail()
	if d.Asset.OS.Value != "Alpine Linux 3.23" || d.Asset.OS.Source != "manual" {
		t.Fatalf("the correction must win: %+v", d.Asset.OS)
	}
	if c := d.Asset.OSCorrection; c == nil || c.Value != "Alpine Linux 3.23" || c.Detected == nil || c.Detected.Value != "Alpine Linux" || c.Detected.Source != "snmp" || c.Disagrees {
		t.Fatalf("correction %+v (SNMP's Alpine Linux does not contradict Alpine Linux 3.23)", c)
	}
	m, ok, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil || !ok || m.OS != "Alpine Linux 3.23" || m.SNMPOS != "Alpine Linux 3.23" || m.StatedOS != "Alpine Linux 3.23" || m.AgentOS != "" || m.ManualOS != "Alpine Linux 3.23" ||
		!strings.HasPrefix(m.OSCorrection, "op@example.com set the OS to Alpine Linux 3.23 on ") {
		t.Fatalf("matching must read the person's OS: %+v %v %v", m, ok, err)
	}

	// The next reads change nothing shown; one that reads another OS makes the device say so.
	rec("Android 9 - 10 (Linux 4.9 - 4.14)", observe.Nmap)
	rec("Ubuntu", observe.SNMP)
	d = detail()
	if d.Asset.OS.Value != "Alpine Linux 3.23" {
		t.Fatalf("the correction must survive the next scan: %+v", d.Asset.OS)
	}
	if c := d.Asset.OSCorrection; c == nil || !c.Disagrees || c.Detected.Value != "Ubuntu" {
		t.Fatalf("the device must say the last read disagrees: %+v", c)
	}

	// The same value again writes nothing; clearing brings back what the sources read.
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine Linux 3.23")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if d := detail(); d.Asset.OS.Value != "Ubuntu" || d.Asset.OS.Source != "snmp" || d.Asset.OSCorrection != nil {
		t.Fatalf("cleared: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); m.SNMPOS != "Ubuntu" || m.ManualOS != "" {
		t.Fatalf("cleared: matching reads the sources again: %+v", m)
	}
	a := e.auditActions()
	if n := countOf(a, "inventory.correct_os"); n != 1 || countOf(a, "inventory.clear_os") != 1 {
		t.Fatalf("audit %v", a)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.correct_os' AND user = 'op@example.com' AND detail = 'Alpine Linux → Alpine Linux 3.23'`) != 1 {
		t.Fatal("the audit row must say who changed what to what")
	}
}

// A person's OS holds against an older reading, the same release written another way, and the old version a source keeps
// repeating; a newer reading from what the device states itself ends it, and the history says so (INV-52).
func TestINV52_CorrectedOSLapsesOnANewerReading(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.0.2.1")
	rec := func(v string, src observe.Source) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: v, Source: src, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	rec("Alpine Linux 3.15", observe.SNMP)
	dev := deviceAt(t, e, ip)
	e.tick(time.Minute)
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine Linux 3.20")}); err != nil {
		t.Fatal(err)
	}
	osNow := func() (string, bool) {
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		return d.Asset.OS.Value, d.Asset.OSCorrection != nil
	}
	for _, keep := range []struct {
		v   string
		src observe.Source
	}{{"Alpine Linux 3.15", observe.SNMP}, {"Alpine Linux 3.18", observe.Agent}, {"Alpine Linux 3.20", observe.SNMP}, {"Debian GNU/Linux 12", observe.Agent},
		{"Linux 4.15 - 5.19", observe.Nmap}, {"Alpine Linux", observe.Passive}} {
		rec(keep.v, keep.src)
		if v, corrected := osNow(); v != "Alpine Linux 3.20" || !corrected {
			t.Fatalf("%q from %s must keep the person's OS, the device says %q", keep.v, keep.src, v)
		}
	}
	rec("Alpine Linux 3.22", observe.Nmap) // a scan's guess never ends it
	if v, corrected := osNow(); v != "Alpine Linux 3.20" || !corrected {
		t.Fatalf("a scan guess must keep the person's OS, the device says %q", v)
	}
	rec("Alpine Linux 3.23", observe.Agent)
	if v, corrected := osNow(); v != "Alpine Linux 3.23" || corrected {
		t.Fatalf("a newer version ends the correction: %q %v", v, corrected)
	}
	if countOf(e.auditActions(), "inventory.os_correction_lapsed") != 1 {
		t.Fatalf("history: %v", e.auditActions())
	}
}

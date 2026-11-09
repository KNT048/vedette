package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// These tests never run a real nmap or touch a network: nmap is a script in t.TempDir() that records its argv and
// prints a hand-written fixture of modules/sensor-active/testdata.

type fakeNmapBin struct{ path, log string }

func newFakeNmap(t *testing.T) *fakeNmapBin {
	t.Helper()
	dir := t.TempDir()
	fx := func(n string) string {
		p, err := filepath.Abs(filepath.Join("..", "..", "modules", "sensor-active", "testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	log := filepath.Join(dir, "argv.log")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" >> %q\necho '--' >> %q\ncase \" $* \" in\n  *\" -sn \"*) cat %q;;\n  *\" --version-intensity \"*) cat %q;;\n  *) cat %q;;\nesac\n",
		log, log, fx("sweep.xml"), fx("fragile.xml"), fx("device.xml"))
	path := filepath.Join(dir, "nmap")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // the fake nmap must be executable
		t.Fatal(err)
	}
	return &fakeNmapBin{path: path, log: log}
}

func (f *fakeNmapBin) calls(t *testing.T) [][]string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	var cur []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "--" {
			out = append(out, cur)
			cur = nil
			continue
		}
		cur = append(cur, l)
	}
	return out
}

// scanTargets lists the argvs that went to one address (the last token of a device scan).
func scanTargets(calls [][]string, ip string) [][]string {
	var out [][]string
	for _, c := range calls {
		if c[len(c)-1] == ip && !slices.Contains(c, "-sn") {
			out = append(out, c)
		}
	}
	return out
}

func (s *stack) saveScope(t *testing.T, fragile ...string) {
	t.Helper()
	_, err := s.d.Inventory.SaveSettings(t.Context(), "admin@acme.example", inventory.SettingsInput{
		Settings: inventory.Settings{
			LANRanges:    []string{"192.168.10.0/24"},
			Active:       inventory.ActiveWindow{Enabled: true, Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00", Rate: 100, Exclusions: []string{"192.168.10.99"}},
			FragileKinds: fragile,
		},
		ScopeConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (s *stack) seen(t *testing.T, ip, mac string, kind string) string {
	t.Helper()
	hint := observe.AssetHint{IP: mustAddr(t, ip), MAC: mac}
	obs := []observe.Observation{{AssetHint: hint, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}}
	if kind != "" {
		obs = append(obs, observe.Observation{AssetHint: hint, Field: observe.Kind, Value: kind, Source: observe.Passive, Confidence: 0.7})
	}
	if err := s.d.Inventory.Record(t.Context(), obs); err != nil {
		t.Fatal(err)
	}
	l, err := s.d.Inventory.Devices(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.IP == ip {
			return d.ID
		}
	}
	t.Fatalf("no device with IP %s", ip)
	return ""
}

// A device a passive sensor saw first, inside an open window: the event queues it, the tick scans it with the right
// argv, and the inventory shows the software the CPEs gave. A device the person never approved is scanned too
// (D-84 (2)); a device declared by hand is not.
func TestSensorActiveScansADiscoveredDevice(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	nm := newFakeNmap(t)
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, time.Local) } // Monday 02:00, inside 01:00-05:00
	svc, err := newSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t)
	id := s.seen(t, "192.168.10.20", "aa:bb:cc:00:00:20", "")
	if n, _ := svc.QueueLen(t.Context()); n != 1 {
		t.Fatalf("queue = %d, the discovered event did not queue the device", n)
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	calls := nm.calls(t)
	want := []string{"--privileged", "-sS", "-sV", "-O", "-n", "--max-rate", "100", "--top-ports", "1000", "-oX", "-", "192.168.10.20"}
	if got := scanTargets(calls, "192.168.10.20"); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("device scans = %q\nwant %q", got, want)
	}
	for _, c := range calls { // the sweep never includes the excluded address
		if slices.Contains(c, "192.168.10.99") {
			t.Fatalf("an excluded address reached argv: %q", c)
		}
	}
	d, err := s.d.Inventory.Detail(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, sw := range d.Asset.Software {
		if sw.Source != "nmap" || sw.Confidence >= 1 {
			t.Errorf("software %+v", sw)
		}
		v := ""
		if sw.Version != nil {
			v = *sw.Version
		}
		found[sw.Vendor+"|"+sw.Product] = v
	}
	if found["openbsd|openssh"] != "8.9p1" || found["apache|http server"] != "2.4.52" {
		t.Fatalf("software = %v", found)
	}
	if d.Asset.OS == nil || d.Asset.OS.Value != "Linux 5.4 - 5.15" || d.Asset.OS.Source != "nmap" {
		t.Fatalf("os = %+v", d.Asset.OS)
	}
	if d.Asset.Approved {
		t.Fatal("scanning must not approve the device")
	}
	// the sweep found two more devices; they were new
	if got := s.count(`SELECT count(*) FROM sa_job WHERE kind = ? AND status = 'done' AND new_devices = 2`, "sweep"); got != 1 {
		t.Fatalf("sweep job rows with 2 new devices = %d", got)
	}

	// a device declared by hand is never scanned
	hand, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.40"})
	if err != nil {
		t.Fatal(err)
	}
	before := len(nm.calls(t))
	if err := svc.ScanDevice(t.Context(), hand.ID, "test"); err == nil {
		t.Fatal("a device declared by hand was scanned")
	}
	if len(nm.calls(t)) != before {
		t.Fatal("a hand-declared device reached nmap")
	}
}

// Fragile devices (D-45) through the real inventory policy: the first scan is the gentle one; afterwards "never"
// beats the type setting and nothing runs.
func TestSensorActiveFragileDevicePolicy(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	nm := newFakeNmap(t)
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, time.Local) }
	svc, err := newSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t, "printer")
	id := s.seen(t, "192.168.10.30", "aa:bb:cc:00:00:30", "printer")

	if err := svc.ScanDevice(t.Context(), id, "discovered"); err != nil {
		t.Fatal(err)
	}
	gentle := []string{"--privileged", "-sS", "-sV", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--top-ports", "100", "-oX", "-", "192.168.10.30"}
	if got := scanTargets(nm.calls(t), "192.168.10.30"); len(got) != 1 || !slices.Equal(got[0], gentle) {
		t.Fatalf("scans = %q, want one gentle scan %q", got, gentle)
	}
	det, err := s.d.Inventory.Detail(t.Context(), id)
	if err != nil || det.Asset.FirstScanAt == nil {
		t.Fatalf("first_scan_at not set: %v %+v", err, det.Asset.FirstScanAt)
	}

	// afterwards: passive only
	if err := svc.ScanDevice(t.Context(), id, "again"); err == nil {
		t.Fatal("a fragile device was scanned a second time")
	}
	never := "never"
	if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", id, inventory.Patch{RegularScan: &never}); err != nil {
		t.Fatal(err)
	}
	if err := s.d.Inventory.SetNotifyNew(t.Context(), "x", false); err != nil { // an unrelated settings change event
		t.Fatal(err)
	}
	if err := svc.ScanDevice(t.Context(), id, "again"); err == nil {
		t.Fatal(`regular_scan "never" did not beat the setting`)
	}
	if n := len(scanTargets(nm.calls(t), "192.168.10.30")); n != 1 {
		t.Fatalf("%d scans of the fragile device, want exactly the first gentle one", n)
	}
	allow := "allow"
	if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", id, inventory.Patch{RegularScan: &allow}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ScanDevice(t.Context(), id, "allowed"); err != nil {
		t.Fatalf("regular_scan allow: %v", err)
	}
	if got := scanTargets(nm.calls(t), "192.168.10.30"); len(got) != 2 || !slices.Contains(got[1], "-O") {
		t.Fatalf("scans = %q, want the second to be a normal one", got)
	}
}

// Module off: the event queues nothing and the scheduler does not run the jobs; nothing reaches nmap.
func TestSensorActiveOffDoesNothing(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	nm := newFakeNmap(t)
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, time.Local) }
	svc, err := newSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t)
	s.setModule("sensor-active", false)
	s.seen(t, "192.168.10.20", "aa:bb:cc:00:00:20", "")
	if n, _ := svc.QueueLen(t.Context()); n != 0 {
		t.Fatalf("queue = %d with the module off", n)
	}
	if n := len(nm.calls(t)); n != 0 {
		t.Fatalf("%d nmap runs with the module off", n)
	}
	s.setModule("sensor-active", true)
	s.seen(t, "192.168.10.21", "aa:bb:cc:00:00:21", "")
	if n, _ := svc.QueueLen(t.Context()); n != 1 {
		t.Fatalf("queue = %d after turning the module on", n)
	}
}

// The module is wired: its jobs register under its own id, and migrations created its tables.
func TestSensorActiveIsWired(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if n := s.count(`SELECT count(*) FROM sqlite_master WHERE name IN ('sa_job', 'sa_probe', 'sa_queue')`); n != 3 {
		t.Fatalf("%d sa_ tables", n)
	}
	js := sensorActiveJobs(*s.d)
	var names []string
	for _, j := range js {
		if j.Module != "sensor-active" {
			t.Errorf("job %s of module %s", j.Name, j.Module)
		}
		names = append(names, j.Name)
	}
	if !slices.Equal(names, []string{"window-tick", "prune-probes"}) {
		t.Fatalf("jobs = %v", names)
	}
	if js[0].Every != time.Minute || js[1].Every != 24*time.Hour {
		t.Fatalf("cadence = %v, %v", js[0].Every, js[1].Every)
	}
	var _ sensoractive.Inventory = sensorInventory{}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

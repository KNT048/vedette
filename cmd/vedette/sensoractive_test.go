package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// These tests never run a real nmap or touch a network: nmap is a script in t.TempDir() that records its argv and
// prints a hand-written fixture of modules/sensor-active/testdata.

// newLocalSensorActive is newSensorActive over the module's own local Prober on a fake nmap script, so a command finishes with no worker.
// Production never builds one (TestProductionRunsNoCaptureAndNoLocalNmap).
func newLocalSensorActive(d deps, path string) (*sensoractive.Service, error) {
	p, err := sensoractive.NewLocalProber(d.Log, path)
	if err != nil {
		return nil, err
	}
	return newSensorActive(d, nmapHealth{p, path})
}

// nmapHealth is a local Prober that says what Health says of a local nmap (the file exists and is executable): the service reads the
// health of a Prober that has a NmapHealth method, so no production parameter is needed to set the path.
type nmapHealth struct {
	sensoractive.Prober
	path string
}

func (h nmapHealth) NmapHealth() string {
	if fi, err := os.Stat(h.path); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return "nmap is not an executable file at " + h.path
	}
	return ""
}

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
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" >> %q\necho '--' >> %q\ncase \" $* \" in\n  *\" -sn \"*) cat %q;;\n  *\" --max-retries \"*) cat %q;;\n  *) cat %q;;\nesac\n",
		log, log, fx("sweep.xml"), fx("fragile.xml"), fx("device.xml"))
	path := filepath.Join(dir, "nmap")
	exectest.WriteScript(t, path, body)
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
	return s.idByIP(t, ip)
}

func (s *stack) idByIP(t *testing.T, ip string) string {
	t.Helper()
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
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) } // Monday 02:00, inside 01:00-05:00
	svc, err := newLocalSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t)
	id := s.seen(t, "192.168.10.20", "aa:bb:cc:00:00:20", "server") // classified by the passive sensor: not fragile
	if n, _ := svc.QueueLen(t.Context()); n != 1 {
		t.Fatalf("queue = %d, the discovered event did not queue the device", n)
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	calls := nm.calls(t)
	want := []string{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info", "-n", "--max-rate", "100", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}
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
	var ports []string // the open ports reach inv_service through observe.ServiceSink (D-350); the closed one does not
	for _, sv := range d.Asset.Services {
		ports = append(ports, strconv.Itoa(sv.Port)+"/"+sv.Proto+" "+sv.Name+" "+sv.Source)
	}
	if want := []string{"22/tcp ssh nmap", "80/tcp http nmap", "8080/tcp http-proxy nmap"}; !slices.Equal(ports, want) {
		t.Fatalf("services = %q, want %q", ports, want)
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
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) }
	svc, err := newLocalSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t, "printer")
	id := s.seen(t, "192.168.10.30", "aa:bb:cc:00:00:30", "printer")

	if err := svc.ScanDevice(t.Context(), id, "discovered"); err != nil {
		t.Fatal(err)
	}
	gentle := []string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"}
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
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) }
	svc, err := newLocalSensorActive(*s.d, nm.path)
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

// D-45 "afterwards passive only", inventory INV-5 "never scanned", M2: the daily sweep (-sn) skips the addresses of
// a fragile device that already had its one gentle scan (and is marked regular_scan=never), of a device declared
// by hand and of the box itself, though they are inside the scope; their neighbours are still swept.
func TestSensorActiveSweepSkipsProtectedAddresses(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	nm := newFakeNmap(t)
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) }
	svc, err := newLocalSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t, "printer")
	printer := s.seen(t, "192.168.10.30", "aa:bb:cc:00:00:30", "printer")
	if err := svc.ScanDevice(t.Context(), printer, "discovered"); err != nil { // the one gentle scan
		t.Fatal(err)
	}
	never := "never"
	if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", printer, inventory.Patch{RegularScan: &never}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.40"}); err != nil {
		t.Fatal(err)
	}
	before := len(nm.calls(t))
	if _, err := svc.DiscoverRanges(t.Context()); err != nil {
		t.Fatal(err)
	}
	var swept []string
	for _, c := range nm.calls(t)[before:] {
		swept = append(swept, c[slices.Index(c, "-oX")+2:]...)
	}
	for _, ip := range []string{"192.168.10.30", "192.168.10.40"} {
		if slices.Contains(swept, ip) {
			t.Errorf("the sweep probed %s, a device the inventory protects", ip)
		}
	}
	if !slices.Contains(swept, "192.168.10.29") || !slices.Contains(swept, "192.168.10.41") {
		t.Errorf("the neighbours of the protected addresses are not swept: %d addresses", len(swept))
	}
	prot, err := sensorInventory{inv: s.d.Inventory}.ProtectedIPs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ifaces, _ := net.InterfaceAddrs(); len(ifaces) > 0 {
		for _, x := range ifaces {
			if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Is4() && !slices.Contains(prot, p.Addr()) {
				t.Errorf("the box's own address %s is not protected", p.Addr())
			}
		}
	}
}

// H1 / D-45: the first active scan of a device whose kind is unknown (everything a sweep finds) is the gentle one,
// never -O or the 1000-port list; it is not scanned any heavier until a person or passive data classifies it.
func TestSensorActiveFirstScanOfAnUnclassifiedDeviceIsGentle(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	nm := newFakeNmap(t)
	s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) }
	svc, err := newLocalSensorActive(*s.d, nm.path)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t, "printer", "camera", "nvr", "nas", "ap", "iot")
	if err := svc.Tick(t.Context()); err != nil { // the sweep finds .2 and .5 (kind unknown), then the queue is drained
		t.Fatal(err)
	}
	for _, ip := range []string{"192.168.10.2", "192.168.10.5"} {
		got := scanTargets(nm.calls(t), ip)
		if len(got) != 1 {
			t.Fatalf("%s: %d device scans, want the one gentle scan", ip, len(got))
		}
		for _, bad := range []string{"-O", "-sV", "1000", "--version-intensity"} {
			if slices.Contains(got[0], bad) {
				t.Errorf("first scan of %s (kind unknown) was %q, not the gentle one", ip, got[0])
			}
		}
		if !slices.Contains(got[0], "-T2") || !slices.Contains(got[0], "--host-timeout") {
			t.Errorf("first scan of %s = %q", ip, got[0])
		}
	}
	// still unclassified after its gentle scan: passive only, blocked with its own reason
	id := s.idByIP(t, "192.168.10.2")
	if err := svc.ScanDevice(t.Context(), id, "again"); !errors.Is(err, sensoractive.ErrBlocked) || !strings.Contains(err.Error(), inventory.ReasonUnclassifiedPassiveOnly) {
		t.Fatalf("second scan of an unclassified device: %v", err)
	}
	// a person classifies it as not fragile: the normal scan is allowed
	server := "server"
	if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", id, inventory.Patch{Kind: &server}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ScanDevice(t.Context(), id, "classified"); err != nil {
		t.Fatalf("classified as server: %v", err)
	}
	if got := scanTargets(nm.calls(t), "192.168.10.2"); len(got) != 2 || !slices.Contains(got[1], "-O") {
		t.Fatalf("scans = %q, want the second to be a normal one", got)
	}
}

// SYS-7: the scope rule sensor-active applies in memory is the inventory's InScope, address for address.
func TestSensorActiveScopeRuleMatchesTheInventory(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	_, err := s.d.Inventory.SaveSettings(t.Context(), "admin@acme.example", inventory.SettingsInput{
		Settings: inventory.Settings{
			LANRanges: []string{"192.168.10.0/24", "10.1.0.0/20", "172.16.5.0/30"},
			Active:    inventory.ActiveWindow{Enabled: true, Days: []int{1}, From: "01:00", To: "05:00", Rate: 100, Exclusions: []string{"192.168.10.0/28", "192.168.10.200", "10.1.4.0/22", "172.16.5.1"}},
		},
		ScopeConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := sensorInventory{inv: s.d.Inventory}.Settings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.168.10.1", "192.168.10.16", "192.168.10.200", "192.168.10.255", "192.168.11.1", "10.1.0.1", "10.1.3.255", "10.1.4.0", "10.1.7.255", "10.1.8.0", "10.1.15.255", "10.1.16.0", "172.16.5.0", "172.16.5.1", "172.16.5.2", "8.8.8.8", "::ffff:192.168.10.20"} {
		a := netip.MustParseAddr(ip)
		want, err := s.d.Inventory.InScope(t.Context(), a)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.InScope(a); got != want {
			t.Errorf("%s: sensor-active says %v, the inventory %v", ip, got, want)
		}
	}
}

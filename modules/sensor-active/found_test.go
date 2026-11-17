package sensoractive_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// Every device check keeps what it found with its job, naming the device: the open ports with nmap's names and the OS it recorded,
// and against the device's previous check of the same reach, the ports opened and closed and the OS guess before it changed. A
// check of another device never counts as this one's previous check.
func TestDeviceCheckKeepsWhatItFoundAndWhatChanged(t *testing.T) {
	t.Parallel()
	fx := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // a fixture of this package
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	out := filepath.Join(t.TempDir(), "out.xml")
	put := func(name string) {
		if err := os.WriteFile(out, fx(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("device.xml")
	e := newEnv(t, fakeOpts{always: out})
	last := func() sa.JobRow {
		t.Helper()
		jobs, err := e.svc.JobsOf(e.ctx(), "a-web", netip.MustParseAddr("192.168.10.20"), 10)
		if err != nil || len(jobs) == 0 {
			t.Fatalf("jobs: %v %v", jobs, err)
		}
		if jobs[0].Found == nil {
			t.Fatalf("the newest check kept nothing: %+v", jobs[0])
		}
		return jobs[0]
	}
	tcp := func(f *sa.DeviceFound) []int {
		var ps []int
		for _, p := range f.Ports {
			ps = append(ps, p.Port)
		}
		return ps
	}

	if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
		t.Fatal(err)
	}
	f := last().Found
	if f.Reach != "top1000" || f.Open != 3 || !slices.Equal(tcp(f), []int{22, 80, 8080}) || f.Ports[0].Name != "ssh" || f.OS != "Linux 5.4 - 5.15" || f.Compared || f.OSWas != "" {
		t.Fatalf("first check: %+v", f)
	}

	put("fortigate.xml")
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
		t.Fatal(err)
	}
	f = last().Found
	if !f.Compared || !slices.Equal(f.New, []int{443, 541}) || !slices.Equal(f.Gone, []int{80, 8080}) || f.OSWas != "Linux 5.4 - 5.15" || f.OS != "Fortinet FortiGate-60F firewall (FortiOS 7.2)" {
		t.Fatalf("second check: %+v", f)
	}

	if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
		t.Fatal(err)
	}
	f = last().Found
	if !f.Compared || len(f.New) != 0 || len(f.Gone) != 0 || f.OSWas != "" {
		t.Fatalf("third check, nothing changed: %+v", f)
	}

	// another device's first check compares with nothing of a-web's
	put("device.xml")
	e.inv.mu.Lock()
	e.inv.assets["a-web"] = netip.MustParseAddr("192.168.10.21")
	e.inv.assets["a-new"] = netip.MustParseAddr("192.168.10.20")
	e.inv.mu.Unlock()
	if err := e.svc.ScanDevice(e.ctx(), "a-new", "check_now"); err != nil {
		t.Fatal(err)
	}
	jobs, err := e.svc.JobsOf(e.ctx(), "a-new", netip.MustParseAddr("192.168.10.20"), 10)
	if err != nil || len(jobs) != 1 || jobs[0].Found == nil || jobs[0].Found.Compared || jobs[0].Found.OSWas != "" {
		t.Fatalf("a-new's jobs: %+v %v (want only its own, compared with nothing)", jobs, err)
	}
}

package sensoractive_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/core/lifecycle"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// Every device check keeps what it found with its job, naming the device: the open ports with nmap's names and the OS it recorded,
// and against the device's previous check of the same reach, the ports opened and closed and the OS guess before it changed. A port
// that sent nothing back (the FortiGate drops every probe it does not answer) is kept once as "no answer", and taken off the list
// when the next check gets no answer from it either; a port the check did not ask about (8080, outside the FortiGate run's list) is
// not called closed. A check of another device never counts as this one's previous check.
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
	if !f.Compared || !slices.Equal(f.New, []int{443, 541}) || len(f.Gone) != 0 || !slices.Equal(f.NoAnswer, []int{80}) || f.OSWas != "Linux 5.4 - 5.15" || f.OS != "Fortinet FortiGate-60F firewall (FortiOS 7.2)" {
		t.Fatalf("second check: %+v", f)
	}

	if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
		t.Fatal(err)
	}
	f = last().Found
	if !f.Compared || len(f.New) != 0 || len(f.Gone) != 0 || len(f.NoAnswer) != 0 || !slices.Equal(f.Dropped, []int{80}) || f.OSWas != "" {
		t.Fatalf("third check, 80 again no answer: %+v", f)
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

// A weekly scan of every port leaves an sa_all_ports row with no normal scan in it (normal_ports '[]'): the first device check after
// it has no earlier check to compare with, so it says what it found and never calls its ports "newly open".
func TestDeviceCheckWithNoEarlierCheckComparesWithNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_all_ports (asset_id, last_at, outcome) VALUES ('a-web', '2026-11-14T01:00:00.000Z', 'not_eligible')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
		t.Fatal(err)
	}
	jobs, err := e.svc.JobsOf(e.ctx(), "a-web", netip.MustParseAddr("192.168.10.20"), 10)
	if err != nil || len(jobs) != 1 || jobs[0].Found == nil {
		t.Fatalf("jobs: %+v %v", jobs, err)
	}
	if f := jobs[0].Found; f.Compared || len(f.New) != 0 || len(f.Gone) != 0 || f.OSWas != "" || f.Open != 3 {
		t.Fatalf("first check compared with an empty baseline: %+v", f)
	}
}

// When two devices merge, the checks of the one that goes become the kept one's: its Last checks lists them and its next check is
// compared with them.
func TestMergedDeviceKeepsTheChecksOfTheOther(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
		t.Fatal(err)
	}
	e.inv.mu.Lock()
	delete(e.inv.assets, "a-web")
	e.inv.assets["a-kept"] = netip.MustParseAddr("192.168.10.20")
	e.inv.mu.Unlock()
	mergeDevices(t, e.db, e.svc, lifecycle.Merge{From: "a-web", Into: "a-kept"})
	// listed for the kept device even at another address (the job names it now)
	jobs, err := e.svc.JobsOf(e.ctx(), "a-kept", netip.MustParseAddr("192.168.10.55"), 10)
	if err != nil || len(jobs) != 1 || jobs[0].AssetID != "a-kept" {
		t.Fatalf("kept device's checks after the merge: %+v %v", jobs, err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-kept", "check_now"); err != nil {
		t.Fatal(err)
	}
	jobs, err = e.svc.JobsOf(e.ctx(), "a-kept", netip.MustParseAddr("192.168.10.20"), 10)
	if err != nil || len(jobs) != 2 || jobs[0].Found == nil || !jobs[0].Found.Compared || len(jobs[0].Found.New) != 0 {
		t.Fatalf("the kept device's next check is compared with the merged one's: %+v %v", jobs, err)
	}
}

// The run over the extra ports can end without an error and still not cover the device: nmap's host discovery missed it there, or
// it reached the host timeout (no port table). That check covered the top 1000 only: it is marked so, compared only outside the
// extra ports, and its OS is not compared, exactly as when that run failed.
func TestExtraRunThatDidNotCoverTheDeviceMarksTheCheck(t *testing.T) {
	t.Parallel()
	for _, extra := range []string{"down.xml", "timedout.xml"} {
		t.Run(extra, func(t *testing.T) {
			t.Parallel()
			abs := func(name string) string {
				p, err := filepath.Abs(filepath.Join("testdata", name))
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			e := newEnv(t, fakeOpts{})
			if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
				t.Fatal(err)
			}
			// the same nmap, but the extra-ports run (the only one with -p) prints a result without the device's ports
			script := filepath.Join(t.TempDir(), "nmap")
			exectest.WriteScript(t, script, `#!/bin/sh
if [ "$1" = "--version" ]; then echo "Nmap version 7.95 ( https://nmap.org )"; exit 0; fi
case " $* " in
  *" -p "*) cat `+abs(extra)+`;;
  *) cat `+abs("device.xml")+`;;
esac
`)
			e.nm.path = script
			e.build()
			if err := e.svc.ScanDevice(e.ctx(), "a-web", "check_now"); err != nil {
				t.Fatal(err)
			}
			jobs, err := e.svc.JobsOf(e.ctx(), "a-web", netip.MustParseAddr("192.168.10.20"), 10)
			if err != nil || len(jobs) != 2 || jobs[0].Status != sa.StatusDone || jobs[0].Found == nil {
				t.Fatalf("jobs: %+v %v", jobs, err)
			}
			if f := jobs[0].Found; !f.ExtraFailed || !f.Compared || !f.ComparedPart || f.OSWas != "" {
				t.Fatalf("a check whose extra-ports run did not cover the device: %+v", f)
			}
		})
	}
}

package sensoractive_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// The sweep skips ProtectedIPs, which are in scope, so a batch has holes. Two sweeps that
// sent packets to different addresses (one skipped .20, the other .30) must leave different probe logs, so an
// admin asked "did the box probe my PLC at .20 last night?" can answer from the log: the row stores the targets
// as merged ranges.
func TestProbeLogTellsWhichAddressesWereProbed(t *testing.T) {
	t.Parallel()
	run := func(protected string) ([]sa.Probe, [][]string) {
		e := newEnv(t, fakeOpts{})
		e.inv.protected = []netip.Addr{netip.MustParseAddr(protected)}
		if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
			t.Fatal(err)
		}
		p, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
		if err != nil {
			t.Fatal(err)
		}
		for i := range p {
			p[i].Time, p[i].JobID = "", "" // compare what the log says was sent, not when
		}
		return p, e.nm.calls(t)
	}
	a, callsA := run("192.168.10.20")
	b, callsB := run("192.168.10.30")
	if slices.EqualFunc(callsA, callsB, slices.Equal[[]string]) {
		t.Fatal("setup: the two sweeps sent the same argv")
	}
	same := slices.EqualFunc(a, b, func(x, y sa.Probe) bool {
		return x.Shape == y.Shape && x.Rate == y.Rate && x.Target == y.Target && x.Result == y.Result && slices.Equal(x.Argv, y.Argv)
	})
	if same {
		t.Errorf("different addresses were probed (.20 skipped vs .30 skipped) but the probe logs are identical: %+v", a)
	}
}

// The row stores the addresses as merged ranges, in the order they were sent: a protected address splits one
// range in two.
func TestProbeLogTargetsAreMergedRanges(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.protected = []netip.Addr{netip.MustParseAddr("192.168.10.20"), netip.MustParseAddr("192.168.10.30")}
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
	if err != nil || len(p) != 1 {
		t.Fatalf("Probes = %d rows, %v", len(p), err)
	}
	const want = "192.168.10.1-192.168.10.19,192.168.10.21-192.168.10.29,192.168.10.31-192.168.10.62"
	if p[0].Target != want {
		t.Errorf("target = %q, want %q", p[0].Target, want)
	}
}

// History stays true when the command templates change: Probes returns the flags stored with the row, it does not
// rebuild them from today's templates.
func TestProbeLogKeepsTheFlagsAsApproved(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	const old = "--privileged -sn -n --max-rate 7 --an-older-flag"
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE sa_probe SET flags = ?`, old)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
	if err != nil || len(p) != 1 {
		t.Fatalf("Probes = %d rows, %v", len(p), err)
	}
	want := append(strings.Fields(old), "-oX", "-")
	if !slices.Equal(p[0].Argv, want) {
		t.Errorf("argv = %q, want the stored %q", p[0].Argv, want)
	}
}

// Isolated addresses never overflow the column: 64 addresses with a gap between each fit.
func TestProbeLogFitsSixtyFourScatteredTargets(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/24"}; s.Exclusions = nil })
	var prot []netip.Addr
	for i := 1; i < 255; i += 2 { // every odd address is protected: the batch is .2 .4 .6 ...
		prot = append(prot, netip.AddrFrom4([4]byte{192, 168, 10, byte(i)}))
	}
	e.inv.protected = prot
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
	if err != nil || len(p) < 1 {
		t.Fatalf("Probes = %d rows, %v", len(p), err)
	}
	if got := strings.Count(p[0].Target, ",") + 1; got != 64 {
		t.Errorf("first row has %d pieces, want 64 scattered addresses: %q", got, p[0].Target)
	}
	if p[0].Result == "" || strings.HasPrefix(p[0].Result, "failed") {
		t.Errorf("result = %q", p[0].Result)
	}
}

// ExportProbes is the "scan_probes" source of GET /core/logs/export: the probe rows as stored, oldest first, in range,
// without a Service (it must work on a box where nmap is missing).
func TestExportProbesIsTheStoredRowsInRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	stored, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
	if err != nil || len(stored) == 0 {
		t.Fatalf("Probes = %d rows, %v", len(stored), err)
	}
	var out bytes.Buffer
	if err := sa.ExportProbes(e.ctx(), e.db, time.Time{}, time.Time{}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(stored) {
		t.Fatalf("%d lines, %d stored", len(lines), len(stored))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got["time"] != stored[0].Time || got["targets"] != stored[0].Target || got["result"] != stored[0].Result || got["job_id"] != stored[0].JobID || got["rate"] != float64(stored[0].Rate) {
		t.Fatalf("line = %v, stored = %+v", got, stored[0])
	}
	if !strings.Contains(got["flags"].(string), strings.Join(stored[0].Argv[:len(stored[0].Argv)-2], " ")) {
		t.Fatalf("flags = %v, argv = %v", got["flags"], stored[0].Argv)
	}
	out.Reset()
	if err := sa.ExportProbes(e.ctx(), e.db, e.base.Add(time.Hour), time.Time{}, &out); err != nil || out.Len() != 0 {
		t.Fatalf("after the run: %v %q", err, out.String())
	}
	out.Reset()
	if err := sa.ExportProbes(e.ctx(), e.db, time.Time{}, e.base.Add(-time.Hour), &out); err != nil || out.Len() != 0 {
		t.Fatalf("before the run: %v %q", err, out.String())
	}
}

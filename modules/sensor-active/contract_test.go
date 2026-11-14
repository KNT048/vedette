package sensoractive_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

func hostsOf(calls [][]string) []string {
	var out []string
	for _, c := range calls {
		out = append(out, targetsOf(c)...)
	}
	return out
}

// INV-1: nothing outside lan_ranges or inside an exclusion ever reaches an argv, including a range that only
// partly overlaps an exclusion and a device the inventory's policy allowed but whose address is out of scope.
func TestContract_INV1_NeverOutsideScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.set(func(s *sa.Settings) {
		s.LANRanges = []string{"192.168.10.0/28", "172.16.5.0/30"}
		s.Exclusions = []string{"192.168.10.8/30", "192.168.10.3", "172.16.5.1"} // /30 overlaps the second half of the /28
	})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	want := []string{"172.16.5.2", "192.168.10.1", "192.168.10.2", "192.168.10.4", "192.168.10.5", "192.168.10.6", "192.168.10.7", "192.168.10.12", "192.168.10.13", "192.168.10.14"} // ascending
	if got := hostsOf(e.nm.calls(t)); !slices.Equal(got, want) {
		t.Fatalf("probed %v\nwant   %v", got, want)
	}
	// the settings of the batch were read before it ran, and every address was tested against them
	if got := hostsOf(e.nm.calls(t)); len(got) != len(want) {
		t.Fatalf("%d addresses probed, want %d", len(got), len(want))
	}

	// A device out of scope, although ScanPolicy said yes: blocked, nothing sent.
	before := len(e.nm.calls(t))
	err := e.svc.ScanDevice(e.ctx(), "a-far", "discovered")
	if !errors.Is(err, sa.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if len(e.nm.calls(t)) != before {
		t.Fatal("an out-of-scope device reached nmap")
	}
	b := e.ev.named(sa.EventScanBlocked)
	if len(b) != 1 || b[0].Data.(sa.BlockedEvent) != (sa.BlockedEvent{AssetID: "a-far", Reason: "out_of_scope"}) {
		t.Fatalf("blocked events = %+v", b)
	}
	// An exclusion added later is honoured by the very next device scan.
	e.inv.set(func(s *sa.Settings) { s.Exclusions = append(s.Exclusions, "192.168.10.20") })
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); !errors.Is(err, sa.ErrBlocked) {
		t.Fatalf("an excluded device was scanned: %v", err)
	}
	if len(e.nm.calls(t)) != before {
		t.Fatal("an excluded device reached nmap")
	}
}

// INV-1 again, on the output side: a host that nmap reports but that was not asked for is never recorded.
func TestContract_INV1_ReportedHostsOutsideTheRunAreIgnored(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil { // the fixture also lists 203.0.113.9
		t.Fatal(err)
	}
	for _, o := range e.sink.observations() {
		if o.AssetHint.IP == netip.MustParseAddr("203.0.113.9") || o.AssetHint.MAC == "AA:BB:CC:00:00:99" {
			t.Fatalf("recorded a host outside the targets: %+v", o)
		}
	}
}

// INV-2: no sweep and no device scan when scanning is off, the scope is not confirmed, or there are no ranges.
func TestContract_INV2_NothingWithoutScopeAndSwitch(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mut  func(*sa.Settings)
		want error
	}{
		"scanning off":        {func(s *sa.Settings) { s.Enabled = false }, sa.ErrScanningOff},
		"scope not confirmed": {func(s *sa.Settings) { s.ScopeConfirmed = false }, sa.ErrScopeNotConfirmed},
		"no ranges":           {func(s *sa.Settings) { s.LANRanges = nil }, sa.ErrNoRanges},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{})
			e.inv.set(tt.mut)
			if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, tt.want) {
				t.Fatalf("DiscoverRanges err = %v, want %v", err, tt.want)
			}
			if err := e.svc.ScanDevice(e.ctx(), "a-web", "x"); !errors.Is(err, tt.want) {
				t.Fatalf("ScanDevice err = %v, want %v", err, tt.want)
			}
			if err := e.svc.Tick(e.ctx()); err != nil {
				t.Fatal(err)
			}
			if n := len(e.nm.calls(t)); n != 0 {
				t.Fatalf("%d nmap runs", n)
			}
			if e.count(`SELECT count(*) FROM sa_job`) != 0 {
				t.Fatal("a job row was written")
			}
		})
	}
}

// INV-3: only inside the window; D-84 (1): even the one gentle scan of a fragile device waits for it.
func TestContract_INV3_OnlyInsideTheWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) {
		e.base = local(9, 12, 0) // Monday noon, window is 01:00-05:00
		e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}
	})
	e.sweptBefore() // not a new box: its first pass is behind it (D-501)
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrOutsideWindow) {
		t.Fatalf("sweep err = %v, want ErrOutsideWindow", err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-printer", "discovered"); !errors.Is(err, sa.ErrOutsideWindow) {
		t.Fatalf("gentle scan err = %v, want ErrOutsideWindow", err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Fatalf("%d nmap runs outside the window", n)
	}
	if len(e.inv.markedIDs()) != 0 {
		t.Fatal("first_scan_at was set without a scan")
	}
}

// INV-3, PRE-3, POST-3: the window closes in the middle of the second batch. The process is killed, the
// batch that finished stays stored, the cut one is dropped, the job is "stopped", and nothing keeps running.
func TestContract_INV3_StopsWhenTheWindowCloses(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 2}, func(e *env) {
		e.base = local(9, 4, 59).Add(58 * time.Second)                                // 2 s to the end of the window
		e.inv.set(func(s *sa.Settings) { s.LANRanges = []string{"192.168.10.0/25"} }) // 126 hosts: batches of 64 and 62
	})
	start := time.Now()
	res, err := e.svc.DiscoverRanges(e.ctx())
	if !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("err = %v, want ErrStopped", err)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("took %v: the sleeping fake nmap was not killed at the window's end", took)
	}
	if res.Status != sa.StatusStopped || res.Targets != 64 {
		t.Fatalf("result = %+v, want stopped after 64 finished targets", res)
	}
	if n := len(e.nm.calls(t)); n != 2 {
		t.Fatalf("%d runs, want 2", n)
	}
	if got := e.str(`SELECT status FROM sa_job`); got != "stopped" {
		t.Fatalf("job status = %q", got)
	}
	if got := e.count(`SELECT count(*) FROM sa_job WHERE finished_at IS NULL`); got != 0 {
		t.Fatal("the job was left running")
	}
	rows := e.count(`SELECT count(*) FROM sa_probe WHERE result LIKE 'stopped:%'`)
	if rows != 1 {
		t.Fatalf("%d stopped probe rows, want 1", rows)
	}
	if fin := e.ev.named(sa.EventScanFinished); len(fin) != 1 || fin[0].Data.(sa.FinishedEvent).Status != "stopped" {
		t.Fatalf("finished events = %+v", fin)
	}
	// The first batch's hosts (.2 and .5 of the fixture) were recorded; the cut batch recorded nothing more.
	if n := len(e.sink.observations()); n != 3 { // .2: mac+vendor, .5: mac
		t.Fatalf("%d observations, want 3 from the finished batch", n)
	}
}

// INV-3 / PRE-3: a settings change that no longer allows the run stops the process now, not at the next batch.
func TestContract_INV3_SettingsChangeStopsTheRunningScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1})
	done := make(chan error, 1)
	go func() { _, err := e.svc.DiscoverRanges(e.ctx()); done <- err }()
	waitFor(t, "the fake nmap to start", func() bool { return len(e.nm.calls(t)) > 0 })
	e.inv.set(func(s *sa.Settings) { s.Enabled = false })
	if err := e.svc.SettingsChanged(e.ctx()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, sa.ErrStopped) {
			t.Fatalf("err = %v, want ErrStopped", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run was not stopped by the settings change")
	}
	if got := e.str(`SELECT status FROM sa_job`); got != "stopped" {
		t.Fatalf("job status = %q", got)
	}
}

// An exclusion added while a batch runs stops it too (the addresses of the run are checked again).
func TestContract_INV1_ExclusionAddedMidRunStopsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1})
	done := make(chan error, 1)
	go func() { _, err := e.svc.DiscoverRanges(e.ctx()); done <- err }()
	waitFor(t, "the fake nmap to start", func() bool { return len(e.nm.calls(t)) > 0 })
	e.inv.set(func(s *sa.Settings) { s.Exclusions = []string{"192.168.10.5"} })
	if err := e.svc.SettingsChanged(e.ctx()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, sa.ErrStopped) {
			t.Fatalf("err = %v, want ErrStopped", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("not stopped")
	}
}

// INV-4: the rate is an integer on the command line, never above the setting, and 1 for the gentle scan.
func TestContract_INV4_RateAndFlags(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}
	e.inv.decision["a-web"] = sa.Decision{Allowed: true, Rate: 5000, Reason: "ok"} // more than the setting: the setting wins
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-printer", "discovered"); err != nil {
		t.Fatal(err)
	}
	calls := e.nm.calls(t)
	if len(calls) != 3 {
		t.Fatalf("%d runs, want 3", len(calls))
	}
	want := [][]string{
		{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", "100", "-oX", "-"},
		{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", "100", "--max-retries", "3", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"},
		{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"},
	}
	for i, w := range want {
		got := calls[i]
		if i == 0 {
			got = got[:len(w)] // the sweep's targets are checked in INV-1
		}
		if !slices.Equal(got, w) {
			t.Errorf("run %d argv = %q\nwant        %q", i, got, w)
		}
	}
	for _, c := range calls {
		for i, a := range c {
			// FORBID-6 (D-504): the only scripts are the two pinned NTLM ones, after a bare --script; never a category or -A/-sC.
			pinned := a == "--script" && i+1 < len(c) && c[i+1] == "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert"
			if strings.HasPrefix(a, "--script") && !pinned || a == "-A" || a == "-sC" {
				t.Errorf("NSE flag %q in %q (FORBID-6)", a, c)
			}
		}
	}
}

// INV-5 / PRE-2 / POST-2: the gentle scan of a fragile device marks first_scan_at only when it finished; a
// decision of "no" is blocked with the inventory's reason and sends nothing.
func TestContract_INV5_GentleScanMarksOnceAndBlockedSendsNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}
	if err := e.svc.ScanDevice(e.ctx(), "a-printer", "discovered"); err != nil {
		t.Fatal(err)
	}
	if got := e.inv.markedIDs(); !slices.Equal(got, []string{"a-printer"}) {
		t.Fatalf("marked = %v", got)
	}
	e.inv.decision["a-printer"] = sa.Decision{Reason: "fragile_passive_only"}
	err := e.svc.ScanDevice(e.ctx(), "a-printer", "again")
	if !errors.Is(err, sa.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if n := len(e.nm.calls(t)); n != 1 {
		t.Fatalf("%d runs, want the one gentle scan only", n)
	}
	b := e.ev.named(sa.EventScanBlocked)
	if len(b) != 1 || b[0].Data.(sa.BlockedEvent) != (sa.BlockedEvent{AssetID: "a-printer", Reason: "fragile_passive_only"}) {
		t.Fatalf("blocked = %+v", b)
	}
	if err := e.svc.ScanDevice(e.ctx(), "nope", "x"); !errors.Is(err, sa.ErrNotFound) {
		t.Fatalf("unknown device err = %v", err)
	}
}

func TestContract_INV5_FailedGentleScanIsNotMarked(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{exitCode: 1})
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}
	if err := e.svc.ScanDevice(e.ctx(), "a-printer", "discovered"); err == nil {
		t.Fatal("a failed run reported success")
	}
	if len(e.inv.markedIDs()) != 0 {
		t.Fatal("a failed gentle scan set first_scan_at: the one scan must be retried")
	}
	if got := e.str(`SELECT status FROM sa_job`); got != "failed" {
		t.Fatalf("job status = %q", got)
	}
	if got := e.str(`SELECT result FROM sa_probe`); !strings.HasPrefix(got, "failed: nmap exited with code 1") {
		t.Fatalf("probe result = %q", got)
	}
}

// INV-6: without the binary the module reports unavailable with a clear message, and has no fallback.
func TestContract_INV6_MissingNmapIsUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) { e.nm.path = filepath.Join(t.TempDir(), "no-nmap-here") })
	h := e.svc.Health(e.ctx())
	if h.Status != "unavailable" || !strings.Contains(h.Message, "nmap is not installed") {
		t.Fatalf("health = %+v", h)
	}
	if _, err := e.svc.DiscoverRanges(e.ctx()); !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("DiscoverRanges err = %v", err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "x"); !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("ScanDevice err = %v", err)
	}
	if err := e.svc.Tick(e.ctx()); !errors.Is(err, sa.ErrUnavailable) {
		t.Fatalf("Tick err = %v: the job history must show why nothing runs", err)
	}
	if e.count(`SELECT count(*) FROM sa_job`) != 0 {
		t.Fatal("a job was recorded for a run that could not start")
	}
	// present but not executable
	plain := filepath.Join(t.TempDir(), "nmap")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.nm.path = plain
	e.build()
	if h := e.svc.Health(e.ctx()); h.Status != "unavailable" {
		t.Fatalf("a non-executable file is %+v", h)
	}
	// and with the fake in place it is ok
	good := newEnv(t, fakeOpts{})
	if h := good.svc.Health(good.ctx()); h.Status != "ok" {
		t.Fatalf("health = %+v", h)
	}
}

// INV-7: output that is cut off, too big, malformed or hostile is discarded as a whole; nothing is recorded.
func TestContract_INV7_UntrustedOutputIsDiscarded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, doc string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	big := write("big.xml", "<nmaprun>"+strings.Repeat(" ", 9<<20)+"</nmaprun>")
	cases := map[string]struct {
		file   string
		result string
	}{
		"larger than the cap": {big, "failed: output over the size limit, discarded"},
		"malformed":           {write("bad.xml", `<nmaprun><host>`), "failed: output not valid, discarded"},
		"entity bomb":         {write("bomb.xml", `<!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>`), "failed: output not valid, discarded"},
		"wrong document":      {write("html.xml", `<html><body>hi</body></html>`), "failed: output not valid, discarded"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{always: c.file})
			res, err := e.svc.DiscoverRanges(e.ctx())
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != sa.StatusFailed || res.Targets != 0 {
				t.Fatalf("result = %+v, want a failed sweep with no finished targets", res)
			}
			if n := len(e.sink.observations()); n != 0 {
				t.Fatalf("%d observations recorded from bad output", n)
			}
			if got := e.str(`SELECT result FROM sa_probe LIMIT 1`); got != c.result {
				t.Fatalf("probe result = %q, want %q", got, c.result)
			}
			if err := e.svc.ScanDevice(e.ctx(), "a-web", "x"); err == nil {
				t.Fatal("a device scan of bad output reported success")
			}
			if len(e.sink.sw) != 0 {
				t.Fatal("software recorded from bad output")
			}
		})
	}
}

// INV-8: a device scan records source nmap with a confidence below 1, and the software from the CPEs.
func TestContract_INV8_ObservationsAndSoftwareFromTheScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, o := range e.sink.observations() {
		if o.Source != "nmap" || o.Confidence < 0 || o.Confidence >= 1 {
			t.Errorf("observation %+v: source must be nmap and confidence below 1", o)
		}
		if o.AssetHint.IP != netip.MustParseAddr("192.168.10.20") {
			t.Errorf("hint %+v", o.AssetHint)
		}
		fields[string(o.Field)] = o.Value
	}
	if fields["os"] != "Linux 5.4 - 5.15" || fields["hostname"] != "web01.lan" || fields["vendor"] != "Acme Networks" {
		t.Fatalf("fields = %v", fields)
	}
	sw := e.sink.sw["192.168.10.20"]
	var cpes []string
	for _, s := range sw {
		cpes = append(cpes, s.CPE)
		if s.Confidence <= 0 || s.Confidence >= 1 {
			t.Errorf("%s confidence %v", s.Product, s.Confidence)
		}
	}
	for _, want := range []string{"cpe:/a:openbsd:openssh:8.9p1", "cpe:/a:apache:http_server:2.4.52", "cpe:/o:linux:linux_kernel"} {
		if !slices.Contains(cpes, want) {
			t.Errorf("software has no %s (got %v)", want, cpes)
		}
	}
}

// A sweep records the MAC and vendor of the hosts that answered and counts the ones the inventory did not know.
func TestSweepRecordsHostsAndCountsNewDevices(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	e.inv.macs = []string{"aa:bb:cc:00:00:02"} // a new device is told by its MAC (L8): .2 is known
	res, err := e.svc.DiscoverRanges(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != sa.StatusDone || res.Targets != 62 || res.NewDevices != 1 {
		t.Fatalf("result = %+v, want 62 targets, 1 new device (.5; .2 is known)", res)
	}
	var macs []string
	for _, o := range e.sink.observations() {
		if o.Field == "mac" {
			macs = append(macs, o.Value)
		}
	}
	if !slices.Equal(macs, []string{"AA:BB:CC:00:00:02", "AA:BB:CC:00:00:05"}) {
		t.Fatalf("macs = %v", macs)
	}
	st, fin := e.ev.named(sa.EventScanStarted), e.ev.named(sa.EventScanFinished)
	if len(st) != 1 || len(fin) != 1 {
		t.Fatalf("events: %d started, %d finished", len(st), len(fin))
	}
	if fin[0].Data.(sa.FinishedEvent) != (sa.FinishedEvent{JobID: res.JobID, Targets: 62, NewDevices: 1, Status: "done"}) {
		t.Fatalf("finished = %+v", fin[0].Data)
	}
}

// INV-9: one probe row per nmap run with the argv as approved; kept 365 days, pruned after.
func TestContract_INV9_ProbeLog(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if _, err := e.svc.DiscoverRanges(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	calls := e.nm.calls(t)
	probes, err := e.svc.Probes(e.ctx(), e.base.Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != len(calls) || len(probes) != 2 {
		t.Fatalf("%d probe rows for %d runs", len(probes), len(calls))
	}
	for i, p := range probes {
		// the row keeps the flags as approved (shape and rate), the addresses are in Target
		if n := len(p.Argv); n > len(calls[i]) || !slices.Equal(p.Argv, calls[i][:n]) || p.Argv[n-2] != "-oX" {
			t.Errorf("row %d argv = %q, the process got %q", i, p.Argv, calls[i])
		}
		if p.Time == "" || p.Target == "" || !strings.HasPrefix(p.Result, "ok:") || p.JobID == "" {
			t.Errorf("row %d = %+v", i, p)
		}
	}
	if probes[1].Target != "192.168.10.20" || probes[0].Target != "192.168.10.1-192.168.10.62" {
		t.Errorf("targets = %q, %q", probes[0].Target, probes[1].Target)
	}
	// Retention: a row from 100 days ago stays (at least 90 days), one from 400 days ago goes.
	old := func(days int) {
		ts := store.FormatTS(e.clock().AddDate(0, 0, -days))
		if err := e.db.Write(e.ctx(), func(tx dbTx) error {
			_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES (?, ?, 'sweep', 10, 1, '--privileged -sn -n --max-rate 10', '10.0.0.1', 'ok')`, ts, probes[0].JobID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	old(100)
	old(400)
	n, err := e.svc.Prune(e.ctx())
	if err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1", n, err)
	}
	if got := e.count(`SELECT count(*) FROM sa_probe`); got != 3 {
		t.Fatalf("%d rows after pruning, want 3 (2 runs + the 100 day old one)", got)
	}
}

// The probe is logged before the process starts: a killed run still leaves its row.
func TestProbeRowExistsWhileTheRunIsInProgress(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{slowFrom: 1})
	done := make(chan struct{})
	ctx := e.ctx()
	go func() { defer close(done); _, _ = e.svc.DiscoverRanges(ctx) }()
	waitFor(t, "a probe row while nmap runs", func() bool { return e.count(`SELECT count(*) FROM sa_probe WHERE result = 'started'`) > 0 })
	e.inv.set(func(s *sa.Settings) { s.Enabled = false })
	_ = e.svc.SettingsChanged(ctx)
	<-done
	if got := e.count(`SELECT count(*) FROM sa_probe WHERE result LIKE 'stopped:%'`); got != 1 {
		t.Fatalf("the cut run's row was not closed: %d", got)
	}
}

// Events carry exactly the documented JSON.
func TestEventPayloads(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		v    any
		want string
	}{
		{sa.StartedEvent{JobID: "saj-1", Kind: "sweep", Targets: 14}, `{"job_id":"saj-1","kind":"sweep","targets":14}`},
		{sa.FinishedEvent{JobID: "saj-1", Targets: 14, NewDevices: 2, Status: "done"}, `{"job_id":"saj-1","targets":14,"new_devices":2,"status":"done"}`},
		{sa.BlockedEvent{AssetID: "a-1", Reason: "out_of_scope"}, `{"asset_id":"a-1","reason":"out_of_scope"}`},
	} {
		b, err := json.Marshal(c.v)
		if err != nil || string(b) != c.want {
			t.Errorf("%T = %s, %v; want %s", c.v, b, err, c.want)
		}
	}
	for _, n := range []string{sa.EventScanStarted, sa.EventScanFinished, sa.EventScanBlocked} {
		if !strings.HasPrefix(n, "sensor.scan.") {
			t.Errorf("event name %q", n)
		}
	}
}

// The queue survives a restart: a new Service on the same database drains it.
func TestQueueSurvivesARestart(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) { e.base = local(9, 12, 0) }) // outside the window: it only queues
	e.sweptBefore()                                                       // not a new box: no first pass (D-501)
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil { // twice: one row
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil || len(e.nm.calls(t)) != 0 {
		t.Fatalf("Tick outside the window: %v, %d runs", err, len(e.nm.calls(t)))
	}
	e.base, e.t0 = local(9, 2, 0), time.Now() // the window opens; a new process starts
	e.build()
	if n, _ := e.svc.QueueLen(e.ctx()); n != 1 {
		t.Fatalf("queue length after restart = %d, want 1", n)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, c := range e.nm.calls(t) {
		kinds = append(kinds, c[1])
	}
	if !slices.Equal(kinds, []string{"-sn", "-sS"}) { // the day's sweep, then the queued device
		t.Fatalf("runs = %v", kinds)
	}
	if n, _ := e.svc.QueueLen(e.ctx()); n != 0 {
		t.Fatalf("queue length after the scan = %d", n)
	}
	if got := e.str(`SELECT reason FROM sa_job WHERE kind = 'device'`); got != "discovered" {
		t.Fatalf("job reason = %q", got)
	}
}

// D-84 (6): one sweep per window; a new window day sweeps again; a stopped sweep is repeated when the window is open.
func TestTickSweepsOncePerWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	for range 3 {
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(e.nm.calls(t)); n != 1 {
		t.Fatalf("%d sweeps in one window, want 1", n)
	}
	e.base, e.t0 = local(10, 2, 0), time.Now() // next night
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.nm.calls(t)); n != 2 {
		t.Fatalf("%d sweeps after the next window opened, want 2", n)
	}
	// a stopped job does not count as "done for this window"
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE sa_job SET status = 'stopped'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.nm.calls(t)); n != 3 {
		t.Fatalf("%d sweeps after a stopped one, want 3", n)
	}
}

// A job a restart left "running" is closed by the next tick.
func TestTickClosesInterruptedJobs(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{}, func(e *env) { e.base = local(9, 12, 0) })
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO sa_job (id, kind, started_at, status) VALUES ('saj-old', 'sweep', ?, 'running')`, store.FormatTS(e.clock()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := e.str(`SELECT status || ': ' || error FROM sa_job WHERE id = 'saj-old'`); got != "stopped: interrupted by a restart" {
		t.Fatalf("job = %q", got)
	}
}

// A device whose scan failed is retried a few times, then dropped from the queue.
func TestQueueDropsADeviceAfterRepeatedFailures(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{exitCode: 1})
	e.inv.set(func(s *sa.Settings) { s.Enabled = true })
	if err := e.svc.Enqueue(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		// the sweep fails too (exit 1) and counts as done for the window; only the device is retried each tick
		if err := e.svc.Tick(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := e.svc.QueueLen(e.ctx()); n != 0 {
		t.Fatalf("queue length = %d, want the device dropped after 3 failures", n)
	}
}

func TestMigrationsUsePrefix(t *testing.T) {
	storetest.AssertMigrationsUsePrefix(t, "sensor-active", sa.Migrations, "sa_", storetest.Migration{Module: "core", FS: core.Migrations})
}

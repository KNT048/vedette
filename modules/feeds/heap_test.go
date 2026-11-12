package feeds

// Tests that read the process-wide heap. Each runs in a process of its own (inOwnProcess), so it runs beside the other
// tests; the file name puts it early in the package's order, so its processes start while the rest still run.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the test starts its own binary again for one test, fixed argv, no shell; SYS-1 is about the product
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ownProcessEnv names the one test a child process of the test binary runs (inOwnProcess).
const ownProcessEnv = "VEDETTE_FEEDS_OWN_PROCESS"

// inOwnProcess lets a test that reads the process-wide heap (peakHeap) run in parallel with the others: in the test binary it
// starts the binary again for this test (or subtest) alone, waits and reports the child's result, and returns false (the caller returns); in
// that child it returns true and the caller runs its body, with no other test allocating beside it. Before this the two heap tests
// were serial, and every parallel test of the package waited ~15 s for them under -race.
func inOwnProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv(ownProcessEnv) == t.Name() {
		return true
	}
	t.Parallel()
	parts := strings.Split(t.Name(), "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+strings.Join(parts, "/"), "-test.v", "-test.count=1", "-test.timeout=5m") //nolint:gosec // re-runs this test binary
	cmd.Env = append(os.Environ(), ownProcessEnv+"="+t.Name())
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("%s in its own process: %v\n%s", t.Name(), err, out)
	}
	t.Logf("%s", out)
	return false
}

// peakHeap runs fn and returns the peak HeapInuse above the starting baseline,
// sampled every millisecond (tolerant: a coarse upper bound, not exact).
func peakHeap(fn func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	fn()
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	if end.HeapInuse > peak.Load() {
		peak.Store(end.HeapInuse)
	}
	close(stop)
	<-done
	if p := peak.Load(); p > base.HeapInuse {
		return p - base.HeapInuse
	}
	return 0
}

// ---------- 3. memory amplification

func TestRegress_MemoryAmplificationIsBounded(t *testing.T) {
	t.Parallel()
	// Each case runs in a process of its own (inOwnProcess), so no other test's or case's memory counts. A tight GC target makes
	// HeapInuse follow live memory instead of garbage waiting to be collected. The input of a case is built in its own process:
	// building all 14 (~5 MB each) up front kept ~70 MB live, and with GCPercent 20 that let ~15 MB of uncollected garbage count as
	// "peak", which made the STIX case flake at the budget on CI.
	big := MaxBodyBytes
	build := func(prefix, unit, suffix string, n int) string {
		return prefix + strings.Repeat(unit, n) + suffix
	}
	attrs := func(unit string) string {
		var b strings.Builder
		b.WriteString("<rss><item ")
		for i := 0; b.Len() < big-40; i++ {
			fmt.Fprintf(&b, unit, i)
		}
		b.WriteString("/></rss>")
		return b.String()
	}
	cases := []struct {
		name   string
		format Format
		in     func() string
	}{
		{"json objects", FormatJSON, func() string { return build("[", "{},", "{}]", big/3-2) }},
		{"json zeros", FormatJSON, func() string { return build("[", "0,", "0]", big/2-2) }},
		{"json empty arrays", FormatJSON, func() string { return build("[", "[],", "[]]", big/3-2) }},
		{"json empty keys", FormatJSON, func() string { return build("{", `"":0,`, `"":0}`, big/5-2) }},
		{"csv commas header", FormatCSV, func() string { return strings.Repeat(",", big) }},
		{"csv commas data", FormatCSV, func() string { return "dst_ip\n" + strings.Repeat(",", big-10) }},
		{"csv comma rows", FormatCSV, func() string { return "dst_ip\n" + strings.Repeat(",\n", big/2-8) }},
		{"xml attrs", FormatRSS, func() string { return attrs("a%x='' ") }},
		{"xml xmlns", FormatRSS, func() string { return attrs("xmlns:n%x='u' ") }},
		{"xml text split by comments", FormatRSS, func() string { return build("<rss>", "a<!---->", "</rss>", big/8-2) }},
		{"xml text split by PIs", FormatRSS, func() string { return build("<rss>", "a<?p?>", "</rss>", big/6-2) }},
		{"xml items", FormatRSS, func() string { return build("<r>", "<item/>", "</r>", big/7-2) }},
		{"stix indicators", FormatSTIX, func() string {
			return `{"objects":[` + strings.Repeat(`{"type":"indicator","pattern":"[ipv4-addr:value = '8.8.8.8']"},`, big/70) + `{}]}`
		}},
		{"lines tiny", FormatLines, func() string { return strings.Repeat("a\n", big/2) }},
	}
	const limit = 80 << 20 // ~64 MB target; race-instrumented heaps run a little larger
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !inOwnProcess(t) {
				return
			}
			old := debug.SetGCPercent(20)
			defer debug.SetGCPercent(old)
			in := fit(c.in()) // built in this process: no other input is live while the parser runs
			var err error
			peak := peakHeap(func() { _, err = ParseFeed(context.Background(), in, KindIOC, DefaultParser(KindIOC, c.format)) })
			if err != nil && !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrBadConfig) {
				t.Errorf("%s: unexpected error %v", c.name, err)
			}
			t.Logf("%s: peak heap %d MB", c.name, peak>>20)
			if peak > limit {
				t.Errorf("%s: peak heap %d MB over the %d MB budget", c.name, peak>>20, limit>>20)
			}
		})
	}
}

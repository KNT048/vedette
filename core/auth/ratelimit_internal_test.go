package auth

import (
	"fmt"
	"math"
	"os"
	"os/exec" //nolint:depguard // the test starts its own binary again with an env var; no external program (SYS-1 is about the product)
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"
)

type fakeNow struct{ t time.Time }

func (f *fakeNow) now() time.Time { return f.t }

func TestLimiter(t *testing.T) {
	t.Parallel()
	c := &fakeNow{t: time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)}
	l := newLimiter(c.now)
	retry := func(ip, email string) int {
		e := l.check(ip, email)
		if e == nil {
			return 0
		}
		if e.Status != 429 || e.Code != "rate_limited" {
			t.Fatalf("error = %+v", e)
		}
		return e.Extra["retry_after"].(int)
	}
	for i := range 9 {
		l.fail("1.1.1.1", "a@x.example")
		if r := retry("1.1.1.1", "a@x.example"); r != 0 {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	l.fail("1.1.1.1", "a@x.example") // the tenth
	if r := retry("1.1.1.1", "a@x.example"); r != 30 {
		t.Fatalf("retry after the 10th failure = %d, want 30", r)
	}
	// Other pairs are untouched; the email is case-insensitive.
	if retry("2.2.2.2", "a@x.example") != 0 || retry("1.1.1.1", "b@x.example") != 0 {
		t.Fatal("limit leaked to another pair")
	}
	if retry("1.1.1.1", "A@X.example") == 0 {
		t.Fatal("email case changed the key")
	}
	c.t = c.t.Add(31 * time.Second)
	if retry("1.1.1.1", "a@x.example") != 0 {
		t.Fatal("still blocked after the wait")
	}
	// The wait doubles with every further failure: 60 s, 120 s, ... capped at 10 minutes.
	for _, want := range []int{60, 120, 240, 480, 600, 600, 600} {
		l.fail("1.1.1.1", "a@x.example")
		if got := retry("1.1.1.1", "a@x.example"); got != want {
			t.Fatalf("retry = %d, want %d", got, want)
		}
		c.t = c.t.Add(time.Duration(want)*time.Second + time.Second)
	}
	// A quiet 15 minutes later the count starts over.
	c.t = c.t.Add(loginWindow + time.Second)
	l.fail("1.1.1.1", "a@x.example")
	if retry("1.1.1.1", "a@x.example") != 0 {
		t.Fatal("old failures still counted")
	}
	// Success forgets everything.
	for range 10 {
		l.fail("3.3.3.3", "c@x.example")
	}
	l.reset("3.3.3.3", "c@x.example")
	if retry("3.3.3.3", "c@x.example") != 0 {
		t.Fatal("reset did not clear")
	}
}

func TestLimiterIsBounded(t *testing.T) {
	t.Parallel()
	c := &fakeNow{t: time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)}
	l := newLimiter(c.now)
	for i := range limiterMaxKeys + 500 {
		l.fail("1.1.1.1", "user"+string(rune('a'+i%26))+time.Duration(i).String()+"@x.example")
	}
	if len(l.m) > limiterMaxKeys {
		t.Fatalf("limiter holds %d keys, cap %d", len(l.m), limiterMaxKeys)
	}
	// An overlong email does not make an overlong key.
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	if k := limiterKey("1.1.1.1", string(long)); len(k) > 400 {
		t.Fatalf("key is %d bytes", len(k))
	}
}

// A flood of junk keys must not reset a guess limit that is in progress.
func TestFloodingTheClientMapKeepsAccountCountersAndRealAttacks(t *testing.T) {
	t.Parallel()
	c := &fakeNow{t: time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)}
	l := newLimiter(c.now)
	for range loginMaxFailures {
		l.fail(twofaKey, "ann@x.example")
	}
	for range loginMaxFailures - 1 {
		l.fail("5.5.5.5", "victim@x.example") // an attack in progress: nine failures, not yet blocked
	}
	for i := range 3 * limiterMaxKeys {
		l.fail(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "junk@x.example")
	}
	if l.check(twofaKey, "ann@x.example") == nil {
		t.Fatal("flooding the limiter reset the per-account two-step counter")
	}
	if _, ok := l.m[limiterKey(twofaKey, "ann@x.example")]; ok {
		t.Fatal("an account counter sits in the evictable client map")
	}
	l.fail("5.5.5.5", "victim@x.example") // the tenth
	if l.check("5.5.5.5", "victim@x.example") == nil {
		t.Fatal("flooding evicted the entry with the most failures before the one-failure junk")
	}
	if len(l.m) > limiterMaxKeys {
		t.Fatalf("client map holds %d keys", len(l.m))
	}
}

func TestRefundDropsEntriesBackAtZero(t *testing.T) {
	t.Parallel()
	c := &fakeNow{t: time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)}
	l := newLimiter(c.now)
	for i := range 1000 {
		a, e := l.begin(fmt.Sprintf("10.0.%d.%d", i>>8, i&255), "junk@x.example")
		if e != nil {
			t.Fatal(e)
		}
		a.refund()
	}
	if len(l.m) != 0 {
		t.Fatalf("%d entries left after every attempt was given back", len(l.m))
	}
}

func TestMaxHashingFor(t *testing.T) {
	t.Parallel()
	const kib = 64 * 1024
	for _, tc := range []struct {
		name  string
		procs int
		mem   int64
		want  int
	}{
		{"32 cores, no memory limit", 32, math.MaxInt64, 16},
		{"32 cores, 2 GiB limit: a quarter of it is 8 runs of 64 MiB", 32, 2 << 30, 8},
		{"2 cores, 2 GiB (the core container)", 2, 2 << 30, 1},
		{"8 cores, 2 GiB", 8, 2 << 30, 4},
		{"1 core", 1, math.MaxInt64, 1},
		{"tiny memory limit still lets one run", 16, 64 << 20, 1},
	} {
		if got := maxHashingFor(tc.procs, tc.mem, kib); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The core Quadlet unit sets Environment=GOMEMLIMIT=<n>MiB (D-150). The test binary is run again with exactly that variable, so the Go runtime reads
// it the way it does in the container; the helper reports the gate defaultMaxHashing computes: min(GOMAXPROCS/2, n MiB/4/64 MiB), at least 1.
// n comes from the golden core unit (the rendered template), not from a second literal here.
func TestDefaultMaxHashingUnderTheCoreUnitMemoryLimit(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "..", "host", "ops", "testdata", "units", "core.container"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^Environment=GOMEMLIMIT=(\d+)MiB$`).FindSubmatch(golden)
	if m == nil {
		t.Fatal("the core unit has no Environment=GOMEMLIMIT=<n>MiB")
	}
	mib, _ := strconv.Atoi(string(m[1]))
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestGateHelperProcess$") //nolint:gosec // re-runs this test binary
	cmd.Env = append(os.Environ(), "VEDETTE_GATE_HELPER=1", "GOMEMLIMIT="+string(m[1])+"MiB")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	var procs, limit, gate int64
	if _, err := fmt.Sscanf(string(regexp.MustCompile(`(?m)^gate .*$`).Find(out)), "gate procs=%d limit=%d gate=%d", &procs, &limit, &gate); err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	if limit != int64(mib)<<20 {
		t.Errorf("the runtime memory limit is %d with GOMEMLIMIT=%dMiB: the env var did not reach it", limit, mib)
	}
	memSide := int64(mib) / 4 / 64
	if want := max(1, min(procs/2, memSide)); gate != want || gate < 1 || gate > memSide {
		t.Errorf("gate = %d with GOMAXPROCS=%d and GOMEMLIMIT=%dMiB, want %d (1..%d)", gate, procs, mib, want, memSide)
	}
}

// TestGateHelperProcess is the child of the test above; it does nothing in a normal run.
func TestGateHelperProcess(t *testing.T) {
	if os.Getenv("VEDETTE_GATE_HELPER") != "1" {
		t.Skip("helper of TestDefaultMaxHashingUnderTheCoreUnitMemoryLimit")
	}
	fmt.Printf("gate procs=%d limit=%d gate=%d\n", runtime.GOMAXPROCS(0), debug.SetMemoryLimit(-1), defaultMaxHashing(DefaultParams))
}

package sensoractive_test

import (
	"context"
	"os"
	"slices"
	"sync"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// fakeProber records what probe() hands it and answers with a fixture.
type fakeProber struct {
	mu       sync.Mutex
	argv     [][]string
	hasDL    []bool
	probeRow []int // rows of sa_probe with result 'started' when it was called (INV-9: written before the run)
	count    func() int
	xml      []byte
}

func (f *fakeProber) Probe(ctx context.Context, argv []string) (sa.Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := ctx.Deadline()
	f.argv, f.hasDL = append(f.argv, slices.Clone(argv)), append(f.hasDL, ok)
	f.probeRow = append(f.probeRow, f.count())
	return sa.Output{XML: f.xml}, nil
}

// probe() calls the Prober with the argv nmapargv builds, under a deadline, after the probe row exists, and
// never starts a process of its own (the fake nmap at NmapPath must not run).
func TestProbeGoesThroughProber(t *testing.T) {
	t.Parallel()
	xml, err := os.ReadFile("testdata/device.xml")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, fakeOpts{})
	fp := &fakeProber{xml: xml, count: func() int { return e.count(`SELECT COUNT(*) FROM sa_probe WHERE result = 'started'`) }}
	e.inv.decision["a-web"] = sa.Decision{Allowed: true, Rate: 100, Reason: "ok"}
	svc, err := sa.New(sa.Config{DB: e.db, Inventory: e.inv, Observe: e.sink, Software: e.sink, Events: e.ev, NmapPath: e.nm.path, Prober: fp, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	want := []string{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", "100", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}
	if len(fp.argv) != 1 || !slices.Equal(fp.argv[0], want) {
		t.Fatalf("Prober got %q, want one call with %q", fp.argv, want)
	}
	if n := len(e.nm.calls(t)); n != 0 {
		t.Errorf("the module started nmap %d times itself", n)
	}
	if !fp.hasDL[0] {
		t.Error("the Prober's context has no deadline")
	}
	if fp.probeRow[0] != 1 {
		t.Errorf("%d probe rows were started when the Prober ran, want 1 (INV-9)", fp.probeRow[0])
	}
	if got := e.count(`SELECT COUNT(*) FROM sa_probe WHERE result LIKE 'ok:%'`); got != 1 {
		t.Errorf("%d finished probe rows, want 1", got)
	}
}

package sensoractive_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// #882: a change of one device stops only the batch that still sends to it, and the round reads that batch again instead of
// starting over from its first batch on the next Tick. The bus is synchronous: the fake worker calls AssetChanged itself, as the
// inventory's publish would while the job is with the worker.

// roundOf runs one Tick of a round over newBigWorld (batches .10-.73 and .74-.79), every device set up with one community; answer
// gets the call number (1-based) and the job, and answers like the worker.
func roundOf(t *testing.T, answer func(ctx context.Context, n int, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error)) (*sa.Service, *fakeInv, *fakeReader) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	r := &fakeReader{}
	r.answer = func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		return answer(ctx, k, j)
	}
	svc, inv := newBigWorld(t, r, 2, 0)
	setUpAll(t, svc, inv)
	return svc, inv, r
}

func rangeIPs(from, to int, skip ...int) []string {
	var out []string
	for i := from; i <= to; i++ {
		if !slices.Contains(skip, i) {
			out = append(out, fmt.Sprintf("192.168.10.%d", i))
		}
	}
	return out
}

// moveTo moves a device to ip in the fake inventory (the old address is free).
func (f *fakeInv) moveTo(id, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.addrs, f.assets[id])
	a := netip.MustParseAddr(ip)
	f.assets[id], f.addrs[a] = a, id
}

// answerOrStop answers like the worker unless the batch was stopped while it held the job.
func answerOrStop(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return juniperAnswers(j), nil
}

// A device the batch's recheck dropped (it moved after the round listed it) changes again while the batch is with the worker: the
// batch does not carry it, so it is not stopped. A device of no batch changing does not stop it either.
func TestSNMPAChangeOfADeviceTheBatchNoLongerHoldsDoesNotStopIt(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	var inv *fakeInv
	stopped := false
	svc, inv, r := roundOf(t, func(ctx context.Context, n int, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		if n == 1 {
			inv.moveTo("a-15", "192.168.10.201") // moved again: the inventory publishes asset.updated
			for _, id := range []string{"a-15", "a-unrelated"} {
				if err := svc.AssetChanged(ctx, id); err != nil {
					t.Error(err)
				}
			}
			stopped = ctx.Err() != nil
		}
		return answerOrStop(ctx, j)
	})
	first := true
	sa.SetBeforeSNMPBatch(svc, func() {
		if first { // after the round listed its devices, before the batch's recheck: a-15 moved away from .15
			first = false
			inv.moveTo("a-15", "192.168.10.200")
		}
	})
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stopped {
		t.Fatal("a change of a device the batch had dropped stopped the batch")
	}
	jobs := r.sent()
	if len(jobs) != 2 || !slices.Equal(ipsOf(jobs[0]), rangeIPs(10, 73, 15)) || !slices.Equal(ipsOf(jobs[1]), rangeIPs(74, 79)) {
		t.Fatalf("%d jobs: %v", len(jobs), jobs)
	}
	for _, j := range jobs {
		if slices.ContainsFunc(ipsOf(j), func(ip string) bool { return ip == "192.168.10.200" || ip == "192.168.10.201" }) {
			t.Fatalf("the moved device's new address was read: %v", ipsOf(j))
		}
	}
}

// A device of batch 2 moves while batch 2 is with the worker: the batch stops (nothing is recorded from it), and the
// round reads batch 2 again without that device, not batch 1 again. The round is then done, and the next Tick sends nothing.
func TestSNMPAMoveOfAHeldDeviceStopsTheBatchAndTheRoundReadsItAgain(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	var inv *fakeInv
	stopped := false
	svc, inv, r := roundOf(t, func(ctx context.Context, n int, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		if n == 2 {
			inv.moveTo("a-75", "192.168.10.200")
			if err := svc.AssetChanged(ctx, "a-75"); err != nil {
				t.Error(err)
			}
			stopped = ctx.Err() != nil
		}
		return answerOrStop(ctx, j)
	})
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("the move of a device the batch held did not stop it")
	}
	jobs := r.sent()
	if len(jobs) != 3 {
		t.Fatalf("%d jobs, want batch 1, batch 2 (stopped), batch 2 again", len(jobs))
	}
	if !slices.Equal(ipsOf(jobs[0]), rangeIPs(10, 73)) || !slices.Equal(ipsOf(jobs[1]), rangeIPs(74, 79)) || !slices.Equal(ipsOf(jobs[2]), rangeIPs(74, 79, 75)) {
		t.Fatalf("jobs read %v, %v, %v", ipsOf(jobs[0]), ipsOf(jobs[1]), ipsOf(jobs[2]))
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(r.sent()) != 3 {
		t.Fatalf("the next Tick read again: %d jobs", len(r.sent()))
	}
}

// A device that changes (a field, no move) while each of two tries of its batch is with the worker is read again once, then left
// out: the round ends however often a device changes.
func TestSNMPADeviceThatKeepsChangingIsLeftOutAndTheRoundEnds(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	svc, _, r := roundOf(t, func(ctx context.Context, n int, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		if n == 2 || n == 3 {
			if err := svc.AssetChanged(ctx, "a-76"); err != nil {
				t.Error(err)
			}
		}
		return answerOrStop(ctx, j)
	})
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs := r.sent()
	if len(jobs) != 4 {
		t.Fatalf("%d jobs, want batch 1, batch 2 twice stopped, batch 2 without .76", len(jobs))
	}
	if !slices.Equal(ipsOf(jobs[2]), rangeIPs(74, 79)) || !slices.Equal(ipsOf(jobs[3]), rangeIPs(74, 79, 76)) {
		t.Fatalf("tries read %v, then %v", ipsOf(jobs[2]), ipsOf(jobs[3]))
	}
}

// Review #881 r2 L2: a device run is two scans (the top 1000 ports, then the extra ports); the targets are cleared between them.
// A device that left the address in between (the inventory moved it while the first scan ran; its event then found no targets to
// compare) gets no second scan at the old address, and the first scan is not recorded either: it is recorded by address, and
// another device, or none, is there now. The run is stopped, not failed.
func TestADeviceThatMovedBetweenTheTwoScansGetsNoSecond(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	xml := fixtureXML(t, "device.xml")
	var mu sync.Mutex
	var calls [][]string
	e.withProber(probeFunc(func(_ context.Context, argv []string) (sa.Output, error) {
		mu.Lock()
		calls = append(calls, argv)
		first := len(calls) == 1
		mu.Unlock()
		if first {
			e.inv.moveTo("a-web", "192.168.10.40")
		}
		return sa.Output{XML: xml}, nil
	}))
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); !errors.Is(err, sa.ErrStopped) {
		t.Fatalf("ScanDevice: %v, want stopped", err)
	}
	if obs := e.sink.observations(); len(obs) != 0 {
		t.Fatalf("the first scan was recorded: %v", obs)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("%d nmap runs, want the first scan only: %v", len(calls), calls)
	}
	if got := targetsOf(calls[0]); !slices.Equal(got, []string{"192.168.10.20"}) {
		t.Fatalf("the first scan probed %v", got)
	}
}

// A device that moves while the second scan starts (after its address was read again) stops it through AssetChanged: the targets
// are set again by then.
func TestADeviceThatMovesAsTheSecondScanStartsStopsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	xml := fixtureXML(t, "device.xml")
	h := &eachAssetInv{fakeInv: e.inv}
	var svc *sa.Service
	var mu sync.Mutex
	var calls int
	var ctxErr error
	reads := 0
	h.onAsset = func(id string) {
		if id != "a-web" {
			return
		}
		if reads++; reads == 3 { // 1: the run's own read, 2: the first scan's, 3: the second scan's
			e.inv.moveTo("a-web", "192.168.10.40")
			if err := svc.AssetChanged(e.ctx(), "a-web"); err != nil {
				t.Error(err)
			}
		}
	}
	var err error
	svc, err = e.newService(sa.Config{DB: e.db, Inventory: h, Observe: e.sink, Software: e.sink, Services: e.sink, Events: e.ev, NmapPath: e.nm.path,
		Prober: probeFunc(func(ctx context.Context, _ []string) (sa.Output, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			ctxErr = ctx.Err()
			return sa.Output{XML: xml}, nil
		}), Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || ctxErr != nil {
		t.Fatalf("%d nmap runs (the last with ctx %v), want the first scan only", calls, ctxErr)
	}
}

// eachAssetInv runs onAsset after every Asset read (the read returns what it read before the hook).
type eachAssetInv struct {
	*fakeInv
	onAsset func(id string)
}

func (h *eachAssetInv) Asset(ctx context.Context, id string) (sa.Asset, error) {
	a, err := h.fakeInv.Asset(ctx, id)
	h.onAsset(id)
	return a, err
}

// Review r1 L1: a batch whose devices keep changing (another one each try) is read at most 4 times, then left for the next window,
// and the round goes on with the next batch.
func TestSNMPABatchWhoseDevicesKeepChangingIsTriedFourTimes(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	svc, _, r := roundOf(t, func(ctx context.Context, n int, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		if n <= 4 {
			if err := svc.AssetChanged(ctx, fmt.Sprintf("a-%d", 10+n)); err != nil {
				t.Error(err)
			}
		}
		return answerOrStop(ctx, j)
	})
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs := r.sent()
	if len(jobs) != 5 || !slices.Equal(ipsOf(jobs[3]), rangeIPs(10, 73)) || !slices.Equal(ipsOf(jobs[4]), rangeIPs(74, 79)) {
		t.Fatalf("%d jobs, want batch 1 four times then batch 2", len(jobs))
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(r.sent()) != 5 {
		t.Fatalf("the next Tick read again: %d jobs", len(r.sent()))
	}
}

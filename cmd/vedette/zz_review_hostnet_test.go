package main

// Independent security review of slice 3-3 (feat/host-net-read): core's use of host-api state/net.
// Each test fails while the defect it names is present.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// FINDING (Low): sensorInventory.ProtectedIPs asks vedette-host on every sweep with no memory of the last
// answer, so one failed state/net call (host restarting, socket busy) drops the appliance's LAN address
// from the protected list and the sweep may probe the box itself (M2). boxSources keeps the last answer
// for exactly this reason ("a host that does not answer right now is still the same box"); the sweep's
// list does not, so the two consumers of the same source disagree.
func TestReviewProtectedIPsKeepTheBoxWhenTheHostBlinks(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	f := lanBox()
	inv := sensorInventory{inv: s.d.Inventory, hostNet: hostNetSource(f)}
	first, err := inv.ProtectedIPs(t.Context())
	if err != nil || !slices.Contains(first, netip.MustParseAddr("192.168.10.250")) {
		t.Fatalf("baseline: %v %v", first, err)
	}
	f.err = errors.New("host restarting")
	second, err := inv.ProtectedIPs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(second, netip.MustParseAddr("192.168.10.250")) {
		t.Fatalf("one failed state/net call removed the box's LAN address from the sweep's protected list: %v", second)
	}
}

// slowFailNet answers once, then fails slowly (a hung or overloaded host): every call takes delay.
type slowFailNet struct {
	mu    sync.Mutex
	calls int
	delay time.Duration
}

func (f *slowFailNet) StateNet(ctx context.Context) (api.NetState, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if n == 1 {
		return lanBox().st, nil
	}
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
	}
	return api.NetState{}, errors.New("timeout")
}

// FINDING (Low): after the 30 s TTL, a failing host is asked again on EVERY BoxAddrs call, while b.mu is
// held for the whole socket call (client timeout 60 s). With a hung host, concurrent connection saves and
// dial-time checks queue behind each other, each waiting for its own failed call. A failed refresh should
// also be remembered for a while (negative cache / backoff) and the socket call should not run under the lock.
func TestReviewBoxAddrsDoesNotQueueOnAFailingHost(t *testing.T) {
	t.Parallel()
	f := &slowFailNet{delay: 150 * time.Millisecond}
	var mu sync.Mutex
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	b := &boxSources{hostNet: hostNetSource(f), now: clock}
	if got := b.BoxAddrs(t.Context()); !contains(got, "192.168.10.250") {
		t.Fatalf("baseline %v", got)
	}
	mu.Lock()
	now = now.Add(hostNetTTL + time.Second)
	mu.Unlock()
	start := time.Now()
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if got := b.BoxAddrs(t.Context()); !contains(got, "192.168.10.250") {
				t.Errorf("last answer lost: %v", got)
			}
		})
	}
	wg.Wait()
	took := time.Since(start)
	f.mu.Lock()
	calls := f.calls - 1
	f.mu.Unlock()
	if calls > 1 || took > 3*f.delay {
		t.Fatalf("6 concurrent BoxAddrs calls against a failing host made %d host calls and took %v (one call takes %v): they queue on b.mu", calls, took, f.delay)
	}
}

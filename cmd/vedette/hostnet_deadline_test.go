package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A lookup the caller starts ends at that caller's deadline, not after hostNetTimeout (15 s); the last good set is served and the
// host is not put in the failure backoff for a deadline that was the caller's own.
func TestHostNetCacheLookupHonoursTheCallersDeadline(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	var hang atomic.Bool
	var calls atomic.Int32
	want := netip.MustParsePrefix("192.168.10.250/32")
	c := newHostNetCache(func(ctx context.Context) ([]netip.Prefix, error) {
		calls.Add(1)
		if hang.Load() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []netip.Prefix{want}, nil
	}, clock)
	if got := c.Get(t.Context()); len(got) != 1 {
		t.Fatalf("first: %v", got)
	}
	mu.Lock()
	now = now.Add(hostNetTTL + time.Second)
	mu.Unlock()
	hang.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := c.Get(ctx)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the lookup outlived the caller's deadline by far: %v", took)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("the previous set was not kept: %v", got)
	}
	hang.Store(false)
	before := calls.Load()
	if c.Get(t.Context()); calls.Load() != before+1 {
		t.Fatalf("a deadline of the caller's own put the host in the failure backoff (%d calls)", calls.Load()-before)
	}
}

// Snapshot is what a webhook delivery or save reads: it never waits for the host, serves the last set, and refreshes in the background.
func TestHostNetCacheSnapshotNeverWaits(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	release := make(chan struct{})
	hung := make(chan struct{})
	var calls atomic.Int32
	var hangs atomic.Bool // the fake host turns unresponsive; set through the closure, never by reassigning c.fetch (a refresh may be reading it)
	want := netip.MustParsePrefix("192.168.10.250/32")
	c := newHostNetCache(func(ctx context.Context) ([]netip.Prefix, error) {
		if hangs.Load() {
			<-hung
			return nil, context.Canceled
		}
		calls.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []netip.Prefix{want}, nil
	}, clock)
	start := time.Now()
	if got := c.Snapshot(); got != nil || time.Since(start) > time.Second {
		t.Fatalf("cold Snapshot = %v after %v: it must return at once with nothing", got, time.Since(start))
	}
	c.Snapshot() // a second one while the first refresh is in flight starts no other lookup
	close(release)
	c.Get(t.Context()) // nothing is known yet, so this waits for the refresh Snapshot started
	if got := c.Snapshot(); len(got) != 1 || got[0] != want {
		t.Fatalf("the background refresh never filled the cache: %v", got)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d lookups for two Snapshots and a read", n)
	}
	// Stale again and the host hangs: still instant, still the old set.
	mu.Lock()
	now = now.Add(hostNetTTL + time.Second)
	mu.Unlock()
	hangs.Store(true)
	start = time.Now()
	if got := c.Snapshot(); len(got) != 1 || time.Since(start) > time.Second {
		t.Fatalf("stale Snapshot = %v after %v", got, time.Since(start))
	}
	close(hung)
}

// notify's BoxAddrs is the Snapshot: a webhook connection or save never waits for vedette-host.
func TestNotifyBoxAddrsNeverWaitsForTheHost(t *testing.T) {
	t.Parallel()
	hung := make(chan struct{})
	c := newHostNetCache(func(ctx context.Context) ([]netip.Prefix, error) {
		select {
		case <-hung:
		case <-ctx.Done():
		}
		return nil, context.Canceled
	}, nil)
	defer close(hung)
	start := time.Now()
	if got, known := notifyBoxAddrs(c)(); len(got) != 0 || known || time.Since(start) > time.Second {
		t.Fatalf("BoxAddrs = %v known %v after %v with a host that has never answered", got, known, time.Since(start))
	}
}

// #157: the set is unknown only while a configured host has never answered; no host is known (container interfaces
// only), and a Box network change (Invalidate) leaves it known: stale is not unknown.
func TestNotifyBoxAddrsKnownOnlyAfterTheHostAnswered(t *testing.T) {
	t.Parallel()
	if _, known := notifyBoxAddrs(nil)(); !known {
		t.Fatal("no host configured must be known")
	}
	box := netip.MustParsePrefix("192.168.1.5/24")
	var answer atomic.Bool
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	later := func() { mu.Lock(); now = now.Add(hostNetBackoff + hostNetTTL); mu.Unlock() } // past the failure backoff and the TTL
	c := newHostNetCache(func(context.Context) ([]netip.Prefix, error) {
		if !answer.Load() {
			return nil, errors.New("host down")
		}
		return []netip.Prefix{box}, nil
	}, clock)
	_ = c.Get(t.Context()) // the host fails
	if _, known := notifyBoxAddrs(c)(); known {
		t.Fatal("a host that has never answered must be unknown")
	}
	answer.Store(true)
	later()
	_ = c.Get(t.Context())
	if got, known := notifyBoxAddrs(c)(); !known || len(got) != 1 || got[0] != box.Addr() {
		t.Fatalf("after the first answer: %v known %v", got, known)
	}
	answer.Store(false)
	c.Invalidate()
	later()
	_ = c.Get(t.Context())
	if got, known := notifyBoxAddrs(c)(); !known || len(got) != 1 {
		t.Fatalf("after Invalidate and a failed refresh the last set stays known: %v known %v", got, known)
	}
}

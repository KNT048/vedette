package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
)

// fakeNet is vedette-host's state/net as core sees it.
type fakeNet struct {
	st    api.NetState
	err   error
	calls int
}

func (f *fakeNet) StateNet(context.Context) (api.NetState, error) {
	f.calls++
	return f.st, f.err
}

func lanBox() *fakeNet {
	return &fakeNet{st: api.NetState{
		Interfaces: []api.NetInterface{
			{Name: "eth0", Role: api.NetRoleManagement, Addresses: []string{"192.168.10.250/24", "fe80::1/64", "fd00:1::5/64"}},
			{Name: "eth1", Role: api.NetRoleSPAN, Addresses: []string{}},
		},
		Decoys: []api.NetDecoy{{IP: "192.168.10.201", MAC: "02:00:00:00:00:01"}},
	}}
}

func TestHostNetSourceGivesSingleAddressPrefixes(t *testing.T) {
	t.Parallel()
	got, err := hostNetSource(lanBox(), nil)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.168.10.250", "fe80::1", "fd00:1::5", "192.168.10.201"} {
		if !contains(got, a) {
			t.Errorf("%s is not reported as the box", a)
		}
	}
	for _, p := range got {
		if p.Bits() != p.Addr().BitLen() {
			t.Errorf("%s is a subnet: the whole LAN would be refused as the box", p)
		}
	}
	if contains(got, "192.168.10.7") {
		t.Error("a neighbour on the LAN counts as the box")
	}
}

func TestHostNetSourceIsNilSafeAndPassesErrors(t *testing.T) {
	t.Parallel()
	if hostNetSource(nil, nil) != nil || hostSocketNet("", nil) != nil {
		t.Fatal("a missing host must give a nil source")
	}
	// A socket path with no host behind it: a source that fails, never one that panics or hangs.
	src := hostSocketNet(filepath.Join(t.TempDir(), "absent.sock"), nil)
	if src == nil {
		t.Fatal("a configured socket must give a source")
	}
	if _, err := src(t.Context()); !errors.Is(err, hostclient.ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
	bad := &fakeNet{err: errors.New("unreachable")}
	if _, err := hostNetSource(bad, nil)(t.Context()); err == nil {
		t.Fatal("an unreachable host was reported as an empty box")
	}
	// A reply with odd text is skipped, not fatal.
	odd := &fakeNet{st: api.NetState{Interfaces: []api.NetInterface{{Addresses: []string{"nonsense", "10.0.0.9/24"}}}, Decoys: []api.NetDecoy{{IP: "x"}}}}
	if got, err := hostNetSource(odd, nil)(t.Context()); err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if hostIPv4s(t.Context(), nil) != nil || newHostNetCache(nil, nil) != nil {
		t.Fatal("no source, some addresses")
	}
	if hostIPv4s(t.Context(), newHostNetCache(hostNetSource(bad, nil), nil)) != nil {
		t.Fatal("a failing host gave addresses")
	}
	if got := hostIPv4s(t.Context(), newHostNetCache(hostNetSource(lanBox(), nil), nil)); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.10.250"), netip.MustParseAddr("192.168.10.201")}) {
		t.Fatalf("%v", got)
	}
}

// INV-23: boxSources over a fake StateNet includes the host's addresses, is nil-safe with no host, and asks the socket once per 30 seconds.
func TestBoxSourcesUseTheHostsAddresses(t *testing.T) {
	t.Parallel()
	f := lanBox()
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	b := &boxSources{hostNet: hostNetSource(f, nil), now: func() time.Time { return now }}
	got := b.BoxAddrs(t.Context())
	for _, a := range []string{"192.168.10.250", "fd00:1::5", "192.168.10.201"} {
		if !contains(got, a) {
			t.Errorf("%s is not refused as the box", a)
		}
	}
	b.BoxAddrs(t.Context())
	now = now.Add(29 * time.Second)
	b.BoxAddrs(t.Context())
	if f.calls != 1 {
		t.Fatalf("the host was asked %d times inside 30 seconds", f.calls)
	}
	now = now.Add(2 * time.Second)
	f.err = errors.New("down")
	if got := b.BoxAddrs(t.Context()); f.calls != 2 || !contains(got, "192.168.10.250") {
		t.Fatalf("after expiry with a dead host: %d calls, %v", f.calls, got)
	}
	// No host: nothing from it, no panic.
	if got := (&boxSources{hostNet: hostNetSource(nil, nil)}).BoxAddrs(t.Context()); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// The sweep must not probe the LAN address of the appliance, which only vedette-host can report.
func TestSensorProtectedIPsIncludeTheHostsAddresses(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	prot, err := sensorInventory{inv: s.d.Inventory, hostNet: newHostNetCache(hostNetSource(lanBox(), nil), nil)}.ProtectedIPs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.168.10.250", "192.168.10.201"} {
		if !slices.Contains(prot, netip.MustParseAddr(a)) {
			t.Errorf("%s is not protected from the sweep", a)
		}
	}
	if slices.Contains(prot, netip.MustParseAddr("fd00:1::5")) {
		t.Error("an IPv6 address in an IPv4 list")
	}
	// A dead host does not break the sweep's own list.
	if _, err := (sensorInventory{inv: s.d.Inventory, hostNet: newHostNetCache(hostNetSource(&fakeNet{err: errors.New("x")}, nil), nil)}).ProtectedIPs(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The honeypot's box address falls back to the appliance's own LAN address.
func TestHoneypotBoxFallsBackToTheHostsAddress(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.saveScope(t)
	a := honeypotInventory{inv: s.d.Inventory, hostNet: newHostNetCache(hostNetSource(lanBox(), nil), nil)}
	b, err := a.Box(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if b.IP != netip.MustParseAddr("192.168.10.250") {
		t.Fatalf("box IP %v, want the host's address inside the declared range", b.IP)
	}
}

// The honeypot's box address is never one of its own decoys, even when the host reports the decoy among the addresses it holds.
func TestHoneypotBoxIsNeverADecoyAddress(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.saveScope(t)
	f := &fakeNet{st: api.NetState{
		Interfaces: []api.NetInterface{{Name: "eth0", Addresses: []string{"192.168.10.201/24"}}}, // the only address inside the declared range is a decoy
		Decoys:     []api.NetDecoy{{IP: "192.168.10.201"}},
	}}
	decoys := func(context.Context) []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.10.201")} }
	a := honeypotInventory{inv: s.d.Inventory, hostNet: newHostNetCache(hostNetSource(f, nil), nil), decoys: decoys}
	b, err := a.Box(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if b.IP == netip.MustParseAddr("192.168.10.201") {
		t.Fatal("the honeypot's box address is its own decoy")
	}
}

// --- the shared provider (hostNetCache) ----------------------------------------------------------------

// One failed state/net call (the host restarting) must not take the appliance's LAN address out of the sweep's protected list: the
// same provider as boxSources keeps the last good answer.
func TestProtectedIPsKeepTheBoxWhenTheHostBlinks(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	f := lanBox()
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	cache := newHostNetCache(hostNetSource(f, nil), func() time.Time { return now })
	inv := sensorInventory{inv: s.d.Inventory, hostNet: cache}
	first, err := inv.ProtectedIPs(t.Context())
	if err != nil || !slices.Contains(first, netip.MustParseAddr("192.168.10.250")) {
		t.Fatalf("baseline: %v %v", first, err)
	}
	f.err = errors.New("host restarting")
	now = now.Add(hostNetTTL + time.Second)
	second, err := inv.ProtectedIPs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(second, netip.MustParseAddr("192.168.10.250")) {
		t.Fatalf("one failed state/net call removed the box's LAN address from the sweep's protected list: %v", second)
	}
}

// slowFailNet answers once, then fails slowly (a hung or overloaded host): every later call takes delay.
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

// After the TTL a failing host is asked once for everybody, not once per caller, and nobody queues behind the socket call.
func TestBoxAddrsDoesNotQueueOnAFailingHost(t *testing.T) {
	t.Parallel()
	f := &slowFailNet{delay: 150 * time.Millisecond}
	var mu sync.Mutex
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	b := &boxSources{hostNet: hostNetSource(f, nil), now: clock}
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
		t.Fatalf("6 concurrent BoxAddrs calls against a failing host made %d host calls and took %v (one call takes %v): they queue", calls, took, f.delay)
	}
}

// A failed refresh is remembered for hostNetBackoff: the dead host is not asked again by every caller, and the last good answer is served meanwhile.
func TestHostNetCacheRemembersAFailureForTenSeconds(t *testing.T) {
	t.Parallel()
	f := lanBox()
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	c := newHostNetCache(hostNetSource(f, nil), func() time.Time { return now })
	if got := c.Get(t.Context()); len(got) == 0 || f.calls != 1 {
		t.Fatalf("first: %v %d", got, f.calls)
	}
	now = now.Add(hostNetTTL + time.Second)
	f.err = errors.New("down")
	for range 5 {
		if got := c.Get(t.Context()); !contains(got, "192.168.10.250") {
			t.Fatalf("the last good answer was lost: %v", got)
		}
	}
	if f.calls != 2 {
		t.Fatalf("%d calls: one failed refresh, then none for the backoff", f.calls)
	}
	now = now.Add(hostNetBackoff - time.Second)
	c.Get(t.Context())
	if f.calls != 2 {
		t.Fatalf("asked again inside the backoff: %d calls", f.calls)
	}
	now = now.Add(2 * time.Second)
	f.err = nil
	if got := c.Get(t.Context()); f.calls != 3 || !contains(got, "192.168.10.201") {
		t.Fatalf("after the backoff the host was not asked again: %d calls %v", f.calls, got)
	}
	// A host that never answered gives nothing, and is not asked again at once either.
	dead := &fakeNet{err: errors.New("never")}
	d := newHostNetCache(hostNetSource(dead, nil), func() time.Time { return now })
	for range 4 {
		if got := d.Get(t.Context()); got != nil {
			t.Fatalf("%v", got)
		}
	}
	if dead.calls != 1 {
		t.Fatalf("%d calls to a host that never answered inside the backoff", dead.calls)
	}
}

// Concurrent first calls share one socket call (nobody has an answer to serve yet), and a caller that gives up its context does not stop the call.
func TestHostNetCacheSharesOneCallAndSurvivesACancelledCaller(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	calls := 0
	c := newHostNetCache(func(context.Context) ([]netip.Prefix, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		once.Do(func() { close(started) })
		<-release
		return []netip.Prefix{netip.MustParsePrefix("192.168.10.250/32")}, nil
	}, nil)
	var wg sync.WaitGroup
	results := make([][]netip.Prefix, 5)
	for i := range results {
		wg.Go(func() { results[i] = c.Get(t.Context()) })
	}
	<-started // the call is in flight: the next callers wait for it
	cctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := c.Get(cctx); got != nil { // a waiter whose context is already done returns at once
		t.Errorf("cancelled waiter got %v", got)
	}
	time.AfterFunc(100*time.Millisecond, func() { close(release) })
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("%d socket calls for concurrent callers", calls)
	}
	for i, r := range results {
		if len(r) != 1 {
			t.Errorf("caller %d got %v", i, r)
		}
	}
}

// The cache never holds its lock across the socket call: a caller that has a good answer is served at once while a refresh is in flight.
func TestHostNetCacheServesTheLastAnswerWhileRefreshing(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	entered := make(chan struct{})
	first := true
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	c := newHostNetCache(func(context.Context) ([]netip.Prefix, error) {
		if first {
			first = false
			return []netip.Prefix{netip.MustParsePrefix("192.168.10.250/32")}, nil
		}
		close(entered)
		<-release
		return nil, errors.New("slow and failed")
	}, clock)
	c.Get(t.Context())
	mu.Lock()
	now = now.Add(hostNetTTL + time.Second)
	mu.Unlock()
	go c.Get(t.Context()) // the leader of the refresh, stuck in the socket call
	<-entered
	done := make(chan []netip.Prefix)
	go func() { done <- c.Get(t.Context()) }()
	select {
	case got := <-done:
		if !contains(got, "192.168.10.250") {
			t.Fatalf("%v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a caller with a good answer queued behind the refresh")
	}
	close(release)
}

// More than 2048 addresses are cut on core's side, with a warning.
func TestHostNetSourceCapsWhatCoreAccepts(t *testing.T) {
	t.Parallel()
	var addrs []string
	for i := range 3000 {
		addrs = append(addrs, fmt.Sprintf("10.%d.%d.1/24", i/250, i%250))
	}
	f := &fakeNet{st: api.NetState{Interfaces: []api.NetInterface{{Name: "eth0", Addresses: addrs}}}}
	var buf bytes.Buffer
	got, err := hostNetSource(f, slog.New(slog.NewTextHandler(&buf, nil)))(t.Context())
	if err != nil || len(got) != maxHostPrefixes {
		t.Fatalf("%d prefixes, %v", len(got), err)
	}
	if !strings.Contains(buf.String(), "more addresses than core accepts") {
		t.Fatalf("no warning: %q", buf.String())
	}
	buf.Reset()
	if got, _ := hostNetSource(lanBox(), slog.New(slog.NewTextHandler(&buf, nil)))(t.Context()); len(got) == 0 || buf.Len() != 0 {
		t.Fatalf("a normal answer warned or was empty: %q", buf.String())
	}
}

// After a change of the box's addresses (Box network: apply, confirm, revert) the next Get asks the host again at
// once, and an answer that was already on its way when the change was made does not stand for the new state.
func TestHostNetCacheInvalidateAsksAgainAndDiscardsAnAnswerInFlight(t *testing.T) {
	t.Parallel()
	f := lanBox()
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	c := newHostNetCache(hostNetSource(f, nil), func() time.Time { return now })
	c.Get(t.Context())
	c.Get(t.Context())
	if f.calls != 1 {
		t.Fatalf("a fresh answer is served from memory: %d calls", f.calls)
	}
	c.Invalidate()
	f.st.Interfaces[0].Addresses = []string{"192.168.10.60/24"}
	if got := c.Get(t.Context()); !contains(got, "192.168.10.60") || contains(got, "192.168.10.250") || f.calls != 2 {
		t.Fatalf("after Invalidate: %v, %d calls", got, f.calls)
	}
	// Invalidate while a fetch is in flight: that answer is used by its caller but never marked fresh.
	gate := make(chan struct{})
	started := make(chan struct{})
	slow := &gatedNet{fakeNet: lanBox(), gate: gate, started: started}
	d := newHostNetCache(hostNetSource(slow, nil), func() time.Time { return now })
	done := make(chan []netip.Prefix)
	go func() { done <- d.Get(t.Context()) }()
	<-started
	d.Invalidate()
	close(gate)
	<-done
	d.Get(t.Context())
	if slow.calls != 2 {
		t.Fatalf("the answer that was in flight during Invalidate must not stand: %d calls", slow.calls)
	}
	var nilCache *hostNetCache
	nilCache.Invalidate() // safe without a host
}

// gatedNet answers state/net only when the gate opens.
type gatedNet struct {
	*fakeNet
	gate    chan struct{}
	started chan struct{}
	once    sync.Once
}

func (g *gatedNet) StateNet(ctx context.Context) (api.NetState, error) {
	g.once.Do(func() { close(g.started) })
	<-g.gate
	return g.fakeNet.StateNet(ctx)
}

// H1: after a management change the admin opens the box at the NEW address. The Host allowlist is fixed at
// start, so an IP literal that is one of the box's own current addresses (from the host, pending change
// included) is accepted too; any other IP and any name off the list stay 421.
func TestHostAllowlistAcceptsTheBoxsOwnAddressesAfterAChange(t *testing.T) {
	t.Parallel()
	f := lanBox()
	cache := newHostNetCache(hostNetSource(f, nil), time.Now)
	h := topHandler(slog.New(slog.DiscardHandler), okHandler(), nil, server.HostMatcher([]string{"box.corp.example"}, boxOwnAddress(cache)), false)
	status := func(host string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/setup", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := status("192.168.10.60:8443"); got != http.StatusMisdirectedRequest {
		t.Fatalf("an address the box does not have yet = %d", got)
	}
	// net.apply: the new address is live while the change waits for the confirmation.
	f.st.Interfaces[0].Addresses = []string{"192.168.10.60/24"}
	cache.Invalidate()
	for host, want := range map[string]int{
		"192.168.10.60:8443": 204, "192.168.10.60": 204, "box.corp.example": 204,
		"192.168.10.99:8443": 421, "192.168.10.99": 421, "evil.example": 421, "other.corp.example": 421, "192.168.10.60.evil.example": 421,
	} {
		if got := status(host); got != want {
			t.Errorf("Host %q = %d, want %d", host, got, want)
		}
	}
	if boxOwnAddress(nil)(netip.MustParseAddr("192.168.10.60")) {
		t.Error("an install without a host knows no addresses")
	}
}

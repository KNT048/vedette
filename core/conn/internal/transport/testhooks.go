package transport

import (
	"net/netip"
	"sync"
)

// The tests of core/conn talk to fakes on 127.0.0.1, which the address policy refuses. These hooks are the only way past it: they
// open one exact socket (address and port) and give one name to it, so a test that asserts that loopback is refused still passes
// next to a test that uses a fake. They live in an internal package: only core/conn and its test-only package conntest can call
// them, and TestConntestIsOnlyImportedByTests fails when anything else does.
var hooks struct {
	mu       sync.RWMutex
	allowed  map[netip.AddrPort]int
	names    map[string]netip.Addr
	redirect map[netip.AddrPort]netip.AddrPort
}

// AllowSocketForTest lets the dialer connect to ap and resolves name to its address. The returned func undoes both.
func AllowSocketForTest(name string, ap netip.AddrPort) func() {
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.allowed == nil {
		hooks.allowed, hooks.names = map[netip.AddrPort]int{}, map[string]netip.Addr{}
	}
	hooks.allowed[ap]++
	if name != "" {
		hooks.names[name] = ap.Addr()
	}
	return func() {
		hooks.mu.Lock()
		defer hooks.mu.Unlock()
		if hooks.allowed[ap]--; hooks.allowed[ap] <= 0 {
			delete(hooks.allowed, ap)
		}
		if name != "" {
			delete(hooks.names, name)
		}
	}
}

func testAllowed(ap netip.AddrPort) bool {
	hooks.mu.RLock()
	defer hooks.mu.RUnlock()
	return hooks.allowed[ap] > 0
}

func testResolve(name string) (netip.Addr, bool) {
	hooks.mu.RLock()
	defer hooks.mu.RUnlock()
	a, ok := hooks.names[name]
	return a, ok
}

// ResolveForTest makes name resolve to a without opening any socket: a test that a refused address is refused, however it was
// reached. The returned func undoes it.
func ResolveForTest(name string, a netip.Addr) func() {
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.allowed == nil {
		hooks.allowed, hooks.names = map[netip.AddrPort]int{}, map[string]netip.Addr{}
	}
	hooks.names[name] = a
	return func() {
		hooks.mu.Lock()
		defer hooks.mu.Unlock()
		delete(hooks.names, name)
	}
}

// RedirectForTest sends every dial to from (an address the policy lets through, like a LAN device) to the socket to, which it also
// opens: a test that exercises a connection saved with an ordinary address without touching that address. The returned func undoes it.
func RedirectForTest(from, to netip.AddrPort) func() {
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if hooks.allowed == nil {
		hooks.allowed, hooks.names = map[netip.AddrPort]int{}, map[string]netip.Addr{}
	}
	if hooks.redirect == nil {
		hooks.redirect = map[netip.AddrPort]netip.AddrPort{}
	}
	hooks.allowed[to]++
	hooks.redirect[from] = to
	return func() {
		hooks.mu.Lock()
		defer hooks.mu.Unlock()
		if hooks.allowed[to]--; hooks.allowed[to] <= 0 {
			delete(hooks.allowed, to)
		}
		delete(hooks.redirect, from)
	}
}

func testRedirect(from netip.AddrPort) (netip.AddrPort, bool) {
	hooks.mu.RLock()
	defer hooks.mu.RUnlock()
	to, ok := hooks.redirect[from]
	return to, ok
}

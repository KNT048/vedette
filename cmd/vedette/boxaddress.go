package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/server"
)

// The Box address (D-465): the host name or IP address the LAN reaches the box at, which every link the box makes carries (notify
// messages and their approval links, sign-in mail, the test message, the block list URL, URL honey tokens, the agent install commands).
// An administrator sets it in Settings → Box network (core keeps it); the default is the management IPv4 vedette-host reports. The fixed
// name "vedette" (fallbackBoxName, still a name of the box's own certificate for old bookmarks) is never used for a link: before D-465 the
// links took the first name of the certificate, which was that name, so every link of an appliance read https://vedette:8443.

const (
	boxAddrTTL     = 30 * time.Second // an answer is used this long (a save and an address change drop it at once: Invalidate)
	boxAddrRetry   = 10 * time.Second // after a failed read the last address is used this long before asking again
	boxAddrTimeout = 2 * time.Second  // one read: the setting in SQLite, and state/net through the Box network page's cache
)

// boxAddrState is one answer of read: the Box address, the earlier ones the box still answers to (review M1), and the Host test for all
// of them (server.HostMatcher; nil when there is none).
type boxAddrState struct {
	addr     string
	previous []string
	match    func(host string) bool
}

// boxAddr holds the Box address for the links, the certificate and the Host allowlist. read is core's NetworkHandlers.BoxAddress (the
// saved address, else the management IPv4, "" when neither is known; and the earlier addresses). flag is the address of an install without
// vedette-host (the container-only compose, D-168, which requires -hosts): the first usable -hosts entry (flagAddress); it is used only
// while read gives "". A read that fails keeps the last answer: a host restarting does not make the links vanish. Safe on nil ("") and for
// concurrent use. No lock is held across read (review L2): the answer is an atomic pointer, so links, the certificate and every request's
// Host test go on with the last answer while one read runs; a read started before an Invalidate never replaces the answer of one after it.
type boxAddr struct {
	read func(ctx context.Context) (string, []string, error) // nil: only flag
	flag string
	now  func() time.Time

	state atomic.Pointer[boxAddrState]

	mu    sync.Mutex // guards until and gen
	until time.Time  // read is asked again after this (also set while a read runs, so callers do not pile up)
	gen   uint64     // bumped by Invalidate
}

// wireBoxAddr sets d.BoxAddr and d.BaseURL (serve, and the wiring tests the same way): the Box address is core's setting, else the
// management IPv4, both read through d.Network once buildServices made it (host: the install has vedette-host); without a host the first
// usable -hosts entry (the container-only compose requires -hosts). listen is -listen: its port goes into the links.
func wireBoxAddr(d *deps, host bool, flagHosts []string, listen string) {
	var read func(ctx context.Context) (string, []string, error)
	if host {
		read = func(ctx context.Context) (string, []string, error) {
			if d.Network == nil {
				return "", nil, errors.New("the Box network handlers are not built yet")
			}
			return d.Network.BoxAddress(ctx)
		}
	}
	d.BoxAddr = newBoxAddr(read, flagAddress(flagHosts))
	d.BaseURL = func() string { return d.BoxAddr.URL(context.Background(), listen) } // notify and response ask with no context; a read is bounded (boxAddrTimeout)
}

// newBoxAddr is a boxAddr over read with flag as the fallback.
func newBoxAddr(read func(ctx context.Context) (string, []string, error), flag string) *boxAddr {
	return &boxAddr{read: read, flag: flag, now: time.Now}
}

// fetch runs one read (at most boxAddrTimeout) and stores its answer unless an Invalidate came after gen.
func (b *boxAddr) fetch(ctx context.Context, gen uint64) {
	cctx, cancel := context.WithTimeout(ctx, boxAddrTimeout)
	a, prev, err := b.read(cctx)
	cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	switch {
	case gen != b.gen: // a newer read owns the answer
	case err != nil && ctx.Err() != nil: // the caller gave up, not core: the next caller asks again
		b.until = time.Time{}
	case err != nil:
		b.until = now.Add(boxAddrRetry)
	default:
		b.until = now.Add(boxAddrTTL)
		st := &boxAddrState{addr: a, previous: prev}
		if names := append(slices.DeleteFunc([]string{a}, func(s string) bool { return s == "" }), prev...); len(names) > 0 {
			st.match = server.HostMatcher(names, nil)
		}
		b.state.Store(st)
	}
}

// Host is the Box address now: asks read when the answer in memory is older than boxAddrTTL (the caller waits for it; one at a time,
// the others use the last answer meanwhile).
func (b *boxAddr) Host(ctx context.Context) string {
	if b == nil {
		return ""
	}
	if b.read != nil {
		b.mu.Lock()
		now, gen := b.now(), b.gen
		stale := !now.Before(b.until)
		if stale {
			b.until = now.Add(boxAddrRetry)
		}
		b.mu.Unlock()
		if stale {
			b.fetch(ctx, gen)
		}
	}
	return b.pick()
}

// pick is the answer in memory, else flag.
func (b *boxAddr) pick() string {
	if st := b.state.Load(); st != nil && st.addr != "" {
		return st.addr
	}
	return b.flag
}

// Names is the Box address and the earlier ones (in memory; the certificate's renewer calls Host first): every name the certificate covers.
func (b *boxAddr) Names(ctx context.Context) []string {
	if b == nil {
		return nil
	}
	a := b.Host(ctx)
	var out []string
	if a != "" {
		out = append(out, a)
	}
	if st := b.state.Load(); st != nil {
		out = append(out, st.previous...)
	}
	return out
}

// Invalidate reads the Box address again now (a save in Box network, a change of the management address; and once at start, before the
// listener serves, so a saved name is answered to from the first request). The read is bounded (boxAddrTimeout); it is waited for, so the
// next link, Host test and certificate check see the new answer.
func (b *boxAddr) Invalidate() {
	if b == nil || b.read == nil {
		return
	}
	b.mu.Lock()
	b.gen++
	gen := b.gen
	b.until = b.now().Add(boxAddrRetry)
	b.mu.Unlock()
	b.fetch(context.Background(), gen)
}

// Allows says whether a Host header names the Box address or an earlier one in memory (never asking read: it runs on every request). A
// name an administrator typed is a name the box answers to, like -hosts: it was chosen by a person, not handed out by DHCP, so it is no
// DNS-rebinding hole (defaultAllowed). The flag address needs nothing here: it is one of -hosts already.
func (b *boxAddr) Allows(host string) bool {
	if b == nil {
		return false
	}
	st := b.state.Load()
	return st != nil && st.match != nil && st.match(host)
}

// URL is https://<Box address>[:port] for links (boxBaseURL), "" when there is none or the box listens on loopback.
func (b *boxAddr) URL(ctx context.Context, listen string) string {
	return boxBaseURL(b.Host(ctx), listen)
}

// flagAddress is the first entry of -hosts a machine on the LAN can reach: not a wildcard, "localhost" or a loopback address; "" when none.
func flagAddress(hosts []string) string {
	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") || strings.EqualFold(h, "localhost") {
			continue
		}
		if a, err := netip.ParseAddr(h); err == nil && a.Unmap().IsLoopback() {
			continue
		}
		return h
	}
	return ""
}

// baseURL is the address people open Vedette at: https://<addr>, with the listen port when it is not 443. Empty when addr is empty or
// the box listens on loopback only (dev): notify then sends no links and refuses approval requests (a link that approves an action must
// point at the real box), and the block list address is shown from /api/v1 on.
func baseURL(addr, listen string) string {
	if addr == "" {
		return ""
	}
	if loop, err := isLoopback(listen); err != nil || loop {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	if port == "443" {
		return "https://" + hostForURL(addr)
	}
	return "https://" + net.JoinHostPort(addr, port)
}

// testBaseURL is the test seam of D-173 (WP-30 slice 9b): the end-to-end box listens on loopback, where baseURL answers "" and notify refuses
// every approval request, so the box of `make e2e-real` answers http://127.0.0.1:<port> for its own listen address. Unexported, no flag, nil in the
// shipped binary: only a _test.go file sets it, so the production derivation above is the only one a real box ever runs.
var testBaseURL func(listen string) string

// boxBaseURL is baseURL, unless a test box has said otherwise for this listen address.
func boxBaseURL(addr, listen string) string {
	if testBaseURL != nil {
		if u := testBaseURL(listen); u != "" {
			return u
		}
	}
	return baseURL(addr, listen)
}

// hostForURL brackets an IPv6 literal.
func hostForURL(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}

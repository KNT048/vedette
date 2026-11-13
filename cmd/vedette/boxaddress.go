package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
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

// boxAddr holds the Box address for the links, the certificate and the Host allowlist. read is core's NetworkHandlers.BoxAddress (the
// saved address, else the management IPv4; "" when neither is known). flag is the address of an install without vedette-host (the
// container-only compose, D-168, which requires -hosts): the first usable -hosts entry (flagAddress); it is used only while read gives "".
// A read that fails keeps the last address: a host restarting does not make the links vanish. Safe on nil ("") and for concurrent use; the
// lock is held across one read (at most boxAddrTimeout), at most once per boxAddrRetry.
type boxAddr struct {
	read func(ctx context.Context) (string, error) // nil: only flag
	flag string
	now  func() time.Time

	mu    sync.Mutex
	addr  string                 // the last answer of read
	until time.Time              // read is asked again after this
	match func(host string) bool // the Host test for addr (server.HostMatcher of [addr]); nil when addr is ""
}

// wireBoxAddr sets d.BoxAddr and d.BaseURL (serve, and the wiring tests the same way): the Box address is core's setting, else the
// management IPv4, both read through d.Network once buildServices made it (host: the install has vedette-host); without a host the first
// usable -hosts entry (the container-only compose requires -hosts). listen is -listen: its port goes into the links.
func wireBoxAddr(d *deps, host bool, flagHosts []string, listen string) {
	var read func(ctx context.Context) (string, error)
	if host {
		read = func(ctx context.Context) (string, error) {
			if d.Network == nil {
				return "", errors.New("the Box network handlers are not built yet")
			}
			return d.Network.BoxAddress(ctx)
		}
	}
	d.BoxAddr = newBoxAddr(read, flagAddress(flagHosts))
	d.BaseURL = func() string { return d.BoxAddr.URL(context.Background(), listen) } // notify and response ask with no context; Host bounds the read (boxAddrTimeout)
}

// newBoxAddr is a boxAddr over read with flag as the fallback.
func newBoxAddr(read func(ctx context.Context) (string, error), flag string) *boxAddr {
	return &boxAddr{read: read, flag: flag, now: time.Now}
}

// Host is the Box address now: asks read when the answer in memory is older than boxAddrTTL. A caller whose own ctx ended is not held
// against read: the next caller asks again.
func (b *boxAddr) Host(ctx context.Context) string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := b.now(); b.read != nil && !now.Before(b.until) {
		cctx, cancel := context.WithTimeout(ctx, boxAddrTimeout)
		a, err := b.read(cctx)
		cancel()
		switch {
		case err != nil && ctx.Err() != nil: // the caller gave up, not core
		case err != nil:
			b.until = now.Add(boxAddrRetry)
		default:
			b.until = now.Add(boxAddrTTL)
			if a != b.addr {
				b.addr, b.match = a, nil
				if a != "" {
					b.match = server.HostMatcher([]string{a}, nil)
				}
			}
		}
	}
	if b.addr != "" {
		return b.addr
	}
	return b.flag
}

// Invalidate drops the answer in memory (a save of the Box address, a change of the management address) and reads it again in the
// background, so the Host allowlist (Allows) knows a new name without waiting for a link or the certificate's check.
func (b *boxAddr) Invalidate() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.until = time.Time{}
	b.mu.Unlock()
	if b.read != nil {
		go b.Host(context.Background())
	}
}

// Allows says whether a Host header names the Box address in memory (never asking read: it runs on every request). A name an administrator
// typed is a name the box answers to, like -hosts: it was chosen by a person, not handed out by DHCP, so it is no DNS-rebinding hole
// (defaultAllowed). The flag address needs nothing here: it is one of -hosts already.
func (b *boxAddr) Allows(host string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	m := b.match
	b.mu.Unlock()
	return m != nil && m(host)
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

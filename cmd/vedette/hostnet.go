package main

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	hostclient "github.com/knt048/vedette/host/client"

	"github.com/knt048/vedette/host/api"
)

// netStateReader is what core needs of vedette-host to learn the box's own addresses: host-api
// state/net. *hostclient.Client implements it; a test gives a fake.
type netStateReader interface {
	StateNet(ctx context.Context) (api.NetState, error)
}

// maxHostPrefixes is how many addresses core accepts from one state/net answer. The host caps its
// own list (64 interfaces of 64 addresses); this is the second bound, on the consumer's side.
const maxHostPrefixes = 2048

// hostNetSource is the raw fetch behind hostNetCache: every address vedette-host reports on the
// box's interfaces (cards, VLANs, bonds, bridges, container bridges) and on its decoys, each as a
// single-address prefix (/32 or /128), so that a connection, a sweep or a trap never mistakes the
// box for a device. core runs in a container and cannot see these addresses itself. nil when this
// install has no host (r == nil). An unreachable host is an error. More than maxHostPrefixes
// addresses are cut, with a warning on log (nil: none).
func hostNetSource(r netStateReader, log *slog.Logger) func(ctx context.Context) ([]netip.Prefix, error) {
	if r == nil {
		return nil
	}
	return func(ctx context.Context) ([]netip.Prefix, error) {
		st, err := r.StateNet(ctx)
		if err != nil {
			return nil, err
		}
		var out []netip.Prefix
		truncated := false
		add := func(a netip.Addr) {
			switch {
			case !a.IsValid():
			case len(out) >= maxHostPrefixes:
				truncated = true
			default:
				a = a.Unmap().WithZone("")
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		for _, i := range st.Interfaces {
			for _, s := range i.Addresses {
				if p, err := netip.ParsePrefix(s); err == nil {
					add(p.Addr())
				}
			}
		}
		for _, d := range st.Decoys {
			if a, err := netip.ParseAddr(d.IP); err == nil {
				add(a)
			}
		}
		if truncated && log != nil {
			log.WarnContext(ctx, "vedette-host reported more addresses than core accepts; the rest are ignored", "kept", maxHostPrefixes)
		}
		return out, nil
	}
}

// hostSocketNet is hostNetSource over the host client of a socket path ("" = no host).
func hostSocketNet(socket string, log *slog.Logger) func(ctx context.Context) ([]netip.Prefix, error) {
	if socket == "" {
		return nil
	}
	return hostNetSource(hostclient.New(socket), log)
}

const (
	hostNetTTL     = 30 * time.Second // a good answer is used this long
	hostNetBackoff = 10 * time.Second // after a failed refresh the last good answer is served this long before asking again
	hostNetTimeout = 15 * time.Second // one socket call, whoever started it
)

// hostNetCache is the one provider of the box's host-reported addresses, shared by core/conn
// (boxSources), the sensor-active sweep and the honeypot's box address. It never errors: a host
// that does not answer right now is still the same box, so the last good answer is served.
// It never holds its lock across the socket call, and concurrent callers share one call.
type hostNetCache struct {
	fetch func(ctx context.Context) ([]netip.Prefix, error)
	now   func() time.Time

	mu       sync.Mutex
	okAt     time.Time // when the last good answer was fetched; zero before the first
	last     []netip.Prefix
	failedAt time.Time // when the last refresh failed; zero when it did not
	flight   chan struct{}
}

// newHostNetCache wraps fetch; nil when there is none (no host), and every method is nil-safe.
func newHostNetCache(fetch func(ctx context.Context) ([]netip.Prefix, error), now func() time.Time) *hostNetCache {
	if fetch == nil {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &hostNetCache{fetch: fetch, now: now}
}

// Get returns the addresses: from memory while fresh, else after one shared refresh. A caller that
// already has a good answer to serve does not wait for a refresh somebody else started.
func (c *hostNetCache) Get(ctx context.Context) []netip.Prefix {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	now := c.now()
	have := !c.okAt.IsZero()
	switch {
	case have && now.Sub(c.okAt) < hostNetTTL,
		!c.failedAt.IsZero() && now.Sub(c.failedAt) < hostNetBackoff:
		l := c.last
		c.mu.Unlock()
		return l
	case c.flight != nil:
		wait, l := c.flight, c.last
		c.mu.Unlock()
		if have {
			return l
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return nil
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.last
	}
	done := make(chan struct{})
	c.flight = done
	c.mu.Unlock()

	// One call for everybody: it must not die with the first caller's context.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostNetTimeout)
	l, err := c.fetch(cctx)
	cancel()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.flight = nil
	close(done)
	if err != nil {
		c.failedAt = c.now()
		return c.last
	}
	c.okAt, c.last, c.failedAt = c.now(), l, time.Time{}
	return l
}

// hostIPv4s is the IPv4 addresses vedette-host reports for the box, best effort (nothing without a host).
func hostIPv4s(ctx context.Context, c *hostNetCache) []netip.Addr {
	var out []netip.Addr
	for _, p := range c.Get(ctx) {
		if p.Addr().Is4() {
			out = append(out, p.Addr())
		}
	}
	return out
}

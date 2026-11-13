package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

// The sources of D-446 (Vedette never connects to itself) for feeds, notify, logs and ai: machineAddrs is the machine's addresses
// (refused on Vedette's own ports), vedetteSelf what is Vedette itself beyond core's own interfaces (refused on every port).

// machineSources are the places the machine's addresses come from. Each is a field so a test can fake it; a nil one adds nothing.
type machineSources struct {
	host     func() ([]netip.Addr, bool) // what vedette-host reports for the appliance (notifyBoxAddrs), with its known flag
	gateways func() []netip.Addr         // the container's default gateways (IPv4, IPv6): the machine on every install
	hosts    []string                    // -hosts (VEDETTE_HOSTS): its IP literals are the machine's addresses the browser uses
	bindIP   string                      // VEDETTE_BIND_IP of the container-only compose: the machine's address 8443 is published on
	aliases  func() []netip.Addr         // what host.docker.internal and host.containers.internal resolve to
}

// addrs is the union of every source; known is the host's flag (true without a host).
func (m machineSources) addrs() ([]netip.Addr, bool) {
	var out []netip.Addr
	known := true
	if m.host != nil {
		out, known = m.host()
	}
	if m.gateways != nil {
		out = append(out, m.gateways()...)
	}
	for _, h := range append(slices.Clone(m.hosts), m.bindIP) {
		if a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(h), "[]")); err == nil && !a.IsUnspecified() {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	if m.aliases != nil {
		out = append(out, m.aliases()...)
	}
	return out, known
}

// machineAddrs is Config.BoxAddrs of feeds, notify, logs and ai (D-446). On the appliance vedette-host reports the machine's
// addresses; on a container-only install core cannot see them, so the gateway, the -hosts literals, VEDETTE_BIND_IP (passed by the
// compose file as an environment variable, which an older image ignores) and the host-alias names stand in for them: without them
// https://<LAN IP>:8443 would reach core's own API through the published port.
func machineAddrs(d *deps) func() ([]netip.Addr, bool) {
	return machineSources{host: notifyBoxAddrs(d.HostNet), gateways: procGateways, hosts: d.Hosts, bindIP: os.Getenv("VEDETTE_BIND_IP"), aliases: hostAliases.get}.addrs
}

// vedetteSelf is Config.SelfAddrs of feeds, notify, logs and ai: the honeypot's decoys, Vedette itself on every port (a webhook to a
// trap would loop: incident, webhook, trap hit). Read lazily through d (the honeypot is built after notify); a record that cannot be
// read counts as none (the decoys stay refused on Vedette's own ports, as part of what vedette-host reports).
func vedetteSelf(d *deps) func() []netip.Addr { return decoySelf{d}.addrs }

// decoySelf reads the decoys for vedetteSelf.
type decoySelf struct{ d *deps }

func (s decoySelf) addrs() []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // one short query; the ports have no context
	defer cancel()
	out, err := lateDecoys(s).DecoyIPsRead(ctx)
	if err != nil {
		return nil
	}
	return out
}

// hostAliasNames are the names Docker (Desktop, or host-gateway) and Podman give the machine that runs the container.
var hostAliasNames = provider.HostAliasNames

// aliasCache resolves hostAliasNames. The first call resolves in place (at most aliasTimeout); after that a stale answer is served
// while one refresh runs in the background, so no check waits on DNS. A name that does not resolve adds nothing.
type aliasCache struct {
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	now     func() time.Time

	mu    sync.Mutex
	addrs []netip.Addr
	at    time.Time // zero: never resolved
	busy  bool
}

const (
	aliasTTL     = 30 * time.Second
	aliasTimeout = time.Second
)

var hostAliases = &aliasCache{
	resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	},
	now: time.Now,
}

func (c *aliasCache) get() []netip.Addr {
	c.mu.Lock()
	first := c.at.IsZero() && !c.busy
	stale := !c.at.IsZero() && c.now().Sub(c.at) >= aliasTTL && !c.busy
	if first || stale {
		c.busy = true
	}
	out := slices.Clone(c.addrs)
	c.mu.Unlock()
	switch {
	case first:
		return c.refresh()
	case stale:
		go c.refresh()
	}
	return out
}

func (c *aliasCache) refresh() []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), aliasTimeout)
	defer cancel()
	var out []netip.Addr
	for _, h := range hostAliasNames {
		as, err := c.resolve(ctx, h)
		if err != nil {
			continue
		}
		for _, a := range as {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addrs, c.at, c.busy = out, c.now(), false
	return slices.Clone(out)
}

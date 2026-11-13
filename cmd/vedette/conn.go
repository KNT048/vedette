package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/modules/response"
)

// newConn builds the store of connections once, in buildServices (deps.Conn): core owns it (D-93), response reads it through
// responseConnections and core's Privacy page asks it through privacyFacts. The ports to inventory and response are read when
// they are asked for, because response is built after the store it reads.
func newConn(d *deps) (*conn.Service, error) {
	return conn.New(conn.Config{
		DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Clock: d.Clock,
		InUse: func(ctx context.Context, id string) (bool, error) {
			if d.Response == nil {
				return false, nil
			}
			return d.Response.ChangesInForce(ctx, id)
		},
		BoxAddrs: (&boxSources{
			ifaces: containerAddrs, gateways: procGateways, hosts: d.Hosts, hostCache: d.HostNet, now: d.Clock,
			decoys: func(ctx context.Context) []netip.Addr {
				if d.Honeypot == nil {
					return nil
				}
				return d.Honeypot.DecoyIPs(ctx)
			},
		}).BoxAddrs,
		AssetExists: func(ctx context.Context, id string) (bool, error) {
			if d.Inventory == nil {
				return true, nil
			}
			refs, err := d.Inventory.DeviceRefs(ctx, []string{id})
			_, ok := refs[id]
			return ok, err
		},
	})
}

// boxSources are the places the box's own addresses come from (D-94: no connection may point at the box). core runs in a
// container, so the interfaces it sees are not the appliance's LAN address: the other sources fill that in. Each is a function so a
// test can fake it; a nil one is skipped.
type boxSources struct {
	// ifaces are the container's own interface addresses with their masks. Each is refused with its whole subnet: nothing
	// legitimate lives in the bridge network of the container.
	ifaces func() []netip.Prefix
	// gateways are the container's default gateways (IPv4 and IPv6), which are the appliance host.
	gateways func() []netip.Addr
	// hosts are the names and addresses the box answers to (-hosts); the IP literals among them are the box.
	hosts []string
	// hostCache is the shared provider of the addresses vedette-host reports for every interface of the appliance and for its
	// decoys (state/net); nil when this install has no host. hostNet is the raw fetch a test can give instead: boxSources then
	// builds its own cache over it. Either way the answer is cached (hostNetTTL) because it is a socket call.
	hostCache *hostNetCache
	hostNet   func(ctx context.Context) ([]netip.Prefix, error)
	// decoys are the addresses the honeypot answers on (the traps are the box too).
	decoys func(ctx context.Context) []netip.Addr

	now func() time.Time

	once sync.Once
}

// cache is the provider of the host's addresses: the shared one, or one built over a raw fetch.
func (b *boxSources) cache() *hostNetCache {
	b.once.Do(func() {
		if b.hostCache == nil {
			b.hostCache = newHostNetCache(b.hostNet, b.now)
		}
	})
	return b.hostCache
}

// BoxAddrs is the union of every source: addresses as /32 or /128, interface subnets as they are. It is the one function that
// answers "is this the box" for the save-time check of core/conn and, from slice 13b-5, for the check of every resolved address at
// dial time. A source that fails or is absent adds nothing; the others still count.
func (b *boxSources) BoxAddrs(ctx context.Context) []netip.Prefix {
	var out []netip.Prefix
	one := func(a netip.Addr) {
		if a.IsValid() {
			a = a.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	if b.ifaces != nil {
		for _, p := range b.ifaces() {
			if p.IsValid() {
				out = append(out, p.Masked())
				one(p.Addr())
			}
		}
	}
	if b.gateways != nil {
		for _, g := range b.gateways() {
			one(g)
		}
	}
	for _, h := range b.hosts {
		if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			one(a)
		}
	}
	out = append(out, b.cache().Get(ctx)...)
	if b.decoys != nil {
		for _, a := range b.decoys(ctx) {
			one(a)
		}
	}
	return out
}

// containerAddrs is ifaces for the real box: every address of every interface of this container, with its mask.
func containerAddrs() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil && !p.Addr().IsLoopback() {
			out = append(out, p)
		}
	}
	return out
}

// defaultGateway reads the default route of a /proc/net/route table (Linux): the gateway of the line whose destination is 0.0.0.0.
func defaultGateway(route io.Reader) (netip.Addr, bool) {
	sc := bufio.NewScanner(route)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		return netip.AddrFrom4(b), true
	}
	return netip.Addr{}, false
}

// defaultGateway6 reads the default route of a /proc/net/ipv6_route table (Linux): the next hop of the lines whose destination is ::/0
// (fields: destination, prefix length, source, source prefix length, next hop, ...; addresses as 32 hex digits), :: left out (a
// route without a next hop). Several default routes give several gateways.
func defaultGateway6(route io.Reader) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(route)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || len(f[4]) != 32 {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil {
			continue
		}
		if a := netip.AddrFrom16([16]byte(b)); !a.IsUnspecified() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// procGateways are the container's default gateways: IPv4 from /proc/net/route, IPv6 from /proc/net/ipv6_route (when IPv6 is on in
// the container network). Not Linux, or no procfs: none.
func procGateways() []netip.Addr {
	var out []netip.Addr
	if f, err := os.Open("/proc/net/route"); err == nil {
		if g, ok := defaultGateway(f); ok {
			out = append(out, g)
		}
		_ = f.Close()
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		out = append(out, defaultGateway6(f)...)
		_ = f.Close()
	}
	return out
}

// responseConnections is response's view of the connections (response.Connections): who exists, which write tools are on,
// and the version the fingerprint of a request is made from.
type responseConnections struct{ c *conn.Service }

func (r responseConnections) List(ctx context.Context) ([]response.ConnectionInfo, error) {
	list, err := r.c.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("connections: %w", err)
	}
	out := make([]response.ConnectionInfo, len(list))
	for i, c := range list {
		out[i] = response.ConnectionInfo{
			Connection: response.Connection{ID: c.ID, Name: c.Name, Enabled: c.Enabled, Kind: c.Kind, WriteTools: conn.WriteTools(c)},
			Target:     c.Target, UpdatedAt: c.UpdatedAt, NotReady: conn.NotReady(c), Allow: c.Allow,
		}
	}
	return out, nil
}

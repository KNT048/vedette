package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
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
			ifaces: containerAddrs, gateway: procGateway, hosts: d.Hosts, hostNet: d.HostNet, now: d.Clock,
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
	// gateway is the container's default gateway, which is the appliance host.
	gateway func() (netip.Addr, bool)
	// hosts are the names and addresses the box answers to (-hosts); the IP literals among them are the box.
	hosts []string
	// hostNet asks vedette-host for the management address and the IPv6 addresses of the appliance (state/net); nil when this
	// install has no host. Its answer is cached for hostNetTTL because it is a socket call.
	hostNet func(ctx context.Context) ([]netip.Prefix, error)
	// decoys are the addresses the honeypot answers on (the traps are the box too).
	decoys func(ctx context.Context) []netip.Addr

	now func() time.Time

	mu       sync.Mutex
	hostAt   time.Time
	hostLast []netip.Prefix
}

const hostNetTTL = 30 * time.Second

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
	if b.gateway != nil {
		if g, ok := b.gateway(); ok {
			one(g)
		}
	}
	for _, h := range b.hosts {
		if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			one(a)
		}
	}
	out = append(out, b.fromHost(ctx)...)
	if b.decoys != nil {
		for _, a := range b.decoys(ctx) {
			one(a)
		}
	}
	return out
}

func (b *boxSources) fromHost(ctx context.Context) []netip.Prefix {
	if b.hostNet == nil {
		return nil
	}
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.hostAt.IsZero() && now().Sub(b.hostAt) < hostNetTTL {
		return b.hostLast
	}
	l, err := b.hostNet(ctx)
	if err != nil {
		return b.hostLast // keep the last answer: a host that does not answer right now is still the same box
	}
	b.hostAt, b.hostLast = now(), l
	return l
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

func procGateway() (netip.Addr, bool) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false // not Linux, or no procfs: no gateway to add
	}
	defer func() { _ = f.Close() }()
	return defaultGateway(f)
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
			Target:     c.Target, UpdatedAt: c.UpdatedAt,
		}
	}
	return out, nil
}

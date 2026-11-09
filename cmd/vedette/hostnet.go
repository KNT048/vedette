package main

import (
	"context"
	"net/netip"

	hostclient "github.com/knt048/vedette/host/client"

	"github.com/knt048/vedette/host/api"
)

// netStateReader is what core needs of vedette-host to learn the box's own addresses: host-api
// state/net. *hostclient.Client implements it; a test gives a fake.
type netStateReader interface {
	StateNet(ctx context.Context) (api.NetState, error)
}

// hostNetSource is boxSources.hostNet, sensorInventory.hostNet and honeypotInventory.hostNet: every
// address vedette-host reports on the cards of the box and on its decoys, each as a single-address
// prefix (/32 or /128), so that a connection, a sweep or a trap never mistakes the box for a device.
// core runs in a container and cannot see these addresses itself. nil when this install has no
// host (r == nil), so every caller stays nil-safe. An unreachable host is an error: the caller
// keeps what it had.
func hostNetSource(r netStateReader) func(ctx context.Context) ([]netip.Prefix, error) {
	if r == nil {
		return nil
	}
	return func(ctx context.Context) ([]netip.Prefix, error) {
		st, err := r.StateNet(ctx)
		if err != nil {
			return nil, err
		}
		var out []netip.Prefix
		add := func(a netip.Addr) {
			if a.IsValid() {
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
		return out, nil
	}
}

// hostSocketNet is hostNetSource over the host client of a socket path ("" = no host).
func hostSocketNet(socket string) func(ctx context.Context) ([]netip.Prefix, error) {
	if socket == "" {
		return nil
	}
	return hostNetSource(hostclient.New(socket))
}

// hostIPv4s is the IPv4 addresses vedette-host reports for the box, best effort: nothing when there
// is no host or it does not answer (the callers still have the container's own addresses).
func hostIPv4s(ctx context.Context, f func(context.Context) ([]netip.Prefix, error)) []netip.Addr {
	if f == nil {
		return nil
	}
	ps, err := f(ctx)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, p := range ps {
		if p.Addr().Is4() {
			out = append(out, p.Addr())
		}
	}
	return out
}

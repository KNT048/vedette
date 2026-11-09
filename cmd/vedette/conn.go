package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"

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
		BoxAddrs: boxAddrs,
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

// boxAddrs is the address of every network interface of the box: no connection may point at the box itself (D-94).
func boxAddrs(context.Context) []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil {
			out = append(out, p.Addr())
		}
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
			Target:     c.Target, UpdatedAt: c.UpdatedAt,
		}
	}
	return out, nil
}

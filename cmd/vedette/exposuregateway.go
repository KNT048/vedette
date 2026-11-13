package main

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// exposureGateway is exposure.Gateway (D-492): the LAN default gateway vedette-host reports (the same read the logs and response
// wiring use), the inventory device with that IP, and that device's open findings. Without a host (container-only) the LAN gateway
// is not visible (the container's own is the Docker bridge), so the answer has no IP and the page says it cannot tell.
type exposureGateway struct {
	state netStateReader // nil: no host
	inv   *inventory.Service
	fnd   *findings.Service
}

func (g exposureGateway) Gateway(ctx context.Context) (exposure.GatewayDevice, error) {
	var out exposure.GatewayDevice
	if g.state == nil {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := g.state.StateNet(ctx)
	if err != nil {
		return out, err
	}
	if st.DefaultRoute == nil {
		return out, nil
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(st.DefaultRoute.Gateway))
	if err != nil || ip.IsUnspecified() {
		return out, nil
	}
	out.IP = ip.Unmap().WithZone("")
	devs, err := g.inv.AllDevices(ctx)
	if err != nil {
		return out, err
	}
	for _, d := range devs {
		if d.IsBox || d.IP != out.IP.String() {
			continue
		}
		out.DeviceID = d.ID
		break
	}
	if out.DeviceID == "" {
		return out, nil
	}
	names, err := g.inv.Names(ctx) // the Devices page's name
	if err != nil {
		return out, err
	}
	out.Name = names[out.DeviceID]
	recs, err := g.fnd.List(ctx, out.DeviceID)
	if err != nil {
		return out, err
	}
	for _, r := range recs {
		if r.Status.Open() {
			out.OpenExploited++
		}
	}
	return out, nil
}

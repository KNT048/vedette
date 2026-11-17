package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// exposureGateway is exposure.Gateway: the LAN default gateway vedette-host reports (the same read the logs and response
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

// ApplianceDevices is exposure.Appliances: the inventory devices of an appliance family a port on the Internet names (a FortiGate
// certificate on the box's public IP), each with its open findings. A device is of the family when one of its software rows carries
// one of the family's KEV keys, or its vendor, model, OS or software text is the family's. The box itself and ignored devices are
// never one. Read on demand (the target list, a snapshot), like Gateway.
func (g exposureGateway) ApplianceDevices(ctx context.Context, q exposure.ApplianceQuery) ([]exposure.ApplianceDevice, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	devs, err := g.inv.AllDevices(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, d := range devs {
		if !d.IsBox && d.IgnoredAt == nil && applianceDevice(d, q) {
			ids = append(ids, d.ID)
		}
	}
	if len(ids) == 0 {
		return []exposure.ApplianceDevice{}, nil
	}
	names, err := g.inv.Names(ctx) // the Devices page's name
	if err != nil {
		return nil, err
	}
	out := make([]exposure.ApplianceDevice, 0, len(ids))
	for _, id := range ids {
		recs, err := g.fnd.List(ctx, id)
		if err != nil {
			return nil, err
		}
		d := exposure.ApplianceDevice{DeviceID: id, Name: names[id]}
		for _, r := range recs {
			if r.Status.Open() {
				d.OpenExploited++
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// applianceDevice says whether a device is of the family the query describes.
func applianceDevice(d inventory.Device, q exposure.ApplianceQuery) bool {
	text := []string{}
	for _, o := range []*inventory.Observed{d.Vendor, d.Model, d.OS} {
		if o != nil {
			text = append(text, o.Value)
		}
	}
	for _, s := range d.Software {
		if s.NotInstalled {
			continue
		}
		for _, k := range s.Kev {
			if slices.Contains(q.KevKeys, strings.ToLower(k)) {
				return true
			}
		}
		text = append(text, s.Vendor+" "+s.Product, s.Display)
	}
	return q.Device != nil && q.Device.MatchString(strings.Join(text, " \n "))
}

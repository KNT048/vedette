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
	ignored := false
	for _, d := range devs {
		if d.IsBox || d.IP != out.IP.String() {
			continue
		}
		out.DeviceID, ignored = d.ID, d.IgnoredAt != nil
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
	if ignored { // still the gateway, but a person ignored it: its findings are left out, as on every findings list
		return out, nil
	}
	recs, err := g.fnd.List(ctx, out.DeviceID)
	if err != nil {
		return out, err
	}
	for _, r := range recs {
		if r.Status.Open() && r.Row.Exploited() {
			out.OpenExploited++
		}
	}
	return out, nil
}

// ApplianceDevices is exposure.Appliances: for every appliance family a port on the Internet may name (a FortiGate certificate on
// the box's public IP), the inventory devices that are one, each with its open findings, in one read of the inventory. A device is
// one by its type (the family's device types: a firewall, a router, a VPN gateway…; never a PC, a phone, a switch of a vendor that
// makes firewalls, an access point or a NAS) and its own identity: its vendor, model or OS (the family's pattern), or a software row
// with one of the family's KEV keys (the keys of the family's own OS; none a VPN client shares). Never the box itself or an ignored
// device. At most exposure.MaxApplianceDevices a family are listed, More counts the others.
func (g exposureGateway) ApplianceDevices(ctx context.Context, qs []exposure.ApplianceQuery) (map[string]exposure.ApplianceMatch, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	devs, err := g.inv.AllDevices(ctx)
	if err != nil {
		return nil, err
	}
	ids := map[string][]string{}
	for _, d := range devs {
		if d.IsBox || d.IgnoredAt != nil {
			continue
		}
		for _, q := range qs {
			if slices.Contains(q.Kinds, d.Kind) && applianceDevice(d, q) {
				ids[q.Family] = append(ids[q.Family], d.ID)
			}
		}
	}
	out := make(map[string]exposure.ApplianceMatch, len(qs))
	for _, q := range qs {
		out[q.Family] = exposure.ApplianceMatch{Devices: []exposure.ApplianceDevice{}}
	}
	if len(ids) == 0 {
		return out, nil
	}
	names, err := g.inv.Names(ctx) // the Devices page's name
	if err != nil {
		return nil, err
	}
	for fam, list := range ids {
		m := exposure.ApplianceMatch{Devices: []exposure.ApplianceDevice{}, More: max(len(list)-exposure.MaxApplianceDevices, 0)}
		for _, id := range list[:min(len(list), exposure.MaxApplianceDevices)] {
			recs, err := g.fnd.List(ctx, id)
			if err != nil {
				return nil, err
			}
			d := exposure.ApplianceDevice{DeviceID: id, Name: names[id]}
			for _, r := range recs {
				if r.Status.Open() && r.Row.Exploited() {
					d.OpenExploited++
				}
			}
			m.Devices = append(m.Devices, d)
		}
		out[fam] = m
	}
	return out, nil
}

// applianceDevice says whether a device is of the family: its own vendor, model or OS, or a software row (not marked not installed)
// with one of the family's KEV keys.
func applianceDevice(d inventory.Device, q exposure.ApplianceQuery) bool {
	var own []string
	for _, o := range []*inventory.Observed{d.Vendor, d.Model, d.OS} {
		if o != nil {
			own = append(own, o.Value)
		}
	}
	if q.Device != nil && q.Device.MatchString(strings.Join(own, " \n ")) {
		return true
	}
	for _, s := range d.Running() {
		for _, k := range s.Kev {
			if slices.Contains(q.KevKeys, strings.ToLower(k)) {
				return true
			}
		}
	}
	return false
}

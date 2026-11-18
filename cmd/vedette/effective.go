package main

import (
	"context"
	"slices"
	"strings"

	"github.com/knt048/vedette/modules/inventory"
)

// effectiveDevice keeps, of a device's software rows, only the row inventory says describes each software (inventory INV-50,
// EffectiveSoftware): a scan banner's "OpenSSH 10.2" next to the agent's 10.2p1 package is the same software, and the readers that
// tell an assistant what the device runs (the Ask context, the MCP asset data) quote the agent's row only, as findings matches on it.
// A device where no two rows can be one software is returned as it is (no extra read); when inventory cannot answer, the rows stay
// as they are rather than leaving the device without software.
func effectiveDevice(ctx context.Context, inv *inventory.Service, d inventory.Device) inventory.Device {
	if inv == nil || !mayShareSoftware(d.Software) {
		return d
	}
	eff, err := inv.EffectiveSoftware(ctx, d.ID)
	if err != nil {
		return d
	}
	shadowed := map[string]bool{}
	for _, e := range eff {
		for _, o := range e.AlsoSeen {
			shadowed[o.ID] = true
		}
	}
	d.Software = slices.DeleteFunc(slices.Clone(d.Software), func(s inventory.Software) bool { return shadowed[s.ID] })
	return d
}

// mayShareSoftware says two rows of the list may be one software: the same vendor and product in any case. Inventory also joins
// rows by their CPE, which this list does not carry, so any device with two rows of one vendor asks it.
func mayShareSoftware(sws []inventory.Software) bool {
	seen := map[string]bool{}
	for _, s := range sws {
		v := strings.ToLower(strings.TrimSpace(s.Vendor))
		if v == "" {
			v = "|" + strings.ToLower(strings.TrimSpace(s.Product))
		}
		if seen[v] {
			return true
		}
		seen[v] = true
	}
	return false
}

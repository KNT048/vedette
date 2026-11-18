package main

import (
	"context"
	"slices"
	"strings"

	"github.com/knt048/vedette/modules/inventory"
)

// effectiveDevice keeps, of a device's software rows, the rows inventory matches (MatchInput, inventory INV-50): the readers that
// tell an assistant what the device runs (the Ask context, the MCP asset data) show the software as findings matches it. A weaker
// source's reading of the same release ("OpenSSH 10.2" from a banner next to the agent's 10.2p1 package) and a reported row a
// person's entry corrects are left out; a reading of another release (an OpenSSH 8.9p1 a scan sees on another port) stays, since it
// is matched as an install of its own. The decision is inventory's: a row is dropped only when MatchInput left it out while it keeps
// another row of the same vendor and product, so rows MatchInput never carries for other reasons stay as they were. A device where no
// two rows share a vendor is returned as it is (no extra read); when inventory cannot answer, the rows stay as they are.
func effectiveDevice(ctx context.Context, inv *inventory.Service, d inventory.Device) inventory.Device {
	if inv == nil || !mayShareSoftware(d.Software) {
		return d
	}
	m, ok, err := inv.MatchInput(ctx, d.ID)
	if err != nil || !ok {
		return d
	}
	kept, matched := map[string]bool{}, map[string]bool{}
	for _, s := range m.Software {
		kept[s.ID], matched[productOf(s.Vendor, s.Product)] = true, true
	}
	d.Software = slices.DeleteFunc(slices.Clone(d.Software), func(s inventory.Software) bool {
		return !kept[s.ID] && matched[productOf(s.Vendor, s.Product)]
	})
	return d
}

func productOf(vendor, product string) string {
	return strings.ToLower(strings.TrimSpace(vendor)) + "|" + strings.ToLower(strings.TrimSpace(product))
}

// mayShareSoftware says two rows of the list may be one software: the same vendor in any case (inventory also joins rows by their
// CPE, which this list does not carry, so any two rows of one vendor ask it).
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

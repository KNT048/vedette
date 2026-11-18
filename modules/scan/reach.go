package scan

import "context"

// Reach says why the vulnerability scan does not reach one device, for the finding page's "why only suspected" line.
type Reach string

// The Reach values. ReachUnknown is every other answer, including "allowed": the inventory's one-device answer does not say
// whether the device is approved or excluded, so the page then says nothing about the scan rather than guess.
const (
	ReachOutside   Reach = "outside"    // the device is outside the confirmed scan ranges
	ReachOff       Reach = "off"        // network scanning is off
	ReachNoRanges  Reach = "no_ranges"  // no scan ranges are confirmed yet
	ReachByHand    Reach = "by_hand"    // the device was added by hand and is not scanned
	ReachDeviceOff Reach = "device_off" // this device's own network scan setting is off
	ReachUnknown   Reach = ""
)

// Reach reads the inventory's scan policy for the one device, as a scan a person picked would meet it: one read, no list of
// devices. A read that fails is ReachUnknown.
func (s *Service) Reach(ctx context.Context, assetID string) (Reach, error) {
	dec, err := s.cfg.Inventory.VulnScanPolicy(ctx, assetID, true)
	if err != nil {
		return ReachUnknown, err
	}
	switch dec.Reason {
	case reasonOutOfScope:
		return ReachOutside, nil
	case "scanning_off":
		return ReachOff, nil
	case reasonNoScope:
		return ReachNoRanges, nil
	case "declared_by_hand":
		return ReachByHand, nil
	case reasonNever:
		return ReachDeviceOff, nil
	}
	return ReachUnknown, nil
}

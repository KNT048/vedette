package scan

import "context"

// Reach says how the vulnerability scan stands to one device, for the finding page's "why only suspected" line.
type Reach string

// The Reach values. Unknown is every reason that is neither of the others (not approved, excluded, no address, the box itself, a
// moved address): the page then says nothing about the scan rather than guess.
const (
	ReachCovered Reach = "covered" // a scan of the device runs its checks
	ReachOutside Reach = "outside" // the device is outside the confirmed scan ranges
	ReachOff     Reach = "off"     // no scan ranges are confirmed yet, or the device's own network scan is off
	ReachUnknown Reach = ""
)

// Reach reads the consent for one device as a scan picked by a person would meet it (the rule of the scan list, one device, no
// list of all). A device that no longer exists, or any read that fails, is ReachUnknown.
func (s *Service) Reach(ctx context.Context, assetID string) (Reach, error) {
	st, err := s.settings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return ReachUnknown, err
	}
	devs, err := s.cfg.Inventory.Devices(ctx)
	if err != nil {
		return ReachUnknown, err
	}
	for _, d := range devs {
		if d.ID != assetID {
			continue
		}
		reason, _, err := s.consent(ctx, st, d, true)
		if err != nil {
			return ReachUnknown, err
		}
		switch reason {
		case "":
			return ReachCovered, nil
		case reasonOutOfScope:
			return ReachOutside, nil
		case "scanning_off", reasonNoScope, reasonNever, "declared_by_hand": // active scanning off, no ranges confirmed, or this device's own network scan off
			return ReachOff, nil
		}
		return ReachUnknown, nil
	}
	return ReachUnknown, nil
}

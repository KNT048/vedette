package scan

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ExternalTarget is a target of the exposure module as the scan list shows it. External targets are listed but
// not scanned by this version (D-126 (4)): the reason is always one of unverified, expired, not_supported.
type ExternalTarget struct {
	ID       string // exposure target id, without the "ext:" prefix
	Value    string // the domain or the IP
	IP       string // the IP of an IP target, the last known address of a domain, or "—"
	Verified bool
	Expired  bool
}

// External lists the exposure module's targets. Nil: the list has no external part.
type External interface {
	Targets(ctx context.Context) ([]ExternalTarget, error)
}

// ExternalPrefix marks an external target id in the scan list (contract.ts ScanTarget.id).
const ExternalPrefix = "ext:"

// TargetView is contract.ts ScanTarget.
type TargetView struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"` // internal | external
	DeviceKind *string `json:"device_kind"`
	Label      string  `json:"label"`
	IP         string  `json:"ip"`
	Fragile    bool    `json:"fragile"`
	Findings   int     `json:"findings"`
	Selectable bool    `json:"selectable"`
	PickOnly   bool    `json:"pick_only"` // only a person's tick picks it (D-126 (2)); the GUI never ticks it for them
	Box        bool    `json:"box"`       // the Vedette box itself: pick-only (D-470), the GUI says so
	Reason     *string `json:"reason"`
}

// reasonText ends the sentence "<label> (<ip>) ..." of a 400 out_of_scope (the mock's REASON).
var reasonText = map[string]string{
	"unapproved":         "has not been approved in the inventory",
	"excluded":           "is on the exclusion list",
	"out_of_scope":       "is outside the confirmed network range",
	"regular_scan_never": "is set to never be scanned in the inventory; change that setting first",
	"unverified":         "has no verified ownership (do it on the External exposure page)",
	"expired":            "verification expired, verify again (on the External exposure page)",
	"not_supported":      "is an external target, and this version does not scan external targets yet",
}

// skipNote is the note of a result row when a device is not scanned at the moment it is reached (INV-1: every
// target is checked again right before its job leaves core).
var skipNote = map[string]string{ //nolint:gosec // G101: notes shown to the user, not credentials
	"unapproved":                "Not approved in the inventory any more; not scanned.",
	"excluded":                  "On the exclusion list; not scanned.",
	"out_of_scope":              "Outside the confirmed scope now; not scanned.",
	"no_ip":                     "The device has no IP address now; not scanned.",
	"scope_not_confirmed":       "The scan scope commitment is not ticked any more; not scanned.",
	"box":                       "The Vedette box itself: scanned only when you pick it in Scan now.",
	"regular_scan_never":        "Set to never be scanned in the inventory; not scanned.",
	"declared_by_hand":          "Added by hand: scanned only when you pick it in Scan now.",
	"fragile_passive_only":      "Fragile device: scanned only when you pick it in Scan now.",
	"unclassified_passive_only": "Device type unknown: scanned only when you pick it in Scan now.",
	"gone":                      "No longer in the inventory; not scanned.",
	"moved":                     "The device's address changed since the scan started; not scanned.",
}

// excluded says whether ip is on the scan module's own exclusion list (INV-1).
func excluded(ip string, list []string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, e := range list {
		if b, err := netip.ParseAddr(e); err == nil && b == a {
			return true
		}
		if p, err := netip.ParsePrefix(e); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// consent is D-126 in one place: may device d be scanned now, and how. explicit is true for a device a person
// picked in Scan now (that pick is the consent for fragile, unclassified and hand-declared devices); schedules and
// KEV rescans pass false. It returns the inventory's decision folded with scan's own rules (approved, scan
// exclusions) as a scan reason: "" when allowed.
func (s *Service) consent(ctx context.Context, st Settings, d Device, explicit bool) (reason string, careful bool, err error) {
	dec, err := s.cfg.Inventory.VulnScanPolicy(ctx, d.ID, explicit)
	if err != nil {
		return "", false, fmt.Errorf("scan: reading the scan policy of %s: %w", d.ID, err)
	}
	switch {
	case dec.Reason == reasonBox || dec.Reason == reasonNever:
		return dec.Reason, false, nil
	case !d.Approved:
		return "unapproved", false, nil // D-84 (2): discovery may look at it, the vulnerability scan does not
	case excluded(d.IP, st.Exclusions):
		return "excluded", false, nil
	case !dec.Allowed:
		return dec.Reason, false, nil
	case dec.IP != "" && dec.IP != d.IP: // review L1: the inventory decided on another address than the one the job would use
		return "moved", false, nil
	}
	return "", dec.Careful, nil
}

// targetReason turns a consent reason into the reason of the scan list, which knows fewer of them; a missing
// commitment is not a target's reason (can_scan says it).
func targetReason(r string) string {
	switch r {
	case "", reasonNoScope:
		return ""
	case "unapproved", "excluded", reasonNever: // the box is never a list reason: picked, it is allowed (D-470)
		return r
	}
	return reasonOutOfScope
}

// Targets lists every device and external target with whether it can be picked in Scan now and why not (S-SCAN-1).
func (s *Service) Targets(ctx context.Context) ([]TargetView, error) {
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	devs, err := s.cfg.Inventory.Devices(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan: reading the devices: %w", err)
	}
	out := make([]TargetView, 0, len(devs))
	for _, d := range devs {
		r, _, err := s.consent(ctx, st, d, true)
		if err != nil {
			return nil, err
		}
		if r == ReasonGone {
			continue
		}
		v := TargetView{ID: d.ID, Kind: "internal", DeviceKind: ptr(d.Kind), Label: d.Label, IP: d.IP, Fragile: d.Fragile || d.Kind == "unknown", Box: d.Box}
		if tr := targetReason(r); tr != "" {
			v.Reason = ptr(tr)
		}
		v.Selectable = v.Reason == nil
		if v.Selectable { // allowed when picked; would an automatic run be refused? then only a pick may include it
			auto, _, err := s.consent(ctx, st, d, false)
			if err != nil {
				return nil, err
			}
			v.PickOnly = auto != ""
		}
		out = append(out, v)
	}
	if err := s.countFindings(ctx, out); err != nil {
		return nil, err
	}
	if s.cfg.External != nil {
		ext, err := s.cfg.External.Targets(ctx)
		if err != nil {
			return nil, fmt.Errorf("scan: reading the external targets: %w", err)
		}
		for _, e := range ext {
			r := "not_supported"
			switch {
			case !e.Verified:
				r = "unverified"
			case e.Expired:
				r = "expired"
			}
			out = append(out, TargetView{ID: ExternalPrefix + e.ID, Kind: "external", Label: e.Value, IP: e.IP, Reason: ptr(r)})
		}
	}
	return out, nil
}

// countFindings sets the number of open findings (suspected or confirmed) of each device.
func (s *Service) countFindings(ctx context.Context, ts []TargetView) error {
	if s.cfg.Findings == nil {
		return nil
	}
	all, err := s.cfg.Findings.List(ctx, "")
	if err != nil {
		return fmt.Errorf("scan: reading the findings: %w", err)
	}
	n := map[string]int{}
	for _, f := range all {
		if f.Status == "confirmed" || f.Status == "suspected" {
			n[f.AssetID]++
		}
	}
	for i := range ts {
		ts[i].Findings = n[ts[i].ID]
	}
	return nil
}

// refusal is the 400 out_of_scope of a target that cannot be picked.
func refusal(t TargetView) error {
	r := "out_of_scope"
	if t.Reason != nil {
		r = *t.Reason
	}
	return apiErr(400, "out_of_scope", "%s (%s) %s, so it cannot be scanned.", t.Label, t.IP, reasonText[r])
}

func unknownTarget(id string) error {
	return apiErr(400, "unknown_target", "There is no target \"%s\" in the scan list.", clip(strings.TrimSpace(id), 40))
}

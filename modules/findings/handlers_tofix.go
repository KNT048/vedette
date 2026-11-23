package findings

import (
	"context"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
)

// toFixActionJS is contract.ts ToFixAction.
type toFixActionJS struct {
	Group      string   `json:"group"`
	SoftwareID string   `json:"software_id"`
	Software   string   `json:"software"`
	Version    string   `json:"version"`
	Product    string   `json:"product"`
	Source     string   `json:"source"`
	Fixed      string   `json:"fixed"`
	Kind       string   `json:"kind"`
	Windows    bool     `json:"windows"`
	Distro     string   `json:"distro"`
	Pro        bool     `json:"pro"`
	Action     string   `json:"action"`
	CVEs       []string `json:"cves"`
	FindingIDs []string `json:"finding_ids"`
	Worst      string   `json:"worst"`
	Ransomware int      `json:"ransomware"`
	Likely     int      `json:"likely"`
	Confirmed  int      `json:"confirmed"`
	Detected   int      `json:"detected"`
	Reported   int      `json:"reported"`
	Suspected  int      `json:"suspected"`
	Checkable  int      `json:"checkable"`
	NVDLag     bool     `json:"nvd_lag"`
	KB         string   `json:"kb"`
	DistroData string   `json:"distro_data"`
}

func toFixActions(us []UpdateAction) []toFixActionJS {
	out := make([]toFixActionJS, 0, len(us))
	for _, u := range us {
		out = append(out, toFixActionJS{Group: u.Group, SoftwareID: u.SoftwareID, Software: u.Software, Version: u.Version, Product: u.Product, Source: u.Source, Fixed: u.Fixed, Kind: u.Kind,
			Windows: u.Windows, Distro: u.Distro, Pro: u.Pro, DistroData: u.DistroData, Action: u.Action, CVEs: nonNil(u.CVEs), FindingIDs: nonNil(u.FindingIDs), Worst: u.Worst,
			Ransomware: u.Ransomware, Likely: u.Likely, Confirmed: u.Confirmed, Detected: u.Detected, Reported: u.Reported, Suspected: u.Suspected, Checkable: u.Checkable, NVDLag: u.NVDLag, KB: u.KB})
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// riskJS is contract.ts DeviceRiskView: a device's badge, the device status every list gives (DeviceStatuses).
type riskJS = DeviceStatus

// risks is every device's status for a page that shows badges; a failure is logged and shows no badge, never fails the page.
func (h *FindingHandlers) risks(ctx context.Context, _ bool) map[string]DeviceStatus {
	m, err := h.svc.DeviceStatuses(ctx)
	if err != nil {
		h.svc.cfg.Log.WarnContext(ctx, "findings: device statuses not read", "error", err)
		return nil
	}
	return m
}

// riskOfView is the badge of device a: nil when it has none or when a is the Vedette box itself.
func riskOfView(m map[string]DeviceStatus, a AssetView) *riskJS {
	st, ok := m[a.ID]
	if !ok || a.Box {
		return nil
	}
	return &st
}

// FindingsGetFindingsToFix implements GET /findings/to-fix: Service.ToFix with each device's name. A device the inventory
// no longer knows is left out (its findings go with it).
func (h *FindingHandlers) FindingsGetFindingsToFix(ctx context.Context, params oas.FindingsGetFindingsToFixParams) (*oas.FindingsGetFindingsToFixOK, error) {
	feedsOn := h.gate == nil || h.gate.Enabled(FeedsModule)
	tf, err := h.svc.ToFix(ctx, feedsOn, params.Asset.Or(""))
	if err != nil {
		return nil, err
	}
	// every marked device's risk (no display cap), for the markers of the Findings table and its filter
	risks := h.risks(ctx, feedsOn)
	ids := make([]string, 0, len(tf.Devices)+len(risks))
	for _, d := range tf.Devices {
		ids = append(ids, d.AssetID)
	}
	if params.Asset.Or("") == "" {
		for id := range risks {
			ids = append(ids, id)
		}
	}
	assets := map[string]AssetView{}
	if len(ids) > 0 {
		if assets, err = h.inv.Assets(ctx, ids); err != nil {
			return nil, fmt.Errorf("findings: to fix: reading devices: %w", err)
		}
	}
	type deviceJS struct {
		Asset        AssetView       `json:"asset"`
		Risk         *riskJS         `json:"risk"`
		Open         int             `json:"open"`
		Exploited    []toFixActionJS `json:"exploited"`
		NoUpdate     []toFixActionJS `json:"no_update"`
		Planned      []toFixActionJS `json:"planned"`
		PlanCompared bool            `json:"plan_compared"`
	}
	out := struct {
		Devices   []deviceJS         `json:"devices"`
		Risks     map[string]*riskJS `json:"risks"`
		Truncated bool               `json:"truncated"`
		PlanRan   bool               `json:"plan_ran"`
		PlanOff   bool               `json:"plan_off"`
	}{Devices: []deviceJS{}, Risks: map[string]*riskJS{}, Truncated: tf.Truncated, PlanRan: tf.PlanRan, PlanOff: tf.PlanOff}
	for _, d := range tf.Devices {
		a, ok := assets[d.AssetID]
		if !ok {
			continue
		}
		// the card's own classification: its marker counts exactly what the card lists (review r2 of #949)
		out.Devices = append(out.Devices, deviceJS{Asset: a, Risk: riskOfView(risks, a), Open: d.Open, Exploited: toFixActions(d.Exploited), NoUpdate: toFixActions(d.NoUpdate),
			Planned: toFixActions(d.Planned), PlanCompared: d.PlanCompared})
	}
	if params.Asset.Or("") == "" {
		for id := range risks {
			if a, ok := assets[id]; ok {
				if v := riskOfView(risks, a); v != nil {
					out.Risks[id] = v
				}
			}
		}
	}
	return Into[oas.FindingsGetFindingsToFixOK](out)
}

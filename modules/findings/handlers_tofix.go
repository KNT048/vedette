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
}

func toFixActions(us []UpdateAction) []toFixActionJS {
	out := make([]toFixActionJS, 0, len(us))
	for _, u := range us {
		out = append(out, toFixActionJS{Group: u.Group, SoftwareID: u.SoftwareID, Software: u.Software, Version: u.Version, Product: u.Product, Source: u.Source, Fixed: u.Fixed, Kind: u.Kind,
			Windows: u.Windows, Distro: u.Distro, Pro: u.Pro, Action: u.Action, CVEs: nonNil(u.CVEs), FindingIDs: nonNil(u.FindingIDs), Worst: u.Worst,
			Ransomware: u.Ransomware, Likely: u.Likely, Confirmed: u.Confirmed, Detected: u.Detected, Reported: u.Reported, Suspected: u.Suspected})
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// riskJS is contract.ts DeviceRisk (G4): a device's risk marker, the same value the device list gives (RiskMap).
type riskJS struct {
	Level     string `json:"level"`
	Exploited int    `json:"exploited"`
	Updates   int    `json:"updates"`
}

// risks is RiskMap for a page that shows markers; a failure is logged and shows no marker, never fails the page (review r1 of #949).
func (h *FindingHandlers) risks(ctx context.Context, feedsOn bool) map[string]AssetRisk {
	m, err := h.svc.RiskMap(ctx, feedsOn)
	if err != nil {
		h.svc.cfg.Log.WarnContext(ctx, "findings: risk markers not read", "error", err)
		return nil
	}
	return m
}

// riskOfView is the marker of device a: nil when clean or when a is the Vedette box itself (its updates are in To fix, the box is not
// marked, G4).
func riskOfView(m map[string]AssetRisk, a AssetView) *riskJS {
	r := m[a.ID]
	if a.Box || r.Level() == "" {
		return nil
	}
	out := &riskJS{Level: r.Level(), Exploited: r.Exploited, Updates: r.Updates}
	if out.Level == "update" {
		out.Exploited = 0
	}
	return out
}

// FindingsGetFindingsToFix implements GET /findings/to-fix (kien G8): Service.ToFix with each device's name. A device the inventory
// no longer knows is left out (its findings go with it).
func (h *FindingHandlers) FindingsGetFindingsToFix(ctx context.Context, params oas.FindingsGetFindingsToFixParams) (*oas.FindingsGetFindingsToFixOK, error) {
	feedsOn := h.gate == nil || h.gate.Enabled(FeedsModule)
	tf, err := h.svc.ToFix(ctx, feedsOn, params.Asset.Or(""))
	if err != nil {
		return nil, err
	}
	risks := h.risks(ctx, feedsOn)
	ids := make([]string, 0, len(tf.Devices))
	for _, d := range tf.Devices {
		ids = append(ids, d.AssetID)
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
		Devices   []deviceJS `json:"devices"`
		Truncated bool       `json:"truncated"`
		PlanRan   bool       `json:"plan_ran"`
		PlanOff   bool       `json:"plan_off"`
	}{Devices: []deviceJS{}, Truncated: tf.Truncated, PlanRan: tf.PlanRan, PlanOff: tf.PlanOff}
	for _, d := range tf.Devices {
		a, ok := assets[d.AssetID]
		if !ok {
			continue
		}
		out.Devices = append(out.Devices, deviceJS{Asset: a, Risk: riskOfView(risks, a), Open: d.Open, Exploited: toFixActions(d.Exploited), NoUpdate: toFixActions(d.NoUpdate),
			Planned: toFixActions(d.Planned), PlanCompared: d.PlanCompared})
	}
	return Into[oas.FindingsGetFindingsToFixOK](out)
}

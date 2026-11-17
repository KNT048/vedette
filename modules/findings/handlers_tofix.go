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

// FindingsGetFindingsToFix implements GET /findings/to-fix (kien G8): Service.ToFix with each device's name. A device the inventory
// no longer knows is left out (its findings go with it).
func (h *FindingHandlers) FindingsGetFindingsToFix(ctx context.Context, params oas.FindingsGetFindingsToFixParams) (*oas.FindingsGetFindingsToFixOK, error) {
	tf, err := h.svc.ToFix(ctx, h.gate == nil || h.gate.Enabled(FeedsModule), params.Asset.Or(""))
	if err != nil {
		return nil, err
	}
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
	type riskJS struct { // G4: the device's risk marker, as the device list gives it (RiskOf)
		Level     string `json:"level"`
		Exploited int    `json:"exploited"`
		Updates   int    `json:"updates"`
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
		var risk *riskJS
		if r := RiskOf(d); r.Level() != "" {
			risk = &riskJS{Level: r.Level(), Exploited: r.Exploited, Updates: r.Updates}
			if risk.Level == "update" {
				risk.Exploited = 0
			}
		}
		out.Devices = append(out.Devices, deviceJS{Asset: a, Risk: risk, Open: d.Open, Exploited: toFixActions(d.Exploited), NoUpdate: toFixActions(d.NoUpdate),
			Planned: toFixActions(d.Planned), PlanCompared: d.PlanCompared})
	}
	return Into[oas.FindingsGetFindingsToFixOK](out)
}

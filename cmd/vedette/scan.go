package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/scan"
)

var (
	scanMu       sync.Mutex
	scanServices = map[*store.DB]*scan.Service{}
)

// scanService builds the scan service once per database, so the handlers and (later) the jobs share it.
// ponytail: no Engine and no template pack yet: the remote nuclei engine over the sensor protocol is slice S5 and the
// pack ships with the scan image (SP-5, D-125), so the scanner is "not available" (can_scan=false, 503
// scanner_unavailable) and nothing is ever sent until then.
func scanService(d deps) *scan.Service {
	scanMu.Lock()
	defer scanMu.Unlock()
	if s := scanServices[d.DB]; s != nil {
		return s
	}
	cfg := scan.Config{DB: d.DB, Audit: d.Audit, Inventory: scanInventory{inv: d.Inventory}, External: scanExternal{svc: exposureService(d)}, Log: d.Log, Clock: d.Clock}
	if d.Findings != nil {
		cfg.Findings = scanFindings{svc: d.Findings}
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Publisher = d.Bus
	}
	svc, err := scan.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	scanServices[d.DB] = svc
	return svc
}

// scanInventory is the inventory as the scan module sees it (scan.Inventory): read only (scan INV-11).
type scanInventory struct{ inv *inventory.Service }

func (s scanInventory) Scope(ctx context.Context) (scan.Scope, error) {
	if s.inv == nil {
		return scan.Scope{}, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return scan.Scope{}, err
	}
	sc := scan.Scope{Networks: st.LANRanges}
	if st.ScopeConfirmedAt != nil {
		sc.ConfirmedAt = *st.ScopeConfirmedAt
	}
	if st.ScopeConfirmedBy != nil {
		sc.ConfirmedBy = *st.ScopeConfirmedBy
	}
	return sc, nil
}

func (s scanInventory) Devices(ctx context.Context) ([]scan.Device, error) {
	if s.inv == nil {
		return nil, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	list, err := s.inv.Devices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]scan.Device, 0, len(list.Items))
	for _, d := range list.Items {
		label := d.IP
		if d.Hostname != nil && *d.Hostname != "" {
			label = *d.Hostname
		}
		sd := scan.Device{ID: d.ID, Label: label, IP: d.IP, Kind: d.Kind, Approved: d.Approved, Fragile: d.Fragile}
		for _, sv := range d.Services {
			if sv.Proto == "" || sv.Proto == "tcp" {
				sd.Services = append(sd.Services, scan.OpenPort{Port: sv.Port, Name: sv.Name})
			}
		}
		out = append(out, sd)
	}
	return out, nil
}

// VulnScanPolicy is inventory's D-126 policy. ponytail: inventory's decision carries sensor-active's rate, not
// whether the device is fragile or unclassified; Careful is taken from the device row (a fragile or unclassified
// device is always slowed, even one allowed regular scans: the safe side), until inventory says it (deferred).
func (s scanInventory) VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (scan.Decision, error) {
	if s.inv == nil {
		return scan.Decision{}, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	dec, err := s.inv.VulnScanPolicy(ctx, assetID, explicit)
	if err != nil {
		return scan.Decision{}, err
	}
	out := scan.Decision{Allowed: dec.Allowed, Reason: dec.Reason}
	if dec.Allowed {
		d, err := s.inv.Device(ctx, assetID)
		if err != nil {
			return scan.Decision{}, err
		}
		out.Careful = d.Fragile || d.Kind == "unknown"
	}
	return out, nil
}

// scanFindings is the findings module as scan needs it (scan.Findings).
type scanFindings struct{ svc *findings.Service }

func (f scanFindings) List(ctx context.Context, assetID string) ([]scan.FindingRef, error) {
	rs, err := f.svc.List(ctx, assetID)
	if err != nil {
		return nil, err
	}
	out := make([]scan.FindingRef, 0, len(rs))
	for _, r := range rs {
		out = append(out, scan.FindingRef{ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: string(r.Status)})
	}
	return out, nil
}

func (f scanFindings) ConfirmFromScan(ctx context.Context, assetID, cve string, ev scan.Evidence) (string, error) {
	r, err := f.svc.ConfirmFromScan(ctx, assetID, cve, findings.Evidence{Summary: ev.Summary, Template: ev.Template, Request: ev.Request, Response: ev.Response, CheckedAt: ev.CheckedAt})
	return r.ID, err
}

func (f scanFindings) RescanClear(ctx context.Context, assetID, cve string) error {
	return f.svc.RescanClear(ctx, assetID, cve)
}

// scanExternal lists the exposure targets for the scan list (listed, not scanned yet: D-126 (4)).
type scanExternal struct{ svc *exposure.Service }

func (e scanExternal) Targets(ctx context.Context) ([]scan.ExternalTarget, error) {
	ts, err := e.svc.Targets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]scan.ExternalTarget, 0, len(ts))
	for _, t := range ts {
		ip := "—"
		if t.Kind == exposure.KindIP {
			ip = t.Value
		}
		out = append(out, scan.ExternalTarget{ID: t.ID, Value: t.Value, IP: ip, Verified: t.VerifiedAt != nil, Expired: t.Validity != nil && *t.Validity == "expired"})
	}
	return out, nil
}

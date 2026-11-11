package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
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
	var inv scanInv // a nil *inventory.Service inside the interface would not compare equal to nil
	if d.Inventory != nil {
		inv = d.Inventory
	}
	cfg := scan.Config{DB: d.DB, Audit: d.Audit, Inventory: scanInventory{inv: inv}, External: scanExternal{svc: exposureService(d)}, Log: d.Log, Clock: d.Clock,
		Location: orgLocationAt(d)} // the window and the schedule are in the organization's zone (review H1); nil (no core, a failed read, an unknown name) starts nothing automated
	if d.Findings != nil {
		cfg.Findings = scanFindings{svc: d.Findings}
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Publisher = d.Bus
	}
	cfg.KEV = scanKEV{feedsKEV{&d}} // the catch-up of new_kev the bus did not bring (S4b, D-144)
	if d.SensorDispatcher != nil {  // S5: the worker in the scan container, over the sensor link, against the pack of its image
		ix, err := nucleipack.Index()
		if err != nil { // a test holds the committed index to pack.Parse: a programming error
			panic("vedette: the embedded nuclei pack index: " + err.Error())
		}
		cfg.Engine, cfg.Pack = scanEngine{d.SensorDispatcher}, ix
	}
	svc, err := scan.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	scanServices[d.DB] = svc
	return svc
}

// scanInventory is the inventory as the scan module sees it (scan.Inventory): read only (scan INV-11).
type scanInventory struct{ inv scanInv }

// scanInv is the part of *inventory.Service the adapter reads (a test counts the reads).
type scanInv interface {
	Settings(ctx context.Context) (inventory.Settings, error)
	Devices(ctx context.Context) (inventory.DeviceList, error)
	VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (inventory.ScanDecision, error)
}

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

// VulnScanPolicy is inventory's D-126 policy; Careful (fragile or unclassified, slowed even when regular scans are
// allowed: the safe side) and the IP come from the same read as the decision. ponytail: scan.Inventory has no
// batch method, so this is one inventory read per device; inventory.VulnScanPolicies is there when it gets one.
func (s scanInventory) VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (scan.Decision, error) {
	if s.inv == nil {
		return scan.Decision{}, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	dec, err := s.inv.VulnScanPolicy(ctx, assetID, explicit)
	if errors.Is(err, inventory.ErrNotFound) { // deleted since the device list was read: it leaves the list (scan review L6)
		return scan.Decision{Reason: scan.ReasonGone}, nil
	}
	if err != nil {
		return scan.Decision{}, err
	}
	out := scan.Decision{Allowed: dec.Allowed, Reason: dec.Reason}
	if dec.Allowed {
		out.Careful, out.IP = dec.Careful, dec.IP.String()
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

// scanJobs is the Jobs func of the scan entry in wiredModules: KEV rescans, the schedule, retention, recovery (S-SCAN-2, S-SCAN-4).
func scanJobs(d deps) []jobs.Job { return scan.Jobs(scanService(d)) }

// onNewKEVForScan queues the rescan of a new KEV entry that has a scan template (scan INV-9); the job does the scan.
func onNewKEVForScan(d deps) func(ctx context.Context, data any) error {
	return func(ctx context.Context, data any) error {
		ev, ok := data.(feeds.NewKEVEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		return scanService(d).OnNewKEV(ctx, scan.NewKEV{CVE: ev.CVE, Vendor: ev.Vendor, Product: ev.Product, HasTemplate: ev.HasTemplate})
	}
}

// scanKEV is feeds' record of the KEV entries it announced, as scan reads it (scan.KEVFeed): nothing while feeds is
// off, since then nothing is announced.
type scanKEV struct{ src feedsKEV }

func (k scanKEV) NewKEVSince(ctx context.Context, at time.Time, cve string, limit int) ([]scan.AnnouncedKEV, error) {
	st, ok := k.src.store()
	if !ok {
		return nil, nil
	}
	list, err := st.NewKEVSince(ctx, at, cve, limit)
	if err != nil {
		return nil, err
	}
	out := make([]scan.AnnouncedKEV, len(list))
	for i, e := range list {
		out[i] = scan.AnnouncedKEV{NewKEV: scan.NewKEV{CVE: e.CVE, Vendor: e.Vendor, Product: e.Product, HasTemplate: e.HasTemplate}, At: e.At}
	}
	return out, nil
}

// scanEngine is the scan container's worker as scan sees it (scan.Engine, S5): the Dispatcher of sensor-active, over the
// sensor protocol (D-125). A run goes out as template ids of the pack core planned with; the Dispatcher checks the
// grammar again, refuses a job planned for another pack before anything is sent (D-133 (4)), and parses nuclei's lines
// fail closed. "Cannot run any job now" (the worker gone or not ready, another pack, a pack that failed its integrity
// check) is handed to scan as scan.ErrEngineDown, so the run stops with the Dispatcher's message.
type scanEngine struct{ d sensoractive.Scanner }

func (e scanEngine) Ready(ctx context.Context) error { return e.d.Ready(ctx) }

func (e scanEngine) Run(ctx context.Context, j scan.Job) ([]nucleiout.Result, error) {
	res, err := e.d.RunNuclei(ctx, sensoractive.NucleiRequest{PackVersion: j.PackVersion, PackSHA256: j.PackSHA256, Templates: j.IDs,
		Targets: j.Targets, Rate: j.Rate, MaxHostErrors: j.MaxHostErrors})
	if errors.Is(err, sensoractive.ErrScannerUnavailable) || errors.Is(err, sensoractive.ErrPackMismatch) || errors.Is(err, sensoractive.ErrPackInvalid) {
		return nil, fmt.Errorf("%w: %w", scan.ErrEngineDown, err)
	}
	return res, err
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
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
	"github.com/knt048/vedette/modules/scan/surface"
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
		cfg.Identify = scanIdentify{d} // D-501: Scan now identifies each device with sensor-active's nmap scan first
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
	VulnScanPolicies(ctx context.Context, assetIDs []string, explicit bool) (map[string]inventory.ScanDecision, error)
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

// deviceLabel names a device as the Devices page does (inventory.Names): hostname, else vendor and model, else the IP. A
// hand-added or LLDP-only device has no IP and must still show its name in the scan list and the reports (D-484).
func deviceLabel(d inventory.AssetCore) string {
	if d.Hostname != nil && *d.Hostname != "" {
		return *d.Hostname
	}
	var hw []string
	for _, o := range []*inventory.Observed{d.Vendor, d.Model} {
		if o != nil && strings.TrimSpace(o.Value) != "" {
			hw = append(hw, strings.TrimSpace(o.Value))
		}
	}
	if len(hw) > 0 {
		return strings.Join(hw, " ")
	}
	return d.IP
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
		sd := scan.Device{ID: d.ID, Label: deviceLabel(d.AssetCore), IP: d.IP, Kind: d.Kind, Approved: d.Approved, Fragile: d.Fragile, LastSeen: d.LastSeen}
		if d.MAC != nil {
			sd.MAC = *d.MAC
		}
		if d.Vendor != nil {
			sd.Vendor = d.Vendor.Value
		}
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
// allowed: the safe side) and the IP come from the same read as the decision. Used for the re-check of one device
// right before its job leaves core (scan INV-1); lists use VulnScanPolicies.
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
	return scanDecision(dec), nil
}

// VulnScanPolicies is inventory.VulnScanPolicies in chunks of inventory.MaxPolicyBatch (D-472): one settings read and
// one query per chunk instead of one read per device. A device deleted since the list was read is absent.
func (s scanInventory) VulnScanPolicies(ctx context.Context, assetIDs []string, explicit bool) (map[string]scan.Decision, error) {
	if s.inv == nil {
		return nil, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	out := make(map[string]scan.Decision, len(assetIDs))
	for c := range slices.Chunk(assetIDs, inventory.MaxPolicyBatch) {
		m, err := s.inv.VulnScanPolicies(ctx, c, explicit)
		if err != nil {
			return nil, err
		}
		for id, dec := range m {
			out[id] = scanDecision(dec)
		}
	}
	return out, nil
}

func scanDecision(dec inventory.ScanDecision) scan.Decision {
	out := scan.Decision{Allowed: dec.Allowed, Reason: dec.Reason}
	if dec.Allowed {
		out.Careful, out.IP = dec.Careful, dec.IP.String()
	}
	return out
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

// scanIdentify is sensor-active's identification as scan sees it (scan.Identifier, D-501): an nmap device scan of a device a person
// picked in Scan now, recorded in the inventory. It runs only while sensor-active is on (SYS-5); off, every device says unavailable.
// The service is looked up at each call: scanService and sensorActiveService are built in either order.
type scanIdentify struct{ d deps }

func (i scanIdentify) Identify(ctx context.Context, assetID string) (scan.Identification, error) {
	if i.d.Reg != nil && !i.d.Reg.Enabled("sensor-active") {
		return scan.Identification{Why: sensoractive.WhyUnavailable}, nil
	}
	svc, err := sensorActiveService(i.d) //nolint:contextcheck // built once per database; its zone lookup has its own short budget
	if err != nil {
		return scan.Identification{}, err
	}
	got, err := svc.IdentifyDevice(ctx, assetID)
	switch {
	case errors.Is(err, sensoractive.ErrStopped) && ctx.Err() != nil: // the run's context: the person's Stop now, or the run's end
		return scan.Identification{}, scan.ErrIdentifyStopped
	case errors.Is(err, sensoractive.ErrStopped): // sensor-active stopped it by itself: the device, the settings or the module changed
		return scan.Identification{}, scan.ErrIdentifyInterrupted
	case errors.Is(err, sensoractive.ErrNotFound):
		return scan.Identification{Why: scan.ReasonGone}, nil
	case err != nil:
		return scan.Identification{}, err
	}
	return scan.Identification{Found: got.Found, Why: got.Why}, nil
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

func (e scanEngine) Run(ctx context.Context, j scan.Job) (nucleiout.Outcome, error) {
	res, err := e.d.RunNuclei(ctx, sensoractive.NucleiRequest{PackVersion: j.PackVersion, PackSHA256: j.PackSHA256, Templates: j.IDs,
		Targets: j.Targets, Rate: j.Rate, MaxHostErrors: j.MaxHostErrors})
	if errors.Is(err, sensoractive.ErrScannerUnavailable) || errors.Is(err, sensoractive.ErrPackMismatch) || errors.Is(err, sensoractive.ErrPackInvalid) {
		return nucleiout.Outcome{}, fmt.Errorf("%w: %w", scan.ErrEngineDown, err)
	}
	return res, err
}

// scanRunner is the scan module's exposure.Runner (D-229, exposure INV-12, scan INV-12): the surface scan of modules/scan/surface,
// within D-57 (7) and LEGAL §3. A domain's names (certificate transparency) are resolved and listed and get HTTP checks by name on
// 80 and 443; an address is port-scanned only when exposure says it is a verified IP target that may be scanned now
// (ScannableIP). Every probe goes to the scan module's probe log first. It runs only while the scan module is on: off, a scan
// answers 409 module_off and nothing is probed, and switching it off stops a scan that runs (SYS-5).
func scanRunner(d deps) exposure.Runner {
	r := &exposureRunner{
		on:      func() bool { return d.Reg == nil || d.Reg.Enabled("scan") }, // a nil Reg: tests that build by hand
		running: map[*int]context.CancelCauseFunc{},
		log:     d.Log,
		// Both services are asked when a scan runs, not here: exposureService builds this runner, and scanService builds exposure's.
		scope: func(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
			return exposureService(d).ScannableIP(ctx, actor, ip)
		},
	}
	s, err := surface.New(surface.Config{Public: exposure.IsPublicIPv4, Probes: scanProbeLog{d: d}, Log: d.Log})
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	r.scan = s
	if d.Reg != nil {
		d.Reg.OnChange(func(id string, enabled bool) {
			if id == "scan" && !enabled {
				r.stopAll()
			}
		})
	}
	return r
}

// scanProbeLog is the scan module's probe log as the surface scan writes it (scan INV-7, INV-12).
type scanProbeLog struct{ d deps }

func (l scanProbeLog) Record(ctx context.Context, ps []surface.Probe) error {
	rows := make([]scan.ExternalProbe, len(ps))
	for i, p := range ps {
		rows[i] = scan.ExternalProbe{ID: p.ID, IP: p.Addr.String(), Label: p.Label, Template: "exposure: " + p.Kind, Request: p.Request, Answered: p.Answered}
	}
	return scanService(l.d).RecordExternalProbes(ctx, rows)
}

// surfaceScan is the part of *surface.Scanner the runner calls (a test hands it a fake that probes nothing).
type surfaceScan interface {
	Domain(ctx context.Context, domain string, mayScanPorts func(context.Context, netip.Addr) bool) (surface.Result, error)
	IP(ctx context.Context, ip netip.Addr) (surface.Result, error)
}

// errScanSwitchedOff is the cause of a scan's context when the scan module is switched off while it runs.
var errScanSwitchedOff = errors.New("vedette: the scan module was switched off")

type exposureRunner struct {
	on    func() bool
	scan  surfaceScan
	scope func(ctx context.Context, actor string, ip netip.Addr) (bool, error)
	log   *slog.Logger

	mu      sync.Mutex
	running map[*int]context.CancelCauseFunc // the scans that run now, stopped when the module is switched off
}

// stopAll cancels every scan that runs (the module was switched off). It does not block: it runs on the registry's goroutine.
func (r *exposureRunner) stopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, cancel := range r.running {
		cancel(errScanSwitchedOff)
	}
}

func (r *exposureRunner) Scan(ctx context.Context, t exposure.ScanTarget) (exposure.Content, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	key := new(int)
	r.mu.Lock()
	r.running[key] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.running, key)
		r.mu.Unlock()
	}()
	if !r.on() { // checked after the scan is registered, so a switch-off cannot fall between the check and the stop
		return exposure.Content{}, exposure.ErrScanOff
	}
	var res surface.Result
	var err error
	switch t.Kind {
	case exposure.KindDomain:
		res, err = r.scan.Domain(ctx, t.Value, func(ctx context.Context, ip netip.Addr) bool {
			ok, err := r.scope(ctx, t.User, ip)
			if err != nil { // fail closed: no port scan of an address exposure could not vouch for
				r.log.ErrorContext(ctx, "exposure_scan_scope_failed", "ip", ip.String(), "error", err)
			}
			return ok && err == nil
		})
	case exposure.KindIP:
		ip, perr := netip.ParseAddr(t.Value)
		if perr != nil {
			return exposure.Content{}, fmt.Errorf("vedette: scanning %q: %w", t.Value, perr)
		}
		res, err = r.scan.IP(ctx, ip)
	default:
		return exposure.Content{}, fmt.Errorf("vedette: scanning %q: unknown kind %q", t.Value, t.Kind)
	}
	switch {
	case errors.Is(context.Cause(ctx), errScanSwitchedOff): // even a scan that finished: the module is off now, nothing is kept
		return exposure.Content{}, exposure.ErrScanOff
	case err == nil:
	case ctx.Err() != nil: // the person hung up: not a fault of the targets
		return exposure.Content{}, err
	case errors.Is(err, surface.ErrCT):
		return exposure.Content{}, fmt.Errorf("%w (%w)", exposure.ErrCTDown, err)
	case errors.Is(err, surface.ErrTooManyNames):
		return exposure.Content{}, exposure.TooManyNames(t.Value)
	case errors.Is(err, surface.ErrTooLong):
		return exposure.Content{}, exposure.ErrScanTooLong
	default:
		return exposure.Content{}, err
	}
	return contentOf(res), nil
}

// contentOf is a surface result in exposure's shape; exposure limits it again before storing it (INV-10).
func contentOf(r surface.Result) exposure.Content {
	c := exposure.Content{Hosts: []exposure.HostRow{}, Ports: []exposure.PortRow{}, AdminPanels: []exposure.AdminRow{}, Certs: []exposure.CertRow{}}
	for _, h := range r.Hosts {
		c.Hosts = append(c.Hosts, exposure.HostRow{Name: h.Name, IP: h.IP.String()})
	}
	for _, p := range r.Ports {
		c.Ports = append(c.Ports, exposure.PortRow{IP: p.IP.String(), Port: p.Port, Service: p.Service, Product: p.Product})
	}
	for _, a := range r.Admin {
		risk := "warn"
		if a.Danger {
			risk = "danger"
		}
		c.AdminPanels = append(c.AdminPanels, exposure.AdminRow{URL: a.URL, Product: a.Product, IP: a.IP.String(), Port: a.Port, Risk: risk})
	}
	for _, x := range r.Certs {
		c.Certs = append(c.Certs, exposure.CertRow{Host: x.Host, Issuer: x.Issuer, ExpiresAt: x.NotAfter.UTC().Format(time.RFC3339)})
	}
	return c
}

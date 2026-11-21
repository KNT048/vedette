package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	_ "time/tzdata" // zone names resolve in a container with no OS zone data (the windows are read in a named zone)

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

var (
	saMu       sync.Mutex
	saServices = map[*store.DB]*sensoractive.Service{}
)

// sensorActiveService builds the sensor-active service once per database, so its jobs and its event handlers
// share one instance (and one "one nmap at a time" lock), like feedsService. The inventory must be built first.
//
// ctx is the caller's: the service keeps only its values (context.WithoutCancel) for the time-zone reads of orgLocation, since it
// outlives any one caller. The first caller's ctx is kept for the life of the process, so a request's context must never be the first
// to build it: keep today's order, where the module's jobs (sensorActiveJobs) or newHandler (the server's start-up ctx) build it before
// any request runs; scanIdentify and the others only find the cached one (#715).
func sensorActiveService(ctx context.Context, d deps) (*sensoractive.Service, error) {
	saMu.Lock()
	defer saMu.Unlock()
	if s := saServices[d.DB]; s != nil {
		return s, nil
	}
	if d.SensorDispatcher == nil {
		return nil, errors.New("sensor-active needs the dispatcher of the sensor link")
	}
	// Production never runs nmap in this process: the Dispatcher hands the command to the worker in the scan
	// container, and the service reads nmap's health from the worker's heartbeat (the Dispatcher is the Prober itself, so its
	// NmapHealth is found by the service's type assertion).
	s, err := newSensorActive(ctx, d, d.SensorDispatcher, d.Runs)
	if err != nil {
		return nil, err
	}
	saServices[d.DB] = s
	if d.Lifecycle != nil { // once per database, like the service: its rows move with a merged device and go with a deleted one
		d.Lifecycle.Register(sensorActiveParticipant(s))
	}
	return s, nil
}

// snmpService is the sensor-active service for the SNMP credential handlers: nil, so they answer 501, when it cannot be
// built (no dispatcher or no inventory, as in some tests); the error is logged where the module's jobs are registered.
func snmpService(ctx context.Context, d deps) *sensoractive.Service {
	if d.SensorDispatcher == nil || d.Inventory == nil {
		return nil
	}
	s, err := sensorActiveService(ctx, d)
	if err != nil {
		return nil
	}
	return s
}

// newSensorActive builds the service over the real inventory (through sensorInventory and core/observe) and
// subscribes its reactions on d.Bus. A subscription acts only while the module is on (SYS-5); a handler error is
// logged by the bus and never reaches the publisher.
//
// Production passes the Dispatcher (sensorActiveService, the only non-test caller); the parameter exists so the tests can pass a
// local Prober on a fake nmap. nil is refused: Config would then fall back to starting nmap in this process.
//
// runs is the box's run manager the module's kinds are registered on (one service per database registers them); nil (a test's own
// service) gives the service a run manager of its own over the database.
func newSensorActive(ctx context.Context, d deps, prober sensoractive.Prober, runs *corerun.Manager) (*sensoractive.Service, error) {
	if d.Inventory == nil {
		return nil, errors.New("sensor-active needs the inventory service")
	}
	if prober == nil { // a nil Prober would make the module start nmap in this process
		return nil, errors.New("sensor-active needs a Prober")
	}
	cfg := sensoractive.Config{Prober: prober, DB: d.DB, Inventory: sensorInventory{inv: d.Inventory, hostNet: d.HostNet}, Observe: d.Inventory, Software: d.Inventory, Services: d.Inventory, Clock: d.Clock, Log: d.Log,
		Location: orgLocation(ctx, d), Secrets: d.Secrets, Audit: d.Audit, // SNMP reads go through the same Dispatcher
		LocalPrefixes: func(ctx context.Context) []netip.Prefix { return boxNetworks(ctx, d.HostNet) }}
	if runs != nil { // a nil *run.Manager inside the field would not compare equal to nil; the kinds are registered before the manager starts
		cfg.Runs = runs
	}
	if d.Bus != nil {
		cfg.Events = sensoractive.PublisherFunc(func(ctx context.Context, e sensoractive.Event) error {
			return d.Bus.Publish(ctx, events.Event{Name: e.Name, Data: e.Data})
		})
	}
	svc, err := sensoractive.New(cfg) //nolint:contextcheck // a run manager of the service's own (tests) lives as long as the service, not a request
	if err != nil {
		return nil, err
	}
	// a scope active discovery could not sweep within a week is refused when it is saved, with the numbers (the range form's rule)
	d.Inventory.SetScopeCost(func(ctx context.Context, st inventory.Settings) inventory.ScopeCost {
		return sweepCost(ctx, d, sensoractive.Settings{LANRanges: st.LANRanges, Exclusions: st.Active.Exclusions, Days: st.Active.Days,
			From: st.Active.From, To: st.Active.To, Rate: st.Active.Rate})
	})
	// A remote worker (the Dispatcher) cannot have reported this early, so only a local nmap is worth a warning at start; the
	// status page says whether the worker reports.
	_, remote := prober.(*sensoractive.Dispatcher)
	if h := svc.Health(ctx); !remote && h.Status != "ok" && d.Log != nil {
		d.Log.WarnContext(ctx, "sensor-active is unavailable", "reason", h.Message)
	}
	if d.Reg != nil { // turning the module off stops the nmap run in progress, also an identification for Scan now
		d.Reg.OnChange(func(id string, enabled bool) { //nolint:contextcheck // a module switch has no context; Stop ends the module's runs on their own
			switch {
			case id != "sensor-active":
			case enabled:
				svc.Resume() // SNMP reads may be sent again (#855)
			default:
				svc.Stop()
			}
		})
		if !d.Reg.Enabled("sensor-active") {
			svc.Stop() //nolint:contextcheck // off at start: nothing SNMP leaves until the module is turned on
		}
	}
	if d.Bus == nil {
		return svc, nil
	}
	on := func(fn func(ctx context.Context, data any) error) events.Handler {
		return func(ctx context.Context, e events.Event) error {
			if d.Reg != nil && !d.Reg.Enabled("sensor-active") {
				return nil
			}
			return fn(ctx, e.Data)
		}
	}
	// A device another sensor saw first waits in the queue for the next window; the queue survives a restart.
	d.Bus.Subscribe(inventory.EventAssetDiscovered, on(func(ctx context.Context, data any) error {
		ev, ok := data.(inventory.AssetEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		return svc.Enqueue(ctx, ev.AssetID, "discovered")
	}))
	// A change to the device being scanned right now (marked fragile, regular scan never, deleted...) stops the run.
	for _, name := range []string{inventory.EventAssetUpdated, inventory.EventAssetDeleted} {
		d.Bus.Subscribe(name, on(func(ctx context.Context, data any) error {
			ev, ok := data.(inventory.AssetEvent)
			if !ok {
				return fmt.Errorf("unexpected payload %T", data)
			}
			// A person turned the device's network scan on: it waits in the queue for the next window, as a new device does.
			if ev.ScanOn {
				if err := svc.Enqueue(ctx, ev.AssetID, "scan_on"); err != nil {
					return err
				}
			}
			return svc.AssetChanged(ctx, ev.AssetID)
		}))
	}
	// The SNMP settings and checks of a device move with a merged one and go with a deleted one inside the inventory's write
	// (sensorActiveParticipant, #829 C4); the bus only stops a run that holds the device (above).
	d.Bus.Subscribe(inventory.EventSettingsChanged, on(func(ctx context.Context, _ any) error {
		return svc.SettingsChanged(ctx)
	}))
	return svc, nil
}

// orgLocation is sensor-active's Config.Location: the organization time zone of core's general settings, read at
// every use so a change applies to the next window check without a restart (INV-3). nil (module falls back to
// the process zone) when core is not built or the read fails or names an unknown zone. The reads keep parent's values but not its
// end (the service outlives the caller that built it), each with its own 2 s budget. parent is held for the life of the process:
// never a request's context (see sensorActiveService).
func orgLocation(parent context.Context, d deps) func() *time.Location {
	base, zone := context.WithoutCancel(parent), orgTimeZone(&d)
	return func() *time.Location { return zone(base) }
}

// sensorActiveJobs is the Jobs func of the sensor-active entry in wiredModules: the window tick every minute and
// the daily prune of the probe log.
func sensorActiveJobs(d deps) []jobs.Job {
	svc, err := sensorActiveService(context.Background(), d) // the Jobs func of wiredModules has no context; the service keeps none
	if err != nil {
		d.Log.Error("sensor-active: the module cannot start, its jobs are not registered", "error", err)
		return nil
	}
	return []jobs.Job{
		{Module: "sensor-active", Name: "window-tick", Every: time.Minute, Run: svc.Tick},
		{Module: "sensor-active", Name: "prune-probes", Every: 24 * time.Hour, Run: func(ctx context.Context) error {
			_, err := svc.Prune(ctx)
			return err
		}},
	}
}

// sensorInventory implements sensoractive.Inventory over inventory.Service: it converts the inventory's neutral
// types to the module's port types so sensor-active never imports the inventory.
type sensorInventory struct {
	inv *inventory.Service
	// hostNet is deps.HostNet: the addresses of the appliance's cards, which core's container cannot see. nil without a host.
	hostNet *hostNetCache
}

func (a sensorInventory) Settings(ctx context.Context) (sensoractive.Settings, error) {
	st, err := a.inv.Settings(ctx)
	if err != nil {
		return sensoractive.Settings{}, err
	}
	return sensoractive.Settings{
		Enabled: st.Active.Enabled, ScopeConfirmed: st.ScopeConfirmedAt != nil,
		LANRanges: st.LANRanges, Exclusions: st.Active.Exclusions,
		Days: st.Active.Days, From: st.Active.From, To: st.Active.To, Rate: st.Active.Rate,
	}, nil
}

func (a sensorInventory) InScope(ctx context.Context, ip netip.Addr) (bool, error) {
	return a.inv.InScope(ctx, ip)
}

func (a sensorInventory) ScanPolicy(ctx context.Context, assetID string) (sensoractive.Decision, error) {
	dec, err := a.inv.ScanPolicy(ctx, assetID)
	if errors.Is(err, inventory.ErrNotFound) {
		return sensoractive.Decision{}, sensoractive.ErrNotFound
	}
	if err != nil {
		return sensoractive.Decision{}, err
	}
	return sensoractive.Decision{Allowed: dec.Allowed, Rate: dec.Rate, Reason: dec.Reason, FirstGentle: dec.Reason == inventory.ReasonFirstGentleScan,
		Fragile: dec.Fragile, Unclassified: dec.Unclassified, Never: dec.Never}, nil
}

// SNMPPolicy implements sensoractive.Inventory.
func (a sensorInventory) SNMPPolicy(ctx context.Context, assetID string) (sensoractive.Decision, error) {
	dec, err := a.inv.SNMPPolicy(ctx, assetID)
	if errors.Is(err, inventory.ErrNotFound) {
		return sensoractive.Decision{}, sensoractive.ErrNotFound
	}
	if err != nil {
		return sensoractive.Decision{}, err
	}
	return sensoractive.Decision{Allowed: dec.Allowed, Rate: dec.Rate, Reason: dec.Reason, FirstGentle: dec.Reason == inventory.ReasonFirstGentleScan,
		Fragile: dec.Fragile, Unclassified: dec.Unclassified, Never: dec.Never}, nil
}

// PendingGentleScans implements sensoractive.PendingGentle.
func (a sensorInventory) PendingGentleScans(ctx context.Context) ([]string, error) {
	return a.inv.PendingGentleScans(ctx)
}

func (a sensorInventory) MarkFirstScan(ctx context.Context, assetID string) error {
	err := a.inv.MarkFirstScan(ctx, assetID)
	if errors.Is(err, inventory.ErrNotFound) {
		return sensoractive.ErrNotFound
	}
	return err
}

func (a sensorInventory) Asset(ctx context.Context, assetID string) (sensoractive.Asset, error) {
	refs, err := a.inv.DeviceRefs(ctx, []string{assetID})
	if err != nil {
		return sensoractive.Asset{}, err
	}
	r, ok := refs[assetID]
	if !ok {
		return sensoractive.Asset{}, sensoractive.ErrNotFound
	}
	ip, _ := netip.ParseAddr(r.IP) // "—" (no IP known) gives the zero Addr
	// The name in Vedette or the host name, else the model, else the vendor; else none ("a device"): Display may be a software or a kind.
	name := r.Vendor
	switch {
	case r.NameOrHost() != nil: // the name in Vedette, else the host name
		name = *r.NameOrHost()
	case r.Model != "":
		name = r.Model
	}
	return sensoractive.Asset{ID: r.ID, IP: ip, Approved: r.Approved, Name: name}, nil
}

func (a sensorInventory) Addresses(ctx context.Context) (map[netip.Addr]string, error) {
	m, err := a.inv.AddressMap(ctx) // uncapped
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]string, len(m))
	for s, id := range m {
		if ip, err := netip.ParseAddr(s); err == nil {
			out[ip] = id
		}
	}
	return out, nil
}

// KnownMACs is every MAC the inventory has, uncapped: the sweep charges only MACs not in it.
func (a sensorInventory) KnownMACs(ctx context.Context) ([]string, error) {
	return a.inv.KnownMACs(ctx)
}

// ProtectedIPs is the inventory's list plus the box's own addresses: the sweep must not probe the machine it runs on
// either. The addresses come from the container's interfaces and from vedette-host (state/net), which is where the
// LAN address of the appliance is.
func (a sensorInventory) ProtectedIPs(ctx context.Context) ([]netip.Addr, error) {
	out, err := a.inv.ProtectedIPs(ctx)
	if err != nil {
		return nil, err
	}
	return a.withBoxCards(ctx, out)
}

// BoxIPs is the inventory's box addresses (its device, the decoys) plus the box's cards, as in ProtectedIPs.
func (a sensorInventory) BoxIPs(ctx context.Context) ([]netip.Addr, error) {
	out, err := a.inv.BoxIPs(ctx)
	if err != nil {
		return nil, err
	}
	return a.withBoxCards(ctx, out)
}

// SNMPKnown implements sensoractive.Inventory (the devices the old credentials are moved to).
func (a sensorInventory) SNMPKnown(ctx context.Context) (read, on []string, err error) {
	return a.inv.SNMPKnown(ctx)
}

// TurnSNMPOn implements sensoractive.Inventory: saving SNMP on a device stores its SNMP switch on, audited as the person.
func (a sensorInventory) TurnSNMPOn(ctx context.Context, actor, assetID string) error {
	on := inventory.SourceOn
	_, err := a.inv.SetSources(ctx, actor, assetID, nil, &on)
	if errors.Is(err, inventory.ErrNotFound) {
		return sensoractive.ErrNotFound
	}
	return err
}

// boxNetworks is the IPv4 networks of the box's cards (the container's interfaces and the appliance's), for the sweep-time
// estimate: addresses there are reached with ARP.
func boxNetworks(ctx context.Context, hostNet *hostNetCache) []netip.Prefix {
	var out []netip.Prefix
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, x := range addrs {
			if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
				out = append(out, p.Masked())
			}
		}
	}
	for _, p := range hostNet.Get(ctx) {
		if p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}

// withBoxCards adds the addresses of the box's own cards: the container's interfaces and the appliance's (vedette-host state/net).
func (a sensorInventory) withBoxCards(ctx context.Context, out []netip.Addr) ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("sensor-active: read the box addresses: %w", err)
	}
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Is4() {
			out = append(out, p.Addr())
		}
	}
	return append(out, hostIPv4s(ctx, a.hostNet)...), nil
}

// SimilarDevices implements sensoractive.SimilarFinder.
func (a sensorInventory) SimilarDevices(ctx context.Context, assetID string) ([]sensoractive.SimilarDevice, error) {
	list, err := a.inv.SimilarDevices(ctx, assetID)
	if errors.Is(err, inventory.ErrNotFound) {
		return nil, sensoractive.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := make([]sensoractive.SimilarDevice, len(list))
	for i, d := range list {
		out[i] = sensoractive.SimilarDevice{ID: d.ID, IP: d.IP, Vendor: d.Vendor, Kind: d.Kind, SameMaker: d.SameMaker, SameType: d.SameType, Approved: d.Approved}
	}
	return out, nil
}

// sweepCost is what one pass of active discovery over st's scope costs (sensoractive Settings.Cost, the box's own networks at one
// packet an address), with the windows of a week: the range form's estimate and the inventory's refusal of a scope too large.
func sweepCost(ctx context.Context, d deps, st sensoractive.Settings) inventory.ScopeCost {
	c := st.Cost(boxNetworks(ctx, d.HostNet))
	days := map[int]bool{}
	for _, x := range st.Days {
		if x >= 1 && x <= 7 {
			days[x] = true
		}
	}
	return inventory.ScopeCost{Addresses: c.Addresses, Pass: c.Pass, Window: c.Window, Windows: c.Windows, WeekWindows: len(days)}
}

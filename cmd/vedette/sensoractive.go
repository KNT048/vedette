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
func sensorActiveService(d deps) (*sensoractive.Service, error) {
	saMu.Lock()
	defer saMu.Unlock()
	if s := saServices[d.DB]; s != nil {
		return s, nil
	}
	if d.SensorDispatcher == nil {
		return nil, errors.New("sensor-active needs the dispatcher of the sensor link")
	}
	// Production never runs nmap in this process (D-113, D-141): the Dispatcher hands the command to the worker in the scan
	// container, and the service reads nmap's health from the worker's heartbeat (the Dispatcher is the Prober itself, so its
	// NmapHealth is found by the service's type assertion).
	s, err := newSensorActive(d, d.SensorDispatcher)
	if err != nil {
		return nil, err
	}
	saServices[d.DB] = s
	return s, nil
}

// newSensorActive builds the service over the real inventory (through sensorInventory and core/observe) and
// subscribes its reactions on d.Bus. A subscription acts only while the module is on (SYS-5); a handler error is
// logged by the bus and never reaches the publisher.
//
// Production passes the Dispatcher (sensorActiveService, the only non-test caller); the parameter exists so the tests can pass a
// local Prober on a fake nmap. nil is refused: Config would then fall back to starting nmap in this process.
func newSensorActive(d deps, prober sensoractive.Prober) (*sensoractive.Service, error) {
	if d.Inventory == nil {
		return nil, errors.New("sensor-active needs the inventory service")
	}
	if prober == nil { // a nil Prober would make the module start nmap in this process
		return nil, errors.New("sensor-active needs a Prober")
	}
	cfg := sensoractive.Config{Prober: prober, DB: d.DB, Inventory: sensorInventory{inv: d.Inventory, hostNet: d.HostNet}, Observe: d.Inventory, Software: d.Inventory, Clock: d.Clock, Log: d.Log,
		Location: orgLocation(d)}
	if d.Bus != nil {
		cfg.Events = sensoractive.PublisherFunc(func(ctx context.Context, e sensoractive.Event) error {
			return d.Bus.Publish(ctx, events.Event{Name: e.Name, Data: e.Data})
		})
	}
	svc, err := sensoractive.New(cfg)
	if err != nil {
		return nil, err
	}
	if h := svc.Health(context.Background()); h.Status != "ok" && d.Log != nil {
		d.Log.Warn("sensor-active is unavailable", "reason", h.Message)
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
	// A device another sensor saw first waits in the queue for the next window (D-84 (6)); the queue survives a restart.
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
			return svc.AssetChanged(ctx, ev.AssetID)
		}))
	}
	d.Bus.Subscribe(inventory.EventSettingsChanged, on(func(ctx context.Context, _ any) error {
		return svc.SettingsChanged(ctx)
	}))
	return svc, nil
}

// orgLocation is sensor-active's Config.Location: the organization time zone of core's general settings, read at
// every use so a change applies to the next window check without a restart (INV-3). nil (module falls back to
// the process zone) when core is not built or the read fails or names an unknown zone.
func orgLocation(d deps) func() *time.Location {
	return func() *time.Location {
		if d.Core == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		name, err := d.Core.OrgTimeZone(ctx)
		if err != nil {
			return nil
		}
		loc, err := time.LoadLocation(name)
		if err != nil {
			return nil
		}
		return loc
	}
}

// sensorActiveJobs is the Jobs func of the sensor-active entry in wiredModules: the window tick every minute and
// the daily prune of the probe log.
func sensorActiveJobs(d deps) []jobs.Job {
	svc, err := sensorActiveService(d)
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
// types to the module's port types so sensor-active never imports the inventory (rules/modules.md).
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
	return sensoractive.Decision{Allowed: dec.Allowed, Rate: dec.Rate, Reason: dec.Reason, FirstGentle: dec.Reason == inventory.ReasonFirstGentleScan}, nil
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
	return sensoractive.Asset{ID: r.ID, IP: ip}, nil
}

func (a sensorInventory) Addresses(ctx context.Context) (map[netip.Addr]string, error) {
	m, err := a.inv.AddressMap(ctx) // uncapped (D-178)
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

// KnownMACs is every MAC the inventory has, uncapped: the sweep charges only MACs not in it (L8).
func (a sensorInventory) KnownMACs(ctx context.Context) ([]string, error) {
	return a.inv.KnownMACs(ctx)
}

// ProtectedIPs is the inventory's list plus the box's own addresses: the sweep must not probe the machine it runs on
// either (M2). The addresses come from the container's interfaces and from vedette-host (state/net), which is where the
// LAN address of the appliance is.
func (a sensorInventory) ProtectedIPs(ctx context.Context) ([]netip.Addr, error) {
	out, err := a.inv.ProtectedIPs(ctx)
	if err != nil {
		return nil, err
	}
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

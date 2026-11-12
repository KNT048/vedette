package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/inventory"
)

// The two folders under -honeypot-dir: core writes ConfigDir (opencanary.conf, honeytokens.json; WP-08 mounts it read-only
// into the honeypot container), the container writes LogDir (opencanary.jsonl; core only reads it).
const (
	HoneypotConfigDir = "config"
	HoneypotLogDir    = "log"
)

// newHoneypot builds the honeypot service once, in buildServices (deps.Honeypot): the job, the HTTP handler and the
// inventory subscription share it. The inventory must be built first. It subscribes its reaction on d.Bus.
func newHoneypot(d *deps) (*honeypot.Service, error) {
	if d.Inventory == nil {
		return nil, errors.New("honeypot needs the inventory service")
	}
	cfg := honeypot.Config{DB: d.DB, Audit: d.Audit, Secrets: d.Secrets, Inventory: honeypotInventory{inv: d.Inventory, hostNet: d.HostNet, decoys: func(ctx context.Context) []netip.Addr {
		if d.Honeypot == nil {
			return nil
		}
		return d.Honeypot.DecoyIPs(ctx)
	}, box: d.BoxName}, Host: newHoneypotHost(d),
		Clock: d.Clock, Log: d.Log, Location: orgLocationAt(*d)}
	if d.HoneypotDir != "" { // two folders (D-89, WP-14 review): core writes config/ (the container mounts it read-only), the container writes log/
		cfg.ConfigDir, cfg.LogDir = filepath.Join(d.HoneypotDir, HoneypotConfigDir), filepath.Join(d.HoneypotDir, HoneypotLogDir)
	}
	if d.Reg != nil {
		cfg.Modules = d.Reg
	}
	if d.Bus != nil {
		cfg.Events = honeypot.PublisherFunc(func(ctx context.Context, e honeypot.Event) error {
			return d.Bus.Publish(ctx, events.Event{Name: e.Name, Data: e.Data})
		})
	}
	svc, err := honeypot.New(cfg)
	if err != nil {
		return nil, err
	}
	if d.Bus != nil {
		svc.Subscribe(d.Bus)
	}
	return svc, nil
}

// honeypotJobs is the Jobs func of the honeypot entry in wiredModules: the run loop (applies the state to the host,
// tails the OpenCanary log; it blocks until the module is turned off, the scheduler starts it again if it fails early)
// and the daily retention.
func honeypotJobs(d deps) []jobs.Job {
	if d.Honeypot == nil {
		return nil
	}
	return []jobs.Job{
		{Module: "honeypot", Name: "run", Every: 15 * time.Second, Run: d.Honeypot.Run},
		{Module: "honeypot", Name: "prune", Every: 24 * time.Hour, Run: func(ctx context.Context) error {
			_, err := d.Honeypot.Prune(ctx)
			return err
		}},
	}
}

// honeypotEnsureOff is the EnsureOff func of the honeypot entry in wiredModules (D-189).
func honeypotEnsureOff(d deps) modreg.Teardown {
	if d.Honeypot == nil {
		return nil
	}
	return d.Honeypot.EnsureOff
}

// notAnAppliance is the Host of a core without -host-socket (dev, a bare box, D-55): nothing can listen, and the module
// says why. With a socket, honeypotHost (honeypothost.go, D-161) talks to vedette-host.
type notAnAppliance struct{}

const notApplianceReason = "this machine is not an appliance: there is no vedette-host to run the honeypot container"

var errNoHost = errors.New("honeypot: there is no vedette-host on this machine")

func (notAnAppliance) Status(context.Context) (honeypot.HostStatus, error) {
	return honeypot.HostStatus{Reason: notApplianceReason}, nil
}
func (notAnAppliance) AddDecoyIP(context.Context, netip.Addr) error    { return errNoHost }
func (notAnAppliance) RemoveDecoyIP(context.Context, netip.Addr) error { return errNoHost }
func (notAnAppliance) StartContainer(context.Context, bool) error      { return errNoHost }
func (notAnAppliance) StopContainer(context.Context) error             { return errNoHost }

// honeypotInventory implements honeypot.Inventory over inventory.Service, converting to the module's types so the
// honeypot never imports the inventory (rules/modules.md).
type honeypotInventory struct {
	inv *inventory.Service
	// hostNet is deps.HostNet: the appliance's own addresses from vedette-host (nil without a host).
	hostNet *hostNetCache
	// decoys are the addresses the traps answer on: the host reports them among the box's addresses, but a decoy is never the box's own address.
	decoys func(context.Context) []netip.Addr
	box    *boxHostName // deps.BoxName: the box's name while the inventory has no box row (nil: "vedette")
}

func (a honeypotInventory) Devices(ctx context.Context) ([]honeypot.Device, error) {
	l, err := a.inv.AllDevices(ctx) // uncapped (D-178): a decoy must never be offered the address of a device the capped list forgot
	if err != nil {
		return nil, err
	}
	out := make([]honeypot.Device, 0, len(l))
	for _, d := range l {
		ip, _ := netip.ParseAddr(d.IP) // "—" (no IP known) gives the zero Addr
		x := honeypot.Device{ID: d.ID, IP: ip, Name: d.IP, Kind: d.Kind, Approved: d.Approved, IsBox: d.IsBox}
		if d.Hostname != nil {
			x.Hostname, x.Name = *d.Hostname, *d.Hostname
		}
		if d.OS != nil {
			x.OS = d.OS.Value
		}
		for _, s := range d.Services {
			x.Ports = append(x.Ports, s.Port)
		}
		out = append(out, x)
	}
	return out, nil
}

func (a honeypotInventory) LANRanges(ctx context.Context) ([]netip.Prefix, error) {
	st, err := a.inv.Settings(ctx)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, r := range st.LANRanges {
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// Box is the box device of the inventory; when it has no IP there (nothing has reported one yet) the address of one of
// its own interfaces inside a declared LAN range stands in, so the scanner of the box can still be told from a hit.
func (a honeypotInventory) Box(ctx context.Context) (honeypot.Box, error) {
	host, ip, found, err := a.inv.BoxName(ctx)
	if err != nil {
		return honeypot.Box{}, err
	}
	b := honeypot.Box{Name: a.box.Name(ctx)} // no box row yet: the name the row will get (#471), never the container's
	if found {
		if host != "" {
			b.Name = host
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			b.IP = a
		}
	}
	if b.IP.IsValid() {
		return b, nil
	}
	ranges, err := a.LANRanges(ctx)
	if err != nil {
		return b, err
	}
	// The appliance's own cards (vedette-host) come first: core's container only sees its bridge.
	var cand []netip.Addr
	var decoys []netip.Addr
	if a.decoys != nil {
		decoys = a.decoys(ctx)
	}
	for _, ip := range hostIPv4s(ctx, a.hostNet) {
		if !slices.Contains(decoys, ip) {
			cand = append(cand, ip)
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil && len(cand) == 0 {
		return b, fmt.Errorf("honeypot: read the box addresses: %w", err)
	}
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil && p.Addr().Is4() {
			cand = append(cand, p.Addr())
		}
	}
	for _, ip := range cand {
		for _, r := range ranges {
			if r.Contains(ip) {
				b.IP = ip
				return b, nil
			}
		}
	}
	return b, nil
}

// orgLocationAt is honeypot's Config.Location: the organization time zone of core's general settings, read at every use
// with the caller's context. nil (the module uses UTC) when core is not built or the read fails or names an unknown zone.
func orgLocationAt(d deps) func(ctx context.Context) *time.Location {
	return func(ctx context.Context) *time.Location {
		if d.Core == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
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

package main

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

var (
	logsMu       sync.Mutex
	logsServices = map[*store.DB]*logs.Service{}
)

// syslogHost is the address the syslog listener binds; empty (production) = every IPv4 address. Only the end-to-end box sets it (e2ebox_test.go), to loopback.
var syslogHost string

// logsService builds the logs service once per database, so the handlers, the purge job and the log export share it
// (nil without a logs.db: a test that builds deps by hand; serve always opens it).
// The volume (lines and counters) is deps.LogsDB, a file of its own next to the main database, so that a flood of syslog
// never waits for the writer of the main one. The syslog listener is a job of the module (logs.Jobs): no source, or the module off, no socket.
func logsService(d deps) *logs.Service {
	if d.LogsDB == nil { // only a test that builds deps by hand: serve always opens logs.db (run in main.go)
		return nil
	}
	logsMu.Lock()
	defer logsMu.Unlock()
	if s := logsServices[d.DB]; s != nil {
		return s
	}
	cfg := logs.Config{Config: d.DB, Volume: d.LogsDB, Audit: d.Audit, Inventory: logsInventory{d.Inventory}, Box: logsBox{d}, Log: d.Log, Clock: d.Clock}
	if d.Bus != nil { // logs.anomaly.detected, which notify opens an incident from (a nil *events.Bus in the interface would not be nil)
		cfg.Events = d.Bus
	}
	if d.SyslogPort != 0 {
		cfg.Syslog.Ports = []int{d.SyslogPort}
	}
	cfg.Syslog.Host = syslogHost
	cfg.NeverCount = logsNeverCount(&d) // D-210: TopAddresses never counts the box, its gateway or a decoy
	svc, err := logs.NewService(cfg)
	if err != nil { // a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	logsServices[d.DB] = svc
	return svc
}

// logsNeverCount is logs' Config.NeverCount: the addresses that the per-address counters never count, from the sources the box already has
// for "is this the box" (core/conn's boxSources, response's responseBoxAddrs): what vedette-host reports for the appliance and the
// decoys of the honeypot (an error while the host has not answered or the decoy record cannot be read: logs keeps its last set), plus the
// container's own addresses, its default gateway and the -hosts literals. Subnets are not listed (an interface of the container may sit
// on the LAN): only the addresses of the box itself.
func logsNeverCount(d *deps) func(context.Context) ([]netip.Addr, error) {
	host := notifyBoxAddrs(d.HostNet)
	decoys := lateDecoys{d}
	return func(ctx context.Context) ([]netip.Addr, error) {
		out, known := host()
		var err error
		if !known {
			err = errHostNetUnknown
		}
		if more, derr := decoys.DecoyIPsRead(ctx); derr != nil {
			err = derr
		} else {
			out = append(out, more...)
		}
		for _, p := range containerAddrs() {
			out = append(out, p.Addr())
		}
		if g, ok := procGateway(); ok {
			out = append(out, g)
		}
		for _, h := range d.Hosts {
			if a, perr := netip.ParseAddr(strings.Trim(h, "[]")); perr == nil {
				out = append(out, a)
			}
		}
		return out, err
	}
}

// logsJobs is the Jobs func of the logs entry in wiredModules.
func logsJobs(d deps) []jobs.Job {
	svc := logsService(d)
	if svc == nil {
		return nil
	}
	return logs.Jobs(svc)
}

// logsInventory answers "which device has this IP" for the sources list. inventory has no read by IP, so it lists every
// device with DevicesOfKind (no row cap, a read error is an error) and picks the addresses asked for; the list is small.
// A by-IP read in inventory would replace this (deferred, for Kiên).
type logsInventory struct{ inv *inventory.Service }

func (a logsInventory) DevicesByIP(ctx context.Context, ips []string) (map[string]logs.Device, error) {
	devs, err := a.inv.DevicesOfKind(ctx, inventory.Kinds)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[ip] = true
	}
	out := map[string]logs.Device{}
	for _, d := range devs {
		if !want[d.IP] {
			continue
		}
		name := d.IP
		if d.Hostname != nil && *d.Hostname != "" {
			name = *d.Hostname
		}
		out[d.IP] = logs.Device{ID: d.ID, Name: name}
	}
	return out, nil
}

// logsBox says where the box listens: its own address inside the first declared LAN range (nil when no range is declared,
// as the page expects) and its host name.
type logsBox struct{ d deps }

func (b logsBox) Info(ctx context.Context) (logs.BoxInfo, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "vedette"
	}
	info := logs.BoxInfo{Hostname: host}
	st, err := b.d.Inventory.Settings(ctx)
	if err != nil {
		return info, err
	}
	if len(st.LANRanges) == 0 {
		return info, nil
	}
	lan := st.LANRanges[0]
	info.LAN = &lan
	prefix, err := netip.ParsePrefix(lan)
	if err != nil || b.d.HostNet == nil {
		return info, nil //nolint:nilerr // an unreadable range or no host: the box address is simply unknown
	}
	for _, p := range b.d.HostNet.Get(ctx) {
		if a := p.Addr(); a.Is4() && prefix.Contains(a) {
			ip := a.String()
			info.IP = &ip
			break
		}
	}
	return info, nil
}

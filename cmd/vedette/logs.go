package main

import (
	"context"
	"crypto/tls"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

var (
	logsMu       sync.Mutex
	logsServices = map[*store.DB]*logs.Service{}
)

// syslogHost is the address the syslog listener binds; empty (production) = every IPv4 address. Only the end-to-end box sets it (e2ebox_test.go), to loopback.
var syslogHost string

// syslogTestTLS stands in for deps.SyslogTLS when the box serves no TLS. Only the end-to-end box sets it (TestE2EBox, e2ebox_test.go), to a
// certificate of its own: that box serves plain HTTP on loopback, and the TLS listener is otherwise unreachable from a browser spec.
// nil in production and in every other test.
var syslogTestTLS *tls.Config

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
	cfg := logs.Config{Config: d.DB, Volume: d.LogsDB, DataDir: d.DataDir, Audit: d.Audit, Inventory: logsInventory{inv: d.Inventory, snmp: logsSNMP(d)}, Box: logsBox{d}, Log: d.Log, Clock: d.Clock, Zone: orgTimeZone(&d),
		Secrets: d.Secrets, BoxAddrs: machineAddrs(&d), SelfAddrs: vedetteSelf(&d)} // the SIEM key is sealed; no SIEM on Vedette itself
	if d.Bus != nil { // logs.anomaly.detected, which notify opens an incident from (a nil *events.Bus in the interface would not be nil)
		cfg.Events = d.Bus
	}
	if d.SyslogPort != 0 {
		cfg.Syslog.Ports = []int{d.SyslogPort}
	}
	cfg.Syslog.Host = syslogHost
	// nil on a loopback or dev box: proto tls is refused and nothing listens for TLS
	cfg.Syslog.TLS = d.SyslogTLS
	cfg.TrustAnchor = d.TrustAnchor // what a device must trust for the box certificate (the box CA, or the owner's chain), shown on the Sources page
	if cfg.Syslog.TLS == nil {
		cfg.Syslog.TLS = syslogTestTLS
	}
	cfg.NeverCount = logsNeverCount(&d)       // TopAddresses never counts the box, its gateway or a decoy
	cfg.Feeds = logsFeeds{&d}                 // L4: destinations are looked up in the indicators of the feeds module (off: no hits)
	cfg.Hostname = d.BoxName.Name             // the HOSTNAME of SIEM records: the machine's name, not the container's (#471)
	cfg.Received = idsReceived(d)             // the stored lines go to the ids module, which reads the IPS events among them (while it is on)
	cfg.Incidents = incidentResolvedSince(&d) // a repeat inside a dedupe time after its incident was resolved is a new one
	svc, err := logs.NewService(cfg)
	if err != nil { // a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	if d.Bus != nil {
		svc.Subscribe(d.Bus) // the handlers queue only while the forwarder job runs, i.e. while the module is on; the box lives as long as the process
	}
	logsServices[d.DB] = svc
	return svc
}

// logsNeverCount is logs' Config.NeverCount: the addresses that the per-address counters never count, from the sources the box already has
// for "is this the box" (core/conn's boxSources, response's responseBoxAddrs): what vedette-host reports for the appliance and the
// decoys of the honeypot (an error while the host has not answered or the decoy record cannot be read: logs keeps its last set), plus the
// container's own addresses, the container's gateway, the LAN default gateway from the host's network state and the -hosts literals. Subnets are not listed (an interface of the container may sit
// on the LAN): only the addresses of the box itself.
func logsNeverCount(d *deps) func(context.Context) ([]netip.Addr, error) {
	host := notifyBoxAddrs(d.HostNet)
	decoys := lateDecoys{d}
	var state netStateReader
	if d.HostSocket != "" {
		state = hostclient.New(d.HostSocket)
	}
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
		out = append(out, procGateways()...) // the container's gateways: the bridge of the host
		// the LAN default gateway, which only the host can see (host-api state/net default_route)
		if state != nil {
			if st, serr := state.StateNet(ctx); serr != nil {
				err = serr
			} else if st.DefaultRoute != nil {
				if g, perr := netip.ParseAddr(st.DefaultRoute.Gateway); perr == nil {
					out = append(out, g)
				}
			}
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

// logsInventory answers "which devices have this address" for the sources list, an incident and a bad connection. inventory has no
// read by address, so it lists every device with DevicesOfKind (no row cap, a read error is an error) and indexes the addresses
// the box knows for each: the listed IP, and the read address a person typed for the device's SNMP (sensor-active's ReadAddresses:
// no secret is opened). The list is small.
type logsInventory struct {
	inv  *inventory.Service
	snmp func(ctx context.Context) (map[string]netip.Addr, error) // device id -> typed read address; nil: no SNMP settings
}

func (a logsInventory) DevicesAt(ctx context.Context, ips []string) (map[string][]logs.DeviceMatch, error) {
	devs, err := a.inv.DevicesOfKind(ctx, inventory.Kinds)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[ip] = true
	}
	via := map[string]map[string]string{} // address -> device id -> how
	add := func(ip, id, how string) {
		if !want[ip] {
			return
		}
		if via[ip] == nil {
			via[ip] = map[string]string{}
		}
		if via[ip][id] == "" { // the listed IP, added first, wins over a read address of the same device
			via[ip][id] = how
		}
	}
	known := make(map[string]bool, len(devs))
	approved := make(map[string]bool, len(devs))
	for _, d := range devs {
		known[d.ID] = true
		approved[d.ID] = d.Approved
		add(d.IP, d.ID, logs.ViaListedIP)
	}
	if a.snmp != nil {
		typed, err := a.snmp(ctx)
		if err != nil {
			return nil, err
		}
		for id, ip := range typed {
			if !known[id] || !want[ip.String()] {
				continue
			}
			// A person typed this address as that device's SNMP read address: it is that device. A device found by a scan at the
			// same address (a firewall's management interface is often scanned as a device of its own) is the same box seen
			// twice, so it does not make the address ambiguous; a device a person approved at it still does.
			for other := range via[ip.String()] {
				if !approved[other] && other != id {
					delete(via[ip.String()], other)
				}
			}
			add(ip.String(), id, logs.ViaSNMPRead)
		}
	}
	var ids []string
	for _, byID := range via {
		for id := range byID {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	// The name is the Devices page's: one light read of the matches. No address beside it: the sources list and a log
	// incident already show the sender's IP.
	st, err := notifyDevices{a.inv}.DeviceStates(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := map[string][]logs.DeviceMatch{}
	for ip, byID := range via {
		for id, how := range byID {
			name := ip
			if d, ok := st[id]; ok && d.Name != "" {
				name = d.Name
			}
			out[ip] = append(out[ip], logs.DeviceMatch{Device: logs.Device{ID: id, Name: name}, Via: how})
		}
		slices.SortFunc(out[ip], func(x, y logs.DeviceMatch) int { return strings.Compare(x.ID, y.ID) })
	}
	return out, nil
}

// logsSNMP reads the read addresses people typed for their devices' SNMP from the sensor-active service when it has been built (the
// module's jobs or the handlers build it at start-up; a request must never be the first to, see sensorActiveService). Not built, or
// a read that fails: no addresses, and a log source is still matched by its listed IP. A failure is logged once per streak of
// failures, not on every lookup.
func logsSNMP(d deps) func(ctx context.Context) (map[string]netip.Addr, error) {
	var failing atomic.Bool
	return func(ctx context.Context) (map[string]netip.Addr, error) {
		saMu.Lock()
		s := saServices[d.DB]
		saMu.Unlock()
		if s == nil {
			return nil, nil
		}
		m, err := s.ReadAddresses(ctx)
		if err != nil {
			if failing.CompareAndSwap(false, true) {
				d.Log.WarnContext(ctx, "logs: the SNMP read addresses of the devices could not be read; sources are matched by listed IP only", "err", err)
			}
			return nil, nil
		}
		failing.Store(false)
		return m, nil
	}
}

// logsBox says where the box listens: its own address inside the first declared LAN range (nil when no range is declared,
// as the page expects) and its host name.
type logsBox struct{ d deps }

func (b logsBox) Info(ctx context.Context) (logs.BoxInfo, error) {
	info := logs.BoxInfo{Hostname: b.d.BoxName.Name(ctx)}
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

// syslogTLS is the TLS configuration of the syslog-over-TLS listener (port 6514, #266 item 2): the HTTPS listener's own,
// cloned, so it presents the same certificate; the clone keeps the GetCertificate of a box-made pair, so a renewal is picked up with
// no restart, and the HTTPS-only parts (the "http/1.1" ALPN) are left behind. nil when the box serves no TLS (loopback or dev): there is
// no certificate to serve, so nothing may listen for TLS. logsService hands it to logs.Config.Syslog.TLS: the listener on 5515 (published as 6514) and the lifting of `tls_unavailable`.
func syslogTLS(https *tls.Config) *tls.Config {
	if https == nil {
		return nil
	}
	c := https.Clone()
	c.NextProtos = nil
	c.ClientAuth = tls.NoClientCert
	if c.MinVersion < tls.VersionTLS12 {
		c.MinVersion = tls.VersionTLS12
	}
	return c
}

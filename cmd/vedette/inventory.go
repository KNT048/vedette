package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	hostapi "github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// newInventory builds the inventory service from the shared deps; buildServices calls it once and stores it in
// deps.Inventory. Its events go to deps.Bus; its KEV data comes from the feeds service (looked up lazily, see
// feedsKEV, because feeds in turn takes the inventory).
// The box's own packages come from vedette-host's dpkg list (Config.Box); a container-only install has no host and so no
// list (the device page says so). findings_count comes from findingCounts.
func newInventory(d *deps) *inventory.Service {
	var pub inventory.Publisher
	if d.Bus != nil {
		pub = inventory.PublisherFunc(func(ctx context.Context, e inventory.Event) error {
			return d.Bus.Publish(ctx, events.Event{Name: e.Name, Data: e.Data})
		})
	}
	// The decoy addresses of the honeypot are the box, not devices (honeypot CONTRACT, open question 2). The honeypot is built
	// after the inventory, so the list is looked up when asked.
	owned := func(ctx context.Context) []netip.Addr {
		if d.Honeypot == nil {
			return nil
		}
		return append(d.Honeypot.DecoyIPs(ctx), d.Honeypot.TrapIPAddrs(ctx)...) // a Trap IP not handed over yet is the box's too (B2 lab)
	}
	if d.Lifecycle == nil {
		d.Lifecycle = &lifecycle.Hooks{}
	}
	cfg := inventory.Config{Zone: orgTimeZone(d), DB: d.DB, Audit: d.Audit, Modules: d.Reg, Clock: d.Clock, Log: d.Log, Events: pub, KEV: feedsKEV{d}, BoxOwnedIPs: owned,
		Findings: findingCounts{d}, Risk: findingCounts{d}, WazuhAgents: wazuhAgents{d}.addresses, DeclaredOS: declaredOS, OSVersion: findings.OSVersion,
		SNMPOf: sourceFacts{d}.snmp, AgentOf: sourceFacts{d}.agent, AskAgent: sourceFacts{d}.askAgent, Lifecycle: d.Lifecycle}
	// The box's own MACs (its cards and the decoys' macvlan links): a foreign MAC on a decoy address is a device (WP-31 M7). Without a
	// host there is no decoy on the wire, and the MACs stay unknown, so nothing changes.
	if d.HostSocket != "" {
		cfg.Box = boxPackages{c: hostclient.New(d.HostSocket), log: d.Log}
		cfg.BoxPorts = boxPorts{c: hostclient.New(d.HostSocket)}.Ports
		macs := &hostMACs{r: hostclient.New(d.HostSocket), now: d.Clock}
		cfg.BoxOwnedMACs = func(ctx context.Context, fresh bool) ([]string, error) {
			if fresh {
				return macs.Fresh(ctx)
			}
			return macs.Get(ctx)
		}
		// The host's decoys, completed by what the honeypot learned at its last Apply: the host answer the inventory holds can be up to a
		// TTL old, older than a decoy added a moment ago (B2 lab).
		cfg.BoxDecoyMACs = func(ctx context.Context, fresh bool) (map[netip.Addr]string, error) {
			m, err := macs.Decoys(ctx, fresh)
			if err != nil || d.Honeypot == nil {
				return m, err
			}
			for ip, mac := range d.Honeypot.ExpectedMACs(ctx) {
				if m == nil {
					m = map[netip.Addr]string{}
				}
				// The honeypot's view wins: it is what the host said at the last Apply (or "": it is handing the address over right now,
				// its MAC may be new), while the host answer here may be a cache older than a decoy re-made with another MAC (B2 lab).
				m[ip] = mac
			}
			return m, nil
		}
		cfg.Gateway = (&gatewayCache{state: hostclient.New(d.HostSocket), now: d.Clock}).Get
	}
	svc, err := inventory.New(cfg)
	if err != nil { // only a missing DB or audit log: a programming error in serve
		panic("vedette: " + err.Error())
	}
	return svc
}

// inventoryJobs keeps the box in the inventory as its first device (INV-3): the job runs as soon as the
// module is on (start-up, or when it is switched on), creates the device once and refreshes it after. service-prune removes
// the open services not seen for 90 days (INV-23); it only deletes past a retention the product states, so it is
// housekeeping and runs while the module is off too. agent-software-prune removes the software an agent has not
// reported for 30 days: a normal job, because the 30 days count only while the inventory and agent-intake are on.
func inventoryJobs(d deps) []jobs.Job {
	svc := d.Inventory
	prune := jobs.Job{Module: "inventory", Name: "service-prune", Every: 6 * time.Hour, Housekeeping: true, Run: func(ctx context.Context) error {
		_, err := svc.PruneServices(ctx)
		return err
	}}
	var hostc *hostclient.Client // one client for every run of the box job
	if d.HostSocket != "" {
		hostc = hostclient.New(d.HostSocket)
	}
	return []jobs.Job{prune, {Module: "inventory", Name: "box", Every: time.Hour, Run: func(ctx context.Context) error {
		// The machine's name, not the container's (#471). No answer from the host since core started: keep the row's name rather
		// than write "vedette" over it.
		host, ok := d.BoxName.Get(ctx)
		if !ok {
			if name, _, found, err := svc.BoxName(ctx); err == nil && found && name != "" {
				host = name
			}
		}
		var ip string
		if hostc != nil {
			// Best effort: a host that does not answer leaves the address unknown until the next run.
			cctx, cancel := context.WithTimeout(ctx, hostNetTimeout)
			if card, ok := d.Network.ManagementCard(cctx); ok && card != "" {
				if st, err := hostc.StateNet(cctx); err == nil {
					ip = boxCardIPv4(st, card)
				}
			}
			cancel()
		}
		// The box's OS from the same answer of the host: findings judge OS-release NVD entries (CVE-2021-3493) by it, as on an
		// agent host. "" (no host, or no answer yet) keeps what the row has.
		box := inventory.BoxInfo{Hostname: host, IP: ip, OS: d.BoxName.OS(), ContainerOnly: d.Reg != nil && d.Reg.ContainerOnly()}
		if _, err := svc.EnsureBox(ctx, box); err != nil {
			return err
		}
		// The box's open ports with its packages (INV-3): one failing does not hold the other back.
		return errors.Join(svc.RefreshBoxPackages(ctx), svc.RefreshBoxServices(ctx))
	}}, {Module: "inventory", Name: "agent-software-prune", Every: time.Hour, Run: svc.PruneAgentSoftware}} // a normal job
}

// boxPackages is inventory's BoxPackages (S-INV-5): vedette-host's GET /v1/state/packages, mapped to software exactly like an
// osquery deb_packages snapshot (agentintake.MapDebPackages), so findings match the box like any server. An older host
// (404 unknown_command) or a dpkg in the middle of a change (409 packages_changing) gives no list: nil, and the inventory keeps
// what it has. The mapped list is never cut: one longer than the inventory stores (5 000 rows) is refused whole by
// UpsertSoftware, so the stored list stays rather than becoming a part of the box.
type boxPackages struct {
	c   *hostclient.Client
	log *slog.Logger
}

// boxPackagesTimeout bounds one read: dpkg-query of a few thousand packages takes well under a second.
const boxPackagesTimeout = 30 * time.Second

func (b boxPackages) Packages(ctx context.Context) ([]inventory.SoftwareItem, error) {
	ctx, cancel := context.WithTimeout(ctx, boxPackagesTimeout)
	defer cancel()
	st, err := b.c.StatePackages(ctx)
	if hostclient.IsCode(err, hostapi.CodeUnknownCommand) {
		return nil, nil
	}
	if hostclient.IsCode(err, hostapi.CodePackagesChanging) { // dpkg is mid-change: keep the last good list, read again next run
		if b.log != nil {
			b.log.InfoContext(ctx, "inventory: dpkg is installing or removing packages on the box; its package list is kept and read again at the next run")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kernel := "" // the box's running kernel: the Kernel row takes its image; unknown keeps the lowest installed one
	if info, err := b.c.Info(ctx); err == nil {
		kernel = info.OS.Kernel
	}
	pkgs := make([]agentintake.DebPackage, len(st.Packages))
	for i, p := range st.Packages {
		pkgs[i] = agentintake.DebPackage{Name: p.Name, Version: p.Version, Source: p.Source, Kernel: kernel}
	}
	sw, dropped := agentintake.MapDebPackages(pkgs)
	if len(sw) == 0 { // the host never sends an empty list; an empty result must not empty the box's software
		return nil, errors.New("vedette: the box's package list maps to no software")
	}
	if dropped > 0 && b.log != nil {
		b.log.WarnContext(ctx, "inventory: some packages of the box are outside the inventory's limits and are not listed", "dropped", dropped, "listed", len(sw))
	}
	out := make([]inventory.SoftwareItem, len(sw))
	for i, s := range sw {
		out[i] = inventory.SoftwareItem{Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: s.Version, CPE: s.CPE, KevKeys: s.KevKeys, Packaged: s.Packaged,
			PkgVersion: s.PkgVersion, PkgSource: s.PkgSource}
	}
	return out, nil
}

// boxPorts is inventory's BoxPorts (INV-3): vedette-host's GET /v1/state/ports, the ports the box listens on at an address other
// than loopback, as open services named by what holds them ("vedette-core", "sshd"). A host older than the read (404
// unknown_command) gives no list: nil, and the inventory keeps what it has. The inventory validates every item (INV-23).
type boxPorts struct{ c *hostclient.Client }

// boxPortsTimeout bounds one read: a walk of /proc of a small box.
const boxPortsTimeout = 30 * time.Second

func (b boxPorts) Ports(ctx context.Context) ([]observe.Service, error) {
	ctx, cancel := context.WithTimeout(ctx, boxPortsTimeout)
	defer cancel()
	st, err := b.c.StatePorts(ctx)
	if hostclient.IsCode(err, hostapi.CodeUnknownCommand) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]observe.Service, len(st.Ports))
	for i, p := range st.Ports {
		out[i] = observe.Service{Port: p.Port, Proto: p.Proto, Name: p.Process}
	}
	return out, nil
}

// findingCounts is inventory's FindingCounter: findings is built after inventory, so its service is looked up when asked. The count
// covers every status, which is what deleting the device deletes (findings' part of the delete runs in the same write, whether the
// module is on or off). With the findings module off the count is 0 and the delete dialog names none: the person cannot see them;
// before the service exists it is 0 too (an empty map, never an error).
type findingCounts struct{ d *deps }

func (f findingCounts) CountByAsset(ctx context.Context) (map[string]int, error) {
	if f.d == nil || f.d.Findings == nil || (f.d.Reg != nil && !f.d.Reg.Enabled("findings")) {
		return map[string]int{}, nil
	}
	return f.d.Findings.CountByAsset(ctx)
}

// RiskByAsset is inventory's RiskSource: findings.RiskMap, one cached batch with To fix's tests (its exploited findings to fix,
// else its recommended updates for a likely-exploited or High+ CVE), from findings (built after inventory, looked up when asked). Findings off or not built: no device is marked. The feeds
// module off: no update counts, as GET /findings/plan then lists none.
func (f findingCounts) RiskByAsset(ctx context.Context) (map[string]inventory.RiskCounts, error) {
	out := map[string]inventory.RiskCounts{}
	if f.d == nil || f.d.Findings == nil || (f.d.Reg != nil && !f.d.Reg.Enabled("findings")) {
		return out, nil
	}
	m, err := f.d.Findings.RiskMap(ctx, f.d.Reg == nil || f.d.Reg.Enabled(findings.FeedsModule))
	if err != nil {
		return nil, err
	}
	for id, r := range m {
		out[id] = inventory.RiskCounts{Exploited: r.Exploited, Updates: r.Updates}
	}
	return out, nil
}

// wazuhAgents is inventory.Config.WazuhAgents (#849): the addresses and MACs agent-intake's Wazuh pulls delivered to, so the Devices
// list tells a Wazuh machine from an osquery one. agent-intake is built after the inventory, so it is asked when needed; none while it
// is not built or is off (what it delivered stays in the inventory, as source agent with no word).
type wazuhAgents struct{ d *deps }

func (w wazuhAgents) addresses(ctx context.Context) ([]string, []string, error) {
	if w.d == nil || w.d.AgentIntake == nil || (w.d.Reg != nil && !w.d.Reg.Enabled("agent-intake")) {
		return nil, nil, nil
	}
	return w.d.AgentIntake.WazuhAgentAddresses(ctx)
}

// gatewayCache is inventory.Config.Gateway: the box's IPv4 default gateway from vedette-host state/net, kept for a minute so
// reading the device list does not ask the host each time; a failed read is kept as unknown (the zero address) for the same minute,
// so a host that does not answer costs one timeout a minute, not one per page (#714 M3).
type gatewayCache struct {
	state netStateReader
	now   func() time.Time
	mu    sync.Mutex
	at    time.Time
	ip    netip.Addr
}

func (g *gatewayCache) Get(ctx context.Context) netip.Addr {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now
	if g.now != nil {
		now = g.now
	}
	if !g.at.IsZero() && now().Sub(g.at) < time.Minute {
		return g.ip
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	st, err := g.state.StateNet(ctx)
	g.ip, g.at = netip.Addr{}, now()
	if err == nil && st.DefaultRoute != nil {
		if ip, err := netip.ParseAddr(strings.TrimSpace(st.DefaultRoute.Gateway)); err == nil && ip.Unmap().Is4() && !ip.IsUnspecified() {
			g.ip = ip.Unmap().WithZone("")
		}
	}
	return g.ip
}

// sourceFacts are inventory.Config.SNMPOf and AgentOf: what sensor-active says of a device's SNMP and agent-intake of the agent that
// reads it, for the device's source rows (GET /inventory/devices/{id}/sources). Both are built after the inventory, so they are asked
// when needed; the inventory says "module off" itself before it asks.
type sourceFacts struct{ d *deps }

func (f sourceFacts) snmp(ctx context.Context, id string) (inventory.SNMPFact, error) {
	sa, err := sensorActiveService(ctx, *f.d)
	if err != nil {
		return inventory.SNMPFact{}, err
	}
	s, err := sa.SNMPDeviceOf(ctx, id)
	if err != nil {
		return inventory.SNMPFact{}, err
	}
	return inventory.SNMPFact{State: s.State, LastAnswerAt: s.LastAnswerAt}, nil
}

func (f sourceFacts) agent(ctx context.Context, id string) (inventory.AgentFact, error) {
	if f.d.AgentIntake == nil {
		return inventory.AgentFact{}, errors.New("agent-intake is not built")
	}
	r, err := f.d.AgentIntake.ReportState(ctx, id)
	if err != nil {
		return inventory.AgentFact{}, err
	}
	out := inventory.AgentFact{Agent: r.Agent, State: r.State, LastSeen: r.LastSeen}
	if t := r.Setup; t != nil {
		out.Token = &inventory.AgentToken{ID: t.ID, Name: t.Name, Kind: t.Kind, Last4: t.Last4, CreatedAt: store.FormatTS(t.CreatedAt), Hosts: t.Hosts,
			CreatedBy: optionalString(t.CreatedBy), DeviceID: optionalString(t.DeviceID), LastReceived: optionalTime(t.LastReceived), ExpiresAt: optionalTime(t.ExpiresAt)}
	}
	return out, nil
}

// askAgent is inventory.Config.AskAgent: a person turned a device's agent on again, so its osquery agent is asked to send its software
// now ("I updated it": the same ask, in the person's name). Best effort: a device whose agent cannot be asked (Wazuh, none, an ask
// still open or made in the last minutes) waits for the agent's next report.
func (f sourceFacts) askAgent(ctx context.Context, actor, id string) {
	if f.d.AgentIntake == nil || f.d.Reg != nil && !f.d.Reg.Enabled("agent-intake") {
		return
	}
	if _, err := f.d.AgentIntake.AskReport(ctx, actor, id); err != nil {
		f.d.Log.DebugContext(ctx, "inventory: the agent turned on again was not asked to report now", "device", id, "error", err.Error())
	}
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optionalTime(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := store.FormatTS(t)
	return &s
}

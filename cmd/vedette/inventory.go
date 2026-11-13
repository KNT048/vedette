package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	hostapi "github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/inventory"
)

// newInventory builds the inventory service from the shared deps; buildServices calls it once and stores it in
// deps.Inventory. Its events go to deps.Bus; its KEV data comes from the feeds service (looked up lazily, see
// feedsKEV, because feeds in turn takes the inventory).
// The box's own packages come from vedette-host's dpkg list (Config.Box, D-470); a container-only install has no host and so no
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
	cfg := inventory.Config{DB: d.DB, Audit: d.Audit, Modules: d.Reg, Clock: d.Clock, Log: d.Log, Events: pub, KEV: feedsKEV{d}, BoxOwnedIPs: owned,
		Findings: findingCounts{d}}
	// The box's own MACs (its cards and the decoys' macvlan links): a foreign MAC on a decoy address is a device (WP-31 M7). Without a
	// host there is no decoy on the wire, and the MACs stay unknown, so nothing changes.
	if d.HostSocket != "" {
		cfg.Box = boxPackages{c: hostclient.New(d.HostSocket), log: d.Log}
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
			for ip, mac := range d.Honeypot.DecoyMACs() {
				if m == nil {
					m = map[netip.Addr]string{}
				}
				if _, ok := m[ip]; !ok {
					m[ip] = mac
				}
			}
			return m, nil
		}
	}
	svc, err := inventory.New(cfg)
	if err != nil { // only a missing DB or audit log: a programming error in serve
		panic("vedette: " + err.Error())
	}
	return svc
}

// inventoryJobs keeps the box in the inventory as its first device (INV-3, D-53): the job runs as soon as the
// module is on (start-up, or when it is switched on), creates the device once and refreshes it after. service-prune removes
// the open services not seen for 90 days (INV-23); it only deletes past a retention the product states, so it is
// housekeeping (D-160, D-202) and runs while the module is off too. agent-software-prune removes the software an agent has not
// reported for 30 days (D-327): a normal job, because the 30 days count only while the inventory and agent-intake are on.
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
		// The box's OS from the same answer of the host (W3-8): findings judge OS-release NVD entries (CVE-2021-3493) by it, as on an
		// agent host. "" (no host, or no answer yet) keeps what the row has.
		box := inventory.BoxInfo{Hostname: host, IP: ip, OS: d.BoxName.OS(), ContainerOnly: d.Reg != nil && d.Reg.ContainerOnly()}
		if _, err := svc.EnsureBox(ctx, box); err != nil {
			return err
		}
		return svc.RefreshBoxPackages(ctx)
	}}, {Module: "inventory", Name: "agent-software-prune", Every: time.Hour, Run: svc.PruneAgentSoftware}} // a normal job (D-327)
}

// boxPackages is inventory's BoxPackages (D-470, S-INV-5): vedette-host's GET /v1/state/packages, mapped to software exactly like an
// osquery deb_packages snapshot (agentintake.MapDebPackages), so findings match the box like any server. A host older than D-470
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
	pkgs := make([]agentintake.DebPackage, len(st.Packages))
	for i, p := range st.Packages {
		pkgs[i] = agentintake.DebPackage{Name: p.Name, Version: p.Version, Source: p.Source}
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
		out[i] = inventory.SoftwareItem{Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: s.Version, CPE: s.CPE, KevKeys: s.KevKeys}
	}
	return out, nil
}

// findingCounts is inventory's FindingCounter: findings is built after inventory, so its service is looked up when asked. The count
// covers every status, which is what deleting the device deletes. With the findings module off, nothing deletes them (the
// asset.deleted subscriber runs only while findings is on), so the count is 0 and the delete dialog promises nothing; before the
// service exists it is 0 too (an empty map, never an error).
type findingCounts struct{ d *deps }

func (f findingCounts) CountByAsset(ctx context.Context) (map[string]int, error) {
	if f.d == nil || f.d.Findings == nil || (f.d.Reg != nil && !f.d.Reg.Enabled("findings")) {
		return map[string]int{}, nil
	}
	return f.d.Findings.CountByAsset(ctx)
}

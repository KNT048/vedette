package main

import (
	"context"
	"net/netip"
	"os"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/inventory"
)

// newInventory builds the inventory service from the shared deps; buildServices calls it once and stores it in
// deps.Inventory. Its events go to deps.Bus; its KEV data comes from the feeds service (looked up lazily, see
// feedsKEV, because feeds in turn takes the inventory).
// ponytail: no box packages (WP-07: Config.Box); the service degrades without them. findings_count comes from findingCounts.
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
		return d.Honeypot.DecoyIPs(ctx)
	}
	cfg := inventory.Config{DB: d.DB, Audit: d.Audit, Modules: d.Reg, Clock: d.Clock, Log: d.Log, Events: pub, KEV: feedsKEV{d}, BoxOwnedIPs: owned,
		Findings: findingCounts{d}}
	// The box's own MACs (its cards and the decoys' macvlan links): a foreign MAC on a decoy address is a device (WP-31 M7). Without a
	// host there is no decoy on the wire, and the MACs stay unknown, so nothing changes.
	if d.HostSocket != "" {
		macs := &hostMACs{r: hostclient.New(d.HostSocket), now: d.Clock}
		cfg.BoxOwnedMACs = func(ctx context.Context, fresh bool) ([]string, error) {
			if fresh {
				return macs.Fresh(ctx)
			}
			return macs.Get(ctx)
		}
	}
	svc, err := inventory.New(cfg)
	if err != nil { // only a missing DB or audit log: a programming error in serve
		panic("vedette: " + err.Error())
	}
	return svc
}

// inventoryJobs keeps the box in the inventory as its first device (INV-3, D-53): the job runs as soon as the
// module is on (start-up, or when it is switched on), creates the device once and refreshes it after.
func inventoryJobs(d deps) []jobs.Job {
	svc := d.Inventory
	return []jobs.Job{{Module: "inventory", Name: "box", Every: time.Hour, Run: func(ctx context.Context) error {
		host, err := os.Hostname()
		if err != nil || host == "" {
			host = "vedette"
		}
		if _, err := svc.EnsureBox(ctx, inventory.BoxInfo{Hostname: host}); err != nil {
			return err
		}
		return svc.RefreshBoxPackages(ctx)
	}}}
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

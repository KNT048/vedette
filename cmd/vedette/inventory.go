package main

import (
	"context"
	"net/netip"
	"os"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/inventory"
)

// newInventory builds the inventory service from the shared deps; buildServices calls it once and stores it in
// deps.Inventory. Its events go to deps.Bus; its KEV data comes from the feeds service (looked up lazily, see
// feedsKEV, because feeds in turn takes the inventory).
// ponytail: no box packages (WP-07: Config.Box) and no findings counter (needs a read method of findings); the service degrades without them.
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
	svc, err := inventory.New(inventory.Config{DB: d.DB, Audit: d.Audit, Modules: d.Reg, Clock: d.Clock, Log: d.Log, Events: pub, KEV: feedsKEV{d}, BoxOwnedIPs: owned})
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

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
	"github.com/knt048/vedette/modules/notify"
)

// Modules do not import each other. Each module declares the port it needs; the adapters below convert
// between that port and the neutral exported methods of the module that provides it (issues #38, #39), so
// the provider's tables stay private (rules/modules.md). They live here because only the binary knows both.

// ---- inventory -> feeds (feeds.Inventory) ----

// feedsInventory implements feeds.Inventory, and feeds.TxSettler so the inventory events of "I have it" go out
// only after feeds' own transaction committed.
type feedsInventory struct{ inv *inventory.Service }

func (a feedsInventory) MatchProducts(ctx context.Context, products []feeds.Product) (map[string][]feeds.MatchedAsset, error) {
	q := make([]inventory.ProductQuery, len(products))
	for i, p := range products {
		q[i] = inventory.ProductQuery{Vendor: p.Vendor, Product: p.Product}
	}
	got, err := a.inv.DevicesRunning(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]feeds.MatchedAsset, len(got))
	for key, list := range got {
		for _, m := range list {
			how := feeds.HaveMaybe
			if m.Exact {
				how = feeds.HaveYes
			}
			out[key] = append(out[key], feeds.MatchedAsset{ID: m.ID, Hostname: m.Hostname, IP: m.IP, Display: m.Display, How: how})
		}
	}
	return out, nil
}

func (a feedsInventory) AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, d feeds.ManualDevice) error {
	return a.inv.AddManualDevice(ctx, tx, actor, inventory.ManualDevice{Kind: d.Kind, Vendor: d.Vendor, Product: d.Product, Display: d.Display, Key: d.Key})
}

func (a feedsInventory) Settle(ctx context.Context, tx *sql.Tx, committed bool) {
	a.inv.Settle(ctx, tx, committed)
}

// ---- feeds -> inventory (inventory.KEV) ----

// feedsKEV implements inventory.KEV from the CISA rows of the feeds service. Until the first pull (the table is
// empty) or while feeds is off it answers like inventory.EmbeddedKEV: the product list shipped with the box, no CVEs.
// The service is looked up on each call because it is built after the inventory (feeds needs the inventory).
type feedsKEV struct{ d *deps }

func (k feedsKEV) store() (*feeds.Store, bool) {
	if k.d.Reg != nil && !k.d.Reg.Enabled("feeds") {
		return nil, false
	}
	s, err := feedsService(*k.d)
	if err != nil {
		return nil, false
	}
	return s.Store(), true
}

func (k feedsKEV) Products(ctx context.Context) (string, []inventory.KEVProduct, error) {
	st, ok := k.store()
	if !ok {
		return inventory.EmbeddedKEV{}.Products(ctx)
	}
	version, list, err := st.KevProducts(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(list) == 0 {
		return inventory.EmbeddedKEV{}.Products(ctx)
	}
	out := make([]inventory.KEVProduct, len(list))
	for i, p := range list {
		out[i] = inventory.KEVProduct{Vendor: p.Vendor, Product: p.Product, Count: p.Count}
	}
	return version, out, nil
}

func (k feedsKEV) CVEs(ctx context.Context, keys []string) ([]string, error) {
	st, ok := k.store()
	if !ok {
		return nil, nil
	}
	return st.KevCVEsByKeys(ctx, keys)
}

// ---- inventory -> findings (findings.Inventory) and feeds -> findings (findings.Feeds) ----

type findingsInventory struct{ inv *inventory.Service }

func (a findingsInventory) Assets(ctx context.Context, ids []string) (map[string]findings.AssetView, error) {
	refs, err := a.inv.DeviceRefs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]findings.AssetView, len(refs))
	for id, r := range refs {
		out[id] = findings.AssetView{ID: r.ID, Hostname: r.Hostname, IP: r.IP, Kind: r.Kind, Display: r.Display}
	}
	return out, nil
}

func (a findingsInventory) MatchInput(ctx context.Context, assetID string) (findings.Asset, bool, error) {
	d, ok, err := a.inv.MatchInput(ctx, assetID)
	if err != nil || !ok {
		return findings.Asset{}, false, err
	}
	out := findings.Asset{ID: d.ID, Name: d.Name, Software: make([]findings.Software, len(d.Software))}
	for i, s := range d.Software {
		out.Software[i] = findings.Software{ID: s.ID, Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: s.Version, KevKeys: s.KevKeys, CPE: s.CPE}
	}
	return out, true, nil
}

type findingsFeeds struct{ st *feeds.Store }

func (a findingsFeeds) KevInfo(ctx context.Context, cves []string) (map[string]findings.KevInfo, error) {
	rows, err := a.st.KevVulnsByCVE(ctx, cves)
	if err != nil {
		return nil, err
	}
	out := make(map[string]findings.KevInfo, len(rows))
	for _, v := range rows {
		var due *string
		if v.DueDate != "" {
			due = &v.DueDate
		}
		out[v.CVE] = findings.KevInfo{Name: v.Name, Vendor: v.Vendor, Product: v.Product, Display: feeds.DisplayOf(v.Vendor, v.Product),
			RequiredAction: v.RequiredAction, Links: v.Links, DateAdded: v.DateAdded, DueDate: due, Ransomware: v.Ransomware, EPSS: v.EPSS, HasTemplate: v.HasTemplate}
	}
	return out, nil
}

// Vulns returns the CISA list for matching. The list has no NVD affected ranges yet, so findings can only
// match by product (basis "product").
func (a findingsFeeds) Vulns(ctx context.Context) ([]findings.Vuln, error) {
	rows, err := a.st.KevVulns(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]findings.Vuln, len(rows))
	for i, v := range rows {
		out[i] = findings.Vuln{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Ransomware: v.Ransomware}
		if v.EPSS != nil {
			out[i].EPSS = *v.EPSS
		}
	}
	return out, nil
}

// findingsPublisher puts findings events on the bus.
type findingsPublisher struct{ bus *events.Bus }

func (p findingsPublisher) Publish(ctx context.Context, name string, payload any) error {
	return p.bus.Publish(ctx, events.Event{Name: name, Data: payload})
}

// ---- inventory -> mitigation (mitigation.Vendors) and the ai stand-in ----

type mitigationVendors struct{ inv *inventory.Service }

func (a mitigationVendors) HasFirewallVendor(ctx context.Context, vendor string) (bool, error) {
	return a.inv.HasDevice(ctx, []string{"firewall", "router"}, vendor)
}

// aiOff is mitigation's AI port until the ai module is wired (WP-25): never available, so the page offers no AI button
// and POST /findings/{id}/ai answers 409 ai_unavailable.
type aiOff struct{}

func (aiOff) Available(context.Context, mitigation.Skill) bool { return false }
func (aiOff) Run(context.Context, mitigation.AIRequest) (mitigation.AIOutput, error) {
	return mitigation.AIOutput{}, mitigation.ErrAIUnavailable
}

// ---- building the services ----

// buildServices builds the module services that others reach through ports, once, in dependency order, and
// subscribes the cross-module reactions. serve calls it after deps has its base fields; the handlers, jobs and
// subscribers all share these instances.
func buildServices(d *deps) error {
	d.Inventory = newInventory(d) // before feeds: feeds takes the inventory (feeds.Inventory)
	fs, err := feedsService(*d)
	if err != nil {
		return fmt.Errorf("feeds: %w", err)
	}
	inv := findingsInventory{d.Inventory}
	feed := findingsFeeds{fs.Store()}
	cfg := findings.ServiceConfig{DB: d.DB, Audit: d.Audit, Inventory: inv, Feeds: feed, Log: d.Log, Clock: d.Clock}
	if d.Bus != nil {
		cfg.Publisher = findingsPublisher{d.Bus}
	}
	if d.Findings, err = findings.NewService(cfg); err != nil {
		return err
	}
	var gate server.ModuleGate // a nil *modreg.Registry inside the interface would not compare equal to nil
	if d.Reg != nil {
		gate = d.Reg
	}
	d.FindingHandlers = findings.NewFindingHandlers(d.Findings, inv, feed, gate)
	provider, err := mitigation.NewProvider(d.DB, mitigationVendors{d.Inventory}, aiOff{})
	if err != nil {
		return err
	}
	d.FindingHandlers.SetGuidance(provider)
	if d.MitigationHandlers, err = mitigation.NewActionHandlers(d.DB, d.Audit, d.Findings, d.FindingHandlers, aiOff{}, d.Clock); err != nil {
		return err
	}
	subscribe(*d)
	return nil
}

// rematchTimeout bounds the work of a baseline re-match: the bus gives a handler 5 seconds, a baseline can mean
// many devices and CVEs. It runs in the publisher's goroutine, so it holds the pull job meanwhile.
const rematchTimeout = 2 * time.Minute

// subscribe wires the events between modules on d.Bus. A subscription acts only while the subscribing module
// is on (SYS-5); a handler error is logged by the bus and never reaches the publisher.
// scan.finding.confirmed -> findings.ConfirmFromScan stays unwired until the scan module exists (deferred).
func subscribe(d deps) {
	if d.Bus == nil {
		return
	}
	on := func(module string, fn func(ctx context.Context, data any) error) events.Handler {
		return func(ctx context.Context, e events.Event) error {
			if d.Reg != nil && !d.Reg.Enabled(module) {
				return nil
			}
			return fn(ctx, e.Data)
		}
	}
	d.Bus.Subscribe(inventory.EventMatchChanged, on("findings", func(ctx context.Context, data any) error {
		ev, ok := data.(inventory.MatchEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		_, err := d.Findings.OnMatchChanged(ctx, ev.AssetID)
		if errors.Is(err, findings.ErrUnknownAsset) {
			return nil // the device was deleted after the event went out
		}
		return err
	}))
	d.Bus.Subscribe(inventory.EventAssetDeleted, on("findings", func(ctx context.Context, data any) error {
		ev, ok := data.(inventory.AssetEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		_, err := d.Findings.OnAssetDeleted(ctx, ev.AssetID)
		return err
	}))
	d.Bus.Subscribe(feeds.EventNewKEV, on("inventory", func(ctx context.Context, data any) error {
		ev, ok := data.(feeds.NewKEVEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		_, err := d.Inventory.RematchCVE(ctx, ev.CVE, ev.Vendor, ev.Product)
		return err
	}))
	d.Bus.Subscribe(feeds.EventSyncBaseline, on("inventory", func(ctx context.Context, _ any) error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rematchTimeout)
		defer cancel()
		ctx = notify.WithBaseline(ctx)
		_, err := d.Inventory.RematchAll(ctx)
		return err
	}))
}

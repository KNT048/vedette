package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/server"
	hostclient "github.com/knt048/vedette/host/client"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	authoidc "github.com/knt048/vedette/modules/auth-oidc"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
	"github.com/knt048/vedette/modules/notify"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
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

// AssetIDs lists every device id for findings' reconcile job: inventory's unfiltered read (no kind filter, no row cap) returns a
// read error as an error, which is what reconcile needs (a short list would make it remove findings of devices that still exist).
func (a findingsInventory) AssetIDs(ctx context.Context) ([]string, error) {
	return a.inv.AssetIDs(ctx)
}

// findingsJobs is findings' reconcile job (D-144): it heals what a lost event left behind.
func findingsJobs(d deps) []jobs.Job { return findings.Jobs(d.Findings) }

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
		if t, err := time.Parse(time.DateOnly, v.DateAdded); err == nil { // an unreadable date stays zero: backlog, never news
			out[i].DateAdded = t
		}
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

// ---- inventory -> mitigation (mitigation.Vendors) ----

type mitigationVendors struct{ inv *inventory.Service }

func (a mitigationVendors) HasFirewallVendor(ctx context.Context, vendor string) (bool, error) {
	return a.inv.HasDevice(ctx, []string{"firewall", "router"}, vendor)
}

// ---- building the services ----

// buildServices builds the module services that others reach through ports, once, in dependency order, and
// subscribes the cross-module reactions. serve calls it after deps has its base fields; the handlers, jobs and
// subscribers all share these instances.
func buildServices(ctx context.Context, d *deps) error {
	// Order: inventory and notify first, then auth with notify's code mailer, then core. notify needs the user
	// directory, the time zone and the device names, which come from auth, core and inventory: its adapters
	// (notifyUsers, orgZone, notifyDevices) read d.Auth and d.Core when asked, so one instance of each service
	// exists and no setter is needed. Without the notify module on, the mailer says it is not available and email
	// two-step accounts get 503 twofa_email_unavailable (INV-8, never password-only).
	var err error
	d.Inventory = newInventory(d) // before feeds: feeds takes the inventory (feeds.Inventory)
	notifySvc := newNotify(d)
	if d.Auth, err = auth.New(auth.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Mailer: notifySvc.CodeMailer(), Clock: d.Clock, Log: d.Log, Argon2: d.Argon2}); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if d.Conn, err = newConn(d); err != nil {
		return fmt.Errorf("connections: %w", err)
	}
	if d.ConnReader, err = read.New(read.Config{Conns: d.Conn, Log: d.Log}); err != nil {
		return fmt.Errorf("connection reader: %w", err)
	}
	if d.OIDC, err = authoidc.New(authoidc.Deps{DB: d.DB, Secrets: d.Secrets, Auth: d.Auth, Audit: d.Audit, Log: d.Log, Clock: d.Clock}); err != nil {
		return fmt.Errorf("auth-oidc: %w", err)
	}
	if d.AgentIntake, err = agentintake.New(agentintake.Config{DB: d.DB, Audit: d.Audit, Sink: d.Inventory, Software: d.Inventory, Secrets: d.Secrets, Conn: d.Conn, Clock: d.Clock, Log: d.Log,
		TrustAnchor: d.TrustAnchor, HostAllowed: d.HostAllowed, BoxURL: d.BaseURL, MirrorDir: d.OsqueryDir}); err != nil {
		return fmt.Errorf("agent-intake: %w", err)
	}
	d.Logs = logexport.New()
	d.PurgeGate = &core.PurgeGate{}
	var scope core.SetupScope // the wizard's LAN ranges become the inventory's scope (INV-15, #350)
	if d.Inventory != nil {
		scope = d.Inventory
	}
	if d.Core, err = core.NewAPIHandlers(core.HandlersConfig{Scope: scope, Logs: d.Logs, SpoolDir: logSpoolDir(d.DataDir), DB: d.DB, Auth: d.Auth, Reg: d.Reg, Audit: d.Audit, Secrets: d.Secrets, Log: d.Log, Clock: d.Clock, Facts: privacyFacts{conns: d.Conn, d: d}, Conns: d.Conn,
		DataDir: d.DataDir, DataFiles: moduleDataFiles, Schema: schemaSets(wiredModules()), Restart: d.Restart, KeyPath: d.KeyPath,
		Host: purgeHost(d), OSBusy: func(ctx context.Context) bool { return d.OS != nil && d.OS.Busy(ctx) }, BeforeWipe: purgeBeforeWipe(d), Gate: d.PurgeGate, AlsoKept: purgeAlsoKept(d), KeepRows: purgeKeptRows(d), AlsoFreeze: purgeFreezes(d)}); err != nil {
		return fmt.Errorf("core: %w", err)
	}
	if d.OS, err = newOSHandlers(*d); err != nil {
		return fmt.Errorf("os updates: %w", err)
	}
	sensor := &spanSensor{reg: d.Reg} // its service comes below: the Box network page needs the sensor and the sensor needs the page's settings
	if d.Network, err = newNetworkHandlers(d, sensor); err != nil {
		return fmt.Errorf("box network: %w", err)
	}
	if d.Honeypot, err = newHoneypot(d); err != nil {
		return fmt.Errorf("honeypot: %w", err)
	}
	sp, err := newSensorPassive(*d)
	if err != nil {
		return fmt.Errorf("sensor-passive: %w", err)
	}
	d.SensorPassive = sp
	sensor.svc = sp
	d.SensorDispatcher = sensoractive.NewDispatcher(sensoractive.DispatcherOptions{Now: d.Clock, Log: d.Log})
	fs, err := feedsService(*d)
	if err != nil {
		return fmt.Errorf("feeds: %w", err)
	}
	inv := findingsInventory{d.Inventory}
	feed := findingsFeeds{fs.Store()}
	// Backlog: findings the reconcile job creates for old KEV entries are D-78 backlog, silent for notify (findings does not import notify).
	cfg := findings.ServiceConfig{DB: d.DB, Audit: d.Audit, Inventory: inv, Feeds: feed, Log: d.Log, Clock: d.Clock, Backlog: notify.WithBaseline}
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
	// The ai service comes before mitigation: mitigation reaches the AI only through this door (mitigation.AI), and the door is
	// unavailable while no profile is assigned, so the page offers no AI button then.
	d.AIFacts = aiFacts{fs.Store(), d.Findings, inv}
	if d.AI, err = newAI(ctx, d, d.AIFacts, aiAsk{fs.Store(), d.Findings, d.Inventory}); err != nil {
		return fmt.Errorf("ai: %w", err)
	}
	aiDoor := aiMitigation{d.AI}
	provider, err := mitigation.NewProvider(d.DB, mitigationVendors{d.Inventory}, aiDoor)
	if err != nil {
		return err
	}
	d.FindingHandlers.SetGuidance(provider)
	if d.MitigationHandlers, err = mitigation.NewActionHandlers(d.DB, d.Audit, d.Findings, d.FindingHandlers, aiDoor, d.Clock); err != nil {
		return err
	}
	d.PackLoader = mitigation.NewLoader(d.DB, d.Audit, packVerifier{trust: d.PackTrust}, d.Log, d.Clock)
	if d.Response, err = newResponse(d); err != nil { //nolint:contextcheck // response's BoxAddrs port has no context: it reads the decoys with its own short budget
		return fmt.Errorf("response: %w", err)
	}
	registerLogSources(d)
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
	d.Bus.Subscribe(feeds.EventNewKEV, on("scan", onNewKEVForScan(d)))          // after inventory's: the findings of the new entry exist when the job looks
	d.Bus.Subscribe(feeds.EventVulnUpdated, on("inventory", rematchUpdated(d))) // D-328: a CVE whose vendor or product changed
	d.Bus.Subscribe(feeds.EventSyncBaseline, on("inventory", func(ctx context.Context, _ any) error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rematchTimeout)
		defer cancel()
		ctx = notify.WithBaseline(ctx)
		_, err := d.Inventory.RematchAll(ctx)
		return err
	}))
	d.Bus.Subscribe(exposure.EventSnapshotCreated, on("response", exposurePortsOpened(d))) // D-384: new_port, the one reader of a new port
}

// rematchUpdated handles feeds.vuln.updated (D-328): the payload names the CISA entries that changed, any field, and the has_template flips
// of a template pull (hundreds at once). Each is announced (inventory.match.changed) to the devices that run its current product and do
// not already have a finding for it, at most once per device per event, so a CVE whose vendor or product changed reaches its new devices.
// A change that moved no key announces nothing to a device that has the finding; a device whose software matches the CVE and has no
// finding for it (a "Multiple Products" entry of its vendor that findings did not turn into a finding, or a missed baseline) is
// announced once per event, and findings then matches the whole device. A finding on a device of the old product stays: findings'
// matcher only adds (its INV-6), and a person or a scan closes a finding. With findings off nothing is left out (its own subscription is off too).
func rematchUpdated(d deps) func(ctx context.Context, data any) error {
	return func(ctx context.Context, data any) error {
		ev, ok := data.(feeds.VulnUpdatedEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		st, ok := feedsKEV{&d}.store()
		if !ok || len(ev.CVEs) == 0 {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rematchTimeout)
		defer cancel()
		rows, err := st.KevVulnsByCVE(ctx, ev.CVEs)
		if err != nil {
			return err
		}
		known := findingKnown(d)
		var errs []error
		for _, v := range rows {
			if _, err := d.Inventory.RematchCVEExcept(ctx, v.CVE, v.Vendor, v.Product, known); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", v.CVE, err))
				if ctx.Err() != nil {
					break
				}
			}
		}
		return errors.Join(errs...)
	}
}

// findingKnown says whether the device needs no announcement for the CVE: it already has a finding for it, open or closed (findings
// never re-creates a pair, INV-6), or it was already announced in this event (findings' OnMatchChanged matches the whole device against
// every CVE, so one announcement per device per event is enough). nil when findings is off or absent, so nothing is left out. Make one
// per event: it remembers what it read and what it let through.
func findingKnown(d deps) func(ctx context.Context, assetID, cve string) (bool, error) {
	if d.Findings == nil || (d.Reg != nil && !d.Reg.Enabled("findings")) {
		return nil
	}
	have := map[string]map[string]bool{} // one read per device for the whole event: a flip of hundreds of CVEs reads each device once
	announced := map[string]bool{}
	return func(ctx context.Context, assetID, cve string) (bool, error) {
		if announced[assetID] {
			return true, nil
		}
		cves, ok := have[assetID]
		if !ok {
			recs, err := d.Findings.List(ctx, assetID)
			if err != nil {
				return false, err
			}
			cves = make(map[string]bool, len(recs))
			for _, r := range recs {
				cves[r.CVE] = true
			}
			have[assetID] = cves
		}
		if cves[cve] {
			return true, nil
		}
		announced[assetID] = true
		return false, nil
	}
}

// privacyFacts answers what the Privacy page asks of other modules: the AI flow is on when a profile is usable, flow 11 when
// auth-oidc has an issuer, flow 12 while a connection is enabled. NTP (flow 10) is always on: the servers of Box network are added
// to the distribution's own chrony sources, which the box never removes (D-166, PRIVACY.md), and core cannot see whether the
// owner removed them by hand. ponytail: "off" needs the host to report chrony's whole source list (`chronyc sources`), a host API change.
type privacyFacts struct {
	conns *conn.Service
	d     *deps // read lazily: the ai service is built after core, which takes this value
}

// AIConfigured: flow 3 is on while an AI profile can be used (a key, or a model inside the network).
func (p privacyFacts) AIConfigured(context.Context) bool {
	return p.d != nil && p.d.AI != nil && p.d.AI.Configured()
}

func (privacyFacts) NTPPublic(context.Context) bool { return true } // see privacyFacts

// OIDCConfigured: flow 11 and the SSO button (auth-options) while auth-oidc has an issuer saved; the caller checks that the module is
// on. A store that cannot be read counts as "yes", like ConnectionsConfigured: the page must not say nothing leaves when it does not know.
func (p privacyFacts) OIDCConfigured(ctx context.Context) bool {
	if p.d == nil || p.d.OIDC == nil {
		return false
	}
	on, err := p.d.OIDC.Configured(ctx)
	return err != nil || on
}

// ConnectionsConfigured: flow 12 is on while an enabled connection exists (D-93). A store that cannot be read counts as "on": the
// Privacy page must never say that nothing leaves the box when it does not know.
func (p privacyFacts) ConnectionsConfigured(ctx context.Context) bool {
	if p.conns == nil {
		return false
	}
	on, err := p.conns.HasEnabled(ctx)
	return err != nil || on
}

// WazuhConnected: flow 14 is on while agent-intake has a Wazuh server saved (D-309); the caller checks that the module is on. A store
// that cannot be read counts as "on", like the others.
func (p privacyFacts) WazuhConnected(ctx context.Context) bool {
	if p.d == nil || p.d.AgentIntake == nil {
		return false
	}
	on, err := p.d.AgentIntake.WazuhConnected(ctx)
	return err != nil || on
}

// newOSHandlers wires the OS update and backup handlers. The host client is built from the socket path and
// connects on each call, so a box whose vedette-host starts later, or an install that has none, needs no
// restart: a missing socket file answers 409 not_appliance at call time (core.hostErr).
func newOSHandlers(d deps) (*core.OSHandlers, error) {
	var h core.Host
	if d.HostSocket != "" {
		h = hostclient.New(d.HostSocket)
	}
	return core.NewOSHandlers(core.OSConfig{
		DB: d.DB, Auth: d.Auth, Audit: d.Audit, Log: d.Log, Host: h, DataDir: d.DataDir, KeyPath: d.KeyPath,
		Zone: d.Core.OrgTimeZone, Clock: d.Clock, Gate: d.PurgeGate,
		Version: version, // the software update check: release documents from core.DefaultReleaseBase with core's own client and the embedded keys (D-341)
	})
}

// newNetworkHandlers wires the Box network handlers (S-CORE-8) on the host client of the socket path (nil without
// a host: every route answers 409 not_appliance). After a change of the box's addresses the shared cache of
// them (conn, sensor-active, honeypot) is dropped.
//
// d is the pointer buildServices fills in: the honeypot is built after this handler, so its decoys are looked up
// when an address is asked about, not now.
func newNetworkHandlers(d *deps, sensor core.SpanSensor) (*core.NetworkHandlers, error) {
	var h core.NetHost
	if d.HostSocket != "" {
		h = hostclient.New(d.HostSocket)
	}
	return core.NewNetworkHandlers(core.NetworkConfig{
		DB: d.DB, Auth: d.Auth, Audit: d.Audit, Log: d.Log, Host: h, Sensor: sensor, Clock: d.Clock, Gate: d.PurgeGate,
		AddressInUse: func(ctx context.Context, ip netip.Addr) (bool, error) {
			return addressInUse(ctx, d.Inventory, d.Honeypot, ip)
		},
		// AddressesChanged: the cached addresses are dropped and the box's certificate follows its management address (D-139).
		AddressesChanged: func() {
			d.HostNet.Invalidate()
			if d.CertKick != nil {
				d.CertKick()
			}
		},
	})
}

// addressInUse says whether a device of the inventory or a decoy of the honeypot has the address.
func addressInUse(ctx context.Context, inv *inventory.Service, hp *honeypot.Service, ip netip.Addr) (bool, error) {
	if hp != nil && slices.Contains(hp.DecoyIPs(ctx), ip) {
		return true, nil
	}
	return inventoryHasAddress(ctx, inv, ip)
}

// inventoryHasAddress says whether a device of the inventory has the address (the box itself excluded: it is the
// page's own address).
func inventoryHasAddress(ctx context.Context, inv *inventory.Service, ip netip.Addr) (bool, error) {
	if inv == nil {
		return false, nil
	}
	return inv.AddressInUse(ctx, ip.String()) // uncapped (D-178): the 2000 row list forgets the oldest device
}

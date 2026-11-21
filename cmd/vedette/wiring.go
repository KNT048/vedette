package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/productid"
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
	"github.com/knt048/vedette/modules/scan"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// Modules do not import each other. Each module declares the port it needs; the adapters below convert
// between that port and the neutral exported methods of the module that provides it (issues #38, #39), so
// the provider's tables stay private. They live here because only the binary knows both.

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
			out[key] = append(out[key], feeds.MatchedAsset{ID: m.ID, Hostname: m.NameOrHost(), IP: m.IP, Display: m.Display, How: how})
		}
	}
	return out, nil
}

// NotAffected implements feeds.PlatformChecker: the devices the findings matcher's platform rules prove are
// not affected by the CVE, read as findings reads them (findingsInventory.MatchInput), so the CVE page agrees with their findings.
func (a feedsInventory) NotAffected(ctx context.Context, cve, vendor, product string, distro []feeds.DistroFix, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if !findings.HasPlatformLimit(cve) { // only a platform-limited CVE reads the devices
		return out, nil
	}
	now := time.Now()
	fixes := make([]findings.DistroFix, len(distro)) // the release a person gave is read against the distribution's feed
	for i, d := range distro {
		fixes[i] = findings.DistroFix{Distro: d.Distro, Release: d.Release, Package: d.Package, Status: d.Status, Fixed: d.Fixed, Pro: d.Pro}
	}
	for _, id := range ids {
		d, ok, err := findingsInventory(a).MatchInput(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok && findings.PlatformRuledOut(d, cve, vendor, product, fixes, now) {
			out[id] = true
		}
	}
	return out, nil
}

// AddManualDevice declares the "I have this" device and returns its id, so feeds records it on the answer and the
// "I have this" scope of findings (INV-11) covers that one device.
func (a feedsInventory) AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, d feeds.ManualDevice) (string, error) {
	return a.inv.AddManualDevice(ctx, tx, actor, inventory.ManualDevice{Kind: d.Kind, Vendor: d.Vendor, Product: d.Product, Display: d.Display, Key: d.Key})
}

func (a feedsInventory) Settle(ctx context.Context, tx *sql.Tx, committed bool) {
	a.inv.Settle(ctx, tx, committed)
}

// Distros implements feeds.DistroLister: the distributions of the devices whose packages the distributions' data names, as
// findings decides it (findings.DeviceDistro), each with those devices' source packages as the security data names them
// (findings.DevicePackages), so a distribution feed is pulled only while a device needs it and keeps tier rows for those packages;
// and "alpine" while a device states Alpine Linux (findings.StatesAlpine), with its apk source packages when an agent read them.
func (a feedsInventory) Distros(ctx context.Context) (map[string]map[string]bool, error) {
	ids, err := a.inv.AssetIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for _, id := range ids {
		d, ok, err := a.inv.MatchInput(ctx, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		// the same rows as the matcher's (vendor and product too: a person's Debian release names its source package by them)
		fa := findingsAsset(d)
		if findings.StatesAlpine(fa) && out[findings.DistroAlpine] == nil { // fetched while a device states Alpine, even with no apk row yet
			out[findings.DistroAlpine] = map[string]bool{}
		}
		dist, _, pkgs := findings.DevicePackages(fa)
		if dist == "" {
			continue
		}
		if out[dist] == nil {
			out[dist] = map[string]bool{}
		}
		for _, p := range pkgs {
			out[dist][p] = true
		}
	}
	return out, nil
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
	names, err := a.inv.Names(ctx) // the Devices page's name (hostname, else vendor and model, else IP), as notify and reports use it
	if err != nil {
		return nil, err
	}
	out := make(map[string]findings.AssetView, len(refs))
	for id, r := range refs {
		out[id] = findings.AssetView{ID: r.ID, Name: names[id], Hostname: r.Hostname, IP: r.IP, Kind: r.Kind, Display: assetDisplay(r), Approved: r.Approved, Ignored: r.Ignored, Box: r.IsBox}
	}
	return out, nil
}

// assetDisplay is what a finding's device is shown running when the finding's page cannot name the matched software (findings
// matchedOn): its operating system, else its kind; never the device's first software by name, which read "Microsoft Edge" under a
// Windows finding (#905). DeviceRef.Display keeps that first row for the callers that name a declared device by it (notify, audit).
func assetDisplay(r inventory.DeviceRef) string {
	if os := strings.TrimSpace(r.OS); os != "" {
		return os
	}
	return r.Kind
}

// AssetIDs lists every device id for findings' reconcile job: inventory's unfiltered read (no kind filter, no row cap) returns a
// read error as an error, which is what reconcile needs (a short list would make it remove findings of devices that still exist).
func (a findingsInventory) AssetIDs(ctx context.Context) ([]string, error) {
	return a.inv.AssetIDs(ctx)
}

// IgnoredIDs and IsIgnored are the devices a person ignored, for findings' reconcile and its write-time check.
func (a findingsInventory) IgnoredIDs(ctx context.Context) ([]string, error) {
	return a.inv.IgnoredIDs(ctx)
}

// textOf is an optional text, "" when absent.
func textOf(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// EffectiveSoftware is findings' port on inventory's one line: the lines the device runs (a line a person said is not installed is
// left out), each with its other readings.
func (a findingsInventory) EffectiveSoftware(ctx context.Context, id string) ([]findings.EffectiveSoftware, error) {
	lines, err := a.inv.SoftwareLines(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]findings.EffectiveSoftware, 0, len(lines))
	for _, r := range lines {
		if r.NotInstalled {
			continue
		}
		e := findings.EffectiveSoftware{ID: r.ID, Vendor: r.Vendor, Product: r.Product, Display: r.Display, Version: textOf(r.Version), PkgVersion: textOf(r.PkgVersion),
			Packaged: r.Packaged, CPE: r.CPE, Source: r.Source, SetBy: r.SetBy, SeenAt: r.SeenAt, Differs: r.Differs, AlsoSeen: make([]findings.AlsoSeen, len(r.AlsoSeen))}
		for j, o := range r.AlsoSeen {
			e.AlsoSeen[j] = findings.AlsoSeen{ID: o.ID, Source: o.Source, Version: o.Version, PkgVersion: o.PkgVersion, SeenAt: o.SeenAt, SameRelease: o.SameRelease}
		}
		out = append(out, e)
	}
	return out, nil
}

func (a findingsInventory) IsIgnored(ctx context.Context, id string) (bool, error) {
	return a.inv.IsIgnored(ctx, id)
}

// findingsJobs is findings' reconcile job: it heals what a lost event left behind; and its KEV reachability audit (reachJob).
func findingsJobs(d deps) []jobs.Job { return append(findings.Jobs(d.Findings), reachJob(d)) }

func (a findingsInventory) MatchInput(ctx context.Context, assetID string) (findings.Asset, bool, error) {
	d, ok, err := a.inv.MatchInput(ctx, assetID)
	if err != nil || !ok {
		return findings.Asset{}, false, err
	}
	out := findingsAsset(d)
	if d.Name == d.ID { // no hostname and no IP (hand-added, LLDP only): the evidence names it as the Devices page does, never by its id
		names, err := a.inv.Names(ctx)
		if err != nil {
			return findings.Asset{}, false, err
		}
		if n := names[d.ID]; n != "" && n != d.ID {
			out.Name = n
		}
	}
	return out, true, nil
}

// findingsAsset is a device as the matcher reads it. The device page asks the matcher which OS a person's declared row gives it
// (inventory Config.DeclaredOS, findings.DeclaredOSRow) through the same conversion.
func findingsAsset(d inventory.MatchDevice) findings.Asset {
	out := findings.Asset{ID: d.ID, Name: d.Name, OS: d.OS, Model: d.Model, StatedOS: d.StatedOS, AgentOS: d.AgentOS, SNMPOS: d.SNMPOS, MAC: d.MAC, ManualOS: d.ManualOS,
		Software: make([]findings.Software, len(d.Software)), OSCorrection: d.OSCorrection, StaleCorrections: d.StaleCorrections}
	for i, s := range d.Software {
		out.Software[i] = findingsSoftware(s)
	}
	if t, err := time.Parse(time.RFC3339Nano, d.StatedOSAt); err == nil {
		out.StatedOSAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, d.SNMPOSAt); err == nil {
		out.SNMPOSAt = t
	}
	for _, s := range d.NotInstalled { // INV-41 (6): rows a person said are not installed; findings closes what only they produce
		out.NotInstalled = append(out.NotInstalled, findingsSoftware(s))
	}
	return out
}

// declaredOS is inventory's Config.DeclaredOS: the matcher's choice among a device's declared OS rows (INV-45).
func declaredOS(d inventory.MatchDevice, candidates []string) (id, version string, err error) {
	id, version = findings.DeclaredOSRow(findingsAsset(d), candidates)
	return id, version, nil
}

func findingsSoftware(s inventory.MatchSoftware) findings.Software {
	out := findings.Software{ID: s.ID, Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: s.Version, KevKeys: s.KevKeys, CPE: s.CPE,
		Source: s.Source, Packaged: s.Packaged, PkgVersion: s.PkgVersion, PkgSource: s.PkgSource, ReportedSource: s.ReportedSource, Correction: s.Correction, Superseded: s.Superseded,
		Key: s.Key, MarkedBy: s.MarkedBy, Guess: s.Guess}
	if t, err := time.Parse(time.RFC3339Nano, s.MarkedAt); err == nil {
		out.MarkedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, s.SeenAt); err == nil {
		out.SeenAt = t
	}
	return out
}

type findingsFeeds struct {
	st    *feeds.Store
	cache *vulnCache       // nil: read the list every time
	on    func() bool      // whether the feeds module is on (TierVulns reads nothing while it is off); nil: on
	clock func() time.Time // nil: time.Now
}

// vulnCache keeps the last list for matching with the feeds stamp it was read under (a rematch of every
// device read the 33k NVD rows once per device and ran out of time).
type vulnCache struct {
	mu    sync.Mutex
	stamp string
	vulns []findings.Vuln // read only once built: the matcher never changes it
	// productsStamp and products: feeds' RangeProducts as read under that stamp
	productsStamp string
	products      []feeds.RangeProduct
}

func (a findingsFeeds) KevInfo(ctx context.Context, cves []string) (map[string]findings.KevInfo, error) {
	rows, err := a.st.KevVulnsByCVE(ctx, cves)
	if err != nil {
		return nil, err
	}
	pub, err := a.st.PublishedOf(ctx, cves) // Only the CVEs asked for (#803)
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
			RequiredAction: v.RequiredAction, Links: v.Links, DateAdded: v.DateAdded, DueDate: due, Ransomware: v.Ransomware, EPSS: v.EPSS, HasTemplate: safeCheckFor(v.CVE), Source: v.SourceID}
		if d, ok := pub[v.CVE]; ok {
			k := out[v.CVE]
			k.Published = &d
			out[v.CVE] = k
		}
	}
	return out, nil
}

// CVSS is feeds' CVSS base score of each CVE that has one (findings INV-22, feeds INV-28).
func (a findingsFeeds) CVSS(ctx context.Context, cves []string) (map[string]findings.CVSS, error) {
	got, err := a.st.CVSSOf(ctx, cves)
	if err != nil {
		return nil, err
	}
	out := make(map[string]findings.CVSS, len(got))
	for cve, c := range got {
		out[cve] = findings.CVSS{Score: c.Score, Version: c.Version, Source: c.Source, Vector: c.Vector}
	}
	return out, nil
}

// TierStatus is feeds' state of the tier feeds for GET /findings/plan.
func (a findingsFeeds) TierStatus(ctx context.Context) (findings.TierStatus, error) {
	st, err := a.st.TierStatus(ctx, time.Now())
	if err != nil {
		return findings.TierStatus{}, err
	}
	return findings.TierStatus{EPSS: string(st.EPSS), Recent: string(st.Recent), EPSSDate: st.EPSSDate, RecentSince: st.RecentSince}, nil
}

// TierStamp is feeds' stamp of the tier data (Store.TierStamp) with the feeds module's switch: the plan job compares every device again
// when it changes.
func (a findingsFeeds) TierStamp(ctx context.Context) (string, error) {
	if a.on != nil && !a.on() {
		return "feeds-off", nil
	}
	return a.st.TierStamp(ctx)
}

// TierVulns is feeds' tier data for "Updates to plan": nothing while the feeds module is off (modules.md: its data is not read).
func (a findingsFeeds) TierVulns(ctx context.Context, keep func(cpe string) bool) ([]findings.TierVuln, error) {
	if a.on != nil && !a.on() {
		return nil, nil
	}
	now := time.Now()
	if a.clock != nil {
		now = a.clock()
	}
	recs, err := a.st.TierRecords(ctx, now, keep)
	if err != nil {
		return nil, err
	}
	out := make([]findings.TierVuln, len(recs))
	for i, r := range recs {
		out[i] = findings.TierVuln{CVE: r.CVE, Tier: r.Tier, Published: r.Published, Severity: strings.ToLower(r.Severity), Score: r.Score, EPSS: r.EPSS, Percentile: r.Percentile,
			Affected: make([]findings.Affected, len(r.Affected)), Platforms: r.Platforms}
		for j, af := range r.Affected {
			out[i].Affected[j] = findings.Affected{CPE: af.CPE, Range: findings.VersionRange{StartIncl: af.StartIncl, StartExcl: af.StartExcl, EndIncl: af.EndIncl, EndExcl: af.EndExcl}}
		}
	}
	return out, nil
}

// TierDistro is the distributions' tier data for "Updates to plan": nothing while the feeds module is off.
func (a findingsFeeds) TierDistro(ctx context.Context, pkgs []findings.DistroPackage) (findings.DistroTier, error) {
	if a.on != nil && !a.on() {
		return findings.DistroTier{}, nil
	}
	now := time.Now()
	if a.clock != nil {
		now = a.clock()
	}
	in := make([]feeds.DistroPackage, len(pkgs))
	for i, p := range pkgs {
		in[i] = feeds.DistroPackage{Distro: p.Distro, Release: p.Release, Package: p.Package}
	}
	td, err := a.st.TierDistroRecords(ctx, now, in)
	if err != nil {
		return findings.DistroTier{}, err
	}
	out := make([]findings.TierVuln, len(td.Records))
	for i, r := range td.Records {
		out[i] = findings.TierVuln{CVE: r.CVE, Tier: r.Tier, Published: r.Published, Severity: strings.ToLower(r.Severity), Score: r.Score, EPSS: r.EPSS, Percentile: r.Percentile,
			Distro: make([]findings.DistroFix, len(r.Distro))}
		for j, d := range r.Distro {
			out[i].Distro[j] = findings.DistroFix{Distro: d.Distro, Release: d.Release, Package: d.Package, Status: d.Status, Fixed: d.Fixed, Pro: d.Pro}
		}
	}
	return findings.DistroTier{Vulns: out, Covered: td.Covered, Known: td.Known, Loading: td.Loading}, nil
}

// Vulns returns the CISA list for matching, each CVE with the NVD affected versions feeds pulled (nvd-kev), or
// those of the CNA's CVE.org record when NVD has none (cve-org). A CVE with neither has none, and findings then
// cannot decide by version.
func (a findingsFeeds) Vulns(ctx context.Context) ([]findings.Vuln, error) {
	stamp := ""
	if a.cache != nil {
		var err error
		if stamp, err = a.st.MatchStamp(ctx); err != nil {
			return nil, err
		}
		a.cache.mu.Lock()
		v, ok := a.cache.vulns, a.cache.vulns != nil && a.cache.stamp == stamp
		a.cache.mu.Unlock()
		if ok {
			return v, nil
		}
	}
	out, err := a.readVulns(ctx)
	if err == nil && a.cache != nil { // the stamp was read first: the list is at least as new as it
		a.cache.mu.Lock()
		a.cache.stamp, a.cache.vulns = stamp, out
		a.cache.mu.Unlock()
	}
	return out, err
}

func (a findingsFeeds) readVulns(ctx context.Context) ([]findings.Vuln, error) {
	rows, err := a.st.KevVulns(ctx)
	if err != nil {
		return nil, err
	}
	affected, err := a.st.KevAffected(ctx)
	if err != nil {
		return nil, err
	}
	fromCVEOrg, err := a.st.RangesFromCVEOrg(ctx) // ranges of the CNA's CVE.org record where NVD has none
	if err != nil {
		return nil, err
	}
	distro, err := a.st.DistroFixes(ctx) // Ubuntu's and Debian's word on their own packages
	if err != nil {
		return nil, err
	}
	loading, err := a.st.DistroLoading(ctx) // a feed on but not loaded keeps Alpine's questions (NVD would raise a false finding)
	if err != nil {
		return nil, err
	}
	published, err := a.st.KevPublished(ctx) // An old KEV CVE is a finding only on confirmed evidence
	if err != nil {
		return nil, err
	}
	out := make([]findings.Vuln, len(rows))
	for i, v := range rows {
		out[i] = findings.Vuln{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Name: v.Name, Ransomware: v.Ransomware, Source: v.SourceID, HasTemplate: v.HasTemplate,
			DistroLoading: loading}
		_, out[i].NVDAnswered = affected[v.CVE] // KevAffected has an entry, even empty, for every CVE NVD or the CVE record answered for
		out[i].RangesFrom = rangesFrom(fromCVEOrg[v.CVE])
		for _, r := range affected[v.CVE] {
			out[i].Affected = append(out[i].Affected, findings.Affected{CPE: r.CPE,
				Range: findings.VersionRange{StartIncl: r.StartIncl, StartExcl: r.StartExcl, EndIncl: r.EndIncl, EndExcl: r.EndExcl}})
		}
		for _, d := range distro[v.CVE] {
			out[i].Distro = append(out[i].Distro, findings.DistroFix{Distro: d.Distro, Release: d.Release, Package: d.Package, Status: d.Status, Fixed: d.Fixed, Pro: d.Pro})
		}
		if t, err := time.Parse(time.DateOnly, v.DateAdded); err == nil { // an unreadable date stays zero: backlog, never news
			out[i].DateAdded = t
		}
		if v.EPSS != nil {
			out[i].EPSS = *v.EPSS
		}
		out[i].Published = published[v.CVE] // zero when NVD has not answered: counts as recent
	}
	return out, nil
}

// MatchSet is what findings' match pass compares the devices with (findings.Feeds.MatchSet): the exploited lists' entries (Vulns),
// then every other catalogue CVE whose ranges name a product the devices run (scope.Keep), whose vendor states versions of such a
// product in its own notation (SchemeCVEs), that a distribution fixed in a package the devices run (scope.Packages) or that a finding
// holds (scope.Pinned), with the ranges the catalogue's precedence gives (feeds' rangeOrigin: NVD's when NVD has any, else the CVE
// record's), the vendor's rows read in the product's version scheme (Schemed), the publication day, EPSS and the distributions' word.
// Every entry, the exploited lists' included, carries the same data whichever of these found it. Nothing while the feeds module is off.
func (a findingsFeeds) MatchSet(ctx context.Context, scope findings.MatchScope) ([]findings.Vuln, error) {
	if a.on != nil && !a.on() {
		return nil, nil
	}
	kev, err := a.Vulns(ctx)
	if err != nil {
		return nil, err
	}
	out := slices.Clone(kev) // the cached list is never written: Schemed is added to the copy
	listed := make(map[string]bool, len(kev))
	for _, v := range kev {
		listed[v.CVE] = true
	}
	more, err := a.catalogueEntries(ctx, scope, listed)
	if err != nil {
		return nil, err
	}
	out = append(out, more...)
	if err := a.withSchemed(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// catalogueEntries is MatchSet's part beyond the exploited lists (listed): the catalogue CVEs the scope reaches, each once.
func (a findingsFeeds) catalogueEntries(ctx context.Context, scope findings.MatchScope, listed map[string]bool) ([]findings.Vuln, error) {
	products, err := a.rangeProducts(ctx)
	if err != nil {
		return nil, err
	}
	var keys []feeds.ProductKey
	for _, k := range products {
		v, p := feeds.MatchName(k.Vendor, k.Product, k.Record)
		if scope.Keep(v, p, k.Record) || k.Record && scope.Keep(k.Vendor, k.Product, true) {
			keys = append(keys, feeds.ProductKey{Vendor: k.Vendor, Product: k.Product})
		}
	}
	ranges, err := a.st.Ranges(ctx, keys)
	if err != nil {
		return nil, err
	}
	reached := map[string]bool{} // CVEs found by a vendor's own rows or a distribution's word, beside the generic ranges
	schemeCVEs, err := a.st.SchemeCVEs(ctx, keys)
	if err != nil {
		return nil, err
	}
	pkgs := make([]feeds.DistroPackage, len(scope.Packages))
	for i, p := range scope.Packages {
		pkgs[i] = feeds.DistroPackage{Distro: p.Distro, Release: p.Release, Package: p.Package}
	}
	distroCVEs, err := a.st.DistroCVEs(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	for _, c := range slices.Concat(schemeCVEs, distroCVEs) {
		reached[c] = true
	}
	var pins []string
	pinSet := map[string]bool{}
	for _, c := range scope.Pinned {
		if !listed[c] && !pinSet[c] {
			pins = append(pins, c)
			pinSet[c] = true
		}
	}
	pinned, err := a.st.RangesOf(ctx, pins)
	if err != nil {
		return nil, err
	}
	byCVE := map[string][]feeds.Range{}
	for _, r := range pinned { // every range of a pinned CVE
		byCVE[r.CVE] = append(byCVE[r.CVE], r)
	}
	for _, r := range ranges { // the ranges of the scope's products of the others
		if !listed[r.CVE] && !pinSet[r.CVE] {
			byCVE[r.CVE] = append(byCVE[r.CVE], r)
		}
	}
	cves := slices.Sorted(maps.Keys(byCVE))
	for _, c := range pins { // a pinned CVE whose ranges are all gone (rejected) is still judged: its findings go away
		if _, ok := byCVE[c]; !ok {
			cves = append(cves, c)
		}
	}
	for _, c := range slices.Sorted(maps.Keys(reached)) {
		if _, ok := byCVE[c]; !ok && !listed[c] && !pinSet[c] {
			cves = append(cves, c)
		}
	}
	if len(cves) == 0 {
		return nil, nil
	}
	cat, err := a.st.Catalogue(ctx, cves)
	if err != nil {
		return nil, err
	}
	distro, err := a.st.DistroFixesFor(ctx, cves)
	if err != nil {
		return nil, err
	}
	loading, err := a.st.DistroLoading(ctx)
	if err != nil {
		return nil, err
	}
	var out []findings.Vuln
	for _, cve := range cves {
		e, inCatalogue := cat[cve]
		rows := byCVE[cve]
		if len(rows) == 0 && !inCatalogue {
			continue // not in the catalogue at all: nothing says anything about it, so it is not judged
		}
		v := findings.Vuln{CVE: cve, NVDAnswered: true, HasTemplate: safeCheckFor(cve), DistroLoading: loading, Origin: recordOrigin(rows)}
		complete := true
		for _, r := range rows {
			complete = complete && (r.DefaultStatus == feeds.DefaultAffected || r.DefaultStatus == feeds.DefaultUnaffected)
			if row, ok := r.MatchRow(); ok {
				v.Affected = append(v.Affected, findings.Affected{CPE: row.CPE,
					Range: findings.VersionRange{StartIncl: row.StartIncl, StartExcl: row.StartExcl, EndIncl: row.EndIncl, EndExcl: row.EndExcl}})
			}
		}
		switch {
		case v.Origin == feeds.OriginNVD || len(rows) == 0:
		case complete:
			v.RangesFrom = findings.RangesCVEOrg
		default:
			v.RangesFrom = findings.RangesCVEOrgPartial
		}
		if e.Published != nil {
			v.Published = *e.Published
		}
		if e.EPSS != nil {
			v.EPSS = *e.EPSS
		}
		for _, d := range distro[cve] {
			v.Distro = append(v.Distro, findings.DistroFix{Distro: d.Distro, Release: d.Release, Package: d.Package, Status: d.Status, Fixed: d.Fixed, Pro: d.Pro})
		}
		if len(v.Affected) > 0 || len(v.Distro) > 0 || pinSet[cve] || reached[cve] {
			out = append(out, v)
		}
	}
	return out, nil
}

// withSchemed adds to each entry of vulns the ranges its vendor states in its own notation, read in the version scheme of the
// product they name (feeds.RangeScheme): what the matcher and findings.FixOf read the vendor's fixed release of a device's train from.
// An entry no such range names is left without any.
func (a findingsFeeds) withSchemed(ctx context.Context, vulns []findings.Vuln) error {
	if len(vulns) == 0 {
		return nil
	}
	cves := make([]string, len(vulns))
	at := make(map[string]int, len(vulns))
	for i, v := range vulns {
		cves[i] = v.CVE
		at[v.CVE] = i
		vulns[i].Schemed = nil // a copy of a cached entry shares its slice: never append to it
	}
	rows, err := a.st.SchemeRangesOf(ctx, cves)
	if err != nil {
		return err
	}
	for _, r := range rows {
		s, sp, _, ok := feeds.RangeScheme(r)
		if !ok {
			continue
		}
		p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
		if !ok {
			continue
		}
		i := at[r.CVE]
		vulns[i].Schemed = append(vulns[i].Schemed, findings.SchemedRange{Product: p.Key, Scheme: s, Span: sp, Origin: r.Origin})
	}
	return nil
}

// recordOrigin is the origin of a CVE's ranges as the catalogue's precedence gave them: nvd when any is NVD's, else cna when the CNA
// gave any, else adp ("" for none).
func recordOrigin(rows []feeds.Range) string {
	origin := ""
	for _, r := range rows {
		switch {
		case r.Origin == feeds.OriginNVD:
			return feeds.OriginNVD
		case r.Origin == feeds.OriginCNA || origin == "":
			origin = r.Origin
		}
	}
	return origin
}

// rangeProducts is feeds' RangeProducts, read once per match stamp (the stamp moves with every pull that writes ranges).
func (a findingsFeeds) rangeProducts(ctx context.Context) ([]feeds.RangeProduct, error) {
	if a.cache == nil {
		return a.st.RangeProducts(ctx)
	}
	stamp, err := a.st.MatchStamp(ctx)
	if err != nil {
		return nil, err
	}
	a.cache.mu.Lock()
	p, ok := a.cache.products, a.cache.products != nil && a.cache.productsStamp == stamp
	a.cache.mu.Unlock()
	if ok {
		return p, nil
	}
	p, err = a.st.RangeProducts(ctx)
	if err == nil {
		a.cache.mu.Lock()
		a.cache.productsStamp, a.cache.products = stamp, p
		a.cache.mu.Unlock()
	}
	return p, err
}

// rangesFrom maps the source feeds stored for a CVE's ranges to what findings may do with them: "" (NVD), a
// complete CVE.org list (may close), or a partial one (may only raise).
func rangesFrom(src string) string {
	switch src {
	case "cve.org":
		return findings.RangesCVEOrg
	case "cve.org-partial":
		return findings.RangesCVEOrgPartial
	}
	return ""
}

// findingsHave is feeds' "I have this" scopes, by declared device, as findings reads them (INV-11).
func findingsHave(st *feeds.Store) func(ctx context.Context) (map[string]findings.Have, error) {
	return func(ctx context.Context) (map[string]findings.Have, error) {
		got, err := st.HaveSince(ctx)
		if err != nil {
			return nil, err
		}
		out := make(map[string]findings.Have, len(got))
		for id, h := range got {
			out[id] = findings.Have{Key: h.Key, Since: h.Since}
		}
		return out, nil
	}
}

// findingsPublisher puts findings events on the bus.
type findingsPublisher struct{ bus *events.Bus }

func (p findingsPublisher) Publish(ctx context.Context, name string, payload any) error {
	return p.bus.Publish(ctx, events.Event{Name: name, Data: payload})
}

// ---- inventory -> mitigation (mitigation.Vendors) ----

type mitigationVendors struct {
	inv *inventory.Service
}

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
	if d.Runs, err = newRuns(d); err != nil { // before the modules: each registers its kinds of run on it
		return fmt.Errorf("runs: %w", err)
	}
	if d.Schedules, err = newSchedules(d); err != nil { // before the modules: each registers its schedules on it
		return fmt.Errorf("schedules: %w", err)
	}
	d.Inventory = newInventory(d) // before feeds: feeds takes the inventory (feeds.Inventory)
	d.BoxName.useRow(boxRowName(d.Inventory))
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
	if d.OIDC, err = authoidc.New(authoidc.Deps{DB: d.DB, Secrets: d.Secrets, Auth: d.Auth, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Zone: orgTimeZone(d)}); err != nil {
		return fmt.Errorf("auth-oidc: %w", err)
	}
	if d.AgentIntake, err = agentintake.New(agentintake.Config{DB: d.DB, Audit: d.Audit, Sink: d.Inventory, Software: d.Inventory, Services: d.Inventory, Approver: d.Inventory, Secrets: d.Secrets, Conn: d.Conn, Clock: d.Clock, Log: d.Log,
		TrustAnchor: d.TrustAnchor, HostAllowed: d.HostAllowed, BoxURL: d.BaseURL, MirrorDir: d.OsqueryDir}); err != nil {
		return fmt.Errorf("agent-intake: %w", err)
	}
	d.Logs = logexport.New()
	d.PurgeGate = &core.PurgeGate{}
	var scope core.SetupScope // the wizard's LAN ranges become the inventory's scope (INV-15, #350)
	if d.Inventory != nil {
		scope = d.Inventory
	}
	if d.Core, err = core.NewAPIHandlers(core.HandlersConfig{Scope: scope, BoxLAN: func(ctx context.Context) (netip.Prefix, bool) { return d.Network.ManagementLAN(ctx) }, Logs: d.Logs, SpoolDir: logSpoolDir(d.DataDir), DB: d.DB, Auth: d.Auth, Reg: d.Reg, Audit: d.Audit, Secrets: d.Secrets, Log: d.Log, Clock: d.Clock, Facts: privacyFacts{conns: d.Conn, d: d}, Names: auditNamer{d: d}, Conns: d.Conn,
		DataDir: d.DataDir, DataFiles: moduleDataFiles, Schema: schemaSets(wiredModules()), Restart: d.Restart, KeyPath: d.KeyPath,
		Host: purgeHost(d), OSBusy: func(ctx context.Context) bool { return d.OS != nil && d.OS.Busy(ctx) }, BeforeWipe: purgeBeforeWipe(d), Gate: d.PurgeGate, AlsoKept: purgeAlsoKept(d), KeepRows: purgeKeptRows(d), AlsoFreeze: purgeFreezes(d)}); err != nil {
		return fmt.Errorf("core: %w", err)
	}
	//nolint:contextcheck // the start-up settle of a first-run restore runs on the OS handlers' own context, bounded to 10 s, like resume
	if d.OS, err = newOSHandlers(*d); err != nil {
		return fmt.Errorf("os updates: %w", err)
	}
	sensor := &spanSensor{reg: d.Reg} // its service comes below: the Box network page needs the sensor and the sensor needs the page's settings
	//nolint:contextcheck // AddressesChanged (core) has no context; Invalidate bounds its own read (boxAddrTimeout)
	if d.Network, err = newNetworkHandlers(d, sensor); err != nil {
		return fmt.Errorf("box network: %w", err)
	}
	if d.Honeypot, err = newHoneypot(d); err != nil {
		return fmt.Errorf("honeypot: %w", err)
	}
	if d.HostSocket != "" {
		d.SensorStart = &startWatch{now: d.Clock}
		d.ScanStart = &startWatch{now: d.Clock, busyOnly: true}
	}
	sp, err := newSensorPassive(*d)
	if err != nil {
		return fmt.Errorf("sensor-passive: %w", err)
	}
	d.SensorPassive = sp
	sensor.svc = sp
	d.SensorDispatcher = sensoractive.NewDispatcher(sensoractive.DispatcherOptions{Now: d.Clock, Log: d.Log, ContainerOnly: d.Reg != nil && d.Reg.ContainerOnly()})
	fs, err := feedsService(*d)
	if err != nil {
		return fmt.Errorf("feeds: %w", err)
	}
	inv := findingsInventory{d.Inventory}
	feed := findingsFeeds{st: fs.Store(), cache: &vulnCache{}, clock: d.Clock}
	if d.Reg != nil {
		feed.on = func() bool { return d.Reg.Enabled("feeds") }
	}
	// Backlog: findings the reconcile job creates for old KEV entries are backlog, silent for notify (findings does not import notify).
	cfg := findings.ServiceConfig{DB: d.DB, Audit: d.Audit, Inventory: inv, Feeds: feed, Log: d.Log, Clock: d.Clock, Zone: orgTimeZone(d), Backlog: notify.WithBaseline,
		HaveSince: findingsHave(fs.Store()), // "I have this" on Home scopes the one device it declared
		Applied:   mitigationApplied,        // a merge keeps the finding a person marked a mitigation item applied on
		Lifecycle: d.Lifecycle,              // a merge that folds two findings tells mitigation and response (registerLifecycle)
		SafeCheck: safeCheckFor}             // "a safe check exists": the scan's own pack, the same answer as KevInfo.HasTemplate
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
	// Home's one read (GET /findings/summary, #825; also the shell's nav badges) carries inventory's device counts and notify's sent
	// messages and open incidents; findings imports neither.
	home := findings.HomeSources{Alerts: notifySvc.SentSince, Incidents: notifySvc.OpenIncidents}
	if d.Inventory != nil {
		home.Devices = d.Inventory.DeviceCounts
	}
	d.FindingHandlers.SetHome(home)
	d.FindingHandlers.SetAgents(agentReports(d))
	d.FindingHandlers.SetScanReach(scanReach(d))
	// The ai service comes before mitigation: mitigation reaches the AI only through this door (mitigation.AI), and the door is
	// unavailable while no profile is assigned, so the page offers no AI button then.
	d.AIFacts = aiFacts{fs.Store(), d.Findings, inv, aiBoxID(d.Inventory)}
	ask := aiAsk{feeds: fs.Store(), findings: d.Findings, inv: d.Inventory, gate: gate}
	if d.AI, err = newAI(ctx, d, d.AIFacts, ask, ask); err != nil { // ask is also device_updates' door, typed (#935)
		return fmt.Errorf("ai: %w", err)
	}
	aiDoor := aiMitigation{svc: d.AI, inv: d.Inventory, log: d.Log}
	if d.HostSocket != "" { // the box's subnets and gateways decide which firewalls are on a device's path; no host, not known
		aiDoor.net = aiNetReader(hostclient.New(d.HostSocket))
	}
	provider, err := mitigation.NewProvider(d.DB, mitigationVendors{d.Inventory}, aiDoor)
	if err != nil {
		return err
	}
	provider.SetAgents(agentReports(d)) // the same agent check as Updates to plan: "How to check" never promises a gone agent
	d.FindingHandlers.SetGuidance(provider)
	if d.MitigationHandlers, err = mitigation.NewActionHandlers(d.DB, d.Audit, d.Findings, d.FindingHandlers, aiDoor, d.Clock); err != nil {
		return err
	}
	d.PackLoader = mitigation.NewLoader(d.DB, d.Audit, packVerifier{trust: d.PackTrust}, d.Log, d.Clock)
	if d.Response, err = newResponse(d); err != nil { //nolint:contextcheck // response's BoxAddrs port has no context: it reads the decoys with its own short budget
		return fmt.Errorf("response: %w", err)
	}
	registerLogSources(d)
	registerLifecycle(d, notifySvc, fs)
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
	// A device's OS or model can decide its findings by itself (an LLDP switch stating "JUNOS 15.1R7.9" has no
	// software row), so a device whose OS or model is new or changed is matched again, as a software change does. Other
	// field changes (hostname, kind, last seen) do not match it again (#703).
	for _, name := range []string{inventory.EventAssetDiscovered, inventory.EventAssetUpdated} {
		d.Bus.Subscribe(name, on("findings", func(ctx context.Context, data any) error {
			ev, ok := data.(inventory.AssetEvent)
			if !ok {
				return fmt.Errorf("unexpected payload %T", data)
			}
			if !ev.Match {
				return nil
			}
			_, err := d.Findings.OnMatchChanged(ctx, ev.AssetID)
			if errors.Is(err, findings.ErrUnknownAsset) {
				return nil // the device was deleted after the event went out
			}
			return err
		}))
	}
	// #910, #920: a software change that keeps the exploited-list keys (an agent's version upgrade, a removed row)
	// sends no match.changed, so the device's "add the version" items and "could not be checked" rows would name the old row until
	// the hourly reconcile: match it again now.
	d.Bus.Subscribe(inventory.EventSoftwareChanged, on("findings", func(ctx context.Context, data any) error {
		ev, ok := data.(inventory.AssetEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		_, err := d.Findings.OnMatchChanged(ctx, ev.AssetID)
		if errors.Is(err, findings.ErrUnknownAsset) {
			return nil // the device was deleted after the event went out
		}
		return err
	}))
	// "Updates to plan" compares a device again on any change of its software (a version upgrade, a new
	// product without an exploited-list key, a removed row: inventory.match.changed covers only exploited-list keys) and on any
	// discovered or updated device (its agent's OS decides platform-limited CVEs). Only a mark: the plan job does the work.
	for _, name := range []string{inventory.EventSoftwareChanged, inventory.EventAssetDiscovered, inventory.EventAssetUpdated} {
		d.Bus.Subscribe(name, on("findings", func(_ context.Context, data any) error {
			ev, ok := data.(inventory.AssetEvent)
			if !ok {
				return fmt.Errorf("unexpected payload %T", data)
			}
			d.Findings.MarkPlan(ev.AssetID)
			return nil
		}))
	}
	// An ignored device's findings stay as they are: ignoring is an attribute of the device, and every list leaves its findings out
	// (while it is ignored nothing new is made: MatchInput says it is not there, AssetIDs leaves it out).
	// A finding on a device, or a honeypot hit from it, is a reason to look at a private-address device that was held out of To review:
	// it joins To review with its one new-device notice (inventory INV-49).
	d.Bus.Subscribe(findings.EventCreated, on("inventory", func(ctx context.Context, data any) error {
		var ev struct {
			AssetID string `json:"asset_id"`
		}
		if err := eventInto(data, &ev); err != nil {
			return err
		}
		return d.Inventory.EarnReview(ctx, ev.AssetID)
	}))
	d.Bus.Subscribe(honeypot.EventHitCreated, on("inventory", func(ctx context.Context, data any) error {
		var ev struct {
			SrcAssetID string `json:"src_asset_id"`
		}
		if err := eventInto(data, &ev); err != nil {
			return err
		}
		if ev.SrcAssetID == "" {
			return nil
		}
		return d.Inventory.EarnReview(ctx, ev.SrcAssetID)
	}))
	d.Bus.Subscribe(feeds.EventNewKEV, on("inventory", func(ctx context.Context, data any) error {
		ev, ok := data.(feeds.NewKEVEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		_, err := d.Inventory.RematchCVE(ctx, ev.CVE, ev.Vendor, ev.Product)
		return err
	}))
	d.Bus.Subscribe(feeds.EventNewKEV, on("scan", onNewKEVForScan(d))) // after inventory's: the findings of the new entry exist when the job looks
	// A device whose network scan was turned off (or that may no longer be scanned) stops being scanned now.
	d.Bus.Subscribe(inventory.EventAssetUpdated, on("scan", func(ctx context.Context, data any) error {
		ev, ok := data.(inventory.AssetEvent)
		if !ok {
			return fmt.Errorf("unexpected payload %T", data)
		}
		return scanService(d).DeviceChanged(ctx, ev.AssetID)
	}))
	d.Bus.Subscribe(feeds.EventVulnUpdated, on("inventory", rematchUpdated(d))) // A CVE whose vendor or product changed
	// The first device that states Alpine Linux (its SNMP answer, its agent, a person's OS) pulls alpine-osv
	// now, not at the next feeds check: until it is loaded that device's Alpine-only CVEs stay questions.
	for _, name := range []string{inventory.EventAssetDiscovered, inventory.EventAssetUpdated} {
		d.Bus.Subscribe(name, on("feeds", alpineWake(d)))
	}
	// New NVD affected versions decide findings again for every device; the first fill is backlog.
	// One event per device; after a later update only the devices of the changed CVEs.
	d.Bus.Subscribe(feeds.EventRangesUpdated, on("inventory", rangesUpdated(&d)))
	d.Bus.Subscribe(feeds.EventSyncBaseline, on("inventory", func(ctx context.Context, _ any) error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rematchTimeout)
		defer cancel()
		ctx = notify.WithBaseline(ctx)
		_, err := d.Inventory.RematchAll(ctx)
		return err
	}))
	d.Bus.Subscribe(exposure.EventSnapshotCreated, on("response", exposurePortsOpened(d))) // new_port, the one reader of a new port
}

// rangesUpdated is the subscriber of feeds.ranges.updated: new affected versions decide findings again. The first fill rematches every
// device as backlog; a later update rematches the devices of the changed exploited-list CVEs. A change of a catalogue CVE's ranges
// (RangesUpdatedEvent.Catalogue, or a CVE no list holds) runs findings' match pass now instead of at its next hour: it is the one
// reader of those CVEs.
func rangesUpdated(d *deps) func(ctx context.Context, data any) error {
	return func(ctx context.Context, data any) error {
		ev, _ := data.(feeds.RangesUpdatedEvent)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rematchTimeout)
		defer cancel()
		wake := func() {
			if d.Wake != nil {
				d.Wake("findings", "reconcile")
			}
		}
		if len(ev.CVEs) == 0 {
			if ev.Catalogue {
				wake()
			}
			return nil
		}
		st, ok := feedsKEV{d}.store()
		if ev.First || !ok {
			if ev.First {
				ctx = notify.WithBaseline(ctx)
			}
			_, err := d.Inventory.RematchAll(ctx)
			return err
		}
		rows, err := st.KevVulnsByCVE(ctx, ev.CVEs)
		if err != nil {
			return err
		}
		refs := make([]inventory.KevRef, len(rows))
		listed := make(map[string]bool, len(rows))
		for i, r := range rows {
			refs[i] = inventory.KevRef{CVE: r.CVE, Vendor: r.Vendor, Product: r.Product}
			listed[r.CVE] = true
		}
		if ev.Catalogue || catalogueChanged(ev.CVEs, listed) {
			wake()
		}
		_, err = d.Inventory.RematchMany(ctx, refs)
		return err
	}
}

// catalogueChanged says a ranges update names a CVE that is on no exploited list (listed): only findings' match pass compares those
// with the devices.
func catalogueChanged(cves []string, listed map[string]bool) bool {
	return slices.ContainsFunc(cves, func(c string) bool { return !listed[c] })
}

// alpineWake wakes the feeds pull job when a device whose OS changed states Alpine Linux and alpine-osv is on but not loaded yet
// (feeds' DistroLoading): the job pulls it at once, the gate (feedsInventory.Distros) now finding the device. Only a change of what the
// matcher reads of the device (AssetEvent.Match) reads it, so a scan's routine updates cost nothing.
func alpineWake(d deps) func(ctx context.Context, data any) error {
	return func(ctx context.Context, data any) error {
		ev, ok := data.(inventory.AssetEvent)
		if !ok || !ev.Match || d.Wake == nil {
			return nil
		}
		st, ok := feedsKEV{&d}.store()
		if !ok {
			return nil
		}
		loading, err := st.DistroLoading(ctx)
		if err != nil || !loading[feeds.DistroAlpine] {
			return err
		}
		a, ok, err := findingsInventory{d.Inventory}.MatchInput(ctx, ev.AssetID)
		if err != nil || !ok || !findings.StatesAlpine(a) {
			return err
		}
		d.Wake("feeds", "pull")
		return nil
	}
}

// rematchUpdated handles feeds.vuln.updated: the payload names the CISA entries that changed, any field, and the has_template flips
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
// to the distribution's own chrony sources, which the box never removes (PRIVACY.md), and core cannot see whether the
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

// ConnectionsConfigured: flow 12 is on while an enabled connection exists. A store that cannot be read counts as "on": the
// Privacy page must never say that nothing leaves the box when it does not know.
func (p privacyFacts) ConnectionsConfigured(ctx context.Context) bool {
	if p.conns == nil {
		return false
	}
	on, err := p.conns.HasEnabled(ctx)
	return err != nil || on
}

// GreenboneEnabled: flow 16 (OpenVAS's images and feed) is on while an administrator has OpenVAS enabled on this box,
// whether the module is on or not (turning the module off stops the containers; the badge then errs on the side of "on"). It reads the exposure service that
// carries cfg.Greenbone, so the badge and the containers cannot disagree; without vedette-host nothing can be enabled.
func (p privacyFacts) GreenboneEnabled(ctx context.Context) bool {
	if p.d == nil || p.d.DB == nil {
		return false
	}
	return exposureService(*p.d).GreenboneEnabled(ctx)
}

// WazuhConnected: flow 14 is on while agent-intake has a Wazuh server saved; the caller checks that the module is on. A store
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
		Zone: d.Core.OrgTimeZone, Setup: d.Core, Clock: d.Clock, Gate: d.PurgeGate,
		Version: version, // the software update check: release documents from core.DefaultReleaseBase with core's own client and the embedded keys
		Wake: func() { // the job of coreJobs (sensorwire.go)
			if d.Wake != nil {
				d.Wake("core", "software-update")
			}
		},
		Installed: func() { // the box's packages changed: read them again now, not at the next hourly box run
			if d.Wake != nil {
				d.Wake("inventory", "box")
			}
		},
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
		// AddressesChanged: the cached addresses are dropped and the box's certificate follows its management address and its
		// Box address (a save, or a new management address that is its default).
		BoxLinks: func(context.Context) core.BoxLinks {
			var base string
			if d.BaseURL != nil {
				base = d.BaseURL()
			}
			return core.BoxLinks{Base: base, SelfSigned: d.SelfSigned}
		},
		AddressesChanged: func() {
			d.HostNet.Invalidate()
			d.BoxAddr.Invalidate()
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
	return inv.AddressInUse(ctx, ip.String()) // uncapped: the 2000 row list forgets the oldest device
}

// mitigationApplied tells findings which findings have a mitigation item a person marked applied (mit_applied): the binary
// reads mitigation's table, inside the merge's transaction, so that findings does not.
func mitigationApplied(ctx context.Context, tx *sql.Tx, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	list, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT finding_id FROM mit_applied WHERE finding_id IN (SELECT value FROM json_each(?))`, string(list))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// agentReports is findings' AgentReports: whether an agent of this box reads the device's software now, by agent-intake's report
// state, the answer the finding page's "I updated it" line reads (an osquery node that calls and is not stale, the Wazuh pull, the
// box itself). agent-intake off, no agent, a silent node or a state that cannot be read: false, so Updates to plan says the version is
// the one an agent last reported, as the finding page does.
func agentReports(d *deps) findings.AgentReports {
	return func(ctx context.Context, id string) bool {
		if d.Inventory != nil {
			if dev, found, err := d.Inventory.AgentDevice(ctx, id); err == nil && found && dev.IsBox {
				return true // the box reads its own packages, agent-intake on or off
			}
		}
		if d.AgentIntake == nil || d.Reg != nil && !d.Reg.Enabled("agent-intake") {
			return false
		}
		st, err := d.AgentIntake.ReportState(ctx, id)
		if err != nil {
			return false
		}
		switch {
		case st.Off: // a person turned the agent off for this device: its data is refused
			return false
		case st.Agent == agentintake.ReportBox:
			return true
		case st.Agent == agentintake.ReportOsquery, st.Agent == agentintake.ReportWazuh:
			return !st.Stale // NodeHealth: quiet is "no agent reports this device now"
		}
		return false
	}
}

// scanReach is how the vulnerability scan stands to a device, for the finding page's "why only suspected" line: unknown (""
// = the line says nothing about the scan) when the scan module cannot be read, off while its module is off.
func scanReach(d *deps) findings.ScanReach {
	return func(ctx context.Context, id string) string {
		if d.Reg != nil && !d.Reg.Enabled("scan") {
			return findings.ScanOff
		}
		r, err := scanService(*d).Reach(ctx, id)
		if err != nil {
			return ""
		}
		switch r {
		case scan.ReachOutside:
			return findings.ScanOutside
		case scan.ReachOff:
			return findings.ScanOff
		case scan.ReachNoRanges:
			return findings.ScanNoRanges
		case scan.ReachByHand:
			return findings.ScanByHand
		case scan.ReachDeviceOff:
			return findings.ScanDeviceOff
		}
		return ""
	}
}

// eventInto reads an event's data, whatever type the publisher gave it, through its JSON form.
func eventInto(data, into any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("read event data: %w", err)
	}
	return json.Unmarshal(raw, into)
}

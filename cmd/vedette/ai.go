package main

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
	"github.com/knt048/vedette/modules/notify"
)

// newAI builds the ai service once, in buildServices (deps.AI): the handlers and the mitigation door share one router and one
// meter. It reads the box time zone from core's general settings once, at start (the meter's day boundary); a change of zone
// applies after a restart. The data it explains from comes through aiFacts, the ports of feeds, findings and the inventory.
func newAI(ctx context.Context, d *deps, facts ai.Facts, data ai.Data) (*ai.Service, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg := ai.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Zone: orgZone(d), Facts: facts, ChainPruner: aiChainPruner{}, Data: data,
		BoxAddrs: machineAddrs(d), SelfAddrs: vedetteSelf(d)} // D-446: no profile on Vedette itself
	if d.ConnReader != nil { // the read tools of the connections (core/conn/read, D-127); a nil *read.Reader in the interface would not compare equal to nil
		cfg.Conns = d.ConnReader
		cfg.ConnTargets = func(ctx context.Context) (map[string]string, error) {
			cs, err := d.Conn.List(ctx)
			if err != nil {
				return nil, fmt.Errorf("ai: connections: %w", err)
			}
			m := make(map[string]string, len(cs))
			for _, c := range cs {
				m[c.ID] = c.Target
			}
			return m, nil
		}
	}
	// the daily verify of the activity log raises a notify incident when the chain is broken (S-AI-8, D-430), and the budget watch
	// one at 80 % (medium) and 100 % (high) of a monthly AI budget (D-531); newNotify is the one instance per database, so this is the
	// service the rest of the box uses. A notify module that is off answers ErrModuleOff, passed on as ai.ErrAlertOff too: the chain
	// check tries again at its next run, the budget watch waits quietly for notify to be turned on (Home still shows the banner).
	cfg.Alert = func(ctx context.Context, id, title, text string, high bool) error {
		sev := notify.Medium
		if high {
			sev = notify.High
		}
		err := newNotify(d).Publish(ctx, notify.Notice{ID: id, Kind: notify.KindIncident, Severity: sev, Title: title, What: text, At: d.Clock()})
		if errors.Is(err, notify.ErrModuleOff) {
			return fmt.Errorf("%w: %w", ai.ErrAlertOff, err)
		}
		return err
	}
	// the log-digest job reads the digest of the logs module (ailogdigest.go)
	cfg.LogDigest = aiLogDigest(d)
	cfg.LogAround = aiLogAround(d)

	if d.Reg != nil { // a nil *modreg.Registry inside the interface would not compare equal to nil
		cfg.Modules = d.Reg
	}
	svc, err := ai.New(ctx, cfg)
	if err == nil && testNewsNetwork != nil {
		testNewsNetwork(svc)
	}
	return svc, err
}

// testNewsNetwork is the test seam of the end-to-end box (D-171 (2), D-426): it points the CVE news fetcher at a fake internet on
// loopback (e2enews_test.go). nil in the release binary, which has no _test file to set it.
var testNewsNetwork func(*ai.Service)

// aiFacts implements ai.Facts: the exploited-list entry from feeds, the devices a CVE matches from findings and the inventory.
type aiFacts struct {
	feeds    *feeds.Store
	findings *findings.Service
	inv      findings.Inventory
	boxID    func(context.Context) (string, error) // the id of the box's own device row, "" when there is none
}

func (f aiFacts) CVE(ctx context.Context, id string) (ai.CVEFacts, bool, error) {
	v, ok, err := f.feeds.VulnByCVE(ctx, id)
	if err != nil || !ok {
		return ai.CVEFacts{}, false, err
	}
	return ai.CVEFacts{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Name: v.Name, Description: v.Description, RequiredAction: v.RequiredAction,
		DateAdded: v.DateAdded, Links: v.Links, Ransomware: v.Ransomware, HasTemplate: v.HasTemplate, Source: v.SourceID}, true, nil
}

func (f aiFacts) AffectedAssets(ctx context.Context, cve string) ([]ai.AssetFact, error) {
	recs, err := f.findings.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var open []findings.Record
	var ids []string
	for _, r := range recs {
		if r.CVE == cve && r.Status.Open() {
			open = append(open, r)
			ids = append(ids, r.AssetID)
		}
	}
	if len(open) == 0 {
		return nil, nil
	}
	assets, err := f.inv.Assets(ctx, ids)
	if err != nil {
		return nil, err
	}
	box := ""
	if f.boxID != nil {
		if box, err = f.boxID(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]ai.AssetFact, 0, len(open))
	for _, r := range open {
		a, ok := assets[r.AssetID]
		if !ok {
			continue
		}
		name := a.IP
		if a.Hostname != nil && *a.Hostname != "" {
			name = *a.Hostname
		}
		out = append(out, ai.AssetFact{Name: name, IP: a.IP, Kind: a.Kind, Basis: string(r.Basis), Status: string(r.Status), IsBox: a.ID == box && box != ""})
	}
	return out, nil
}

// aiBoxID finds the box's own device row for the explanation's citation (D-422). ponytail: reads every device (AllDevices) once per
// explanation that has an open finding, about 100-300 ms at 10k devices; upgrade path: a narrow inventory read of the is_box row.
func aiBoxID(inv *inventory.Service) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if inv == nil {
			return "", nil
		}
		devs, err := inv.AllDevices(ctx)
		if err != nil {
			return "", err
		}
		for _, d := range devs {
			if d.IsBox {
				return d.ID, nil
			}
		}
		return "", nil
	}
}

// aiMitigation is mitigation's door to the AI (mitigation.AI): it turns a finding into data blocks for ai.Service.Brief and the
// answer back into text. The AI never gets a write tool here (SYS-8); mitigation stores the answer as an AI result.
type aiMitigation struct {
	svc *ai.Service
	// inv gives the device's own facts (vendor, model, OS, software, open ports) and the firewalls and routers of the network, so the
	// AI writes config for what is there (M2-2); nil = the facts of the finding row only.
	inv *inventory.Service
}

func jobOf(s mitigation.Skill) ai.Job {
	if s == mitigation.SkillConfig {
		return ai.JobMitigationConfig
	}
	return ai.JobExplainFinding
}

func (m aiMitigation) Available(_ context.Context, s mitigation.Skill) bool {
	return m.svc.Available(jobOf(s))
}

// aiMaxFirewalls is how many firewalls and routers the config skill is told about: one config block each, so a network with many
// gets the first ones by id (the device list's order); the answer has room for about eight blocks.
const aiMaxFirewalls = 6

func (m aiMitigation) Run(ctx context.Context, req mitigation.AIRequest) (mitigation.AIOutput, error) {
	row := req.Finding
	var dev *inventory.Device
	var walls []inventory.Device
	if m.inv != nil {
		if d, err := m.inv.Device(ctx, row.AssetID); err == nil {
			dev = &d
		} else if !errors.Is(err, inventory.ErrNotFound) { // a device deleted meanwhile: the row's own facts are what is left
			return mitigation.AIOutput{}, fmt.Errorf("ai mitigation: device: %w", err)
		}
		if req.Skill == mitigation.SkillConfig {
			kd, err := m.inv.DevicesOfKind(ctx, []string{"firewall", "router"}) // the kinds mitigation.Vendors reads (INV-5)
			if err != nil {
				return mitigation.AIOutput{}, fmt.Errorf("ai mitigation: firewalls: %w", err)
			}
			for _, k := range kd {
				if len(walls) == aiMaxFirewalls {
					break
				}
				if d, err := m.inv.Device(ctx, k.ID); err == nil {
					walls = append(walls, d)
				} else if !errors.Is(err, inventory.ErrNotFound) {
					return mitigation.AIOutput{}, fmt.Errorf("ai mitigation: firewall: %w", err)
				}
			}
		}
	}
	data := aiFindingData(req, dev, walls)
	q := "Explain this finding."
	if req.Skill == mitigation.SkillConfig {
		q = "Write the configuration for this finding: the device's own workaround and a rule for each firewall in the network block."
	}
	ans, err := m.svc.Brief(ctx, ai.BriefRequest{Job: jobOf(req.Skill), Actor: req.User, Target: row.CVE, Question: q, Data: data})
	if err != nil {
		// the ai module's own error (not set up, cut off, wrong format, a hook, the provider, the cap) goes to the page as it is: the
		// handler answers with it, so the person reads what really happened (beta 0.1.0-beta.1: a cut answer read "No AI profile is
		// assigned")
		return mitigation.AIOutput{}, err
	}
	out := mitigation.AIOutput{Model: ans.Model, Profile: ans.Profile, InputTok: ans.TokensIn, OutputTok: ans.TokensOut, Paragraphs: ans.Paragraphs, Steps: ans.Steps,
		Shortened: ans.Shortened, ActivityID: ans.ActivityID}
	for _, c := range ans.Configs {
		note := ""
		if c.BasedOn != "" {
			note = "Based on: " + c.BasedOn
		}
		out.Configs = append(out.Configs, findings.CodeStep{Title: c.Title, Code: c.Code, Note: note, SideEffect: c.SideEffect})
	}
	if k := row.Kev; k != nil {
		for _, l := range k.Links { // the box builds the sources from the feed entry; a model never supplies a link
			if u, err := url.Parse(l); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && len(out.Citations) < 2 {
				out.Citations = append(out.Citations, findings.Citation{Title: strings.TrimPrefix(u.Hostname(), "www."), URL: l})
			}
		}
	}
	return out, nil
}

// Caps on what one finding sends, so a device with a thousand packages does not fill the prompt.
const (
	aiMaxSoftware = 20
	aiMaxPorts    = 30
)

// aiFindingData is what the AI gets for a finding: the same facts the finding page shows (M2-2: the answer said "the data does not
// list affected versions" while the Evidence named "before 20.4"). The exploited-list entry; the device with its vendor, model, OS,
// software and open ports, the Evidence sentence (the installed version and the affected range), the fixed release or the fix of each
// release line, the basis and confidence; and for the config skill the firewalls and routers of the inventory, whose vendor decides the
// syntax of the firewall rule. Device data is the customer's own network data, as before: the job carries internal data (INV-3 of ai)
// and goes through the privacy rule and the before_ai hooks like every call.
func aiFindingData(req mitigation.AIRequest, dev *inventory.Device, walls []inventory.Device) []ai.DataBlock {
	row := req.Finding
	var feed, d strings.Builder
	if k := row.Kev; k != nil {
		fmt.Fprintf(&feed, "CVE: %s\nVendor: %s\nProduct: %s\nName: %s\nExploited-list source: %s\nRequired action (from that source): %s\nAdded to the exploited list: %s\nUsed in ransomware campaigns: %t\nPublic check template exists: %t\nLinks: %s\n",
			row.CVE, k.Vendor, k.Product, k.Name, ai.ListLabel(k.Source), k.RequiredAction, k.DateAdded, k.Ransomware, k.HasTemplate, strings.Join(k.Links, " "))
	} else {
		fmt.Fprintf(&feed, "CVE: %s\n", row.CVE)
	}
	if c := row.CVSS; c != nil {
		fmt.Fprintf(&feed, "CVSS %s base score: %.1f (%s)\n", c.Version, c.Score, c.Vector)
	}
	if a := row.Asset; a != nil {
		fmt.Fprintf(&d, "Device: %s, IP %s, kind %s, %s\n", a.Name, a.IP, a.Kind, a.Display)
	}
	if dev != nil {
		if v := aiDeviceFacts(*dev); v != "" {
			fmt.Fprintf(&d, "%s\n", v)
		}
		var sw []string
		for _, s := range dev.Software[:min(len(dev.Software), aiMaxSoftware)] {
			sw = append(sw, strings.TrimSpace(s.Display+" "+aiStr(s.Version)))
		}
		if len(sw) > 0 {
			fmt.Fprintf(&d, "Installed software: %s\n", strings.Join(sw, "; "))
		}
		fmt.Fprintf(&d, "Open ports: %s\n", aiPorts(*dev))
	}
	if e := row.Evidence; e != nil && e.Summary != "" {
		fmt.Fprintf(&d, "Evidence (installed version and affected range): %s\n", e.Summary)
	}
	fmt.Fprintf(&d, "%s\n", aiFixedIn(req.FixedIn))
	fmt.Fprintf(&d, "Finding status: %s, severity %s, matched by %s, confidence %.2f\nA confirmed recommendation pack exists: %t\n", row.Status, row.Severity, row.Basis, row.Confidence, req.HasPack)
	blocks := []ai.DataBlock{{Kind: ai.DataFeed, Source: "exploited list entry " + row.CVE, Text: feed.String()}, {Kind: "inventory", Source: "the device of the finding", Text: d.String()}}
	if req.Skill != mitigation.SkillConfig {
		return blocks
	}
	var n strings.Builder
	if len(walls) == 0 {
		n.WriteString("No firewall or router is in the inventory.\n")
	} else {
		n.WriteString("Firewalls and routers in the inventory:\n")
		for _, w := range walls {
			fmt.Fprintf(&n, "- %s, IP %s, kind %s; %s\n", aiDeviceName(w), w.IP, w.Kind, cmp.Or(aiDeviceFacts(w), "vendor not known"))
		}
	}
	return append(blocks, ai.DataBlock{Kind: "inventory", Source: "the firewalls of the network", Text: n.String()})
}

// aiDeviceFacts is "Vendor: …; Model: …; Operating system: …" with the values the inventory has, "" when it has none.
func aiDeviceFacts(d inventory.Device) string {
	var f []string
	for _, kv := range [][2]string{{"Vendor", aiObserved(d.Vendor)}, {"Model", aiObserved(d.Model)}, {"Operating system", aiObserved(d.OS)}} {
		if kv[1] != "" {
			f = append(f, kv[0]+": "+kv[1])
		}
	}
	return strings.Join(f, "; ")
}

// aiPorts lists the device's open ports with the service and product a scan read ("80/tcp http (Apache httpd 2.4.58)").
func aiPorts(d inventory.Device) string {
	if len(d.Services) == 0 {
		return "none known"
	}
	var ps []string
	for _, sv := range d.Services[:min(len(d.Services), aiMaxPorts)] {
		p := fmt.Sprintf("%d/%s %s", sv.Port, sv.Proto, sv.Name)
		if prod := strings.TrimSpace(aiStr(sv.Product) + " " + aiStr(sv.Version)); prod != "" {
			p += " (" + prod + ")"
		}
		ps = append(ps, p)
	}
	return strings.Join(ps, "; ")
}

// aiFixedIn is the page's "Fixed version" fact in one line.
func aiFixedIn(f *findings.FixedIn) string {
	if f == nil {
		return "Fixed version: NVD's affected versions name none; the vendor advisory in the links names it."
	}
	var b strings.Builder
	b.WriteString("Fixed version (" + f.Source + "): ")
	if f.Version != "" {
		b.WriteString("installed " + f.Version + "; ")
	}
	switch f.Kind {
	case "fixed":
		b.WriteString("fixed in " + f.Fixed)
	case "up_to":
		b.WriteString("affected up to and including " + f.Fixed + ", no fixed release named")
	case "distro":
		b.WriteString("install the security updates of " + cmp.Or(f.Distro, "the distribution"))
		if f.DistroFixed != "" {
			b.WriteString(", fixed package " + f.DistroFixed + " for release " + f.DistroRelease)
		}
	case "feature_update", "esu":
		b.WriteString("fixed in build " + f.Fixed + " (" + f.Kind + ")")
	}
	var br []string
	for _, x := range f.Branches {
		br = append(br, cmp.Or(x.Branch, "a release line")+" fixed in "+x.Fixed)
	}
	if len(br) > 0 {
		if f.Kind != "branches" {
			b.WriteString("; ")
		}
		b.WriteString("fix per release line: " + strings.Join(br, ", "))
	}
	if f.More > 0 {
		fmt.Fprintf(&b, "; %d more release lines have a fix", f.More)
	}
	if f.NoFix > 0 {
		fmt.Fprintf(&b, "; %d release lines have no fixed release", f.NoFix)
	}
	if strings.HasSuffix(b.String(), ": ") {
		b.WriteString("not named; the vendor advisory in the links names it")
	}
	return b.String()
}

// aiChainPruner hands the retention prune of the activity log to core's chainhead.Prune, which moves the anchor and lowers the head in
// the prune's own transaction: the ai module never writes those core tables.
type aiChainPruner struct{}

func (aiChainPruner) Prune(ctx context.Context, tx *sql.Tx, chain, lastPrunedID, lastPrunedHash string, removed int64, now time.Time) error {
	return chainhead.Prune(ctx, tx, chain, lastPrunedID, lastPrunedHash, removed, now)
}

// aiJobs is the Jobs func of the ai entry in wiredModules: "activity-prune" and "activity-verify".
func aiJobs(d deps) []jobs.Job { return d.AI.Jobs() }

// aiAsk implements ai.Data for the read tools of "Ask your data": devices from the inventory, findings from findings and indicators
// from feeds. Reads only, through the exported reads of those modules (S-AI-5).
type aiAsk struct {
	feeds    *feeds.Store
	findings *findings.Service
	inv      *inventory.Service
}

func aiStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func aiObserved(o *inventory.Observed) string {
	if o == nil {
		return ""
	}
	return o.Value
}

func aiDeviceName(d inventory.Device) string {
	switch {
	case d.Hostname != nil && *d.Hostname != "":
		return *d.Hostname
	case d.Model != nil && d.Model.Value != "":
		return d.Model.Value
	}
	return d.IP
}

func (a aiAsk) Assets(ctx context.Context) ([]ai.AssetRow, error) {
	devs, err := a.inv.AllDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("ai ask: devices: %w", err)
	}
	out := make([]ai.AssetRow, 0, len(devs))
	for _, d := range devs {
		r := ai.AssetRow{ID: d.ID, Name: aiDeviceName(d), IP: d.IP, Kind: d.Kind, Vendor: aiObserved(d.Vendor), Model: aiObserved(d.Model), OS: aiObserved(d.OS), Approved: d.Approved,
			FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Origin: d.Origin, IsBox: d.IsBox}
		if d.Summary != nil {
			r.SeenBy = d.Summary.Source
		}
		for _, sv := range d.Services {
			r.Ports = append(r.Ports, fmt.Sprintf("%d/%s %s", sv.Port, sv.Proto, sv.Name))
		}
		for _, sw := range d.Software {
			r.Software = append(r.Software, strings.TrimSpace(sw.Display+" "+aiStr(sw.Version)))
		}
		out = append(out, r)
	}
	return out, nil
}

func (a aiAsk) names(ctx context.Context) (map[string]inventory.Device, error) {
	devs, err := a.inv.AllDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("ai ask: devices: %w", err)
	}
	m := make(map[string]inventory.Device, len(devs))
	for _, d := range devs {
		m[d.ID] = d
	}
	return m, nil
}

func aiFindingRow(r findings.Record, devs map[string]inventory.Device) ai.FindingRow {
	f := ai.FindingRow{ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: string(r.Status), Severity: string(r.Severity), Basis: string(r.Basis), Confidence: r.Confidence,
		FirstSeen: r.FirstSeen.UTC().Format(time.RFC3339), LastSeen: r.LastSeen.UTC().Format(time.RFC3339)}
	if !r.AcceptedUntil.IsZero() {
		f.AcceptedUntil = r.AcceptedUntil.UTC().Format(time.DateOnly)
	}
	if d, ok := devs[r.AssetID]; ok {
		f.Asset, f.AssetIP = aiDeviceName(d), d.IP
	}
	if r.Evidence != nil {
		f.Evidence = r.Evidence.Summary
	}
	return f
}

func (a aiAsk) Findings(ctx context.Context) ([]ai.FindingRow, error) {
	recs, err := a.findings.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("ai ask: findings: %w", err)
	}
	devs, err := a.names(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ai.FindingRow, len(recs))
	for i, r := range recs {
		out[i] = aiFindingRow(r, devs)
	}
	return out, nil
}

func (a aiAsk) Finding(ctx context.Context, id string) (ai.FindingRow, bool, error) {
	r, err := a.findings.Get(ctx, id)
	if errors.Is(err, findings.ErrNotFound) {
		return ai.FindingRow{}, false, nil
	}
	if err != nil {
		return ai.FindingRow{}, false, fmt.Errorf("ai ask: finding: %w", err)
	}
	devs := map[string]inventory.Device{}
	if d, err := a.inv.Device(ctx, r.AssetID); err == nil {
		devs[r.AssetID] = d
	}
	return aiFindingRow(r, devs), true, nil
}

func (a aiAsk) IOC(ctx context.Context, kind, value string) (ai.IOCFact, bool, error) {
	key, ok := feeds.IOCKey(kind, value) // a private or reserved address, or a name that cannot be public, is never an indicator
	if !ok {
		return ai.IOCFact{}, false, nil
	}
	rec, found, err := a.feeds.IOCLookup(ctx, kind, key)
	if err != nil {
		return ai.IOCFact{}, false, fmt.Errorf("ai ask: indicator: %w", err)
	}
	if !found {
		return ai.IOCFact{}, false, nil
	}
	out := ai.IOCFact{Kind: rec.Type, Value: rec.Value, FirstSeen: rec.FirstSeen.UTC().Format(time.RFC3339), LastSeen: rec.LastSeen.UTC().Format(time.RFC3339)}
	for _, g := range rec.Sightings {
		if g.Enabled { // a switched-off feed is not pulled: its listings are stale (as in logsFeeds.Lookup); no source left is "not listed"
			out.Sources = append(out.Sources, g.SourceName)
		}
	}
	return out, true, nil
}

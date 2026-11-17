package main

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/server"
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
func newAI(ctx context.Context, d *deps, facts ai.Facts, data ai.Data, updates ai.Updates) (*ai.Service, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg := ai.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Zone: orgZone(d), Facts: facts, ChainPruner: aiChainPruner{}, Data: data,
		Updates: updates, BoxAddrs: machineAddrs(d), SelfAddrs: vedetteSelf(d)} // D-446: no profile on Vedette itself
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
		if n := aiVal(a.Name, 64); n != "" && a.Name != a.ID { // the name every page shows (inventory.Names: the name in Vedette first, G2), as the AI gets text
			name = n
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
	log *slog.Logger // an inventory read that fails is logged and the AI gets the row's own facts (#897 r1 L5); nil = not logged
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
	dev, walls := m.facts(ctx, req)
	data := aiFindingData(req, dev, walls)
	q := "Explain this finding."
	if req.Skill == mitigation.SkillConfig {
		q = "Write the configuration for this finding: the device's own workaround and a rule for each firewall in the network block."
	}
	ans, err := m.svc.Brief(ctx, ai.BriefRequest{Job: jobOf(req.Skill), Actor: req.User, Target: row.CVE, Question: q, Data: data, Trusted: aiTrusted(row, dev, walls)})
	if err != nil {
		// the ai module's own error (not set up, cut off, wrong format, a hook, the provider, the cap) goes to the page as it is: the
		// handler answers with it, so the person reads what really happened (beta 0.1.0-beta.1: a cut answer read "No AI profile is
		// assigned")
		return mitigation.AIOutput{}, err
	}
	out := mitigation.AIOutput{Model: ans.Model, Profile: ans.Profile, InputTok: ans.TokensIn, OutputTok: ans.TokensOut, Paragraphs: ans.Paragraphs, Steps: ans.Steps,
		Shortened: ans.Shortened, NoConfigReason: ans.NoConfigReason, ActivityID: ans.ActivityID}
	for _, c := range ans.Configs {
		note := ""
		if c.BasedOn != "" {
			note = "Based on: " + c.BasedOn
		}
		out.Configs = append(out.Configs, findings.CodeStep{Title: c.Title, Code: c.Code, Note: note, SideEffect: c.SideEffect, Check: c.Check})
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

// facts reads the device of the finding and, for the config skill, the firewalls and routers of the inventory (the kinds
// mitigation.Vendors reads, INV-5). A device deleted meanwhile is left out; a read that fails is logged and left out too, so the AI
// still answers from the row's own facts instead of the page getting a bare 500 (#897 r1 L5).
func (m aiMitigation) facts(ctx context.Context, req mitigation.AIRequest) (dev *inventory.Device, walls []inventory.Device) {
	if m.inv == nil {
		return nil, nil
	}
	failed := func(what string, err error) {
		if m.log != nil && !errors.Is(err, inventory.ErrNotFound) {
			m.log.WarnContext(ctx, "ai mitigation: reading the inventory failed; the AI gets the finding's own facts", "what", what, "err", err)
		}
	}
	if d, err := m.inv.Device(ctx, req.Finding.AssetID); err == nil {
		dev = &d
	} else {
		failed("device", err)
	}
	if req.Skill != mitigation.SkillConfig {
		return dev, nil
	}
	kd, err := m.inv.DevicesOfKind(ctx, []string{"firewall", "router"})
	if err != nil {
		failed("firewalls", err)
		return dev, nil
	}
	for _, k := range kd {
		if len(walls) == aiMaxFirewalls {
			break
		}
		if d, err := m.inv.Device(ctx, k.ID); err == nil {
			walls = append(walls, d)
		} else {
			failed("firewall", err)
		}
	}
	return dev, walls
}

// aiMaxPorts caps the open ports one finding sends.
const aiMaxPorts = 30

// aiTrusted are the addresses the box knows for the finding from structured fields: the device's IP and the firewalls' IPs, never a
// banner, a name or the Evidence text. A config naming any other address is flagged on the page (#897 r2).
func aiTrusted(row findings.Row, dev *inventory.Device, walls []inventory.Device) []netip.Addr {
	var out []netip.Addr
	add := func(ip string) {
		if a, err := netip.ParseAddr(ip); err == nil && a.Zone() == "" && !slices.Contains(out, a.Unmap()) {
			out = append(out, a.Unmap())
		}
	}
	if row.Asset != nil {
		add(row.Asset.IP)
	}
	if dev != nil {
		add(dev.IP)
	}
	for _, w := range walls {
		add(w.IP)
	}
	return out
}

// aiVal is an inventory or feed value as the AI gets it: one line (a line break in a banner or a name cannot fake a line of the data
// block), no control characters, at most n characters (#897 r1 M1). The device and the network choose many of these values (a scan's
// banner, a DHCP name, an SNMP description), so they are data, never more than a short phrase.
func aiVal(s string, n int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
			return ' '
		case unicode.Is(unicode.Cf, r): // bidi controls, zero-width characters (#897 r2 L2)
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// aiHostRE is the host name rule of the box's own texts (rules/security.md, mitigation INV-4).
var aiHostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// aiIP is an address as the AI gets it: one that parses, else "no IP address".
func aiIP(s string) string {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.String()
	}
	return "no IP address"
}

// aiName is a device's name for the AI: the name a person gave it in Vedette (G2; an operator typed it, no < or >), its host name when
// it is a plain one, else its model, else its address.
func aiName(d inventory.Device) string {
	if d.UserName != nil {
		if n := aiVal(*d.UserName, 64); n != "" {
			return n
		}
	}
	if d.Hostname != nil && aiHostRE.MatchString(*d.Hostname) {
		return *d.Hostname
	}
	if v := aiVal(aiObserved(d.Model), 60); v != "" {
		return v
	}
	return aiIP(d.IP)
}

// aiFindingData is what the AI gets for a finding: the same facts the finding page shows (M2-2: the answer said "the data does not
// list affected versions" while the Evidence named "before 20.4"). The exploited-list entry; the device with its vendor, model, OS,
// software and open ports, the Evidence sentence (the installed version and the affected range), the fixed release or the fix of each
// release line, the basis and confidence; and for the config skill the firewalls and routers of the inventory, whose vendor decides the
// syntax of the firewall rule. Device data is the customer's own network data, as before: the job carries internal data (INV-3 of ai)
// and goes through the privacy rule and the before_ai hooks like every call.
func aiFindingData(req mitigation.AIRequest, dev *inventory.Device, walls []inventory.Device) []ai.DataBlock {
	row := req.Finding
	var feed, d strings.Builder
	links := 0
	if k := row.Kev; k != nil {
		links = len(k.Links)
		fmt.Fprintf(&feed, "CVE: %s\nVendor: %s\nProduct: %s\nName: %s\nExploited-list source: %s\nRequired action (from that source): %s\nAdded to the exploited list: %s\nUsed in ransomware campaigns: %t\nPublic check template exists: %t\nLinks: %s\n",
			row.CVE, aiVal(k.Vendor, 100), aiVal(k.Product, 100), aiVal(k.Name, 200), ai.ListLabel(k.Source), aiVal(k.RequiredAction, 400), aiVal(k.DateAdded, 20), k.Ransomware, k.HasTemplate, aiVal(strings.Join(k.Links, " "), 1000))
	} else {
		fmt.Fprintf(&feed, "CVE: %s\n", row.CVE)
	}
	if c := row.CVSS; c != nil {
		fmt.Fprintf(&feed, "CVSS %s base score: %.1f (%s)\n", c.Version, c.Score, aiVal(c.Vector, 200))
	}
	fmt.Fprintf(&feed, "%s\n", aiAttack(row.CVSS))
	if a := row.Asset; a != nil {
		fmt.Fprintf(&d, "Device: %s, IP %s, kind %s\n", aiVal(a.Name, 100), aiIP(a.IP), aiVal(a.Kind, 30))
	}
	if dev != nil {
		if v := aiDeviceFacts(*dev); v != "" {
			fmt.Fprintf(&d, "%s\n", v)
		}
		if sw := aiMatched(row, *dev); sw != "" {
			fmt.Fprintf(&d, "Software of the finding: %s\n", sw)
		}
		fmt.Fprintf(&d, "Open ports: %s\n", aiPorts(*dev))
	}
	if e := row.Evidence; e != nil && e.Summary != "" {
		fmt.Fprintf(&d, "Evidence (installed version and affected range): %s\n", aiVal(e.Summary, 600))
	}
	fmt.Fprintf(&d, "%s\n", aiFixedIn(req.FixedIn, links > 0))
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
			fmt.Fprintf(&n, "- %s, IP %s, kind %s; %s\n", aiName(w), aiIP(w.IP), aiVal(w.Kind, 30), cmp.Or(aiDeviceFacts(w), "vendor not known"))
		}
	}
	return append(blocks, ai.DataBlock{Kind: "inventory", Source: "the firewalls of the network", Text: n.String()})
}

// aiAttack says how the vulnerability is reached, from the CVSS vector: the config skill writes a firewall rule only for a flaw
// reached over the network (#897 r1 H1: a local Windows flaw got rules for ports 135-445).
func aiAttack(c *findings.CVSS) string {
	if c == nil {
		return "Attack vector: not known (no CVSS score)."
	}
	m := map[string]string{}
	for _, part := range strings.Split(c.Vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	av := map[string]string{"N": "network", "A": "adjacent network", "L": "local (an account or code on the device)", "P": "physical access"}[m["AV"]]
	if av == "" {
		return "Attack vector: not known."
	}
	ui := "not stated"
	switch m["UI"] {
	case "N":
		ui = "not needed"
	case "R", "P", "A":
		ui = "needed (a user must open or click something)"
	}
	return "Attack vector (CVSS): " + av + "; user interaction: " + ui + "."
}

// aiMatched is the software row the finding is about, with its version: the row whose "<name> <version>" the Evidence states (the
// matcher writes it so), else the row whose product is the exploited entry's product. Only that row goes, not the device's whole
// software list (#897 r1 L3); a short name that happens to be inside the Evidence ("Go", "R") does not count (r2 L3). findings keeps no
// software id on a finding, so the Evidence and the product are what name it.
func aiMatched(row findings.Row, d inventory.Device) string {
	var out []string
	for _, s := range d.Software {
		v := aiStr(s.Version)
		hit := v != "" && s.Display != "" && row.Evidence != nil && strings.Contains(strings.ToLower(row.Evidence.Summary), strings.ToLower(s.Display+" "+v))
		if k := row.Kev; !hit && k != nil && k.Product != "" && s.Product != "" {
			hit = strings.EqualFold(strings.ReplaceAll(s.Product, "_", " "), k.Product)
		}
		if hit && len(out) < 3 {
			out = append(out, strings.TrimSpace(aiVal(s.Display, 100)+" "+aiVal(v, 60)))
		}
	}
	return strings.Join(out, "; ")
}

// aiDeviceFacts is "Vendor: …; Model: …; Operating system: …" with the values the inventory has, "" when it has none.
func aiDeviceFacts(d inventory.Device) string {
	var f []string
	for _, kv := range [][2]string{{"Vendor", aiVal(aiObserved(d.Vendor), 100)}, {"Model", aiVal(aiObserved(d.Model), 100)}, {"Operating system", aiVal(aiObserved(d.OS), 100)}} {
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
		p := fmt.Sprintf("%d/%s %s", sv.Port, aiVal(sv.Proto, 8), aiVal(sv.Name, 40))
		if prod := strings.TrimSpace(aiVal(aiStr(sv.Product), 60) + " " + aiVal(aiStr(sv.Version), 40)); prod != "" { // a banner the device chose
			p += " (" + prod + ")"
		}
		ps = append(ps, p)
	}
	return strings.Join(ps, "; ")
}

// aiFixedIn is the page's "Fixed version" fact in one line, with what the page says about it (Ubuntu Pro, the distribution's own
// updates, #897 r1 L2). links: the exploited entry has links (a vendor advisory may name the fix).
func aiFixedIn(f *findings.FixedIn, links bool) string {
	if f == nil {
		if links {
			return "Fixed version: not known on this box (NVD's affected versions name none); the vendor advisory in the links may name it."
		}
		return "Fixed version: not known on this box (NVD's affected versions name none)."
	}
	var b strings.Builder
	b.WriteString("Fixed version (" + aiVal(f.Source, 80) + "): ")
	if f.Version != "" {
		b.WriteString("installed " + aiVal(f.Version, 60) + "; ")
	}
	switch f.Kind {
	case "fixed":
		b.WriteString("fixed in " + aiVal(f.Fixed, 60))
	case "up_to":
		b.WriteString("affected up to and including " + aiVal(f.Fixed, 60) + ", no fixed release named")
	case "end_listed": // W76-1: the AI called 20.4 "the fixed release" from the Evidence's "before 20.4"; the page says it is not
		b.WriteString("inside the range NVD lists as before " + aiVal(f.Fixed, 60) + ", but " + aiVal(f.Fixed, 60) +
			" is not a fix: NVD lists it, or releases of it, as affected too, and names no fixed release for this version; the vendor advisory lists the releases that fix it")
	case "distro":
		b.WriteString("install the security updates of " + cmp.Or(aiVal(f.Distro, 40), "the distribution") + " (its packages carry the fix under their own numbers)")
		if f.DistroFixed != "" {
			b.WriteString(", fixed package " + aiVal(f.DistroFixed, 80) + " for release " + aiVal(f.DistroRelease, 20))
		}
		if f.DistroPro {
			b.WriteString(", only in Ubuntu Pro (ESM)")
		}
		if f.Fixed != "" {
			b.WriteString(", upstream fixed release " + aiVal(f.Fixed, 60))
		}
	case "feature_update":
		b.WriteString("no update of this release fixes it; move to a later release from build " + aiVal(f.Fixed, 60))
	case "esu":
		b.WriteString("fixed in build " + aiVal(f.Fixed, 60) + ", which comes only with Extended Security Updates")
	}
	var br []string
	for _, x := range f.Branches {
		br = append(br, cmp.Or(aiVal(x.Branch, 40), "a release line")+" fixed in "+aiVal(x.Fixed, 60))
	}
	if len(br) > 0 {
		if !strings.HasSuffix(b.String(), ": ") && !strings.HasSuffix(b.String(), "; ") {
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
	if f.Kind != "distro" && f.Distro != "" {
		b.WriteString("; if it was installed from " + aiVal(f.Distro, 40) + "'s packages, install " + aiVal(f.Distro, 40) + "'s security updates instead")
	}
	if s := strings.TrimSuffix(b.String(), "; "); strings.HasSuffix(s, ": ") {
		return s + "not named; not known on this box."
	}
	return strings.TrimSuffix(b.String(), "; ")
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
	gate     server.ModuleGate // the feeds switch for device_updates' recommended updates (as GET /findings/plan); nil = on
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
	switch n := d.NameOrHost(); {
	case n != nil && aiVal(*n, 64) != "": // the name in Vedette, else the host name (G2), as the AI gets text
		return aiVal(*n, 64)
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

// DeviceUpdates is findings.DeviceUpdates for device_updates (G9): the same updates the Findings page and "Recommended updates" show.
func (a aiAsk) DeviceUpdates(ctx context.Context, assetID string) (ai.DeviceUpdates, bool, error) {
	u, ok, err := a.findings.DeviceUpdates(ctx, assetID, a.gate == nil || a.gate.Enabled(findings.FeedsModule))
	if err != nil || !ok {
		return ai.DeviceUpdates{}, ok, err
	}
	rows := func(us []findings.UpdateAction) []ai.UpdateRow {
		out := make([]ai.UpdateRow, len(us))
		for i, x := range us {
			out[i] = ai.UpdateRow{Action: x.Action, Software: x.Software, Version: x.Version, Fixed: x.Fixed, CVEs: x.CVEs, Worst: x.Worst, Ransomware: x.Ransomware,
				Likely: x.Likely, Confirmed: x.Confirmed, Detected: x.Detected, Reported: x.Reported, Suspected: x.Suspected}
		}
		return out
	}
	return ai.DeviceUpdates{Open: u.Open, Exploited: rows(u.Exploited), NoUpdate: rows(u.NoUpdate), Planned: rows(u.Planned), PlanRan: u.PlanRan,
		PlanCompared: u.PlanCompared, PlanOff: u.PlanOff}, true, nil
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

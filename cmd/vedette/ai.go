package main

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/observe"
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
		Updates: updates, BoxAddrs: machineAddrs(d), SelfAddrs: vedetteSelf(d)} // No profile on Vedette itself
	if d.ConnReader != nil { // the read tools of the connections (core/conn/read); a nil *read.Reader in the interface would not compare equal to nil
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
	// the daily verify of the activity log raises a notify incident when the chain is broken (S-AI-8), and the budget watch
	// one at 80 % (medium) and 100 % (high) of a monthly AI budget; newNotify is the one instance per database, so this is the
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

// testNewsNetwork is the test seam of the end-to-end box: it points the CVE news fetcher at a fake internet on
// loopback (e2enews_test.go). nil in the release binary, which has no _test file to set it.
var testNewsNetwork func(*ai.Service)

// aiFacts implements ai.Facts: the exploited-list entry from feeds, the devices a CVE matches from findings and the inventory.
type aiFacts struct {
	feeds *feeds.Store
	cases caseSource
	inv   findings.Inventory
	boxID func(context.Context) (string, error) // the id of the box's own device row, "" when there is none
}

// CVE reads the brief of the CVE, any CVE the catalogue holds: the exploited-list entry's words when a list has it, the brief as the text
// of the data block with its references numbered from 1.
func (f aiFacts) CVE(ctx context.Context, id string) (ai.CVEFacts, bool, error) {
	b, ok, err := f.feeds.Brief(ctx, id)
	if err != nil || !ok {
		return ai.CVEFacts{}, false, err
	}
	c := findingCase{Brief: b, Known: true}
	links := c.Links()
	out := ai.CVEFacts{CVE: b.CVE, Product: b.Display, Name: b.Title, Description: b.Description, Brief: c.briefFeedText(links), BriefKey: c.briefKeyText(links)}
	for _, l := range links {
		out.Refs = append(out.Refs, ai.BriefRef{Title: l.Title, URL: l.URL})
	}
	if len(b.Lists) > 0 {
		l := b.Lists[0]
		out.Vendor, out.Product, out.Name, out.Description = l.Vendor, cmp.Or(l.Display, l.Product), cmp.Or(l.Name, b.Title), cmp.Or(l.Description, b.Description)
		out.RequiredAction, out.DateAdded, out.Links, out.Ransomware, out.Source = l.RequiredAction, l.DateAdded, l.Links, l.Ransomware, l.Source
	}
	out.HasTemplate = slices.ContainsFunc(b.Signals, func(g feeds.BriefSignal) bool { return g.Kind == "public_exploit" && g.Source == "nuclei-templates" })
	return out, true, nil
}

func (f aiFacts) AffectedAssets(ctx context.Context, cve string) ([]ai.AssetFact, error) {
	open, err := f.cases.Many(ctx, findings.ViewFilter{CVE: cve, OpenOnly: true})
	if err != nil || len(open) == 0 {
		return nil, err
	}
	ids := make([]string, len(open))
	for i, c := range open {
		ids[i] = c.View.Finding.AssetID
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
	for _, c := range open {
		a, ok := assets[c.View.Finding.AssetID]
		if !ok || a.Ignored { // a device a person ignored is left out, as on every list
			continue
		}
		name := a.IP
		if n := aiVal(a.Name, 64); n != "" && a.Name != a.ID { // the name every page shows (inventory.Names: the name in Vedette first), as the AI gets text
			name = n
		}
		out = append(out, ai.AssetFact{Name: name, IP: a.IP, Kind: a.Kind, Basis: aiBasisWord(c.View.Finding), Status: aiOpenWord(c.View.Finding),
			Fix: c.FixText(), Confirmation: c.ConfirmText(), IsBox: a.ID == box && box != ""})
	}
	return out, nil
}

// aiOpenWord is "confirmed" for an open finding a safe check, the device itself or a person confirmed, else "suspected": the words the
// assistant's tools filter by.
func aiOpenWord(f findings.Finding) string {
	if f.Confirmed() {
		return "confirmed"
	}
	return "suspected"
}

// aiBasisWord is how the finding was found, in the assistant's words: scan, person, device (its own report) or version.
func aiBasisWord(f findings.Finding) string {
	switch {
	case f.Verified == findings.VerifiedScan || f.Basis == findings.DetectScan:
		return "scan"
	case f.Verified == findings.VerifiedPerson:
		return "person"
	case f.Verified == findings.VerifiedDevice:
		return "device"
	}
	return "version"
}

// aiBoxID finds the box's own device row for the explanation's citation. ponytail: reads every device (AllDevices) once per
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
	// cases reads the finding as every place reads it: its view and the brief of its CVE.
	cases caseSource
	// inv gives the device's own facts (vendor, model, OS, software, open ports) and the firewalls and routers of the network, so the
	// AI writes config for what is there; nil = the facts of the finding row only.
	inv *inventory.Service
	log *slog.Logger // an inventory read that fails is logged and the AI gets the row's own facts (#897); nil = not logged
	// net reads the box's own network (its subnets and default gateways), which decides which firewalls are on a device's path;
	// nil = no host, the path is not known.
	net func(context.Context) aiNet
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

// aiMaxFirewalls is how many firewalls and routers the config skill may write a rule for: one config block each, so a network with
// many gets the first ones by id (the device list's order); the answer has room for about eight blocks.
const aiMaxFirewalls = 6

func (m aiMitigation) Run(ctx context.Context, req mitigation.AIRequest) (mitigation.AIOutput, error) {
	fc, err := m.cases.One(ctx, req.FindingID)
	if err != nil {
		return mitigation.AIOutput{}, fmt.Errorf("ai mitigation: reading the finding: %w", err)
	}
	row := fc.subject()
	dev, walls := m.facts(ctx, req.Skill, fc)
	data, links := aiFindingData(req, fc, dev, walls)
	var q ai.Instruction = "Answer the four questions for this finding."
	if req.Skill == mitigation.SkillConfig {
		q = "Answer the four questions for this finding, then write the configuration: the device's own workaround and a rule for each firewall the network block says is on the device's path."
	}
	refs := make([]ai.BriefRef, len(links))
	for i, l := range links {
		refs[i] = ai.BriefRef{Title: l.Title, URL: l.URL}
	}
	ans, err := m.svc.Brief(ctx, ai.BriefRequest{Job: jobOf(req.Skill), Actor: req.User, Target: row.CVE, Question: q, Data: data, Refs: refs, Trusted: aiTrusted(row, dev, walls)})
	if err != nil {
		// the ai module's own error (not set up, cut off, wrong format, a hook, the provider, the cap) goes to the page as it is: the
		// handler answers with it, so the person reads what really happened (beta 0.1.0-beta.1: a cut answer read "No AI profile is
		// assigned")
		return mitigation.AIOutput{}, err
	}
	out := mitigation.AIOutput{Model: ans.Model, Profile: ans.Profile, InputTok: ans.TokensIn, OutputTok: ans.TokensOut, Paragraphs: ans.Paragraphs, Steps: ans.Steps,
		Shortened: ans.Shortened, NoConfigReason: ans.NoConfigReason, ActivityID: ans.ActivityID}
	for _, x := range ans.Answers {
		a := findings.AIAnswer{Key: x.Key, Text: x.Text}
		for _, l := range x.Links {
			a.Links = append(a.Links, findings.AILink{Title: l.Title, URL: l.URL})
		}
		out.Answers = append(out.Answers, a)
	}
	for _, c := range ans.Configs {
		note := ""
		if c.BasedOn != "" {
			note = "Based on: " + c.BasedOn
		}
		var warns []findings.CodeWarning
		for _, w := range c.Warnings {
			warns = append(warns, findings.CodeWarning{Line: w.Line, Kind: w.Kind, Text: w.Text})
		}
		out.Configs = append(out.Configs, findings.CodeStep{Title: c.Title, Code: c.Code, Note: note, SideEffect: c.SideEffect, Check: c.Check, Warnings: warns})
	}
	aiMarkAssumed(out.Configs, walls, aiDeviceNames(row, dev))
	for _, l := range links[:min(len(links), 2)] { // the box builds the sources from the brief's own references; a model never supplies a link
		out.Citations = append(out.Citations, findings.Citation{Title: l.Title, URL: l.URL})
	}
	return out, nil
}

// facts reads the device of the finding and, for the config skill, the firewalls and routers of the inventory (the kinds
// mitigation.Vendors reads, INV-5) that are on the device's path (aiPickWalls). A device deleted meanwhile is left out; a read that
// fails is logged and left out too, so the AI still answers from the row's own facts instead of the page getting a bare 500 (#897).
func (m aiMitigation) facts(ctx context.Context, skill mitigation.Skill, fc findingCase) (dev *inventory.Device, walls aiFirewalls) {
	if m.inv == nil {
		return nil, walls
	}
	failed := func(what string, err error) {
		if m.log != nil && !errors.Is(err, inventory.ErrNotFound) {
			m.log.WarnContext(ctx, "ai mitigation: reading the inventory failed; the AI gets the finding's own facts", "what", what, "err", err)
		}
	}
	if d, err := m.inv.Device(ctx, fc.View.Finding.AssetID); err == nil {
		dev = &d
	} else {
		failed("device", err)
	}
	if skill != mitigation.SkillConfig {
		return dev, walls
	}
	kd, err := m.inv.DevicesOfKind(ctx, []string{"firewall", "router"})
	if err != nil {
		failed("firewalls", err)
		return dev, walls
	}
	var n aiNet
	if m.net != nil {
		n = m.net(ctx)
	}
	target := aiTarget{ID: fc.View.Finding.AssetID}
	if dev != nil {
		target.IP = dev.IP
		if dev.MAC != nil {
			target.MAC = *dev.MAC
		}
	} else if fc.View.Device.HasIP() {
		target.IP = fc.View.Device.IP
	}
	ids, sel := aiPickWalls(n, target, kd)
	paths := sel.Paths
	sel.Paths = nil
	for i, id := range ids {
		if d, err := m.inv.Device(ctx, id); err == nil {
			sel.Walls, sel.Paths = append(sel.Walls, d), append(sel.Paths, paths[i])
		} else {
			failed("firewall", err)
		}
	}
	return dev, sel
}

// aiMaxPorts caps the open ports one finding sends.
const aiMaxPorts = 30

// aiDeviceNames are the names the finding's device goes by in a config block's title.
func aiDeviceNames(row aiSubject, dev *inventory.Device) []string {
	var out []string
	if row.AssetName != "" {
		out = append(out, row.AssetName, row.AssetIP)
	}
	if dev != nil {
		out = append(out, aiName(*dev), aiObserved(dev.Model), aiObserved(dev.Vendor), dev.IP)
		if dev.Hostname != nil {
			out = append(out, *dev.Hostname)
		}
	}
	return out
}

// aiTrusted are the addresses the box knows for the finding from structured fields: the device's IP, the IPs of the firewalls a rule
// may be written for and the device's gateway, never a banner, a name or the Evidence text. A config naming any other address (a
// firewall that is not on the device's path among them) is flagged on the page (#897).
func aiTrusted(row aiSubject, dev *inventory.Device, walls aiFirewalls) []netip.Addr {
	var out []netip.Addr
	add := func(ip string) {
		if a, err := netip.ParseAddr(ip); err == nil && a.Zone() == "" && !slices.Contains(out, a.Unmap()) {
			out = append(out, a.Unmap())
		}
	}
	add(row.AssetIP)
	if dev != nil {
		add(dev.IP)
	}
	for _, w := range walls.Walls {
		add(w.IP)
	}
	if walls.Gateway.IsValid() {
		add(walls.Gateway.String())
	}
	return out
}

// aiVal is an inventory or feed value as the AI gets it: one line (a line break in a banner or a name cannot fake a line of the data
// block), no control characters, at most n characters (#897). The device and the network choose many of these values (a scan's
// banner, a DHCP name, an SNMP description), so they are data, never more than a short phrase.
func aiVal(s string, n int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
			return ' '
		case unicode.Is(unicode.Cf, r): // bidi controls, zero-width characters (#897)
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// aiHostRE is the host name rule of the box's own texts (mitigation INV-4).
var aiHostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// aiIP is an address as the AI gets it: one that parses, else "no IP address".
func aiIP(s string) string {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.String()
	}
	return "no IP address"
}

// aiName is a device's name for the AI: the name a person gave it in Vedette (an operator typed it, no < or >), its host name when
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

// aiSubject is what the port and software helpers need to know about the finding: the CVE, the software line it is on, the evidence
// sentence, the product of the exploited-list entry (empty when the CVE is on no list) and the device's name and address.
type aiSubject struct {
	CVE, SoftwareID, Evidence string
	Vendor, Product           string
	AssetName, AssetIP        string
}

func (c findingCase) subject() aiSubject {
	f := c.View.Finding
	s := aiSubject{CVE: f.CVE, SoftwareID: f.SoftwareID, AssetName: c.View.Device.Name}
	if c.View.Device.HasIP() {
		s.AssetIP = c.View.Device.IP
	}
	if f.Evidence != nil {
		s.Evidence = f.Evidence.Summary
	}
	if len(c.Brief.Lists) > 0 {
		s.Vendor, s.Product = c.Brief.Lists[0].Vendor, c.Brief.Lists[0].Product
	}
	return s
}

// aiFindingData is what the AI gets for a finding, from the one source every place reads (findingCase): the CVE brief (title,
// weakness, scores, the exploited lists, the affected versions and the fixed release of each train, the record's solution and
// workaround, the references it may cite by number), then the device with its vendor, model, OS, software and open ports, the fix of
// this device (the stored fix the finding page shows) and who confirmed the finding; and for the config skill the firewalls and
// routers on the device's path (aiNetworkBlock), whose vendor decides the syntax of the firewall rule. The numbered references are
// returned too: the model names a reference by its number and the box writes the link. Device data is the customer's own network
// data, as before: the job carries internal data (INV-3 of ai) and goes through the privacy rule and the before_ai hooks like every call.
func aiFindingData(req mitigation.AIRequest, fc findingCase, dev *inventory.Device, walls aiFirewalls) ([]ai.DataBlock, []caseLink) {
	row := fc.subject()
	links := fc.Links()
	var d strings.Builder
	if a := fc.View.Device; a.Name != "" {
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
		if req.Skill == mitigation.SkillConfig {
			if v := aiVulnPorts(row, *dev); v != "" {
				fmt.Fprintf(&d, "Ports of the vulnerable product: %s\n", v)
			}
			if s := aiSafeApply(*dev); s != "" {
				fmt.Fprintf(&d, "Safe apply on this device: %s\n", s)
			}
		}
	}
	d.WriteString(fc.deviceFactsText())
	fmt.Fprintf(&d, "A confirmed recommendation pack exists: %t\n", req.HasPack)
	blocks := []ai.DataBlock{ai.Untrusted(ai.SourceFeed, "CVE brief "+fc.View.Finding.CVE, fc.briefFeedText(links)), ai.Untrusted(ai.SourceDevice, "the device of the finding", d.String())}
	if req.Skill != mitigation.SkillConfig {
		return blocks, links
	}
	return append(blocks, ai.Untrusted(ai.SourceDevice, "the firewalls of the network", aiNetworkBlock(walls))), links
}

// aiMatched is the software row the finding is about, with its version: the row the matcher matched it on (the finding's software
// line), else, for a finding whose line is gone, the row whose product is the exploited entry's product. Only that row goes, not the
// device's whole software list (#897), and the finding's evidence sentence is never parsed for a name. d holds one row per software
// line (inventory's one line), so a weaker source's reading of the same software ("OpenSSH 10.2" from a banner) is never it.
func aiMatched(row aiSubject, d inventory.Device) string {
	if row.SoftwareID != "" {
		for _, s := range d.Software {
			if s.ID == row.SoftwareID && !s.NotInstalled {
				return strings.TrimSpace(aiVal(s.Display, 100) + " " + aiVal(aiStr(s.Version), 60))
			}
		}
	}
	var out []string
	for _, s := range d.Software {
		if s.NotInstalled { // a person said it is not on the device (inventory INV-41 (6))
			continue
		}
		v := aiStr(s.Version)
		hit := row.Product != "" && s.Product != "" && strings.EqualFold(strings.ReplaceAll(s.Product, "_", " "), row.Product)
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

// aiScanned are the device's open ports a scan read: the rows an agent or the box listed (source agent, named by their program) are
// left out, so the AI request carries what PRIVACY.md says (open ports with the service, product and version a scan read) and the
// port limit is spent on them.
func aiScanned(rows []inventory.ServiceRow) []inventory.ServiceRow {
	var out []inventory.ServiceRow
	for _, sv := range rows {
		if sv.Source != string(observe.Agent) {
			out = append(out, sv)
		}
	}
	return out
}

// aiPorts lists the device's open ports with the service and product a scan read ("80/tcp http (Apache httpd 2.4.58)").
func aiPorts(d inventory.Device) string {
	svcs := aiScanned(d.Services)
	if len(svcs) == 0 {
		return "none known"
	}
	var ps []string
	for _, sv := range svcs[:min(len(svcs), aiMaxPorts)] {
		p := fmt.Sprintf("%d/%s %s", sv.Port, aiVal(sv.Proto, 8), aiVal(sv.Name, 40))
		if prod := strings.TrimSpace(aiVal(aiStr(sv.Product), 60) + " " + aiVal(aiStr(sv.Version), 40)); prod != "" { // a banner the device chose
			p += " (" + prod + ")"
		}
		ps = append(ps, p)
	}
	return strings.Join(ps, "; ")
}

// aiWebNames are the names a scan gives a web server's port, plain or TLS, on its usual and alternate ports. An HTTP proxy port
// (8080) is most often a web interface too. MS RPC over HTTP (http-rpc-epmap) is not a web server.
var aiWebNames = []string{"http", "https", "http-alt", "https-alt", "http-proxy", "http-mgmt", "www", "www-http"}

// aiTLSNames maps the name of a service's TLS port (implicit TLS, or STARTTLS for "submission") to its plain service.
var aiTLSNames = map[string]string{
	"imaps": "imap", "pop3s": "pop3", "smtps": "smtp", "submission": "smtp", "submissions": "smtp", "ldaps": "ldap", "ftps": "ftp",
	"telnets": "telnet", "nntps": "nntp", "ircs": "irc", "ircs-u": "irc", "sip-tls": "sip", "sips": "sip", "domain-s": "domain",
}

// The family names a port can get besides its own service name.
const (
	aiWebFamily = "web"
	aiTLSFamily = "TLS, service not identified"
)

// aiServiceFamily is the service a scan's port name stands for, with the TLS layer and the alternate-port names folded in: "http",
// "https", "ssl/https", "ssl/http", "http-alt" and "https-alt" are all web; "imaps" is "imap". A TLS port whose service the scan
// could not read ("ssl", "ssl/unknown") is aiTLSFamily: an embedded web interface often answers so. "" for a port the scan named
// nothing on.
func aiServiceFamily(name string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "?") // nmap's "http?" is a guess of the same service
	tls := strings.HasPrefix(n, "ssl/") || strings.HasPrefix(n, "tls/") || n == "ssl" || n == "tls"
	n = strings.TrimPrefix(strings.TrimPrefix(n, "ssl/"), "tls/")
	switch {
	case tls && (n == "ssl" || n == "tls" || n == "unknown" || n == "tcpwrapped"):
		return aiTLSFamily
	case n == "" || n == "unknown" || n == "tcpwrapped":
		return ""
	case slices.Contains(aiWebNames, n):
		return aiWebFamily
	case aiTLSNames[n] != "":
		return aiTLSNames[n]
	}
	return aiVal(n, 40)
}

// aiGenericWords are words of product and vendor names that do not tell one product from another ("Junos OS", "Exchange Server").
var aiGenericWords = map[string]bool{"os": true, "server": true, "http": true, "httpd": true, "https": true, "web": true, "the": true,
	"for": true, "and": true, "software": true, "service": true, "services": true, "network": true, "networks": true, "management": true,
	"manager": true, "interface": true, "firmware": true, "edition": true, "enterprise": true, "daemon": true, "ssl": true, "tls": true,
	"inc": true, "corp": true, "corporation": true, "systems": true, "system": true, "device": true, "devices": true, "platform": true,
	"appliance": true, "multiple": true, "products": true, "product": true, "version": true, "ltd": true, "co": true, "com": true}

// aiWords are the distinctive words of a name, lower case: no generic word, no number, nothing shorter than 3 letters.
func aiWords(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(w) >= 3 && !aiGenericWords[w] && strings.Trim(w, "0123456789") != "" && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

// aiProductWords are the words that name the finding's product: the exploited entry's product without the vendor's own words
// ("Apache" of "Apache Tomcat" names Apache httpd too), else the device's software rows the finding matched. vendor: the entry
// vendor's words. A port runs the product only when every one of these words is on it ("Windows Server Update Service" is not
// "Microsoft Windows RPC").
func aiProductWords(row aiSubject, d inventory.Device) (product, vendor []string) {
	if row.Product != "" {
		vendor = aiWords(row.Vendor)
		for _, w := range aiWords(strings.ReplaceAll(row.Product, "_", " ")) {
			if !slices.Contains(vendor, w) {
				product = append(product, w)
			}
		}
	}
	if len(product) > 0 {
		return product, vendor
	}
	matched := aiMatched(row, d)
	for _, s := range d.Software {
		if s.NotInstalled || !slices.Contains(s.Kev, row.CVE) && (s.Display == "" || !strings.Contains(matched, s.Display)) {
			continue
		}
		for _, w := range aiWords(s.Display) {
			if !slices.Contains(vendor, w) && !slices.Contains(product, w) {
				product = append(product, w)
			}
		}
		break // the first matched row names it; two rows' words together would match nothing
	}
	return product, vendor
}

// aiBanner is a value the device chose (a product, a version, a service name) as this line quotes it: brackets for parentheses and
// no other separator of the line, so a banner cannot fake a "runs it" or "write no rule" part ("15.2(7)E" stays "15.2[7]E").
func aiBanner(s string, n int) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		switch r {
		case '(':
			return '['
		case ')':
			return ']'
		case ';', ':', ',':
			return ' '
		}
		return r
	}, aiVal(s, n))), " ")
}

// aiPortLabel is one port as the data shows it: "443/tcp ssl/https (product)" or "(product not read)".
func aiPortLabel(sv inventory.ServiceRow) string {
	p := fmt.Sprintf("%d/%s %s", sv.Port, aiBanner(sv.Proto, 8), aiBanner(sv.Name, 40))
	if prod := strings.TrimSpace(aiBanner(aiStr(sv.Product), 60) + " " + aiBanner(aiStr(sv.Version), 40)); prod != "" {
		return p + " (" + prod + ")"
	}
	return p + " (product not read)"
}

// aiPlatform reports whether the finding is on the device's own platform (its operating system or firmware: Junos OS, IOS XE,
// FortiOS, Windows) rather than on an application it runs, by whole words:
//   - the entry's whole product (its vendor's words aside) is in the device's OS: "Windows" on "Windows Server 2022", never
//     "Windows Server Update Service" there; or
//   - the device is the entry vendor's own and the entry's product is an operating system or firmware: a word "os", "ios", "eos",
//     "firmware" or one ending in "os" (Junos, FortiOS, PAN-OS, SonicOS), never a word of the vendor's name (Sophos).
func aiPlatform(row aiSubject, d inventory.Device, product, vendor []string) bool {
	if row.Product == "" || len(product) == 0 {
		return false
	}
	osWords := aiWords(aiObserved(d.OS))
	if !slices.ContainsFunc(product, func(w string) bool { return !slices.Contains(osWords, w) }) {
		return true
	}
	if !slices.ContainsFunc(aiWords(aiObserved(d.Vendor)), func(w string) bool { return slices.Contains(vendor, w) }) {
		return false
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(row.Product), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if slices.Contains(vendor, w) {
			continue
		}
		if w == "os" || w == "ios" || w == "eos" || w == "firmware" || (len(w) >= 5 && strings.HasSuffix(w, "os")) {
			return true
		}
	}
	return false
}

// aiTitle is the page title the scan read on a port ("title: …" of its detail), "" when it read none.
func aiTitle(detail string) string {
	for _, part := range strings.Split(detail, "; ") {
		if t, ok := strings.CutPrefix(part, "title: "); ok {
			return t
		}
	}
	return ""
}

// aiVulnPorts is the "Ports of the vulnerable product" fact: which open ports a scan read serve the finding's product. The finding
// has no port, and a device often runs several web servers (a public site on 80/443, an admin console on 8443, Tomcat on 8080), so
// "every web port" over-blocks and "the port with a product" under-blocks (port 80 "http" with a product, 443 "ssl/https" without
// one, both the same web interface).
//   - A platform finding (the device's own OS or firmware): every interface of the device runs the platform, and a banner that names
//     it on one port (telnet, SNMP) says nothing about the vulnerable one, so the box lists every named port by service, plain and TLS
//     together, and the model covers all ports of the interface the vulnerability names.
//   - An application finding: a port whose scanned product or page names the whole product runs it. The other ports of that
//     service (plain or TLS) are split: one where the scan read another product runs another one (no rule; a reverse proxy in front
//     of the product is the case the scan cannot tell); one with no product is most likely the same server unless another product
//     serves the service, its page title does not name the product, or its title or certificate names another product of the
//     device; else not known. A port of another service is never excluded, whatever its product: an application often names
//     itself on one protocol and serves its web front end behind the web server's banner (Exchange: SMTP names Exchange, OWA on 443
//     says IIS). When no port names the product, every port is a candidate, listed by service.
//
// "" when the scan read no named port.
func aiVulnPorts(row aiSubject, d inventory.Device) string {
	svcs := aiScanned(d.Services)
	svcs = svcs[:min(len(svcs), aiMaxPorts)]
	product, vendor := aiProductWords(row, d)
	type port struct {
		sv               inventory.ServiceRow
		fam, prod, label string
		words, title     []string
		runs             bool
	}
	var ps []port
	seen := map[string]bool{}
	for _, sv := range svcs {
		fam := aiServiceFamily(sv.Name)
		key := fmt.Sprintf("%d/%s", sv.Port, sv.Proto)
		if fam == "" || seen[key] {
			continue
		}
		seen[key] = true
		words := aiWords(aiStr(sv.Product) + " " + aiStr(sv.Detail))
		ps = append(ps, port{sv: sv, fam: aiBanner(fam, 40), prod: strings.ToLower(strings.TrimSpace(aiStr(sv.Product))), label: aiPortLabel(sv),
			words: words, title: aiWords(aiTitle(aiStr(sv.Detail))),
			runs: len(product) > 0 && !slices.ContainsFunc(product, func(w string) bool { return !slices.Contains(words, w) })})
	}
	if len(ps) == 0 {
		return ""
	}
	var fams []string
	for _, p := range ps {
		if !slices.Contains(fams, p.fam) {
			fams = append(fams, p.fam)
		}
	}
	join := func(ls []string) string { return strings.Join(ls, ", ") }
	byService := func() string {
		var groups []string
		for _, f := range fams {
			var ls []string
			for _, p := range ps {
				if p.fam == f {
					ls = append(ls, p.label)
				}
			}
			groups = append(groups, f+": "+join(ls))
		}
		return strings.Join(groups, "; ")
	}
	if aiPlatform(row, d, product, vendor) {
		return "the vulnerability is in the device's own platform, which serves all of its interfaces, so the scan cannot tell which port " +
			"serves the vulnerable one. Ports by service (a service's plain and TLS ports together): " + byService()
	}
	if !slices.ContainsFunc(ps, func(p port) bool { return p.runs }) {
		return "not known: the scan read the finding's product on no port. Candidates by service: " + byService()
	}
	runFam, otherFam := map[string]bool{}, map[string]bool{}
	var otherWords []string // the words of the other products the scan read on the device
	for _, p := range ps {
		switch {
		case p.runs:
			runFam[p.fam] = true
		case p.prod != "":
			otherFam[p.fam] = true
			for _, w := range aiWords(p.prod) {
				if !slices.Contains(product, w) && !slices.Contains(vendor, w) {
					otherWords = append(otherWords, w)
				}
			}
		}
	}
	namesOther := func(p port) bool {
		return (len(p.title) > 0 && !slices.ContainsFunc(product, func(w string) bool { return slices.Contains(p.title, w) })) ||
			slices.ContainsFunc(p.words, func(w string) bool { return slices.Contains(otherWords, w) })
	}
	var runs, same, unknownSame, unknownOther, other []string
	for _, p := range ps {
		switch {
		case p.runs:
			runs = append(runs, p.label)
		case !runFam[p.fam]:
			unknownOther = append(unknownOther, p.label)
		case p.prod != "":
			other = append(other, p.label)
		case !otherFam[p.fam] && !namesOther(p):
			same = append(same, p.label)
		default:
			unknownSame = append(unknownSame, p.label)
		}
	}
	out := "runs it (the scan read it there): " + join(runs)
	for _, part := range []struct {
		head string
		ls   []string
	}{
		{"most likely the same server (the same service, plain or TLS, product not read)", same},
		{"the same service, not known which product", unknownSame},
		{"other services, not known which product (the product may serve one of them behind another banner)", unknownOther},
		{"the same service, another product (write no rule for these; the scan cannot tell a reverse proxy in front of the product)", other},
	} {
		if len(part.ls) > 0 {
			out += "; " + part.head + ": " + join(part.ls)
		}
	}
	return out
}

// Sources of the safe-apply steps (vendor documentation):
//   - Junos commit confirmed: https://www.juniper.net/documentation/en_US/junos13.2/topics/reference/command-summary/commit.html
//   - IOS XR commit confirmed (the default unit is seconds): https://community.cisco.com/t5/networking-knowledge-base/understanding-quot-commit-quot-command-in-ios-xr/ta-p/3154033
//   - IOS / IOS XE configure terminal revert timer, configure confirm (needs an archive path): Cisco IOS "Configuration Replace and
//     Configuration Rollback" guide; https://networklessons.com/cisco/ccnp-route/configuration-archive-rollback-cisco-ios ;
//     reload in / reload cancel: Cisco IOS Configuration Fundamentals Command Reference, "reload".
//   - FortiOS cfg-save revert, cfg-revert-timeout, execute cfg save: https://docs.fortinet.com/document/fortigate/6.0.5/cli-reference/846611/cfg-save ;
//     https://community.fortinet.com/t5/FortiGate/Technical-Tip-Auto-restore-a-previous-config-if-the-change-fails/ta-p/209749
//   - Arista EOS configure session, commit timer: https://www.arista.com/en/um-eos/eos-session-management-commands
//   - VyOS commit-confirm, confirm, save, config-management commit-confirm action: https://docs.vyos.io/en/latest/cli.html
//   - EdgeOS commit-confirm, confirm: https://help.uisp.com/hc/en-us/articles/22591199766551-EdgeRouter-Configuration-and-Operational-Mode
//   - RouterOS Safe Mode (9-minute TCP timeout, 100-action history): https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management
//
// Platforms whose confirm step is not documented the same way across releases (Aruba AOS-CX checkpoint auto) are left out.

// aiJunosModel is a Juniper model line that runs Junos, also when the model value starts with the vendor or is a virtual one (vSRX).
var aiJunosModel = regexp.MustCompile(`(^|[^a-z])v?(ex|srx|mx|qfx|acx|ptx|nfx)[0-9]`)

// aiAristaModel is an Arista switch that runs EOS (DCS-7050SX3, CCS-720XP, 7280R3); not an Arista access point or firewall.
var aiAristaModel = regexp.MustCompile(`^(arista[ -]+)?((dcs|ccs)-|7[0-9]{3})`)

// aiRouterOSModel is a MikroTik router line that runs RouterOS (RB4011, CCR2004, hAP ax2, hEX, CHR); never a CRS/CSS switch, which
// may run SwOS and has no Safe Mode then.
var aiRouterOSModel = regexp.MustCompile(`^(mikrotik[ -]+)?(rb[0-9]|routerboard|ccr|hap|hex|chr|l009)`)

// aiCiscoIOS is Cisco IOS or IOS XE in an operating system name (not NX-OS, ASA or Apple's iOS, whose vendor is not Cisco).
var aiCiscoIOS = regexp.MustCompile(`(^|[^a-z-])ios([ -]?xe)?([^a-z]|$)`)

// aiSafeApply is how a remote change is applied on a platform so that it undoes itself when it locks the person out, for the
// platforms whose command line has such a mode (sources above); "" for every other one, and the model is told not to name one then.
// The platform is read from the inventory's vendor, model and operating system. Each text says which commands are separate steps
// (an interactive prompt or a key, never a line of the pasted block) and what happens when the change is not confirmed.
func aiSafeApply(d inventory.Device) string {
	vendor, model, osName := strings.ToLower(aiObserved(d.Vendor)), strings.ToLower(aiObserved(d.Model)), strings.ToLower(aiObserved(d.OS))
	all := vendor + " " + model + " " + osName
	switch {
	case strings.Contains(all, "junos") || (strings.Contains(vendor, "juniper") && aiJunosModel.MatchString(model)):
		return "Junos: the block ends with `commit confirmed 5` instead of `commit`; check that access still works, then run `commit` within those 5 minutes; when it is not confirmed, Junos rolls the change back by itself, without a restart."
	case strings.Contains(vendor, "cisco") && (strings.Contains(osName, "ios xr") || strings.Contains(osName, "ios-xr") || strings.Contains(osName, "iosxr")):
		return "Cisco IOS XR: the block ends with `commit confirmed 300` (seconds) instead of `commit`; check that access still works, then run `commit`; when it is not confirmed, IOS XR rolls the change back by itself, without a restart."
	case strings.Contains(vendor, "cisco") && aiCiscoIOS.MatchString(osName):
		return "Cisco IOS: when `show archive` lists an archive path, enter configuration with `configure terminal revert timer 10` instead of `configure terminal`, paste the change, `end`, check that access still works, then run `configure confirm` within 10 minutes and `write memory` (without it the change is gone after the next restart); when it is not confirmed, IOS restores the previous configuration without a restart. With no archive path: as a separate step before the change (never a line of the pasted block, it asks questions: answer no to saving and confirm the reload), run `reload in 10`; after the change check access, run `reload cancel`, then `write memory`; when it is not cancelled, the whole device restarts with its saved configuration, traffic through it stops for minutes, and every change not saved before is lost."
	case strings.Contains(osName, "fortios") || strings.Contains(model, "fortigate") || strings.Contains(model, "fortiwifi"):
		return "FortiOS: as a separate step before the change, `config system global`, `set cfg-save revert`, `set cfg-revert-timeout 600`, `end`; apply the change, check that access still works, then `execute cfg save` within those 600 seconds, and set `cfg-save` back to `automatic` (it is a global setting that stays); when it is not saved, the FortiGate restarts with its previous configuration, and traffic through it stops during the restart."
	case (strings.Contains(vendor, "arista") || strings.Contains(osName, "arista")) && (slices.Contains(strings.Fields(osName), "eos") || aiAristaModel.MatchString(model)):
		return "Arista EOS: enter the change in a session, `configure session <SESSION_NAME>` instead of `configure terminal`, and end it with `commit timer 00:05:00` instead of `commit`; check that access still works, then run `configure session <SESSION_NAME> commit` within those 5 minutes and `copy running-config startup-config` (without it the change is gone after the next restart); when it is not confirmed, EOS rolls the session back by itself, without a restart."
	case strings.Contains(all, "vyos"):
		return "VyOS: the block ends with `commit-confirm 5` instead of `commit`; check that access still works, then run `confirm` and `save` (without `save` the change is gone after the next restart); when it is not confirmed, VyOS restarts into its saved configuration (traffic through it stops during the restart) unless `system config-management commit-confirm action reload` is set."
	case strings.Contains(osName, "edgeos") || (strings.Contains(vendor, "ubiquiti") && strings.Contains(model, "edgerouter")):
		return "Ubiquiti EdgeOS: the block ends with `commit-confirm 5` instead of `commit`; check that access still works, then run `confirm` and `save` (without `save` the change is gone after the next restart); when it is not confirmed, the router restarts with its saved configuration, and traffic through it stops during the restart."
	case strings.Contains(osName, "routeros") || (osName == "" && strings.Contains(vendor, "mikrotik") && aiRouterOSModel.MatchString(model)): //nolint:misspell // RouterOS is the product name
		return "MikroTik RouterOS: as a separate step, turn on Safe Mode (Ctrl+X in the terminal, or the Safe Mode button in WinBox) before pasting, keep the change under 100 commands (past that, Safe Mode ends and nothing is undone), check that access still works, then press Ctrl+X again to keep it; when the session drops in Safe Mode, RouterOS undoes the change about 9 minutes later."
	}
	return ""
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
	cases    caseSource
	inv      *inventory.Service
	gate     server.ModuleGate // the feeds switch for device_updates' recommended updates; nil = on
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
	case n != nil && aiVal(*n, 64) != "": // the name in Vedette, else the host name, as the AI gets text
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
			Ignored: d.IgnoredAt != nil, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Origin: d.Origin, IsBox: d.IsBox}
		if d.Summary != nil {
			r.SeenBy = d.Summary.Source
		}
		for _, sv := range aiScanned(d.Services) {
			r.Ports = append(r.Ports, fmt.Sprintf("%d/%s %s", sv.Port, sv.Proto, sv.Name))
		}
		for _, sw := range d.Running() { // not the software a person said is not on the device (inventory INV-41 (6))
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

// aiUrgencyText says in plain words why a finding matters now, from its urgency status code: the model calls a flaw exploited only
// when attackers use it.
func aiUrgencyText(code string) string {
	switch code {
	case findings.CodeUnderAttack:
		return "under attack: an intrusion alert on this network named this CVE (attackers are using it)"
	case findings.CodeExploited:
		return "exploited in the wild: attackers use this flaw"
	case findings.CodePublicExploit:
		return "a public exploit is available; no report that attackers use it against this network"
	case findings.CodeCriticalEdge:
		return "critical flaw on a device attackers target first; no report that it is exploited"
	}
	return "update recommended: no sign that this flaw is exploited"
}

// aiFindingRow is a finding as the tools show it, from its view: the status words the tools filter by (confirmed or suspected while
// open, the resolution once handled), how it was found, why it matters now, the fix of this device and who confirmed it.
func aiFindingRow(c findingCase, devs map[string]inventory.Device) ai.FindingRow {
	f := c.View.Finding
	row := ai.FindingRow{ID: f.ID, AssetID: f.AssetID, CVE: f.CVE, Status: aiStatusWord(f), Severity: aiSeverityWord(c.View.Severity), Basis: aiBasisWord(f),
		Confidence: aiConfidence(f), Urgency: findings.LayerCode(f.Urgency), FirstSeen: f.FirstSeen.UTC().Format(time.RFC3339), LastSeen: f.LastSeen.UTC().Format(time.RFC3339),
		Fix: c.FixText(), Confirmation: c.ConfirmText()}
	if !f.AcceptedUntil.IsZero() {
		row.AcceptedUntil = f.AcceptedUntil.UTC().Format(time.DateOnly)
	}
	if d, ok := devs[f.AssetID]; ok {
		row.Asset, row.AssetIP = aiDeviceName(d), d.IP
	}
	if f.Evidence != nil {
		row.Evidence = f.Evidence.Summary
	}
	return row
}

// aiStatusWord is the status of a finding in the tools' words: confirmed or suspected while open, else how it was handled.
func aiStatusWord(f findings.Finding) string {
	switch {
	case f.State == findings.StateOpen:
		return aiOpenWord(f)
	case f.Resolution == findings.ResolutionAccepted:
		return "risk_accepted"
	}
	return string(f.Resolution)
}

// aiSeverityWord is the CVSS band of the CVE, "medium" while it has no score (the tools rank an unscored finding there).
func aiSeverityWord(c *findings.CVSS) string {
	if c == nil {
		return "medium"
	}
	return findings.SeverityBand(*c)
}

// aiConfidence is how sure the box is, for the tools' ranking: a safe check's for a confirmed finding, the version match's otherwise.
func aiConfidence(f findings.Finding) float64 {
	if f.Confirmed() {
		return findings.ConfScan
	}
	return findings.ConfVersion
}

func (a aiAsk) Findings(ctx context.Context) ([]ai.FindingRow, error) {
	vs, err := a.findings.Views(ctx, findings.ViewFilter{})
	if err != nil {
		return nil, fmt.Errorf("ai ask: findings: %w", err)
	}
	devs, err := a.names(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ai.FindingRow, len(vs))
	for i, v := range vs {
		out[i] = aiFindingRow(findingCase{View: v}, devs)
	}
	return out, nil
}

func (a aiAsk) Finding(ctx context.Context, id string) (ai.FindingRow, bool, error) {
	c, err := a.cases.One(ctx, id)
	if errors.Is(err, findings.ErrNotFound) {
		return ai.FindingRow{}, false, nil
	}
	if err != nil {
		return ai.FindingRow{}, false, fmt.Errorf("ai ask: finding: %w", err)
	}
	if c.View.Device.Ignored { // as the findings list: a device a person ignored is left out
		return ai.FindingRow{}, false, nil
	}
	devs := map[string]inventory.Device{}
	if d, err := a.inv.Device(ctx, c.View.Finding.AssetID); err == nil {
		devs[c.View.Finding.AssetID] = d
	}
	row := aiFindingRow(c, devs)
	row.Workaround = c.WorkaroundText()
	return row, true, nil
}

// DeviceUpdates is the By device card of one device for device_updates: its fix blocks, the same ones the Findings page shows. A block
// that names a release to install is an update (urgent when its status is one of the four urgent ones, else a recommended update); a
// block of an urgent status with no release to name is a software with no named update; a recommended block with no release has nothing
// to install and is left out.
func (a aiAsk) DeviceUpdates(ctx context.Context, assetID string) (ai.DeviceUpdates, bool, error) {
	if _, err := a.inv.Device(ctx, assetID); errors.Is(err, inventory.ErrNotFound) {
		return ai.DeviceUpdates{}, false, nil
	} else if err != nil {
		return ai.DeviceUpdates{}, false, err
	}
	cards, err := a.findings.ByDevice(ctx, findings.ListFilter{Device: assetID}, findings.Page{Limit: 1})
	if err != nil {
		return ai.DeviceUpdates{}, false, err
	}
	out := ai.DeviceUpdates{PlanOff: a.gate != nil && !a.gate.Enabled(findings.FeedsModule)}
	if len(cards.Items) == 0 {
		return out, true, nil
	}
	card := cards.Items[0]
	out.Open = card.Counts.UnderAttack + card.Counts.Exploited + card.Counts.PublicExploit + card.Counts.CriticalEdge
	for _, b := range card.Blocks {
		urgent := b.Status != findings.CodeUpdateRecommended
		row, named := aiUpdateRow(b)
		switch {
		case named && urgent:
			out.Exploited = append(out.Exploited, row)
		case named && !out.PlanOff: // with the feeds module off recommended updates are not listed, as planNote tells the model
			out.Planned = append(out.Planned, row)
		case urgent:
			out.NoUpdate = append(out.NoUpdate, row)
		}
	}
	return out, true, nil
}

// aiUpdateRow is a fix block as device_updates shows it: the update in words, what it clears (worst first), how the findings are known.
func aiUpdateRow(b findings.FixBlockJS) (row ai.UpdateRow, named bool) {
	fx := b.Fix
	row = ai.UpdateRow{Fixed: aiStr(fx.Version)}
	installed := ""
	if b.Software != nil {
		row.Software, installed = b.Software.Name, aiStr(b.Software.Version)
		row.Version = installed
	}
	for _, f := range b.Findings {
		row.CVEs = append(row.CVEs, f.CVE)
		switch f.Verified {
		case string(findings.VerifiedScan), string(findings.VerifiedPerson):
			row.Confirmed++
		case string(findings.VerifiedDevice):
			row.Detected++
		default:
			row.Suspected++
		}
	}
	switch {
	case b.Severity.Critical > 0:
		row.Worst = "critical"
	case b.Severity.High > 0:
		row.Worst = "high"
	case b.Severity.Medium > 0:
		row.Worst = "medium"
	case b.Severity.Low > 0:
		row.Worst = "low"
	}
	action := capitalFirst(findings.FixWords(findings.Fix{Kind: findings.FixKind(fx.Kind), Version: row.Fixed, Ref: aiStr(fx.Ref), Channel: findings.FixChannel(fx.Channel)}, fx.Product, installed))
	row.Action = cmp.Or(action, "No fixed release is named for "+cmp.Or(row.Software, "this software"))
	return row, action != ""
}

func capitalFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
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
			out.Sources = append(out.Sources, a.feeds.CreditName(ctx, g))
		}
	}
	return out, true, nil
}

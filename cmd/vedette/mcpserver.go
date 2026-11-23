package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	mcpserver "github.com/knt048/vedette/modules/mcp-server"
)

var (
	mcpMu       sync.Mutex
	mcpServices = map[*modreg.Registry]*mcpserver.Service{}
)

// mcpService builds the mcp-server module once per registry (the handler and the listener share it). Its data comes through
// mcpSource: the inventory and findings services and the feeds handlers, each reduced to the fields the tools may show.
func mcpService(d deps) (*mcpserver.Service, error) {
	mcpMu.Lock()
	defer mcpMu.Unlock()
	if s := mcpServices[d.Reg]; s != nil {
		return s, nil
	}
	s, err := mcpserver.New(mcpserver.Config{DB: d.DB, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Modules: d.Reg, Listen: d.MCPListen, InContainer: d.MCPInContainer, Version: version,
		Source: mcpSource{reg: d.Reg, inv: d.Inventory, findings: d.Findings, cases: caseSource{findings: d.Findings, feeds: feedsStore(d)}, feeds: feedsHandlers(d)}})
	if err != nil {
		return nil, err
	}
	mcpServices[d.Reg] = s
	return s, nil
}

func mcpHandlers(d deps) *mcpserver.McpHandlers {
	s, err := mcpService(d)
	if err != nil {
		panic("mcp-server: cannot build the module: " + err.Error())
	}
	return mcpserver.NewMcpHandlers(s)
}

// parseMCPListen reads -mcp-listen: an IP literal and a port on loopback (INV-5). In a container (inContainer) the unspecified
// address 0.0.0.0 or [::] is taken too: the runtime forwards the unit's 127.0.0.1 publish to the container's own address, never to
// its loopback. Empty is the default: 0.0.0.0:8765 in a container, else 127.0.0.1:8765. The units rely on that default
// instead of passing the flag, so a unit of this release still starts an older core image, which refuses 0.0.0.0.
func parseMCPListen(s string, inContainer bool) (netip.AddrPort, error) {
	if s == "" {
		if inContainer {
			return netip.AddrPortFrom(netip.IPv4Unspecified(), mcpserver.DefaultListen.Port()), nil
		}
		return mcpserver.DefaultListen, nil
	}
	a, err := netip.ParseAddrPort(s)
	if err != nil || a.Port() == 0 || !a.Addr().IsLoopback() && (!inContainer || !a.Addr().IsUnspecified()) {
		return netip.AddrPort{}, fmt.Errorf("-mcp-listen %q must be a loopback address and port, such as 127.0.0.1:8765 (0.0.0.0:8765 only inside a container)", s)
	}
	return a, nil
}

// containerMarkers are the files container runtimes put into every container: Podman's /run/.containerenv, Docker's /.dockerenv.
var containerMarkers = []string{"/run/.containerenv", "/.dockerenv"}

// inContainer says whether this process runs in a container: one of containerMarkers exists.
func inContainer() bool {
	for _, f := range containerMarkers {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// mcpSource implements mcpserver.Source. Each scope answers only while the module that owns its data is on.
type mcpSource struct {
	reg      *modreg.Registry
	inv      *inventory.Service
	findings *findings.Service
	cases    caseSource
	feeds    *feeds.FeedHandlers
}

func (s mcpSource) need(module string) error {
	if s.reg == nil || !s.reg.Enabled(module) {
		return mcpserver.SourceOffError{Module: module}
	}
	return nil
}

func observed(o *inventory.Observed) *string {
	if o == nil || o.Value == "" {
		return nil
	}
	v := o.Value
	return &v
}

func mcpAsset(d inventory.Device) mcpserver.Asset {
	a := mcpserver.Asset{ID: d.ID, Kind: d.Kind, Vendor: observed(d.Vendor), Model: observed(d.Model), OS: observed(d.OS), Approved: d.Approved,
		Ignored: d.IgnoredAt != nil, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Services: []mcpserver.NetService{}, Software: []mcpserver.Software{}}
	if d.IP != "" && d.IP != "—" {
		ip := d.IP
		a.IP = &ip
	}
	if d.Hostname != nil && *d.Hostname != "" {
		h := *d.Hostname
		a.Hostname = &h
	}
	switch n := d.NameOrHost(); {
	case n != nil: // the name in Vedette, else the host name
		a.Name = *n
	case a.IP != nil:
		a.Name = *a.IP
	default:
		a.Name = d.ID
	}
	for _, sv := range d.Services {
		a.Services = append(a.Services, mcpserver.NetService{Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: sv.Product, Version: sv.Version})
	}
	for _, sw := range d.Running() { // not the software a person said is not on the device (inventory INV-41 (6))
		a.Software = append(a.Software, mcpserver.Software{Name: sw.Display, Vendor: sw.Vendor, Product: sw.Product, Version: sw.Version})
	}
	return a
}

func (s mcpSource) Assets(ctx context.Context) ([]mcpserver.Asset, error) {
	if err := s.need("inventory"); err != nil {
		return nil, err
	}
	list, err := s.inv.Devices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mcpserver.Asset, 0, len(list.Items))
	for _, d := range list.Items {
		out = append(out, mcpAsset(d))
	}
	return out, nil
}

func (s mcpSource) Asset(ctx context.Context, id string) (mcpserver.Asset, bool, error) {
	if err := s.need("inventory"); err != nil {
		return mcpserver.Asset{}, false, err
	}
	d, err := s.inv.Device(ctx, id)
	if errors.Is(err, inventory.ErrNotFound) {
		return mcpserver.Asset{}, false, nil
	}
	if err != nil {
		return mcpserver.Asset{}, false, err
	}
	return mcpAsset(d), true, nil
}

const mcpTS = "2006-01-02T15:04:05.000Z"

func mcpFinding(c findingCase) mcpserver.Finding {
	f := c.View.Finding
	out := mcpserver.Finding{ID: f.ID, AssetID: f.AssetID, CVE: f.CVE, Status: aiStatusWord(f), Severity: aiSeverityWord(c.View.Severity), Confidence: aiConfidence(f),
		Basis: aiBasisWord(f), Urgency: findings.LayerCode(f.Urgency), FirstSeen: f.FirstSeen.UTC().Format(mcpTS), LastSeen: f.LastSeen.UTC().Format(mcpTS),
		Fix: c.FixText(), Verification: c.ConfirmWords(), History: []mcpserver.HistoryStep{}}
	if !f.ResolvedAt.IsZero() {
		at := f.ResolvedAt.UTC().Format(mcpTS)
		out.ResolvedAt = &at
	}
	if !f.AcceptedUntil.IsZero() {
		out.AcceptedUntil = f.AcceptedUntil.UTC().Format(time.DateOnly)
	}
	if e := f.Evidence; e != nil && e.Template != "" { // which check and when: the summary names the device, the request and response stay on the box
		out.Evidence = &mcpserver.Evidence{Template: e.Template, CheckedAt: e.CheckedAt.UTC().Format(mcpTS)}
	}
	for _, e := range c.View.Events { // when and what, never who or their note
		out.History = append(out.History, mcpserver.HistoryStep{At: e.TS.UTC().Format(mcpTS), Action: mcpAction(e)})
	}
	return out
}

// mcpAction is what an event of a finding did, in a word: its kind, and for a handling the resolution.
func mcpAction(e findings.Event) string {
	if e.Kind == findings.EvHandled && e.Detail.Resolution.Valid() {
		return string(e.Detail.Resolution)
	}
	return string(e.Kind)
}

func (s mcpSource) Findings(ctx context.Context) ([]mcpserver.Finding, error) {
	if err := s.need("findings"); err != nil {
		return nil, err
	}
	cs, err := s.cases.Many(ctx, findings.ViewFilter{})
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(cs, func(a, b findingCase) int {
		if c := b.View.Finding.FirstSeen.Compare(a.View.Finding.FirstSeen); c != 0 {
			return c
		}
		return strings.Compare(a.View.Finding.ID, b.View.Finding.ID)
	})
	out := make([]mcpserver.Finding, 0, len(cs))
	for _, c := range cs {
		out = append(out, mcpFinding(c))
	}
	return out, nil
}

func (s mcpSource) Finding(ctx context.Context, id string) (mcpserver.Finding, bool, error) {
	if err := s.need("findings"); err != nil {
		return mcpserver.Finding{}, false, err
	}
	c, err := s.cases.One(ctx, id)
	if errors.Is(err, findings.ErrNotFound) {
		return mcpserver.Finding{}, false, nil
	}
	if err != nil {
		return mcpserver.Finding{}, false, err
	}
	return mcpFinding(c), true, nil
}

func optNum(v oas.NilFloat64) *float64 {
	if x, ok := v.Get(); ok {
		return &x
	}
	return nil
}

// CVE answers from the brief of the CVE: any CVE the catalogue holds, with the exploited-list entry when a list has it. The devices
// that run the product are inventory data: a feeds token does not get them (INV-2).
func (s mcpSource) CVE(ctx context.Context, cve string) (mcpserver.CVEEntry, bool, error) {
	if err := s.need("feeds"); err != nil {
		return mcpserver.CVEEntry{}, false, err
	}
	if s.cases.feeds == nil {
		return mcpserver.CVEEntry{}, false, nil
	}
	b, ok, err := s.cases.feeds.Brief(ctx, cve)
	if err != nil || !ok {
		return mcpserver.CVEEntry{}, false, err
	}
	return mcpEntry(b), true, nil
}

// mcpEntry is a brief as the lookup_cve tool shows it.
func mcpEntry(b feeds.Brief) mcpserver.CVEEntry {
	e := mcpserver.CVEEntry{CVE: b.CVE, Vendor: "", Product: b.Display, Name: b.Title, Description: b.Description, Links: []string{}, Title: b.Title, NVDStatus: b.NVDStatus,
		Solution: b.Solution, Workaround: briefWorkaround(b), NVDURL: b.NVDURL, RecordURL: b.RecordURL}
	if b.Published != nil {
		e.Published = b.Published.UTC().Format(time.DateOnly)
	}
	if len(b.Lists) > 0 {
		l := b.Lists[0] // the owner entry: its words
		e.Vendor, e.Product, e.Name, e.Description = l.Vendor, cmp.Or(l.Display, l.Product), cmp.Or(l.Name, b.Title), cmp.Or(l.Description, b.Description)
		e.RequiredAction, e.Source, e.DateAdded, e.Ransomware = l.RequiredAction, l.Source, l.DateAdded, l.Ransomware
		if l.DueDate != "" {
			d := l.DueDate
			e.DueDate = &d
		}
		e.Links = slices.Clone(l.Links)
	}
	if b.EPSS != nil {
		e.EPSS = &b.EPSS.Score
	}
	e.HasScanTemplate = slices.ContainsFunc(b.Signals, func(g feeds.BriefSignal) bool { return g.Kind == "public_exploit" && g.Source == "nuclei-templates" })
	for _, w := range b.CWE {
		e.Weaknesses = append(e.Weaknesses, mcpserver.Weakness{ID: w.ID, Name: w.Name})
	}
	if c := b.CVSS; c != nil {
		x := &mcpserver.CVSS{Score: c.Score, Severity: strings.ToLower(c.Severity), Version: c.Version, Vector: c.Vector}
		if r := c.Reading; r != nil {
			x.AttackVector, x.PrivilegesRequired, x.UserInteraction = r.AttackVector, r.PrivilegesRequired, r.UserInteraction
		}
		e.CVSS = x
	}
	for _, r := range b.Ranges {
		if r.Counts && r.Versions != "" {
			e.AffectedVersions = append(e.AffectedVersions, r.Versions)
		}
	}
	e.AffectedFrom = b.RangesFrom
	for _, f := range b.Fixes {
		e.FixedReleases = append(e.FixedReleases, mcpserver.FixedTrain{Train: f.Train, Release: f.Release})
	}
	for _, r := range b.References {
		e.References = append(e.References, mcpserver.Reference{URL: r.URL, Group: r.Group})
	}
	return e
}

func (s mcpSource) IOC(ctx context.Context, value string) (mcpserver.IOCAnswer, error) {
	if err := s.need("feeds"); err != nil {
		return mcpserver.IOCAnswer{}, err
	}
	res, err := s.feeds.FeedsGetFeedsSearch(ctx, oas.FeedsGetFeedsSearchParams{Q: value})
	if err != nil {
		return mcpserver.IOCAnswer{}, err
	}
	ioc, ok := res.GetFeedsGetFeedsSearch1Ioc()
	if !ok {
		return mcpserver.IOCAnswer{}, mcpserver.ErrNotIOC
	}
	out := mcpserver.IOCAnswer{Value: ioc.Value, Type: string(ioc.Type), Sources: []string{}}
	if hit, ok := ioc.Hit.Get(); ok {
		verdict, score, first, last := string(hit.Verdict), hit.Score, hit.FirstSeen, hit.LastSeen
		out.Listed, out.Verdict, out.Category, out.Sources, out.Score, out.FirstSeen, out.LastSeen = true, &verdict, hit.Category, slices.Clone(hit.Sources), &score, &first, &last
	}
	return out, nil
}

func (s mcpSource) Hot(ctx context.Context, window string) ([]mcpserver.HotCVE, error) {
	if err := s.need("feeds"); err != nil {
		return nil, err
	}
	res, err := s.feeds.FeedsGetFeedsHot(ctx, oas.FeedsGetFeedsHotParams{Window: oas.FeedsGetFeedsHotWindow(window)})
	if err != nil {
		return nil, err
	}
	out := []mcpserver.HotCVE{}
	for _, row := range res.Rows { // row.MatchedAssets and row.YouHave are inventory data: dropped (INV-2)
		for _, c := range row.Cves {
			out = append(out, mcpserver.HotCVE{CVE: c.Cve, Vendor: row.Vendor, Product: row.Product, DateAdded: c.DateAdded, Ransomware: c.Ransomware,
				EPSS: optNum(c.Epss), HasScanTemplate: c.HasTemplate})
		}
	}
	return out, nil
}

// startMCP makes the listener follow the module's switch (POST-1). The listener stops when ctx ends.
func startMCP(ctx context.Context, d deps) error {
	s, err := mcpService(d)
	if err != nil {
		return err
	}
	s.Follow(ctx, d.Reg.OnChange)
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		s.Stop(stop)
	}()
	return nil
}

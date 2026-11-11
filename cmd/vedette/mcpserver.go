package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
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
// mcpSource: the inventory and findings services and the feeds handlers, each reduced to the fields the tools may show (D-233).
func mcpService(d deps) (*mcpserver.Service, error) {
	mcpMu.Lock()
	defer mcpMu.Unlock()
	if s := mcpServices[d.Reg]; s != nil {
		return s, nil
	}
	s, err := mcpserver.New(mcpserver.Config{DB: d.DB, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Modules: d.Reg, Listen: d.MCPListen, Version: version,
		Source: mcpSource{reg: d.Reg, inv: d.Inventory, findings: d.Findings, feeds: feedsHandlers(d)}})
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

// parseMCPListen reads -mcp-listen: an IP literal and a port on loopback (INV-5).
func parseMCPListen(s string) (netip.AddrPort, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil || !a.Addr().IsLoopback() || a.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("-mcp-listen %q must be a loopback address and port, such as 127.0.0.1:8765", s)
	}
	return a, nil
}

// mcpSource implements mcpserver.Source. Each scope answers only while the module that owns its data is on.
type mcpSource struct {
	reg      *modreg.Registry
	inv      *inventory.Service
	findings *findings.Service
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
		FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Services: []mcpserver.NetService{}, Software: []mcpserver.Software{}}
	if d.IP != "" && d.IP != "—" {
		ip := d.IP
		a.IP = &ip
	}
	if d.Hostname != nil && *d.Hostname != "" {
		h := *d.Hostname
		a.Hostname = &h
	}
	switch {
	case a.Hostname != nil:
		a.Name = *a.Hostname
	case a.IP != nil:
		a.Name = *a.IP
	default:
		a.Name = d.ID
	}
	for _, sv := range d.Services {
		a.Services = append(a.Services, mcpserver.NetService{Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: sv.Product, Version: sv.Version})
	}
	for _, sw := range d.Software {
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

func mcpFinding(r findings.Record) mcpserver.Finding {
	f := mcpserver.Finding{ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: string(r.Status), Severity: string(r.Severity), Confidence: r.Confidence,
		Basis: string(r.Basis), FirstSeen: r.FirstSeen.UTC().Format(mcpTS), LastSeen: r.LastSeen.UTC().Format(mcpTS), History: []mcpserver.HistoryStep{}}
	if !r.ResolvedAt.IsZero() {
		at := r.ResolvedAt.UTC().Format(mcpTS)
		f.ResolvedAt = &at
	}
	if e := r.Evidence; e != nil { // which check and when: the summary names the device, the request and response stay on the box (D-233)
		f.Evidence = &mcpserver.Evidence{Template: e.Template, CheckedAt: e.CheckedAt.UTC().Format(mcpTS)}
	}
	for _, h := range r.History { // when and what, never who or their note
		f.History = append(f.History, mcpserver.HistoryStep{At: h.TS.UTC().Format(mcpTS), Action: h.Action})
	}
	return f
}

func (s mcpSource) Findings(ctx context.Context) ([]mcpserver.Finding, error) {
	if err := s.need("findings"); err != nil {
		return nil, err
	}
	recs, err := s.findings.List(ctx, "")
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(recs, func(a, b findings.Record) int {
		if c := b.FirstSeen.Compare(a.FirstSeen); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	out := make([]mcpserver.Finding, 0, len(recs))
	for _, r := range recs {
		out = append(out, mcpFinding(r))
	}
	return out, nil
}

func (s mcpSource) Finding(ctx context.Context, id string) (mcpserver.Finding, bool, error) {
	if err := s.need("findings"); err != nil {
		return mcpserver.Finding{}, false, err
	}
	r, err := s.findings.Get(ctx, id)
	if errors.Is(err, findings.ErrNotFound) {
		return mcpserver.Finding{}, false, nil
	}
	if err != nil {
		return mcpserver.Finding{}, false, err
	}
	return mcpFinding(r), true, nil
}

func optStr(v oas.NilString) *string {
	if x, ok := v.Get(); ok {
		return &x
	}
	return nil
}

func optNum(v oas.NilFloat64) *float64 {
	if x, ok := v.Get(); ok {
		return &x
	}
	return nil
}

func (s mcpSource) CVE(ctx context.Context, cve string) (mcpserver.CVEEntry, bool, error) {
	if err := s.need("feeds"); err != nil {
		return mcpserver.CVEEntry{}, false, err
	}
	v, err := s.feeds.FeedsGetFeedsCveID(ctx, oas.FeedsGetFeedsCveIDParams{ID: cve})
	if e, ok := apierr.As(err); ok && e.Status == 404 {
		return mcpserver.CVEEntry{}, false, nil
	}
	if err != nil {
		return mcpserver.CVEEntry{}, false, err
	}
	// v.Matched (the devices that run the product) is inventory data: a feeds token does not get it (INV-2)
	return mcpserver.CVEEntry{CVE: v.Cve, Vendor: v.Vendor, Product: v.Product, Name: v.Name, Description: v.Description, RequiredAction: v.RequiredAction,
		DateAdded: v.DateAdded, DueDate: optStr(v.DueDate), Ransomware: v.Ransomware, EPSS: optNum(v.Epss), HasScanTemplate: v.HasTemplate, Links: slices.Clone(v.Links)}, true, nil
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

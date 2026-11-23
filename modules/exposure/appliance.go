package exposure

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/content/adminpages"
)

// S-EXP-1, INV-33: the admin or VPN page of a network appliance (a firewall, a VPN gateway, a router), a server's management
// card or a tool, named by what a port states about itself on any port: the names of its TLS certificate (FortiGate's default
// certificate is issued to "FortiGate" or to its serial number), its page title, its Server header, where its first page redirects,
// or the product and CPE service identification read. The table is content/adminpages, the same one the scan module's surface scan
// applies to its GET of /. An admin page is an admin row (a VPN portal faces the Internet by design: it is named, not counted), and
// an appliance is tied, when it is read, to the inventory devices of its family and their open exploited vulnerabilities.

// The values of Appliance.Kind.
const (
	ApplianceAdmin      = "admin"        // the management page
	ApplianceVPN        = "vpn"          // the VPN portal: meant to face the Internet, not an admin page
	ApplianceAdminOrVPN = "admin_or_vpn" // the family serves both from one certificate, Server header or product name
)

// The values of Appliance.Evidence: which statement of the port named it.
const (
	EvidenceCert     = "certificate"
	EvidenceTitle    = "title"
	EvidenceServer   = "server"
	EvidenceRedirect = "redirect"
	EvidenceProduct  = "product"
)

// MaxApplianceDevices is how many devices of a family an appliance lists; ApplianceMatch.More counts the others.
const MaxApplianceDevices = 5

// applianceTTL is how long one read of the inventory answers for every appliance of the pages read meanwhile (the list page polls
// while a scan runs); a failed read keeps the last answer.
const applianceTTL = time.Minute

type (
	// Appliance is the product a port or an admin row names (contract.ts Appliance). Name is the family ("FortiGate") or, for a
	// product of no appliance family, the product ("Synology DSM"). Devices are the inventory devices of the family, set when read:
	// nil when Vedette cannot tell (not a family, no inventory wired, or no read has succeeded yet), empty when the inventory has none.
	Appliance struct {
		Name     string            `json:"name"`
		Vendor   string            `json:"vendor"`
		Kind     string            `json:"kind"`
		Evidence string            `json:"evidence"`
		Devices  []ApplianceDevice `json:"devices" nullable:"true"` // nil: Vedette cannot tell (null in the API)
		More     int               `json:"more,omitempty"`          // devices of the family beyond the first MaxApplianceDevices
		fp       *adminpages.Fingerprint
	}
	// ApplianceDevice is one inventory device of the family and how many open exploited vulnerabilities it has.
	ApplianceDevice struct {
		DeviceID      string `json:"device_id"`
		Name          string `json:"name"`
		OpenExploited int    `json:"open_exploited"`
	}
)

// applianceOf is the product a port names, or nil. svc is the service row of the same address and port, nil when none.
func applianceOf(p PortRow, svc *ServiceRow) *Appliance {
	page := adminpages.Page{Title: p.Title, Server: p.Server, Location: p.Location, CertNames: p.CertNames, Products: []string{p.Product}}
	if svc != nil {
		page.Products = append(page.Products, svc.Product, svc.CPE, svc.Extra)
	}
	m, ok := adminpages.Identify(page)
	if !ok {
		return nil
	}
	return applianceFrom(m.Fingerprint, m.Evidence)
}

func applianceFrom(fp *adminpages.Fingerprint, ev string) *Appliance {
	a := &Appliance{Name: fp.Product, Kind: ApplianceAdmin, Evidence: evidenceOf(ev), fp: fp}
	if fp.Family != nil {
		a.Name, a.Vendor = fp.Family.Name, fp.Family.Vendor
	}
	switch {
	case !fp.Admin:
		a.Kind = ApplianceVPN
	case fp.Family != nil && fp.Family.SharedVPN && ev != adminpages.EvTitle:
		a.Kind = ApplianceAdminOrVPN // a certificate, a Server header or a product name says nothing about which page answers
	}
	return a
}

func evidenceOf(ev string) string {
	switch ev {
	case adminpages.EvCert:
		return EvidenceCert
	case adminpages.EvTitle:
		return EvidenceTitle
	case adminpages.EvServer:
		return EvidenceServer
	case adminpages.EvRedirect:
		return EvidenceRedirect
	}
	return EvidenceProduct // the product a scan named (the surface scan read it from the body or a header)
}

func portKey(ip string, port int) string { return fmt.Sprintf("%s:%d", ipKey(ip), port) }

// servicesByPort indexes service rows by address and port.
func servicesByPort(services []ServiceRow) map[string]*ServiceRow {
	out := make(map[string]*ServiceRow, len(services))
	for i := range services {
		out[portKey(services[i].IP, services[i].Port)] = &services[i]
	}
	return out
}

// applianceAdmins is admins with one row more for each port this scan saw that names an admin page (or a page that may be either
// the admin page or the VPN portal) and has no admin row yet. A port kept from an earlier scan (INV-22) adds none: its page was not
// read this time. The same rows come out however often it runs on its own result, so it is applied when a scan is stored and again
// when a snapshot is read (a snapshot of an older release, a fingerprint added since).
func applianceAdmins(admins []AdminRow, ports []PortRow, services []ServiceRow) []AdminRow {
	have := map[string]bool{}
	for _, a := range admins {
		have[portKey(a.IP, a.Port)] = true
	}
	svc := servicesByPort(services)
	out := admins
	for _, p := range ports {
		k := portKey(p.IP, p.Port)
		if have[k] || p.LastSeen != "" || p.Port < 1 || p.Port > 65535 {
			continue
		}
		a := applianceOf(p, svc[k])
		if a == nil || a.Kind == ApplianceVPN || !webPage(p, svc[k], a) {
			continue // a VPN portal, or a service that is no web page (SSH, FTP, an API): the port is named, it is no admin page
		}
		have[k] = true
		risk := "warn"
		if a.fp.Danger {
			risk = "danger"
		}
		out = append(out, AdminRow{URL: adminURL(p), Product: a.fp.Product, IP: p.IP, Port: p.Port, Risk: risk})
	}
	return out
}

// webPage says whether the port that named the appliance serves its web page: a web service, a statement only a web page makes
// (its title, Server header or redirect), or the family's certificate on a TLS port nothing else identified, other than a port where
// that certificate answers another protocol (FortiGate's FGFM on 541).
func webPage(p PortRow, svc *ServiceRow, a *Appliance) bool {
	web := func(name string) bool { return strings.HasPrefix(baseService(name), "http") }
	switch {
	case web(p.Service) || svc != nil && web(svc.Name):
		return true
	case a.Evidence == EvidenceTitle || a.Evidence == EvidenceServer || a.Evidence == EvidenceRedirect:
		return true
	case a.Evidence == EvidenceCert:
		if f := a.fp.Family; f != nil && slices.Contains(f.NotWebPorts, p.Port) {
			return false
		}
		tls := func(name string) bool { return name == "ssl" || name == "ssl/unknown" }
		return tls(p.Service) && (svc == nil || tls(svc.Name) || svc.Name == "")
	}
	return false
}

// adminURL is the address of the page: https when the port speaks TLS (a certificate, a TLS service name), else http.
func adminURL(p PortRow) string {
	scheme := "http"
	if len(p.CertNames) > 0 || p.Service == "ssl" || p.Service == "https" || strings.HasPrefix(p.Service, "ssl/") || strings.HasSuffix(p.Service, "https") {
		scheme = "https"
	}
	host := p.IP
	if a, err := netip.ParseAddr(p.IP); err == nil && a.Is6() {
		host = "[" + a.String() + "]"
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, p.Port)
}

// nameAppliances sets the appliance on each port and admin row that names one (without devices: tieAppliances adds them). An admin
// row takes the appliance of its port when both name the same product family, else the one its product names.
func nameAppliances(ports []PortRow, admins []AdminRow, services []ServiceRow) {
	svc := servicesByPort(services)
	byPort := map[string]*Appliance{}
	for i := range ports {
		k := portKey(ports[i].IP, ports[i].Port)
		ports[i].Appliance = applianceOf(ports[i], svc[k])
		if ports[i].Appliance != nil {
			byPort[k] = ports[i].Appliance
		}
	}
	for i := range admins {
		var a *Appliance
		if fp := adminpages.ByProduct(admins[i].Product); fp != nil {
			a = applianceFrom(fp, adminpages.EvProduct)
		}
		if p := byPort[portKey(admins[i].IP, admins[i].Port)]; p != nil && (a == nil || a.Name == p.Name) {
			a = p
		}
		if a != nil {
			c := *a
			admins[i].Appliance = &c
		}
	}
}

// applianceCache is the last answer of the inventory about every appliance family.
type applianceCache struct {
	mu       sync.Mutex
	at       time.Time // when devs was read
	devs     map[string]ApplianceMatch
	reading  bool      // a read runs now: other pages take the last answer instead of waiting for it
	failedAt time.Time // when the last read failed: the next one waits applianceRetry
	failing  bool      // the last read failed: logged once, until a read succeeds again
}

// applianceRetry is how long a failed read of the inventory waits before the next one; applianceReadTimeout bounds one read.
const (
	applianceRetry       = 10 * time.Second
	applianceReadTimeout = 15 * time.Second
)

// familyDevices is the inventory's answer for every family: one read for every page read within applianceTTL, made without the
// lock and apart from the request (a page that is closed does not cancel it). While it runs, and after a failure, pages take the
// last answer (nil before the first success: the page then makes no claim about the inventory).
func (s *Service) familyDevices(ctx context.Context) map[string]ApplianceMatch {
	c := &s.appliances
	now := s.clock()
	c.mu.Lock()
	fresh := c.devs != nil && now.Sub(c.at) < applianceTTL
	waiting := c.failing && now.Sub(c.failedAt) < applianceRetry
	if fresh || waiting || c.reading {
		devs := c.devs
		c.mu.Unlock()
		return devs
	}
	c.reading = true
	c.mu.Unlock()

	fams := adminpages.Families()
	qs := make([]ApplianceQuery, 0, len(fams))
	for _, f := range fams {
		qs = append(qs, ApplianceQuery{Family: f.ID, KevKeys: f.KevKeys, Device: f.Device, Kinds: f.Kinds})
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), applianceReadTimeout)
	got, err := s.cfg.Appliances.ApplianceDevices(rctx, qs)
	cancel()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.reading = false
	if err != nil {
		if !c.failing {
			s.cfg.Log.WarnContext(ctx, "exposure: reading the devices of the appliance families", "err", err)
		}
		c.failing, c.failedAt = true, s.clock()
		return c.devs
	}
	if c.failing {
		s.cfg.Log.InfoContext(ctx, "exposure: reading the devices of the appliance families works again")
	}
	c.failing, c.at, c.devs = false, s.clock(), got
	return got
}

// tieAppliances adds the inventory devices of its family to every appliance of the rows (Config.Appliances). Without the port or
// an answer, or for a product of no family, Devices stays nil.
func (s *Service) tieAppliances(ctx context.Context, ports []PortRow, admins []AdminRow) {
	if s.cfg.Appliances == nil {
		return
	}
	var all []*Appliance
	for i := range ports {
		if a := ports[i].Appliance; a != nil && a.fp.Family != nil {
			all = append(all, a)
		}
	}
	for i := range admins {
		if a := admins[i].Appliance; a != nil && a.fp.Family != nil {
			all = append(all, a)
		}
	}
	if len(all) == 0 {
		return
	}
	devs := s.familyDevices(ctx)
	if devs == nil {
		return
	}
	for _, a := range all {
		m := devs[a.fp.Family.ID]
		a.Devices = make([]ApplianceDevice, 0, len(m.Devices))
		for _, d := range m.Devices {
			a.Devices = append(a.Devices, ApplianceDevice{DeviceID: d.DeviceID, Name: cleanName(d.Name), OpenExploited: max(d.OpenExploited, 0)})
		}
		a.More = max(m.More, 0)
	}
}

// tieLatest ties the appliances of the open ports of every target's newest snapshot. The copies share each port's *Appliance, so
// the devices land on the rows of latest.
func (s *Service) tieLatest(ctx context.Context, latest map[string]latestResult) {
	var ports []PortRow
	for _, r := range latest {
		ports = append(ports, r.Ports...)
	}
	s.tieAppliances(ctx, ports, nil)
}

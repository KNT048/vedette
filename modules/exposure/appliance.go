package exposure

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// S-EXP-1: the management or VPN page of a network appliance (a firewall, a VPN gateway, a router) that answers on the Internet.
// These are the devices attacked first: their admin and VPN pages are on the CISA list of exploited vulnerabilities again and
// again. A port names the appliance by what it states about itself, on any port: the names of its TLS certificate (FortiGate's
// default certificate is issued to "FortiGate" or to its serial number, "FGT60F…"), its page title, its Server header, or the
// product and CPE that service identification read. Such a port is listed as an admin interface (unless it states that it is the
// VPN portal, which faces the Internet by design), and is tied, when it is read, to the inventory devices of the same family and
// their open exploited vulnerabilities (Config.Appliances).

// The values of Appliance.Kind.
const (
	ApplianceAdmin      = "admin"        // the device's management page
	ApplianceVPN        = "vpn"          // its VPN portal: meant to face the Internet, not an admin page
	ApplianceAdminOrVPN = "admin_or_vpn" // the family serves both from one certificate or product name (FortiGate's admin and SSL-VPN pages)
)

// The values of Appliance.Evidence: which statement of the port named the family.
const (
	EvidenceCert    = "certificate" // a name of its TLS certificate
	EvidenceTitle   = "title"       // its web page's title
	EvidenceServer  = "server"      // its HTTP Server header
	EvidenceProduct = "product"     // the product, CPE or extra information the scan read on it
)

type (
	// Appliance is the appliance family a port or an admin row names (contract.ts Appliance). Devices are the inventory devices of
	// that family, set when the snapshot or the target list is read: nil when Vedette cannot tell (no inventory wired, or its read
	// failed), empty when no device of the family is in the inventory.
	Appliance struct {
		Name     string            `json:"name"`
		Vendor   string            `json:"vendor"`
		Kind     string            `json:"kind"`
		Evidence string            `json:"evidence"`
		Devices  []ApplianceDevice `json:"devices"`
	}
	// ApplianceDevice is one inventory device of the family and how many open exploited vulnerabilities it has.
	ApplianceDevice struct {
		DeviceID      string `json:"device_id"`
		Name          string `json:"name"`
		OpenExploited int    `json:"open_exploited"`
	}
)

// applianceFamily is one family of appliance. says reads each statement of a port: words or serial numbers only that family uses,
// never a word an ordinary site could carry alone ("Juniper" is a common word; "Juniper Networks", "JUNOS" and "J-Web" are not).
// The words come from the device identification rules (content/devicetypes/rules.json) and the scan module's admin-page
// fingerprints (modules/scan/surface/admin.go); kevKeys are the family's KEV vendor|product pairs (content/catalog/kev-products.json,
// held by TestApplianceFamilies_KEVKeysAreKEVProducts), without the vendor's "Multiple Products", which other product lines share.
type applianceFamily struct {
	name, vendor string
	kind         string // when no statement says it is the VPN portal
	says         *regexp.Regexp
	device       *regexp.Regexp // an inventory device's vendor, model, OS and software text that is this family
	kevKeys      []string
}

var applianceFamilies = []applianceFamily{
	{name: "FortiGate", vendor: "Fortinet", kind: ApplianceAdminOrVPN,
		says:    regexp.MustCompile(`\bFG(T|VM)[0-9A-Z]{4,}|(?i:\bforti(gate|os|wifi)\b|\bfortinet ssl[- ]?vpn\b)`),
		device:  regexp.MustCompile(`(?i)\bforti(gate|os|wifi)\b`),
		kevKeys: []string{"fortinet|fortios", "fortinet|fortios and fortiadc", "fortinet|fortios and fortiproxy", "fortinet|fortios and fortiproxy ssl-vpn"}},
	{name: "Palo Alto firewall", vendor: "Palo Alto Networks", kind: ApplianceAdminOrVPN,
		says:    regexp.MustCompile(`(?i)\bpalo ?alto ?networks\b|\bpan-os\b|\bglobal-?protect\b`),
		device:  regexp.MustCompile(`(?i)\bpalo ?alto\b|\bpan-os\b`),
		kevKeys: []string{"palo alto networks|pan-os"}},
	{name: "SonicWall", vendor: "SonicWall", kind: ApplianceAdminOrVPN,
		says:   regexp.MustCompile(`(?i)\bsonicwall\b|\bsonicos\b`),
		device: regexp.MustCompile(`(?i)\bsonicwall\b|\bsonicos\b`),
		kevKeys: []string{"sonicwall|sonicos", "sonicwall|sma100", "sonicwall|sma100 appliances", "sonicwall|sma 100 appliances", "sonicwall|sma1000 appliances",
			"sonicwall|sma1000 appliance", "sonicwall|sslvpn sma100", "sonicwall|secure remote access (sra)"}},
	{name: "Cisco ASA", vendor: "Cisco", kind: ApplianceAdminOrVPN,
		says:   regexp.MustCompile(`(?i)\bcisco (asa|asdm)\b|\badaptive[ _]security[ _]appliance\b|\banyconnect\b|/\+cscoe\+/`),
		device: regexp.MustCompile(`(?i)\bcisco asa\b|\badaptive security appliance\b|\basa ?55[0-9]{2}`),
		kevKeys: []string{"cisco|adaptive security appliance (asa)", "cisco|adaptive security appliance (asa) and firepower threat defense (ftd)",
			"cisco|adaptive security appliance and firepower threat defense", "cisco|anyconnect secure",
			"cisco|secure firewall adaptive security appliance (asa) and secure firewall threat defense (ftd)",
			"cisco|secure firewall adaptive security appliance and secure firewall threat defense", "cisco|secure firewall asa software and cisco secure ftd software"}},
	{name: "Ivanti Connect Secure", vendor: "Ivanti", kind: ApplianceAdminOrVPN,
		says:   regexp.MustCompile(`(?i)\b(ivanti|pulse) (connect )?secure\b|/dana-na/`),
		device: regexp.MustCompile(`(?i)\b(ivanti|pulse) (connect )?secure\b|\bconnect secure\b`),
		kevKeys: []string{"ivanti|connect secure", "ivanti|connect secure and policy secure", "ivanti|connect secure, policy secure, and neurons",
			"ivanti|connect secure, policy secure, and zta gateways", "ivanti|pulse connect secure", "ivanti|pulse connect secure and pulse policy secure",
			"pulse secure|pulse connect secure"}},
	{name: "Citrix NetScaler", vendor: "Citrix", kind: ApplianceAdminOrVPN,
		says:   regexp.MustCompile(`(?i)\bnetscaler\b|\bcitrix (adc|gateway)\b`),
		device: regexp.MustCompile(`(?i)\bnetscaler\b|\bcitrix (adc|gateway)\b`),
		kevKeys: []string{"citrix|netscaler", "citrix|netscaler adc and gateway", "citrix|netscaler adc and netscaler gateway",
			"citrix|application delivery controller (adc) and gateway", "citrix|application delivery controller (adc), gateway, and sd-wan wanop appliance"}},
	{name: "MikroTik router", vendor: "MikroTik", kind: ApplianceAdmin,
		says:    regexp.MustCompile(`(?i)\b(routeros|mikrotik|webfig)\b`),      //nolint:misspell // RouterOS is the product name
		device:  regexp.MustCompile(`(?i)\b(mikrotik|routeros|routerboard)\b`), //nolint:misspell // RouterOS is the product name
		kevKeys: []string{"mikrotik|routeros"}},                                //nolint:misspell // RouterOS is the product name
	{name: "Juniper", vendor: "Juniper Networks", kind: ApplianceAdmin,
		says:    regexp.MustCompile(`(?i)\bjuniper (networks|web device manager)\b|\bjunos\b|\bj-web\b|\bv?srx[0-9]{3,4}\b`),
		device:  regexp.MustCompile(`(?i)\bjuniper\b|\bjunos\b`),
		kevKeys: []string{"juniper|junos os"}},
}

// vpnSays is a statement that the page is the VPN portal itself (the surface scan's "Fortinet SSL VPN", "GlobalProtect Portal").
var vpnSays = regexp.MustCompile(`(?i)\bssl[- ]?vpn\b|\bglobal-?protect\b|\banyconnect\b|/\+cscoe\+/|\b(ivanti|pulse) connect secure\b|/dana-na/|\b(citrix|netscaler) gateway\b`)

// statement is one thing a port states about itself, and which kind of evidence it is.
type statement struct{ text, evidence string }

// statements are what a port and the service row nmap read there state, strongest first: the certificate (issued to the
// device), the page title, the Server header, then the product, CPE and extra information.
func statements(p PortRow, svc *ServiceRow) []statement {
	var out []statement
	for _, n := range p.CertNames {
		out = append(out, statement{n, EvidenceCert})
	}
	out = append(out, statement{p.Title, EvidenceTitle}, statement{p.Server, EvidenceServer}, statement{p.Product, EvidenceProduct})
	if svc != nil {
		out = append(out, statement{svc.Product, EvidenceProduct}, statement{svc.CPE, EvidenceProduct}, statement{svc.Extra, EvidenceProduct})
	}
	return out
}

// applianceOf is the appliance family a port names, or nil. svc is the service row of the same address and port, nil when none.
func applianceOf(p PortRow, svc *ServiceRow) *Appliance {
	for _, st := range statements(p, svc) {
		if st.text == "" {
			continue
		}
		for _, f := range applianceFamilies {
			if !f.says.MatchString(st.text) {
				continue
			}
			kind := f.kind
			if vpnSays.MatchString(st.text) {
				kind = ApplianceVPN
			}
			return &Appliance{Name: f.name, Vendor: f.vendor, Kind: kind, Evidence: st.evidence}
		}
	}
	return nil
}

// applianceOfProduct is the family an admin row's product names (the scan module's fingerprint name, "FortiGate"), or nil.
func applianceOfProduct(product string) *Appliance {
	return applianceOf(PortRow{Product: product}, nil)
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

// applianceAdmins is admins with one row more for each port that names an appliance's admin page (or a page that may be either
// its admin or its VPN page) and has no admin row yet. The same rows come out however often it runs on its own result, so it is
// applied when a scan is stored and again when a snapshot is read (a snapshot of an older release, a rule added since).
func applianceAdmins(admins []AdminRow, ports []PortRow, services []ServiceRow) []AdminRow {
	have := map[string]bool{}
	for _, a := range admins {
		have[portKey(a.IP, a.Port)] = true
	}
	svc := servicesByPort(services)
	out := admins
	for _, p := range ports {
		k := portKey(p.IP, p.Port)
		if have[k] || p.Port < 1 || p.Port > 65535 {
			continue
		}
		a := applianceOf(p, svc[k])
		if a == nil || a.Kind == ApplianceVPN {
			continue
		}
		have[k] = true
		out = append(out, AdminRow{URL: adminURL(p), Product: a.Name, IP: p.IP, Port: p.Port, Risk: "danger"})
	}
	return out
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

// nameAppliances sets the appliance on each port and admin row that names one (without devices: tieAppliances adds them).
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
		a := applianceOfProduct(admins[i].Product)
		if p := byPort[portKey(admins[i].IP, admins[i].Port)]; p != nil && (a == nil || a.Name == p.Name) {
			a = p
		}
		if a != nil {
			c := *a
			admins[i].Appliance = &c
		}
	}
}

// tieAppliances adds the inventory devices of its family to every appliance of the rows (Config.Appliances), asking once per
// family. Without the port, or when a read fails (logged), Devices stays nil: the page then makes no claim about the inventory.
func (s *Service) tieAppliances(ctx context.Context, ports []PortRow, admins []AdminRow) {
	if s.cfg.Appliances == nil {
		return
	}
	found := map[string][]ApplianceDevice{}
	failed := map[string]bool{}
	tie := func(a *Appliance) {
		if a == nil || failed[a.Name] {
			return
		}
		devs, ok := found[a.Name]
		if !ok {
			f := familyNamed(a.Name)
			if f == nil {
				return
			}
			got, err := s.cfg.Appliances.ApplianceDevices(ctx, ApplianceQuery{KevKeys: f.kevKeys, Device: f.device})
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "exposure: reading the devices of an appliance family", "family", a.Name, "err", err)
				failed[a.Name] = true
				return
			}
			devs = make([]ApplianceDevice, 0, len(got))
			for _, d := range got {
				devs = append(devs, ApplianceDevice{DeviceID: d.DeviceID, Name: cleanName(d.Name), OpenExploited: max(d.OpenExploited, 0)})
			}
			found[a.Name] = devs
		}
		a.Devices = devs
	}
	for i := range ports {
		tie(ports[i].Appliance)
	}
	for i := range admins {
		tie(admins[i].Appliance)
	}
}

// tieLatest ties the appliances of the open ports of every target's newest snapshot, asking once per family for the whole list.
// The copies share each port's *Appliance, so the devices land on the rows of latest.
func (s *Service) tieLatest(ctx context.Context, latest map[string]latestResult) {
	var ports []PortRow
	for _, r := range latest {
		ports = append(ports, r.Ports...)
	}
	s.tieAppliances(ctx, ports, nil)
}

func familyNamed(name string) *applianceFamily {
	for i := range applianceFamilies {
		if applianceFamilies[i].name == name {
			return &applianceFamilies[i]
		}
	}
	return nil
}

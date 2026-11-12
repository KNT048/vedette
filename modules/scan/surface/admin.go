package surface

import (
	"html"
	"regexp"
	"strings"
)

// page is what one GET of / returned, lower-cased for matching. All of it came from the target: untrusted (SYS-6).
type page struct {
	title    string // the <title>, unescaped, spaces collapsed
	server   string // the Server header
	body     string // the first maxPageBody bytes
	location string // the Location header of a redirect that was not followed
	header   map[string]bool
}

var (
	titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	iloRE   = regexp.MustCompile(`(^|[^a-z])ilo([^a-z]|$)`) // "iLO 5", not "silo"
)

// readTitle returns the title of an HTML page: unescaped, spaces collapsed, at most 200 characters.
func readTitle(body string) string {
	m := titleRE.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(m[1])), " ")
	if r := []rune(t); len(r) > 200 {
		t = string(r[:200])
	}
	return t
}

// fingerprint names a product from its first page. admin false is a product that is meant to face the Internet (a VPN portal): it
// names the port but is not an admin page.
type fingerprint struct {
	product string
	admin   bool
	danger  bool // "close now"; otherwise "restrict by IP"
	match   func(p page) bool
}

func in(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// loginish: a title that is about signing in to a device, so that a brand name alone (a shop selling ASUS phones) is not a router.
func loginish(t string) bool {
	return in(t, "login", "log in", "sign in", "router", "modem", "gateway", "wireless", "web management")
}

// fingerprints are checked in order; the first that matches names the page (D-229). They read the title, a few headers and
// markers of the page that only that product uses; never a word that an ordinary site could contain. Admin pages of network,
// storage and server hardware and of tools that run code are "danger" (close now: they are attacked first, and several are on
// the KEV list); admin pages of applications that have their own sign-in and are often published on purpose are "warn".
var fingerprints = []fingerprint{
	// VPN portals face the Internet by design: they name the port, they are not admin pages.
	{"Fortinet SSL VPN", false, false, func(p page) bool { return in(p.body, "/remote/login") || in(p.location, "/remote/login") }},
	{"Palo Alto GlobalProtect", false, false, func(p page) bool { return in(p.body, "global-protect") || in(p.title, "globalprotect") }},
	{"Cisco AnyConnect", false, false, func(p page) bool { return in(p.body, "/+cscoe+/") || in(p.location, "/+cscoe+/") }},
	{"Ivanti Connect Secure", false, false, func(p page) bool { return in(p.body, "/dana-na/") || in(p.location, "/dana-na/") }},
	{"Citrix Gateway", false, false, func(p page) bool { return in(p.title, "citrix gateway", "netscaler gateway") }},
	// Network devices and firewalls.
	{"FortiGate", true, true, func(p page) bool { return in(p.title, "fortigate") || in(p.body, "ftnt-fortinet-grid", "fgt_lang") }},
	{"MikroTik RouterOS", true, true, func(p page) bool { return in(p.title, "routeros", "mikrotik") || in(p.body, "webfig") }}, //nolint:misspell // RouterOS is the product name
	{"pfSense", true, true, func(p page) bool { return in(p.title, "pfsense") }},
	{"OPNsense", true, true, func(p page) bool { return in(p.title, "opnsense") }},
	{"Sophos Firewall", true, true, func(p page) bool {
		return in(p.title, "sophos") && (loginish(p.title) || in(p.title, "firewall", "utm", "webadmin"))
	}},
	{"SonicWall", true, true, func(p page) bool { return in(p.title, "sonicwall") || in(p.server, "sonicwall") }},
	{"Palo Alto Networks", true, true, func(p page) bool { return in(p.title, "palo alto networks", "pan-os") }},
	{"Cisco", true, true, func(p page) bool {
		return in(p.title, "cisco") && (loginish(p.title) || in(p.title, "asdm", "systems"))
	}},
	{"Ubiquiti UniFi", true, true, func(p page) bool { return in(p.title, "unifi", "ubiquiti", "airos") }},
	{"DrayTek Vigor", true, true, func(p page) bool { return in(p.title, "draytek") || in(p.title, "vigor") && loginish(p.title) }},
	{"Zyxel", true, true, func(p page) bool { return in(p.title, "zyxel") }},
	{"TP-Link", true, true, func(p page) bool { return in(p.title, "tp-link", "tplink") }},
	{"ASUS router", true, true, func(p page) bool { return in(p.title, "asus") && loginish(p.title) || in(p.title, "asuswrt") }},
	{"NETGEAR", true, true, func(p page) bool { return in(p.title, "netgear") && loginish(p.title) }},
	{"Huawei router", true, true, func(p page) bool { return in(p.title, "huawei") && loginish(p.title) }},
	{"ZTE router", true, true, func(p page) bool { return in(p.title, "zte") && loginish(p.title) }},
	{"GPON home gateway", true, true, func(p page) bool { return in(p.title, "gpon") }},
	{"Hikvision camera", true, true, func(p page) bool { return in(p.title, "hikvision") || in(p.body, "doc/page/login.asp") }},
	{"Dahua camera", true, true, func(p page) bool { return in(p.title, "dahua") }},
	// Storage, servers and their out-of-band management.
	{"Synology DSM", true, true, func(p page) bool { return in(p.title, "synology", "diskstation") }},
	{"QNAP", true, true, func(p page) bool { return in(p.title, "qnap") || in(p.server, "qnap") }},
	{"TrueNAS", true, true, func(p page) bool { return in(p.title, "truenas") }},
	{"Proxmox VE", true, true, func(p page) bool { return in(p.title, "proxmox") }},
	{"VMware ESXi", true, true, func(p page) bool { return in(p.title, "esxi", "vmware host client") }},
	{"VMware vCenter", true, true, func(p page) bool { return in(p.title, "vsphere", "vcenter") }},
	{"HPE iLO", true, true, func(p page) bool { return in(p.title, "lights-out") || iloRE.MatchString(p.title) }},
	{"Dell iDRAC", true, true, func(p page) bool { return in(p.title, "idrac") }},
	{"Supermicro IPMI", true, true, func(p page) bool { return in(p.title, "supermicro") }},
	// Tools that run code or read data without much in the way.
	{"Jenkins", true, true, func(p page) bool { return p.header["x-jenkins"] || in(p.title, "[jenkins]") }},
	{"phpMyAdmin", true, true, func(p page) bool { return in(p.title, "phpmyadmin") }},
	{"Adminer", true, true, func(p page) bool { return in(p.title, "adminer") }},
	{"Webmin", true, true, func(p page) bool { return in(p.title, "webmin") || in(p.server, "miniserv") }},
	{"Portainer", true, true, func(p page) bool { return in(p.title, "portainer") }},
	{"Kibana", true, true, func(p page) bool { return in(p.title, "kibana") || p.header["kbn-name"] }},
	{"Elasticsearch", true, true, func(p page) bool { return in(p.body, "you know, for search") }},
	{"Apache CouchDB", true, true, func(p page) bool { return in(p.body, `"couchdb":"welcome"`) }},
	// Applications with their own sign-in, often published on purpose.
	{"Grafana", true, false, func(p page) bool { return in(p.title, "grafana") }},
	{"cPanel", true, false, func(p page) bool { return in(p.title, "cpanel", "webhost manager") }},
	{"Plesk", true, false, func(p page) bool { return in(p.title, "plesk") }},
	{"Home Assistant", true, false, func(p page) bool { return in(p.title, "home assistant") }},
	// Any other device login.
	{"Router login page", true, true, func(p page) bool { return in(p.title, "router", "modem") && loginish(p.title) }},
}

// identify returns the fingerprint of a page, or nil.
func identify(p page) *fingerprint {
	for i := range fingerprints {
		if fingerprints[i].match(p) {
			return &fingerprints[i]
		}
	}
	return nil
}

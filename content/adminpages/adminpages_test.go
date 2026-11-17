package adminpages

import (
	"encoding/json"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// The table is ours: it loads, every fingerprint has a source, every family has a device pattern and KEV keys that are KEV
// vendor|product pairs, and no family carries a key a VPN client of the same vendor carries in the catalog.
func TestTable(t *testing.T) {
	t.Parallel()
	if err := Err(); err != nil {
		t.Fatal(err)
	}
	var kev []struct{ Vendor, Product string }
	if err := json.Unmarshal(catalogdata.KEVProducts, &kev); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, p := range kev {
		known[strings.ToLower(p.Vendor)+"|"+strings.ToLower(p.Product)] = true
	}
	var curated []struct {
		Kind     string   `json:"kind"`
		KevMatch []string `json:"kev_match"`
	}
	if err := json.Unmarshal(catalogdata.Curated, &curated); err != nil {
		t.Fatal(err)
	}
	client := map[string]bool{}
	for _, c := range curated {
		if c.Kind == "pc" || c.Kind == "laptop" || c.Kind == "smartphone" {
			for _, k := range c.KevMatch {
				client[k] = true
			}
		}
	}
	for _, f := range Families() {
		if len(f.KevKeys) == 0 || f.Device == nil {
			t.Errorf("family %s has no KEV key or no device pattern", f.ID)
		}
		for _, k := range f.KevKeys {
			if !known[k] {
				t.Errorf("family %s: %q is not a KEV vendor|product pair", f.ID, k)
			}
			if client[k] {
				t.Errorf("family %s: %q is a key of a client product in the catalog", f.ID, k)
			}
		}
	}
	if len(Fingerprints()) < 50 {
		t.Errorf("%d fingerprints: the table lost rows", len(Fingerprints()))
	}
}

// One case is what a port stated and what it should be named ("" = nothing).
type pageCase struct {
	name     string
	p        Page
	product  string
	evidence string
}

var cases = []pageCase{
	// FortiGate: the default certificate (issued to "FortiGate" or the serial number), the FortiOS Server header, the redirect to the
	// SSL-VPN login, a title.
	{"default certificate", Page{CertNames: []string{"FortiGate"}}, "FortiGate", EvCert},
	{"FortiGate 60F serial", Page{CertNames: []string{"FGT60FTK2109ABCD"}}, "FortiGate", EvCert},
	{"FortiGate 100F serial", Page{CertNames: []string{"FG100FTK20012345"}}, "FortiGate", EvCert},
	{"FortiGate 1000F serial", Page{CertNames: []string{"FG1K0FTB21900001"}}, "FortiGate", EvCert},
	{"FortiGate VM serial", Page{CertNames: []string{"FGVM02TM22000000"}}, "FortiGate", EvCert},
	{"FortiWiFi serial", Page{CertNames: []string{"FWF60FTK21000001"}}, "FortiGate", EvCert},
	{"FortiGate Rugged serial", Page{CertNames: []string{"FGR60FTK21000001"}}, "FortiGate", EvCert},
	{"FortiOS Server header", Page{Server: "xxxxxxxx-xxxxx"}, "FortiGate", EvServer},
	{"FortiGate title", Page{Title: "FortiGate"}, "FortiGate", EvTitle},
	{"FortiGate title with a host name", Page{Title: "fw01 - FortiGate"}, "FortiGate", EvTitle},
	{"FortiOS CPE", Page{Products: []string{"cpe:/o:fortinet:fortios"}}, "FortiGate", EvProduct},
	{"SSL-VPN redirect", Page{Location: "https://vpn.example.com:10443/remote/login?lang=en"}, "Fortinet SSL VPN", EvRedirect},
	{"SSL-VPN behind the default certificate", Page{CertNames: []string{"FortiGate"}, Products: []string{"Fortinet SSL VPN"}}, "Fortinet SSL VPN", EvProduct},
	// The other families.
	{"GlobalProtect portal", Page{Title: "GlobalProtect Portal"}, "Palo Alto GlobalProtect", EvTitle},
	{"GlobalProtect redirect", Page{Location: "/global-protect/login.esp"}, "Palo Alto GlobalProtect", EvRedirect},
	{"PAN-OS login", Page{Title: "Palo Alto Networks - Login"}, "Palo Alto Networks", EvTitle},
	{"SonicWall admin", Page{Title: "SonicWall - Authentication"}, "SonicWall", EvTitle},
	{"SonicWall Server header", Page{Server: "SonicWALL"}, "SonicWall", EvServer},
	{"SonicWall SSL VPN", Page{Server: "SonicWALL SSL-VPN Web Server"}, "SonicWall SSL VPN", EvServer},
	{"Cisco ASDM", Page{Title: "Cisco ASDM 7.18"}, "Cisco ASA", EvTitle},
	{"AnyConnect portal", Page{Location: "/+CSCOE+/logon.html"}, "Cisco AnyConnect", EvRedirect},
	{"Ivanti title", Page{Title: "Ivanti Connect Secure"}, "Ivanti Connect Secure", EvTitle},
	{"Pulse redirect", Page{Location: "/dana-na/auth/url_default/welcome.cgi"}, "Ivanti Connect Secure", EvRedirect},
	{"NetScaler gateway", Page{Title: "NetScaler Gateway"}, "Citrix Gateway", EvTitle},
	{"Citrix redirect", Page{Location: "/logon/LogonPoint/index.html"}, "Citrix Gateway", EvRedirect},
	{"Check Point SNX", Page{Title: "Check Point SSL Network Extender"}, "Check Point SSL VPN", EvTitle},
	{"Check Point portal redirect", Page{Location: "/sslvpn/Login/Login"}, "Check Point SSL VPN", EvRedirect},
	{"F5 TMUI redirect", Page{Title: "BIG-IP&reg;- Redirect"}, "F5 BIG-IP", EvTitle},
	{"F5 TMUI", Page{Location: "/tmui/login.jsp"}, "F5 BIG-IP", EvRedirect},
	{"F5 configuration utility page", Page{Body: "<title>BIG-IP Configuration Utility</title> ... F5 Networks, Inc."}, "F5 BIG-IP", EvBody},
	{"WatchGuard authentication portal", Page{Title: "Fireware XTM User Authentication"}, "WatchGuard SSL VPN", EvTitle},
	{"WatchGuard SSL VPN redirect", Page{Location: "/sslvpn_logon.shtml"}, "WatchGuard SSL VPN", EvRedirect},
	{"WatchGuard admin", Page{Title: "WatchGuard Login"}, "WatchGuard Firebox", EvTitle},
	{"Juniper J-Web", Page{Title: "Log In - Juniper Web Device Manager"}, "Juniper J-Web", EvTitle},
	{"Junos CPE", Page{Products: []string{"cpe:/o:juniper:junos"}}, "Juniper J-Web", EvProduct},
	{"MikroTik", Page{Title: "RouterOS router configuration page"}, "MikroTik RouterOS", EvTitle},
	{"Sophos", Page{Title: "Sophos Firewall"}, "Sophos Firewall", EvTitle},
	{"Zyxel", Page{Title: "Zyxel USG FLEX 100"}, "", ""}, // a product line in the title is more than the brand, and no sign-in word
	{"Zyxel login", Page{Title: "Zyxel Login"}, "Zyxel", EvTitle},
	// What the surface scan knew stays known.
	{"Synology", Page{Title: "synology diskstation - nas01"}, "Synology DSM", EvTitle},
	{"Jenkins", Page{Title: "Dashboard [Jenkins]"}, "Jenkins", EvTitle},
	{"Jenkins header", Page{Headers: map[string]bool{"x-jenkins": true}}, "Jenkins", EvHeader},
	{"iLO", Page{Title: "Integrated Lights-Out 5"}, "HPE iLO", EvTitle},
	{"iLO login", Page{Title: "iLO 5 Login"}, "HPE iLO", EvTitle},
	{"Grafana", Page{Title: "Grafana"}, "Grafana", EvTitle},
	{"ASUS", Page{Title: "ASUS Router Login"}, "ASUS router", EvTitle},
	{"GPON", Page{Title: "GPON Home Gateway"}, "GPON home gateway", EvTitle},
	{"Elasticsearch", Page{Body: `{"name":"x","tagline":"You Know, for Search"}`}, "Elasticsearch", EvBody},
	{"router login", Page{Title: "Router Login"}, "Router login page", EvTitle},
	// Not an admin page: a product word on an ordinary site, a part of a longer certificate name, a VPN title with no vendor.
	{"a shop", Page{Title: "FortiGate 60F price | Example Shop"}, "", ""},
	{"a how-to", Page{Title: "How to configure FortiOS 7.4"}, "", ""},
	{"news", Page{Title: "Palo Alto Networks stock rises"}, "", ""},
	{"a guide", Page{Title: "Patching Citrix ADC: a guide"}, "", ""},
	{"consulting", Page{Title: "NetScaler consulting | Example"}, "", ""},
	{"a partner", Page{Title: "Juniper Networks partner"}, "", ""},
	{"stock", Page{Title: "SRX300 in stock"}, "", ""},
	{"a how-to about the client", Page{Title: "How to install GlobalProtect"}, "", ""},
	{"a shared certificate", Page{CertNames: []string{"www.example.com", "fortigate.example.com"}}, "", ""},
	{"words that look like a serial", Page{CertNames: []string{"FGTS2024"}}, "", ""},
	{"a word that looks like a serial", Page{CertNames: []string{"FGTSDIGITAL"}}, "", ""},
	{"a VPN title with no vendor", Page{Title: "SSL VPN Service"}, "", ""},
	{"Webex", Page{Title: "Cisco Webex"}, "", ""},
	{"partners", Page{Title: "our partners: cisco, fortinet", Body: "we resell fortinet and pfsense"}, "", ""},
	{"laptops", Page{Title: "acme store - asus laptops"}, "", ""},
	{"silo", Page{Title: "grain silo supplies"}, "", ""},
	{"router deals", Page{Title: "Best router deals"}, "", ""},
	{"OpenSSH", Page{Products: []string{"OpenSSH 9.6p1 Ubuntu 3ubuntu13.20"}}, "", ""},
}

func TestIdentify(t *testing.T) {
	t.Parallel()
	for _, c := range cases {
		m, ok := Identify(c.p)
		got := ""
		if ok {
			got = m.Product
		}
		switch {
		case c.product == "" && ok:
			t.Errorf("%s: named %s by %s, want nothing", c.name, got, m.Evidence)
		case c.product != "" && (got != c.product || m.Evidence != c.evidence):
			t.Errorf("%s: got %q by %q, want %q by %q", c.name, got, m.Evidence, c.product, c.evidence)
		}
	}
}

func TestByProduct(t *testing.T) {
	t.Parallel()
	if fp := ByProduct("fortinet ssl vpn"); fp == nil || fp.Admin || fp.Family == nil || fp.Family.ID != "fortigate" {
		t.Fatalf("Fortinet SSL VPN = %+v", fp)
	}
	if ByProduct("nginx") != nil {
		t.Fatal("nginx is not a product of the table")
	}
}

package devicetypes

import (
	"slices"
	"strings"
	"testing"
)

// The file is ours: every type has a known category and acts as one of the 13 kinds, each of which is a type acting as itself, ids
// are unique and in the database's format, and no alias names two types.
func TestTypesFile(t *testing.T) {
	t.Parallel()
	cats := map[string]bool{}
	for _, c := range Categories() {
		if cats[c.ID] || c.Label == "" {
			t.Errorf("category %q is a duplicate or has no label", c.ID)
		}
		cats[c.ID] = true
	}
	if len(cats) < 12 || len(cats) > 14 {
		t.Errorf("%d categories, want 12 to 14 (D-511)", len(cats))
	}
	seen := map[string]bool{}
	names := map[string]string{}
	for _, ty := range Types() {
		if seen[ty.ID] {
			t.Errorf("type %q twice", ty.ID)
		}
		seen[ty.ID] = true
		if len(ty.ID) > 40 || strings.Trim(ty.ID, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
			t.Errorf("type id %q is not [a-z0-9_]{1,40} (inv_asset.kind CHECK)", ty.ID)
		}
		if !cats[ty.Category] || ty.Label == "" {
			t.Errorf("type %q: category %q unknown or no label", ty.ID, ty.Category)
		}
		if !slices.Contains(Kinds, ty.ActsAs) {
			t.Errorf("type %q acts as %q, not one of the 13 kinds", ty.ID, ty.ActsAs)
		}
		for _, a := range append([]string{ty.Label}, ty.Aliases...) {
			if other, ok := names[Fold(a)]; ok && other != ty.ID {
				t.Errorf("%q names both %s and %s", a, other, ty.ID)
			}
			names[Fold(a)] = ty.ID
		}
	}
	for _, k := range Kinds {
		if ActsAs(k) != k || !Valid(k) {
			t.Errorf("kind %q must stay a type acting as itself (stored rows, settings, rules)", k)
		}
	}
	// What behaviour keys on stays where it was: phones, embedded and OT types are fragile like iot, a VPN gateway is a firewall.
	for typ, kind := range map[string]string{"smartphone": "iot", "ip_phone": "iot", "plc": "iot", "ups": "iot", "laptop": "pc", "vpn_gateway": "firewall", "modem": "router", "dvr": "nvr", "virtual_machine": "server"} {
		if ActsAs(typ) != kind {
			t.Errorf("%s acts as %s, want %s", typ, ActsAs(typ), kind)
		}
	}
	if ActsAs("nonsense") != Unknown || Valid("nonsense") {
		t.Error("an unknown id must act as unknown and be invalid")
	}
	if got := ActingAs([]string{"router", "firewall"}); !slices.Contains(got, "modem") || !slices.Contains(got, "vpn_gateway") || slices.Contains(got, "switch") {
		t.Errorf("ActingAs(router, firewall) = %v", got)
	}
	for name, want := range map[string]string{"Wi-Fi (AP)": "ap", "camera_recorder": "nvr", "IP phone": "ip_phone", "notebook": "laptop", "Laptop": "laptop", "desktop": "pc", "other": "unknown", "VoIP": "ip_phone"} {
		if got, ok := Lookup(name); !ok || got != want {
			t.Errorf("Lookup(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	// #714 review LOW: a smart switch is a network switch; words too broad to name one type are no aliases.
	if got, _ := Lookup("smart switch"); got != "switch" {
		t.Errorf("Lookup(smart switch) = %q, want switch", got)
	}
	for _, broad := range []string{"hub", "appliance", "console"} {
		if got, ok := Lookup(broad); ok {
			t.Errorf("Lookup(%q) = %q: too broad to be an alias", broad, got)
		}
	}
	// A load balancer and a proxy stand in front of everyone's traffic: they act as routers, so never-touch keeps them (D-511).
	if ActsAs("proxy") != "router" || ActsAs("load_balancer") != "router" {
		t.Error("proxy and load balancer must act as router (never-touch infrastructure)")
	}
}

// Every rule names a type, has at least one condition and a sentence, and the first rules (what a device states) come before the
// guesses from its maker.
func TestRulesFile(t *testing.T) {
	t.Parallel()
	ids := map[string]bool{}
	for _, r := range rules {
		if ids[r.ID] {
			t.Errorf("rule %q twice", r.ID)
		}
		ids[r.ID] = true
		if !Valid(r.Type) || r.Type == Unknown {
			t.Errorf("rule %s: type %q", r.ID, r.Type)
		}
		if r.Confidence <= 0 || r.Confidence > 0.6 {
			t.Errorf("rule %s: confidence %v outside (0, 0.6]: a guess stays below what a sensor states", r.ID, r.Confidence)
		}
		if len(r.Vendor)+len(r.MACPrefix)+len(r.PortsAny)+len(r.PortsAll)+len(r.LastOctet) == 0 && r.Text == "" && r.Hostname == "" && r.Model == "" && r.OS == "" && !r.Gateway {
			t.Errorf("rule %s has no condition", r.ID)
		}
		for _, a := range r.Alternatives {
			if !Valid(a) || a == r.Type || a == Unknown {
				t.Errorf("rule %s: alternative %q", r.ID, a)
			}
		}
		if r.Says == "" || strings.HasSuffix(r.Says, ".") {
			t.Errorf("rule %s: says %q (one clause, no full stop)", r.ID, r.Says)
		}
		for _, v := range r.Vendor {
			if v != strings.ToLower(v) {
				t.Errorf("rule %s: vendor %q must be lower case", r.ID, v)
			}
		}
	}
}

func svc(port int, name string) Service { return Service{Port: port, Proto: "tcp", Name: name} }

// Rules from what a device states win over its maker, and the evidence says what matched.
func TestIdentify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name               string
		f                  Facts
		typ, model, saying string
	}{
		{"FortiGate certificate", Facts{Vendor: "Fortinet", VendorFromCard: true, Services: []Service{{Port: 443, Proto: "tcp", Name: "https", Detail: "certificate: commonName=FGT60FTK2109ABCD/organizationName=Fortinet"}}},
			"firewall", "FortiGate 60F", `Port 443 says "FGT60FTK2109ABCD": a FortiGate firewall.`},
		{"FortiAP certificate", Facts{Vendor: "Fortinet", VendorFromCard: true, Services: []Service{{Port: 443, Proto: "tcp", Detail: "certificate: commonName=FP221E3X17001234"}}},
			"ap", "FortiAP 221E", "FortiAP"},
		{"Juniper J-Web title with model", Facts{Vendor: "Juniper Networks", VendorFromCard: true, Services: []Service{{Port: 443, Proto: "tcp", Detail: "title: Log In - EX2300-24P - J-Web"}}},
			"switch", "Juniper EX2300-24P", "Juniper switch"},
		{"nmap device type of a service", Facts{Services: []Service{{Port: 80, Proto: "tcp", Product: "Hikvision IP camera httpd", Detail: "device type: webcam"}}},
			"camera", "", "IP camera"},
		{"gateway", Facts{IP: "192.168.18.1", Gateway: true, Services: []Service{svc(53, "domain"), svc(443, "https")}},
			"router", "", "It is the box's default gateway: the network's router"},
		{"gateway that is a FortiGate", Facts{IP: "10.0.0.1", Gateway: true, Vendor: "Fortinet, Inc.", VendorFromCard: true},
			"firewall", "", "It is the box's default gateway and Fortinet network card"},
		{"agent make is not a card", Facts{Vendor: "Dell Inc.", Services: []Service{svc(22, "ssh")}},
			"server", "", "Made by Dell and port 22 (ssh)"},
		// #714 review LOW: iDRAC9 is a management card; Intelbras is not Intel; a Dell box with SSH is only perhaps a server; a VMware
		// card is hedged; a Fortinet card offers the access point and the switch next to the firewall.
		{"iDRAC9 title", Facts{Vendor: "Dell", VendorFromCard: true, Services: []Service{svc(22, "ssh"), {Port: 443, Proto: "tcp", Detail: "title: iDRAC9"}}},
			"bmc", "", "management card"},
		{"Dell and SSH", Facts{Vendor: "Dell", VendorFromCard: true, Services: []Service{svc(22, "ssh")}}, "server", "", "perhaps a Linux server or a Linux computer"},
		{"VMware card", Facts{Vendor: "VMware, Inc.", VendorFromCard: true}, "virtual_machine", "", "a VMware host's own management card"},
		{"no signal", Facts{Vendor: "Hewlett Packard", VendorFromCard: true, Services: []Service{svc(80, "http"), svc(443, "https"), svc(8000, "http-alt")}},
			"", "", ""},
		{"udp ports do not count", Facts{Services: []Service{{Port: 554, Proto: "udp"}}}, "", "", ""},
	}
	if g, ok := Identify(Facts{Vendor: "Intelbras", VendorFromCard: true, Services: []Service{svc(22, "ssh")}}); ok {
		t.Errorf("Intelbras + SSH guessed %+v: it is no PC maker", g)
	}
	if g, _ := Identify(Facts{Vendor: "Fortinet", VendorFromCard: true, Services: []Service{svc(22, "ssh")}}); !slices.Equal(g.Alternatives, []string{"ap", "switch"}) {
		t.Errorf("Fortinet guess alternatives = %v, want ap, switch", g.Alternatives)
	}
	for _, c := range cases {
		g, ok := Identify(c.f)
		if c.typ == "" {
			if ok {
				t.Errorf("%s: guessed %+v from too little", c.name, g)
			}
			continue
		}
		if !ok || g.Type != c.typ || g.Model != c.model || !strings.Contains(g.Evidence, c.saying) {
			t.Errorf("%s: got %+v, want %s %q evidence containing %q", c.name, g, c.typ, c.model, c.saying)
		}
	}
}

package mitigation

import (
	"context"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

func (fakeVendors) OpenPorts(context.Context, string) ([]OpenPort, error) { return nil, nil }

// portVendors is fakeVendors with the open ports of every device.
type portVendors struct {
	fakeVendors
	open []OpenPort
}

func (v portVendors) OpenPorts(context.Context, string) ([]OpenPort, error) { return v.open, nil }

func hardeningRow(ip, kind, vendor, product string) findings.Row {
	return findings.Row{ID: "f-1", CVE: "CVE-2024-6387", Asset: &findings.AssetView{ID: "a-1", Name: "web01", IP: ip, Kind: kind},
		Kev: &findings.KevInfo{Vendor: vendor, Product: product}}
}

func guideOf(t *testing.T, h *findings.Hardening, vendor string) findings.FirewallGuide {
	t.Helper()
	for _, g := range h.Firewall {
		if g.Vendor == vendor {
			return g
		}
	}
	t.Fatalf("no %s guide in %+v", vendor, h.Firewall)
	return findings.FirewallGuide{}
}

// codeOf is every command of a guide, in one string.
func codeOf(g findings.FirewallGuide) string {
	var b strings.Builder
	steps := append(append(append([]findings.CodeStep{}, g.Steps...), g.Verify...), g.Undo...)
	if g.Alternative != nil {
		steps = append(steps, g.Alternative.Steps...)
	}
	for _, s := range steps {
		b.WriteString(s.Code + "\n")
	}
	return b.String()
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s lacks %q:\n%s", what, sub, s)
		}
	}
}

// INV-8: the open ports of the software, for each firewall vendor, with the admin network left for the page to fill in.
func TestContract_INV8_GeneralHardeningRestrictsTheSoftwaresPortsForEveryVendor(t *testing.T) {
	t.Parallel()
	p := &Provider{vendors: portVendors{fakeVendors: fakeVendors{"fortinet": true}, open: []OpenPort{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH"}, {Port: 80, Proto: "tcp", Name: "http"}, {Port: 22, Proto: "tcp", Name: "ssh"},
	}}}
	h, err := p.hardening(t.Context(), hardeningRow("10.0.0.5", "server", "OpenBSD", "OpenSSH"), nil, nil)
	if err != nil || h == nil {
		t.Fatalf("hardening = %v, %v", h, err)
	}
	if h.PortsFrom != portsSeen || len(h.Ports) != 1 || h.Ports[0] != (findings.HardeningPort{Port: 22, Proto: "tcp", Service: "ssh"}) || h.Target != "10.0.0.5" || h.Self {
		t.Fatalf("ports = %s %+v, target %q", h.PortsFrom, h.Ports, h.Target)
	}
	if h.AdminExample != adminExample4 || h.Checks == nil || h.Family != "OpenSSH" {
		t.Fatalf("hardening = %+v", h)
	}
	if len(h.Firewall) != 3 {
		t.Fatalf("guides = %+v", h.Firewall)
	}
	fg := guideOf(t, h, "fortigate")
	if !fg.Detected || guideOf(t, h, "mikrotik").Detected || guideOf(t, h, "generic").Detected {
		t.Fatal("detected must follow the inventory (INV-5)")
	}
	mustContain(t, "FortiGate", codeOf(fg), `set subnet {ADMIN_NET}`, `edit "vedette-host-10-0-0-5"`, "set subnet 10.0.0.5/32", "set tcp-portrange 22\n",
		"set srcaddr-negate enable", `set dstaddr "vedette-host-10-0-0-5"`, "set action deny", `set service "vedette-ports-10-0-0-5"`, "move <ID> before <FIRST-ID>")
	mustContain(t, "MikroTik", codeOf(guideOf(t, h, "mikrotik")), "address-list add list=vedette-admin address={ADMIN_NET}",
		"chain=forward action=drop dst-address=10.0.0.5 src-address-list=!vedette-admin protocol=tcp dst-port=22 place-before=0")
	gen := codeOf(guideOf(t, h, "generic"))
	mustContain(t, "nftables", gen, "table inet vedette_10_0_0_5", "ip daddr 10.0.0.5 ip saddr != {ADMIN_NET} tcp dport { 22 } drop",
		"hook forward", "hook input", "sudo nft delete table inet vedette_10_0_0_5",
		"sudo iptables -I INPUT -d 10.0.0.5 ! -s {ADMIN_NET} -p tcp -m multiport --dports 22 -m comment --comment vedette -j DROP",
		"sudo iptables -D FORWARD -d 10.0.0.5 ! -s {ADMIN_NET} -p tcp -m multiport --dports 22")
	for _, g := range h.Firewall {
		if g.Steps[0].SideEffect == "" {
			t.Errorf("%s: the side effect must be stated before the paste (INV-4)", g.Vendor)
		}
		if strings.Contains(codeOf(g), "80") {
			t.Errorf("%s: port 80 is not OpenSSH's: %s", g.Vendor, codeOf(g))
		}
	}
}

// INV-8: no port of the software known: every new inbound connection except from the admin network, and the page says so.
func TestContract_INV8_UnknownPortsRestrictAllInboundAndSaySo(t *testing.T) {
	t.Parallel()
	h := generalHardening(hardeningInput{Row: hardeningRow("192.168.10.21", "nas", "QNAP", "Photo Station"), Firewall: true, Checks: true,
		Open: []OpenPort{{Port: 8080, Proto: "tcp", Name: "http-proxy"}}})
	if h.PortsFrom != portsAll || len(h.Ports) != 0 || h.Family != "General" {
		t.Fatalf("ports = %s %+v (%s)", h.PortsFrom, h.Ports, h.Family)
	}
	for _, g := range h.Firewall {
		mustContain(t, g.Vendor+" intro", g.Intro, "blocks every new connection to the device except from your admin network")
		mustContain(t, g.Vendor+" side effect", g.Steps[0].SideEffect, "Everything else the device serves")
	}
	mustContain(t, "FortiGate", codeOf(guideOf(t, &h, "fortigate")), `set service "ALL"`)
	mustContain(t, "MikroTik", codeOf(guideOf(t, &h, "mikrotik")), "connection-state=new")
	mustContain(t, "nftables", codeOf(guideOf(t, &h, "generic")), "ip daddr 192.168.10.21 ip saddr != {ADMIN_NET} ct state new drop", `iifname "lo" accept`,
		"! -i lo -m conntrack --ctstate NEW")
	if strings.Contains(codeOf(guideOf(t, &h, "fortigate")), "service custom") {
		t.Fatal("no port list: no custom service")
	}
}

// INV-8 + INV-4: a device value goes in only as a parsed IP; anything else is <IP>, never escaped into a command.
func TestContract_INV8_UnsafeDeviceValuesNeverReachTheConfigs(t *testing.T) {
	t.Parallel()
	for _, ip := range []string{"10.0.0.5; rm -rf /", "$(id)", "fe80::1%eth0", "—", "", "10.0.0.5\nreboot", "`id`"} {
		h := generalHardening(hardeningInput{Row: hardeningRow(ip, "server", "Linux", "Kernel"), Firewall: true,
			Open: []OpenPort{{Port: 22, Proto: "tcp", Name: "ssh;reboot"}, {Port: 0, Proto: "tcp"}, {Port: 23, Proto: "sctp"}}})
		if h.Target != "<IP>" {
			t.Errorf("%q: target = %q", ip, h.Target)
		}
		for _, g := range h.Firewall {
			code := codeOf(g)
			for _, bad := range []string{"rm -rf", "$(id)", "%eth0", "reboot", "`id`", "ssh;"} {
				if strings.Contains(code, bad) {
					t.Errorf("%q: %s config carries %q", ip, g.Vendor, bad)
				}
			}
			mustContain(t, g.Vendor, g.Intro, "replace <IP> with its address")
		}
		if len(h.Ports) != 1 || h.Ports[0].Service != "" {
			t.Errorf("%q: ports = %+v (bad ports dropped, odd service name not shown)", ip, h.Ports)
		}
	}
	// a valid IPv6 address: the IPv6 forms
	h := generalHardening(hardeningInput{Row: hardeningRow("2001:db8::5", "server", "OpenBSD", "OpenSSH"), Firewall: true, Open: []OpenPort{{Port: 22, Proto: "tcp", Name: "ssh"}}})
	if h.Target != "2001:db8::5" || h.AdminExample != adminExample6 {
		t.Fatalf("v6 = %+v", h)
	}
	mustContain(t, "FortiGate v6", codeOf(guideOf(t, &h, "fortigate")), "config firewall address6", "set ip6 2001:db8::5/128", "set srcaddr6-negate enable", "set dstaddr6")
	mustContain(t, "MikroTik v6", codeOf(guideOf(t, &h, "mikrotik")), "/ipv6 firewall filter add")
	mustContain(t, "nftables v6", codeOf(guideOf(t, &h, "generic")), "ip6 daddr 2001:db8::5 ip6 saddr != {ADMIN_NET}", "sudo ip6tables -I INPUT", "vedette_2001_db8__5")
}

// INV-8: the firewall's own CVE protects its own admin access: local-in policies on a FortiGate, chain input on a MikroTik,
// with the usual admin ports when none was seen.
func TestContract_INV8_TheFirewallItselfGetsItsOwnAdminAccessRestricted(t *testing.T) {
	t.Parallel()
	h := generalHardening(hardeningInput{Row: hardeningRow("192.168.1.1", "firewall", "Fortinet", "FortiOS"), Firewall: true})
	if !h.Self || h.PortsFrom != portsUsual || len(h.Ports) != 3 {
		t.Fatalf("FortiOS = %+v", h)
	}
	fg := codeOf(guideOf(t, &h, "fortigate"))
	mustContain(t, "FortiGate self", fg, "config firewall local-in-policy", "set tcp-portrange 22 80 443", "set action accept", "set action deny", "set trusthost1 {ADMIN_NET}")
	if strings.Contains(fg, "config firewall policy\n") {
		t.Fatal("a forward policy does not protect the FortiGate itself")
	}
	mustContain(t, "intro", guideOf(t, &h, "fortigate").Intro, "usual ports")
	mustContain(t, "side effect", guideOf(t, &h, "fortigate").Steps[0].SideEffect, "lock yourself out")

	h = generalHardening(hardeningInput{Row: hardeningRow("192.168.88.1", "router", "MikroTik", "RouterOS"), Firewall: true,
		Open: []OpenPort{{Port: 8291, Proto: "tcp", Name: "unknown"}, {Port: 53, Proto: "udp", Name: "domain"}}})
	if !h.Self || h.PortsFrom != portsSeen || len(h.Ports) != 1 || h.Ports[0].Port != 8291 {
		t.Fatalf("RouterOS = %+v", h)
	}
	mk := codeOf(guideOf(t, &h, "mikrotik"))
	mustContain(t, "MikroTik self", mk, "chain=input action=drop src-address-list=!vedette-admin protocol=tcp dst-port=8291", "/ip service set [find] address={ADMIN_NET}")
	if strings.Contains(mk, "dst-address=") {
		t.Fatal("chain input needs no device address")
	}
}

// INV-8, D-21: the checks are per family, name no CVE-specific sign, point to the advisory, and are never a confirmed pack.
func TestContract_INV8_ChecksArePerFamilyAndClaimNothingAboutTheCVE(t *testing.T) {
	t.Parallel()
	cases := []struct{ kind, vendor, product, family, want string }{
		{"pc", "Microsoft", "Windows", "Windows", "Get-WinEvent"},
		{"server", "Microsoft", "Exchange Server", "Windows web server (IIS)", "C:\\inetpub"},
		{"server", "Linux", "Kernel", "Linux", "sudo ss -tulpn"},
		{"server", "OpenBSD", "OpenSSH", "OpenSSH", "sshd -T"},
		{"server", "Apache", "HTTP Server", "Web server on Linux", "/var/log/apache2/access.log"},
		{"switch", "Juniper", "Junos OS", "Juniper Junos OS", "show system commit"},
		{"firewall", "Fortinet", "FortiOS", "Fortinet FortiOS", "show system admin"},
		{"router", "MikroTik", "RouterOS", "MikroTik RouterOS", "/system scheduler print"},
		{"router", "Cisco", "IOS XE Software", "Cisco IOS", "show control-plane host open-ports"},
		{"firewall", "Palo Alto Networks", "PAN-OS", "Network device", "Compare the running configuration"},
		{"nas", "QNAP", "Photo Station", "General", "software's own user list"},
	}
	for _, c := range cases {
		h := generalHardening(hardeningInput{Row: hardeningRow("10.0.0.9", c.kind, c.vendor, c.product), Checks: true})
		if h.Family != c.family || h.Checks == nil || len(h.Firewall) != 0 {
			t.Errorf("%s %s: family %q, checks %v, firewall %d", c.vendor, c.product, h.Family, h.Checks != nil, len(h.Firewall))
			continue
		}
		all := h.Checks.Summary
		for _, in := range h.Checks.Indicators {
			all += in.Title + in.Detail
			for _, cm := range in.Commands {
				all += cm.Code
			}
		}
		mustContain(t, c.product, all, c.want, "not specific to CVE-2024-6387", "vendor advisory", "call home")
		if strings.Contains(strings.ToLower(all), "confirmed") || strings.Contains(all, "10.0.0.9") {
			t.Errorf("%s: the general checks must not claim confirmation nor carry device values: %s", c.product, all)
		}
		if len(h.Checks.IfFound) == 0 {
			t.Errorf("%s: no if-found steps", c.product)
		}
	}
}

// POST-1: a confirmed pack's own firewall guides and compromise signs win; the general block fills only what the pack leaves out.
func TestContract_INV8_TheConfirmedPackWinsWhereItHasItsOwn(t *testing.T) {
	t.Parallel()
	p := &Provider{vendors: fakeVendors{}}
	row := hardeningRow("10.0.0.5", "server", "OpenBSD", "OpenSSH")
	full := &findings.MitigationPack{Firewall: []findings.FirewallGuide{{Vendor: "generic"}}}
	if h, err := p.hardening(t.Context(), row, full, &findings.CompromiseCheck{}); err != nil || h != nil {
		t.Fatalf("pack with both = %+v, %v", h, err)
	}
	h, err := p.hardening(t.Context(), row, full, nil)
	if err != nil || h == nil || h.Checks == nil || len(h.Firewall) != 0 {
		t.Fatalf("pack without compromise = %+v, %v", h, err)
	}
	h, err = p.hardening(t.Context(), row, &findings.MitigationPack{}, &findings.CompromiseCheck{})
	if err != nil || h == nil || h.Checks != nil || len(h.Firewall) != 3 {
		t.Fatalf("pack without firewall = %+v, %v", h, err)
	}
}

// POST-1 end to end: a finding without a pack carries the general block on GET /findings/{id}.
func TestContract_INV8_FindingWithoutPackShowsGeneralHardening(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.vendors["mikrotik"] = true
	code, b := r.call("GET", "/findings/"+r.ids[otherCVE], "viewer", "")
	if code != 200 || b["pack"] != nil {
		t.Fatalf("%d %v", code, b)
	}
	h, _ := b["hardening"].(map[string]any)
	if h == nil || h["target"] != "192.168.10.21" || h["ports_from"] != "all" || h["checks"] == nil {
		t.Fatalf("hardening = %v", b["hardening"])
	}
	det := map[string]bool{}
	for _, g := range h["firewall"].([]any) {
		gm := g.(map[string]any)
		det[gm["vendor"].(string)] = gm["detected"].(bool)
	}
	if len(det) != 3 || !det["mikrotik"] || det["fortigate"] || det["generic"] {
		t.Fatalf("detected = %v", det)
	}
}

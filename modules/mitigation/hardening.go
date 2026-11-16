package mitigation

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/modules/findings"
)

// General hardening (INV-8, M2-1): while no maintainer-confirmed pack ships for a CVE, every finding still gets a ready firewall
// config that lets only the admin network reach the device, for the firewall the inventory lists, and general "Have I been hit?"
// checks for its software family. Both are written here, by reviewed code, from the device's parsed IP and the ports inventory saw
// open: nothing in them is about the CVE, so they are not a recommendation (D-21) and the page labels them so. Vedette never runs
// them (FORBID-1): they are text the person pastes.

// adminExample is the admin network the page starts with, marked there as an example to change.
const (
	adminExample4 = "192.168.1.0/24"
	adminExample6 = "fd00::/64"
	// maxPorts is the most ports one config lists (iptables multiport takes 15); more than that and the config restricts all.
	maxPorts = 15
)

// The ways the ports of a config are known (findings.Hardening.PortsFrom).
const (
	portsSeen  = "seen"
	portsUsual = "usual"
	portsAll   = "all"
)

// hardening is the general hardening of a finding, or nil when the confirmed pack covers both parts (POST-1).
func (p *Provider) hardening(ctx context.Context, r findings.Row, pack *findings.MitigationPack, comp *findings.CompromiseCheck) (*findings.Hardening, error) {
	in := hardeningInput{Row: r, Firewall: pack == nil || len(pack.Firewall) == 0, Checks: comp == nil}
	if !in.Firewall && !in.Checks {
		return nil, nil
	}
	if in.Firewall {
		var err error
		if r.Asset != nil && r.Asset.ID != "" {
			if in.Open, err = p.vendors.OpenPorts(ctx, r.Asset.ID); err != nil {
				return nil, fmt.Errorf("mitigation: reading the device's open ports: %w", err)
			}
		}
		in.Detected = map[string]bool{}
		for guide, vendor := range inventoryVendor {
			if in.Detected[guide], err = p.vendors.HasFirewallVendor(ctx, vendor); err != nil {
				return nil, fmt.Errorf("mitigation: looking up firewall vendor: %w", err)
			}
		}
	}
	h := generalHardening(in)
	return &h, nil
}

// hardeningInput is what generalHardening needs: the finding, what inventory knows, and which parts the pack leaves open.
type hardeningInput struct {
	Row      findings.Row
	Open     []OpenPort      // ports seen open on the device
	Detected map[string]bool // guide vendor (fortigate, mikrotik) -> the inventory lists one
	Firewall bool            // write the firewall configs
	Checks   bool            // write the compromise checks
}

// generalHardening builds the hardening block. It is pure, so every case is a unit test.
func generalHardening(in hardeningInput) findings.Hardening {
	fam := familyOf(in.Row)
	h := findings.Hardening{Software: softwareName(in.Row), Family: fam.label}
	if in.Checks {
		c := fam.checks(h.Software, in.Row.CVE)
		h.Checks = &c
	}
	if !in.Firewall {
		return h
	}
	t := targetOf(in.Row.Asset)
	h.Target, h.AdminExample = t.ip, adminExample4
	if t.v6 {
		h.AdminExample = adminExample6
	}
	h.Self = fam.self != ""
	h.Ports, h.PortsFrom = portsFor(fam, in.Open)
	c := cfg{t: t, ports: h.Ports, from: h.PortsFrom, software: h.Software}
	h.Firewall = []findings.FirewallGuide{
		withDetected(fortigateGuide(c, fam.self == "fortigate"), in.Detected),
		withDetected(mikrotikGuide(c, fam.self == "mikrotik"), in.Detected),
		genericGuide(c),
	}
	return h
}

func withDetected(g findings.FirewallGuide, d map[string]bool) findings.FirewallGuide {
	g.Detected = d[g.Vendor]
	return g
}

// softwareName is the software as the page names it (the KEV entry's plain name).
func softwareName(r findings.Row) string {
	if r.Kev == nil {
		return "the software"
	}
	if r.Kev.Display != "" {
		return r.Kev.Display
	}
	return strings.TrimSpace(r.Kev.Vendor + " " + r.Kev.Product)
}

// target is the device address as the configs write it. Only a parsed IP (no zone) goes in (INV-4); anything else is "<IP>".
type target struct {
	ip   string // "10.0.0.5", or "<IP>"
	ok   bool
	v6   bool
	slug string // the address in object names: dots and colons as dashes or underscores
}

func targetOf(a *findings.AssetView) target {
	if a != nil {
		if addr, err := netip.ParseAddr(a.IP); err == nil && addr.Zone() == "" {
			addr = addr.Unmap()
			s := addr.String()
			return target{ip: s, ok: true, v6: addr.Is6(), slug: strings.NewReplacer(".", "-", ":", "-").Replace(s)}
		}
	}
	return target{ip: "<IP>"}
}

// portsFor picks the ports of the config: the open ports of the device that belong to the software, else (the device is the
// firewall itself) the software's usual admin ports, else none, which means every new inbound connection.
func portsFor(fam family, open []OpenPort) ([]findings.HardeningPort, string) {
	var out []findings.HardeningPort
	seen := map[[2]any]bool{}
	for _, o := range open {
		if o.Port < 1 || o.Port > 65535 || (o.Proto != "tcp" && o.Proto != "udp") || fam.service == nil || !fam.service(o) {
			continue
		}
		k := [2]any{o.Port, o.Proto}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, findings.HardeningPort{Port: o.Port, Proto: o.Proto, Service: serviceName(o.Name)})
	}
	slices.SortFunc(out, func(a, b findings.HardeningPort) int {
		if a.Proto != b.Proto {
			return strings.Compare(a.Proto, b.Proto)
		}
		return a.Port - b.Port
	})
	switch {
	case len(out) > 0 && len(out) <= maxPorts:
		return out, portsSeen
	case len(fam.usual) > 0:
		return slices.Clone(fam.usual), portsUsual
	}
	return nil, portsAll
}

// serviceName keeps a service name only when it is plain (it is shown on the page, not put in a config).
func serviceName(s string) string {
	if len(s) > 40 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '/' || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}

// cfg is what every vendor's config is written from.
type cfg struct {
	t        target
	ports    []findings.HardeningPort
	from     string
	software string
}

func (c cfg) byProto(proto string) []string {
	var out []string
	for _, p := range c.ports {
		if p.Proto == proto {
			out = append(out, strconv.Itoa(p.Port))
		}
	}
	return out
}

func (c cfg) protos() []string {
	var out []string
	for _, p := range []string{"tcp", "udp"} {
		if len(c.byProto(p)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// portList is the ports in words ("22/tcp (ssh), 443/tcp").
func (c cfg) portList() string {
	parts := make([]string, 0, len(c.ports))
	for _, p := range c.ports {
		s := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		if p.Service != "" {
			s += " (" + p.Service + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// intro says what the config does and why these ports, in the same words for every vendor.
func (c cfg) intro(self bool) string {
	var what string
	switch c.from {
	case portsSeen:
		what = fmt.Sprintf("Vedette saw %s answer on %s of %s. This config lets only your admin network reach those ports; the rest of the device is unchanged.", c.software, c.portList(), c.t.ip)
	case portsUsual:
		what = fmt.Sprintf("Vedette has not seen which ports the admin pages of %s answer on, so this config uses their usual ports: %s. If you moved an admin page to another port, change it in the config.", c.t.ip, c.portList())
	default:
		what = fmt.Sprintf("Vedette has not seen which port %s answers on at %s, so this config blocks every new connection to the device except from your admin network.", c.software, c.t.ip)
	}
	if self {
		what += " It protects the firewall's own admin access, so it applies to every connection to it."
	} else {
		what += " A firewall only filters what passes through it: computers in the same network segment as the device still reach it directly."
	}
	if !c.t.ok {
		what += " This device has no IP address in your inventory: replace <IP> with its address."
	}
	return what
}

// sideEffect is stated before the person pastes (INV-4).
func (c cfg) sideEffect(self bool) string {
	switch {
	case self:
		return "Admins outside the admin network can no longer sign in to the firewall, and a VPN portal on one of these ports stops for everyone outside it. Check the admin network first, or you can lock yourself out."
	case c.from == portsAll:
		return "Everything else the device serves (shared folders, web pages, printing, remote desktop) stops for computers outside the admin network that reach it through this firewall."
	}
	return "Computers outside the admin network can no longer reach these ports of the device through this firewall."
}

const verifyByHand = "From a computer outside the admin network, connect to the device on one of the ports: it must fail. From the admin network it must still work."

// fortigateGuide writes the FortiGate CLI: address objects, a service of the ports and a deny policy for everyone but the admin
// network; for a FortiGate's own CVE, local-in policies that keep its admin ports to the admin network.
func fortigateGuide(c cfg, self bool) findings.FirewallGuide {
	g := findings.FirewallGuide{Vendor: "fortigate", Label: "FortiGate", Intro: c.intro(self)}
	addr, addrSet, addrKey := "address", "subnet", "srcaddr"
	if c.t.v6 {
		addr, addrSet, addrKey = "address6", "ip6", "srcaddr6"
	}
	admin := fmt.Sprintf("config firewall %s\n    edit \"vedette-admin-net\"\n        set %s %s\n    next\nend", addr, addrSet, findings.AdminNetPlaceholder)
	svcName, service := "vedette-ports-"+c.t.slug, "\"ALL\""
	if !c.t.ok {
		svcName = "vedette-ports"
	}
	var svc string
	if len(c.ports) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "config firewall service custom\n    edit %q\n", svcName)
		for _, p := range c.protos() {
			fmt.Fprintf(&b, "        set %s-portrange %s\n", p, strings.Join(c.byProto(p), " "))
		}
		b.WriteString("    next\nend")
		svc, service = b.String(), strconv.Quote(svcName)
	}
	if self {
		policy := "local-in-policy"
		if c.t.v6 {
			policy = "local-in-policy6"
		}
		code := admin + "\n"
		if svc != "" {
			code += svc + "\n"
		}
		code += fmt.Sprintf("config firewall %s\n    edit 0\n        set intf \"any\"\n        set srcaddr \"vedette-admin-net\"\n        set dstaddr \"all\"\n        set action accept\n        set service %s\n        set schedule \"always\"\n    next\n    edit 0\n        set intf \"any\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action deny\n        set service %s\n        set schedule \"always\"\n    next\nend", policy, service, service)
		g.Steps = []findings.CodeStep{{Title: "FortiGate CLI: allow the admin network to the admin ports, deny everyone else", Code: code,
			Note:       "Paste it in the CLI console (the >_ icon at the top of the FortiGate page) or over SSH. The first policy allows the admin network, the second denies the rest; FortiGate checks them in that order.",
			SideEffect: c.sideEffect(true)}}
		g.Alternative = &findings.Alternative{Title: "Or: trusted hosts on each admin account", Intro: "Trusted hosts limit where an admin account may sign in from. Set them on every admin account (show system admin lists them).",
			Steps: []findings.CodeStep{{Title: "FortiGate CLI: trusted host of the admin account", Code: fmt.Sprintf("config system admin\n    edit \"admin\"\n        set trusthost1 %s\n    next\nend", findings.AdminNetPlaceholder),
				Note: "Replace admin with the account name; repeat for each account."}}}
		g.Verify = []findings.CodeStep{{Title: "Show the policies", Code: "show firewall " + policy, Note: verifyByHand}}
		g.Undo = []findings.CodeStep{{Title: "Delete the two policies", Code: fmt.Sprintf("config firewall %s\n    delete <ID>\nend", policy), Note: "Use the IDs the show command above lists for the two Vedette policies."}}
		return g
	}
	host := "vedette-host-" + c.t.slug
	hostSet := c.t.ip + "/32"
	if c.t.v6 {
		hostSet = c.t.ip + "/128"
	}
	if !c.t.ok {
		host, hostSet = "vedette-host", "<IP>/32"
	}
	dst := "dstaddr"
	if c.t.v6 {
		dst = "dstaddr6"
	}
	code := fmt.Sprintf("config firewall %s\n    edit \"vedette-admin-net\"\n        set %s %s\n    next\n    edit %q\n        set %s %s\n    next\nend\n", addr, addrSet, findings.AdminNetPlaceholder, host, addrSet, hostSet)
	if svc != "" {
		code += svc + "\n"
	}
	code += fmt.Sprintf("config firewall policy\n    edit 0\n        set name %q\n        set srcintf \"any\"\n        set dstintf \"any\"\n        set %s \"vedette-admin-net\"\n        set %s-negate enable\n        set %s %q\n        set action deny\n        set service %s\n        set schedule \"always\"\n        set logtraffic all\n    next\nend",
		policyName(c.t), addrKey, addrKey, dst, host, service)
	g.Steps = []findings.CodeStep{
		{Title: "FortiGate CLI: deny the device's ports to everyone but the admin network", Code: code,
			Note:       "Paste it in the CLI console (the >_ icon at the top of the FortiGate page) or over SSH. FortiGate adds the policy at the bottom of the list.",
			SideEffect: c.sideEffect(false)},
		{Title: "Move the policy to the top", Code: fmt.Sprintf("show firewall policy | grep -f %s\nconfig firewall policy\n    move <ID> before <FIRST-ID>\nend", host),
			Note: "The show command prints the policy with its ID (edit <ID>). <FIRST-ID> is the top policy in Policy & Objects, Firewall Policy. You can also drag the policy to the top there. Until it is above your allow policies it does nothing."},
	}
	g.Verify = []findings.CodeStep{{Title: "Show the policy", Code: "show firewall policy | grep -f " + host,
		Note: verifyByHand + " Blocked attempts appear in Log & Report, Forward Traffic."}}
	undo := "config firewall policy\n    delete <ID>\nend\n"
	if svc != "" {
		undo += fmt.Sprintf("config firewall service custom\n    delete %q\nend\n", svcName)
	}
	undo += fmt.Sprintf("config firewall %s\n    delete %q\nend", addr, host)
	g.Undo = []findings.CodeStep{{Title: "Remove the policy and its objects", Code: undo, Note: "vedette-admin-net stays: other Vedette policies may use it."}}
	return g
}

// policyName is the FortiGate policy name (at most 35 characters).
func policyName(t target) string {
	n := "vedette-restrict-" + t.slug
	if !t.ok {
		n = "vedette-restrict"
	}
	if len(n) > 35 {
		n = n[:35]
	}
	return n
}

// mikrotikGuide writes RouterOS: an address list of the admin network and drop rules for the device's ports (chain forward), or
// for a MikroTik's own CVE, the router's own ports (chain input).
func mikrotikGuide(c cfg, self bool) findings.FirewallGuide {
	g := findings.FirewallGuide{Vendor: "mikrotik", Label: "MikroTik", Intro: c.intro(self)}
	fw := "/ip firewall"
	if c.t.v6 {
		fw = "/ipv6 firewall"
	}
	comment := "Vedette: restrict " + c.t.ip
	if self {
		comment = "Vedette: restrict admin access"
	}
	chain, dst := "forward", " dst-address="+c.t.ip
	if self {
		chain, dst = "input", ""
	}
	lines := []string{fmt.Sprintf("%s address-list add list=vedette-admin address=%s comment=\"Vedette admin network\"", fw, findings.AdminNetPlaceholder)}
	rule := func(extra string) string {
		return fmt.Sprintf("%s filter add chain=%s action=drop%s src-address-list=!vedette-admin%s place-before=0 comment=%q", fw, chain, dst, extra, comment)
	}
	if len(c.ports) == 0 {
		lines = append(lines, rule(" connection-state=new"))
	}
	for _, p := range c.protos() {
		lines = append(lines, rule(fmt.Sprintf(" protocol=%s dst-port=%s", p, strings.Join(c.byProto(p), ","))))
	}
	g.Steps = []findings.CodeStep{{Title: "RouterOS terminal: drop the ports for everyone but the admin network", Code: strings.Join(lines, "\n"),
		Note:       "Paste it in a terminal (WinBox, New Terminal, or SSH). place-before=0 puts the rule first; on a router with no filter rule yet, remove it.",
		SideEffect: c.sideEffect(self)}}
	if self {
		g.Alternative = &findings.Alternative{Title: "Or: limit the router's services to the admin network", Intro: "RouterOS can limit each of its own services (WinBox, SSH, web, API) to a network.",
			Steps: []findings.CodeStep{{Title: "RouterOS terminal: services only from the admin network", Code: "/ip service set [find] address=" + findings.AdminNetPlaceholder,
				Note: "/ip service print shows the services and the networks they accept."}}}
	}
	g.Verify = []findings.CodeStep{{Title: "Show the rules and their counters", Code: fmt.Sprintf("%s filter print stats where comment=%q", fw, comment), Note: verifyByHand}}
	g.Undo = []findings.CodeStep{{Title: "Remove the rules", Code: fmt.Sprintf("%s filter remove [find comment=%q]", fw, comment), Note: "The vedette-admin address list stays: other Vedette rules may use it."}}
	return g
}

// genericGuide writes nftables (and iptables as the other way) for a Linux firewall or the Linux device itself: one table of
// its own per device, so removing it touches nothing else.
func genericGuide(c cfg) findings.FirewallGuide {
	g := findings.FirewallGuide{Vendor: "generic", Label: "Linux (nftables)", Intro: c.intro(false) + " The same config works on a Linux firewall or router and on the device itself when it runs Linux."}
	fam, ipt := "ip", "iptables"
	if c.t.v6 {
		fam, ipt = "ip6", "ip6tables"
	}
	table := "vedette_" + strings.ReplaceAll(c.t.slug, "-", "_")
	if !c.t.ok {
		table = "vedette_device"
	}
	match := fmt.Sprintf("%s daddr %s %s saddr != %s", fam, c.t.ip, fam, findings.AdminNetPlaceholder)
	var rules []string
	if len(c.ports) == 0 {
		rules = []string{match + " ct state new drop"}
	}
	for _, p := range c.protos() {
		rules = append(rules, fmt.Sprintf("%s %s dport { %s } drop", match, p, strings.Join(c.byProto(p), ", ")))
	}
	chain := func(name, hook string, lo bool) string {
		var b strings.Builder
		fmt.Fprintf(&b, "    chain %s {\n        type filter hook %s priority 0; policy accept;\n", name, hook)
		if lo {
			b.WriteString("        iifname \"lo\" accept\n")
		}
		for _, r := range rules {
			b.WriteString("        " + r + "\n")
		}
		b.WriteString("    }\n")
		return b.String()
	}
	code := fmt.Sprintf("sudo nft -f - <<'EOF'\ntable inet %s {\n%s%s}\nEOF", table, chain("forward", "forward", false), chain("input", "input", len(c.ports) == 0))
	g.Steps = []findings.CodeStep{{Title: "nftables: drop the ports for everyone but the admin network", Code: code,
		Note:       "The forward chain filters traffic routed to the device, the input chain traffic to this machine when it is the device. The rules last until the next restart: to keep them, add the table to /etc/nftables.conf.",
		SideEffect: c.sideEffect(false)}}
	var ins, del []string
	for _, chainName := range []string{"FORWARD", "INPUT"} {
		base := fmt.Sprintf("-d %s ! -s %s", c.t.ip, findings.AdminNetPlaceholder)
		var specs []string
		if len(c.ports) == 0 {
			lo := ""
			if chainName == "INPUT" {
				lo = " ! -i lo"
			}
			specs = append(specs, base+lo+" -m conntrack --ctstate NEW")
		}
		for _, p := range c.protos() {
			specs = append(specs, fmt.Sprintf("%s -p %s -m multiport --dports %s", base, p, strings.Join(c.byProto(p), ",")))
		}
		for _, s := range specs {
			ins = append(ins, fmt.Sprintf("sudo %s -I %s %s -m comment --comment vedette -j DROP", ipt, chainName, s))
			del = append(del, fmt.Sprintf("sudo %s -D %s %s -m comment --comment vedette -j DROP", ipt, chainName, s))
		}
	}
	g.Alternative = &findings.Alternative{Title: "Or: iptables", Intro: "For a system that still uses iptables. The rules go first in each chain.",
		Steps: []findings.CodeStep{{Title: "iptables: drop the ports for everyone but the admin network", Code: strings.Join(ins, "\n"), SideEffect: c.sideEffect(false)},
			{Title: "iptables: remove them again", Code: strings.Join(del, "\n")}}}
	g.Verify = []findings.CodeStep{{Title: "Show the table", Code: "sudo nft list table inet " + table, Note: verifyByHand}}
	g.Undo = []findings.CodeStep{{Title: "Remove the table", Code: "sudo nft delete table inet " + table}}
	return g
}

// family is a software family the checks and the ports are written for. Only families the KEV entry names reliably.
type family struct {
	id    string
	label string
	self  string                   // the firewall guide that protects the device itself: "fortigate", "mikrotik" or ""
	usual []findings.HardeningPort // the usual admin ports when the device is the firewall itself
	// service reports whether an open port belongs to the software; nil: the family has no port of its own (restrict all)
	service func(OpenPort) bool
	checks  func(software, cve string) findings.CompromiseCheck
}

func tcp(port int, name string) findings.HardeningPort {
	return findings.HardeningPort{Port: port, Proto: "tcp", Service: name}
}

func hasAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func isWeb(o OpenPort) bool {
	n := strings.ToLower(o.Name)
	return strings.Contains(n, "http") || o.Port == 80 || o.Port == 443 || o.Port == 8080 || o.Port == 8443
}

// isAdmin is a remote management service of a network device.
func isAdmin(o OpenPort) bool {
	n := strings.ToLower(o.Name)
	return isWeb(o) || hasAny(n, "ssh", "telnet", "snmp", "winbox") || slices.Contains([]int{22, 23, 161, 830, 8291, 8728, 8729}, o.Port)
}

func isSSH(o OpenPort) bool {
	return strings.ToLower(o.Name) == "ssh" || strings.Contains(strings.ToLower(o.Product), "openssh") || (o.Port == 22 && o.Proto == "tcp")
}

// isWindowsRemote is a Windows remote access service: RPC, SMB, RDP, WinRM.
func isWindowsRemote(o OpenPort) bool {
	n := strings.ToLower(o.Name)
	return o.Proto == "tcp" && (slices.Contains([]int{135, 139, 445, 3389, 5985, 5986}, o.Port) || hasAny(n, "msrpc", "microsoft-ds", "netbios-ssn", "ms-wbt-server", "wsman"))
}

// isLinuxRemote is a Linux remote access service: SSH, telnet, VNC, Cockpit, Webmin.
func isLinuxRemote(o OpenPort) bool {
	n := strings.ToLower(o.Name)
	return isSSH(o) || o.Proto == "tcp" && (slices.Contains([]int{23, 5900, 9090, 10000}, o.Port) || hasAny(n, "telnet", "vnc"))
}

// familyOf maps the finding to a family from the KEV entry's vendor and product, then the device's type.
func familyOf(r findings.Row) family {
	var vendor, product string
	if r.Kev != nil {
		vendor, product = strings.ToLower(r.Kev.Vendor), strings.ToLower(r.Kev.Product)
	}
	vp := vendor + " " + product
	kind := ""
	if r.Asset != nil {
		kind = devicetypes.ActsAs(r.Asset.Kind)
	}
	switch {
	case vendor == "fortinet" && hasAny(product, "fortios", "fortiproxy", "fortigate"):
		return family{id: "fortios", label: "Fortinet FortiOS", self: "fortigate", service: isAdmin, checks: fortiosChecks,
			usual: []findings.HardeningPort{tcp(22, "ssh"), tcp(80, "http"), tcp(443, "https")}}
	case vendor == "mikrotik" && strings.Contains(product, "routeros"):
		return family{id: "routeros", label: "MikroTik RouterOS", self: "mikrotik", service: isAdmin, checks: routerosChecks,
			usual: []findings.HardeningPort{tcp(21, "ftp"), tcp(22, "ssh"), tcp(23, "telnet"), tcp(80, "www"), tcp(443, "www-ssl"), tcp(8291, "winbox"), tcp(8728, "api"), tcp(8729, "api-ssl")}}
	case vendor == "juniper" && strings.Contains(product, "junos"):
		return family{id: "junos", label: "Juniper Junos OS", service: isAdmin, checks: junosChecks}
	case vendor == "cisco" && (strings.HasPrefix(product, "ios") || strings.Contains(product, " ios")):
		return family{id: "ciscoios", label: "Cisco IOS", service: isAdmin, checks: ciscoChecks}
	case strings.Contains(product, "openssh"):
		return family{id: "openssh", label: "OpenSSH", service: isSSH, checks: opensshChecks}
	case vendor == "microsoft" && hasAny(product, "exchange", "sharepoint", "internet information services", "iis"):
		return family{id: "mswebapp", label: "Windows web server (IIS)", service: isWeb, checks: iisChecks}
	case vendor == "microsoft":
		return family{id: "windows", label: "Windows", service: isWindowsRemote, checks: windowsChecks}
	case hasAny(vp, "http server", "httpd", "nginx", "tomcat", "struts", "weblogic", "confluence", "jira", "gitlab", "jenkins", "drupal",
		"wordpress", "joomla", "magento", "coldfusion", "ofbiz", "moveit", "zimbra", "roundcube", "teamcity", "php", "atlassian"):
		return family{id: "web", label: "Web server on Linux", service: isWeb, checks: webChecks}
	case hasAny(vendor, "linux", "canonical", "debian", "red hat", "redhat", "suse", "gnu", "sudo", "polkit") || hasAny(product, "linux", "kernel", "glibc", "polkit"):
		return family{id: "linux", label: "Linux", service: isLinuxRemote, checks: linuxChecks}
	case hasAny(vendor, "fortinet", "juniper", "cisco", "palo alto", "citrix", "ivanti", "pulse secure", "sonicwall", "f5", "zyxel", "d-link",
		"tp-link", "netgear", "draytek", "ubiquiti", "sophos", "watchguard", "array networks", "tenda", "totolink", "mikrotik", "check point") ||
		slices.Contains([]string{"firewall", "router", "switch", "ap"}, kind):
		return family{id: "netdevice", label: "Network device", service: isAdmin, checks: netdeviceChecks}
	}
	return family{id: "generic", label: "General", checks: genericChecks}
}

// ---- "Have I been hit?": general signs per family (text only, INV-6, INV-8) ----

func summaryFor(family, software, cve string) string {
	return fmt.Sprintf("General checks for %s (%s): signs any intruder tends to leave. They are not specific to %s: the vendor advisory and the exploited-list entry (links in What to do) name the files, accounts and addresses seen for this CVE.", software, family, cve)
}

var ifFound = []string{
	"Take the device off the network, but leave it powered on: its memory and temporary files are evidence.",
	"Keep what you found: copy the logs and the files before you change anything.",
	"From a clean computer, change every password and key the device holds or uses (admin accounts, VPN users, service accounts), and anywhere they are reused.",
	"Rebuild the device from a known good install or firmware and update it before you connect it again: an update alone does not remove what an intruder left.",
	"Get help: your incident response provider or your national CERT.",
}

var outbound = findings.Indicator{Kind: "log", Title: "Connections the device started to the internet",
	Detail: "In your firewall's traffic log, look for connections from the device to outside addresses it has no reason to reach, above all at night or in a steady rhythm (every few minutes): intruders' tools call home."}

func check(family, software, cve string, in ...findings.Indicator) findings.CompromiseCheck {
	return findings.CompromiseCheck{Summary: summaryFor(family, software, cve), Indicators: append(in, outbound), IfFound: slices.Clone(ifFound)}
}

func cmd(label, code string) findings.Command { return findings.Command{Label: label, Code: code} }

var windowsIndicators = []findings.Indicator{
	{Kind: "log", Title: "New or changed accounts", Detail: "Security log events 4720 (account created), 4722 (enabled), 4724 (password reset), 4728, 4732 and 4756 (added to a group) that nobody in your team did, and members of Administrators you do not know.",
		Commands: []findings.Command{
			cmd("PowerShell as administrator: account changes in the last 30 days", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4722,4724,4728,4732,4756; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message"),
			cmd("PowerShell: members of Administrators", "Get-LocalGroupMember -Group Administrators"),
		}},
	{Kind: "log", Title: "Remote sign-ins and cleared logs", Detail: "Network and remote desktop sign-ins (event 4624, logon types 3 and 10) from addresses you do not know, and event 1102: someone cleared the Security log.",
		Commands: []findings.Command{
			cmd("PowerShell as administrator: remote sign-ins in the last 7 days", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Where-Object { $_.Properties[8].Value -in 3,10 } | Format-Table TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='From';e={$_.Properties[18].Value}}"),
			cmd("PowerShell as administrator: the Security log was cleared", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue | Format-List TimeCreated, Message"),
		}},
	{Kind: "process", Title: "New services, scheduled tasks and listening programs", Detail: "Services installed recently (System log event 7045), scheduled tasks outside Microsoft's folder, and programs listening on ports you cannot explain, above all from user or temporary folders.",
		Commands: []findings.Command{
			cmd("PowerShell as administrator: services installed in the last 30 days", "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Format-List TimeCreated, Message"),
			cmd("PowerShell: scheduled tasks outside Microsoft's folder", "Get-ScheduledTask | Where-Object TaskPath -notlike '\\Microsoft\\*' | Format-Table TaskPath, TaskName, State"),
			cmd("PowerShell as administrator: listening programs", "Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, @{n='Program';e={(Get-Process -Id $_.OwningProcess).Path}}"),
		}},
}

func windowsChecks(software, cve string) findings.CompromiseCheck {
	return check("Windows", software, cve, windowsIndicators...)
}

func iisChecks(software, cve string) findings.CompromiseCheck {
	web := []findings.Indicator{
		{Kind: "web", Title: "New script files in the web folders", Detail: "Web shells are small .aspx, .ashx or .asmx files dropped in a web folder: under C:\\inetpub, Exchange's FrontEnd\\HttpProxy folder, or SharePoint's LAYOUTS folder. Look for ones changed recently that no update explains.",
			Commands: []findings.Command{cmd("PowerShell as administrator: script files under C:\\inetpub changed in the last 30 days", "Get-ChildItem -Path C:\\inetpub -Recurse -Include *.aspx,*.ashx,*.asmx,*.asp -File -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) | Format-Table LastWriteTime, FullName")}},
		{Kind: "log", Title: "Web server log", Detail: "IIS logs are in C:\\inetpub\\logs\\LogFiles. Look for POST requests to .aspx files you do not know, and one address requesting many pages within seconds."},
		{Kind: "process", Title: "The web server starting a command shell", Detail: "w3wp.exe (the IIS worker) should not start cmd.exe or powershell.exe.",
			Commands: []findings.Command{cmd("PowerShell as administrator: shells started by w3wp.exe", "Get-CimInstance Win32_Process -Filter \"Name='cmd.exe' OR Name='powershell.exe'\" | Where-Object { (Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.ParentProcessId)\").Name -eq 'w3wp.exe' } | Format-List ProcessId, CommandLine")}},
	}
	return check("Windows web server", software, cve, append(web, windowsIndicators...)...)
}

var linuxIndicators = []findings.Indicator{
	{Kind: "log", Title: "Sign-ins", Detail: "Sign-ins at odd hours or from addresses you do not know. The log is /var/log/auth.log (Debian, Ubuntu) or /var/log/secure (Red Hat family), or the journal.",
		Commands: []findings.Command{
			cmd("Last sign-ins", "sudo last -a -n 50"),
			cmd("SSH sign-ins in the last 30 days", "sudo journalctl _COMM=sshd --since \"30 days ago\" | grep -E \"Accepted|Invalid user\""),
		}},
	{Kind: "file", Title: "New accounts and keys", Detail: "Accounts with user id 0 besides root, accounts nobody created, members of sudo or wheel you do not know, and authorized_keys files changed recently.",
		Commands: []findings.Command{
			cmd("Accounts with a login shell or user id 0", "awk -F: '$3 == 0 || $3 >= 1000 { print $1, $3, $7 }' /etc/passwd"),
			cmd("Members of the admin groups", "getent group sudo wheel"),
			cmd("authorized_keys changed in the last 30 days", "sudo find /root /home -name authorized_keys -mtime -30 -ls"),
		}},
	{Kind: "process", Title: "Listening programs and programs run from temporary folders", Detail: "Ports you cannot explain, and programs running from /tmp, /var/tmp or /dev/shm, or whose file was deleted after start.",
		Commands: []findings.Command{
			cmd("Listening ports and their programs", "sudo ss -tulpn"),
			cmd("Programs running from temporary folders or deleted files", "sudo ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/|\\(deleted\\)'"),
			cmd("Established connections and their programs", "sudo ss -tnp state established"),
		}},
	{Kind: "file", Title: "Start-up entries and changed system files", Detail: "Cron jobs, systemd units and /etc/ld.so.preload changed recently, and system files that no longer match their package.",
		Commands: []findings.Command{
			cmd("Start-up entries changed in the last 30 days", "sudo find /etc/cron* /var/spool/cron /etc/systemd/system /etc/ld.so.preload -mtime -30 -ls 2>/dev/null"),
			cmd("Debian, Ubuntu: files that differ from their package", "sudo dpkg --verify"),
			cmd("Red Hat family: files that differ from their package", "sudo rpm -Va"),
		}},
}

func linuxChecks(software, cve string) findings.CompromiseCheck {
	return check("Linux", software, cve, linuxIndicators...)
}

func opensshChecks(software, cve string) findings.CompromiseCheck {
	ssh := findings.Indicator{Kind: "file", Title: "SSH server settings", Detail: "Settings nobody in your team changed: root sign-in or passwords allowed again, another keys file, a keys command.",
		Commands: []findings.Command{
			cmd("The settings sshd runs with", "sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|authorizedkeysfile|authorizedkeyscommand) '"),
			cmd("When the settings files changed", "ls -l --time-style=long-iso /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"),
		}}
	return check("Linux", software, cve, append([]findings.Indicator{ssh}, linuxIndicators...)...)
}

func webChecks(software, cve string) findings.CompromiseCheck {
	web := []findings.Indicator{
		{Kind: "web", Title: "New script files in the web folders", Detail: "Web shells are small .php, .jsp or .jspx files dropped where the web server serves files. Look for ones changed recently that no update explains.",
			Commands: []findings.Command{cmd("Script files changed in the last 30 days", "sudo find /var/www /srv /usr/share/nginx /opt -type f \\( -name '*.php' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.jspx' \\) -mtime -30 -ls 2>/dev/null")}},
		{Kind: "log", Title: "Web server log", Detail: "The access log is /var/log/apache2/access.log, /var/log/httpd/access_log, /var/log/nginx/access.log, or Tomcat's logs/localhost_access_log. Look for POST requests to script files you do not know, and long encoded parameters.",
			Commands: []findings.Command{cmd("POST requests to script files", "sudo grep -hE '\"POST [^\"]*\\.(php|phtml|jsp|jspx)' /var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log 2>/dev/null | tail -n 50")}},
		{Kind: "process", Title: "The web server running other programs", Detail: "Programs of the web server's user that are not the web server itself (a shell, curl, wget, a miner).",
			Commands: []findings.Command{cmd("Programs of the web server's user", "ps -eo user,pid,ppid,lstart,cmd | grep -E '^(www-data|apache|nginx|tomcat) ' | grep -vE 'apache2|httpd|nginx|java|php-fpm'")}},
		{Kind: "web", Title: "The application's own administrators and add-ons", Detail: "In the application's admin pages: administrators, API tokens and plugins or extensions nobody in your team added."},
	}
	return check("Web server on Linux", software, cve, append(web, linuxIndicators...)...)
}

func junosChecks(software, cve string) findings.CompromiseCheck {
	return check("Juniper Junos OS", software, cve,
		findings.Indicator{Kind: "log", Title: "Configuration changes and sign-ins", Detail: "Commits nobody in your team made, and sign-ins from addresses you do not know.",
			Commands: []findings.Command{
				cmd("Junos CLI: who committed and when", "show system commit"),
				cmd("Junos CLI: what the last commit changed", "show system rollback compare 1 0"),
				cmd("Junos CLI: sign-ins in the log", "show log messages | match \"UI_LOGIN_EVENT|UI_AUTH_EVENT|UI_COMMIT\""),
			}},
		findings.Indicator{Kind: "file", Title: "Accounts and files", Detail: "Login accounts nobody created, and files in /var/tmp or /tmp you did not put there.",
			Commands: []findings.Command{
				cmd("Junos CLI: login accounts", "show configuration system login | display set"),
				cmd("Junos CLI: who is signed in", "show system users"),
				cmd("Junos CLI: files in /var/tmp", "file list /var/tmp/ detail"),
			}},
		findings.Indicator{Kind: "process", Title: "Listening ports", Detail: "Ports the device listens on that its configuration does not explain.",
			Commands: []findings.Command{cmd("Junos CLI: listening ports", "show system connections | match LISTEN")}},
	)
}

func fortiosChecks(software, cve string) findings.CompromiseCheck {
	return check("Fortinet FortiOS", software, cve,
		findings.Indicator{Kind: "log", Title: "Admin sign-ins and configuration changes", Detail: "In Log & Report, System Events: admin sign-ins from addresses you do not know and configuration changes nobody in your team made.",
			Commands: []findings.Command{
				cmd("FortiGate CLI: admin accounts", "show system admin"),
				cmd("FortiGate CLI: local VPN users", "show user local"),
			}},
		findings.Indicator{Kind: "file", Title: "Policies and admin access", Detail: "Firewall policies that allow traffic nobody asked for, and admin access (set allowaccess) on interfaces facing the internet.",
			Commands: []findings.Command{
				cmd("FortiGate CLI: firewall policies", "show firewall policy"),
				cmd("FortiGate CLI: interfaces and their admin access", "show system interface"),
			}},
		findings.Indicator{Kind: "process", Title: "Unknown processes", Detail: "Process names that are not FortiOS daemons (sh, busybox, nc, unknown names).",
			Commands: []findings.Command{cmd("FortiGate CLI: top processes", "diagnose sys top 1 30")}},
	)
}

func routerosChecks(software, cve string) findings.CompromiseCheck {
	return check("MikroTik RouterOS", software, cve,
		findings.Indicator{Kind: "file", Title: "Users and sign-ins", Detail: "Users nobody created, and sign-ins from addresses you do not know.",
			Commands: []findings.Command{
				cmd("RouterOS: users", "/user print detail"),
				cmd("RouterOS: who is signed in", "/user active print"),
				cmd("RouterOS: sign-ins in the log", "/log print where message~\"logged in\""),
			}},
		findings.Indicator{Kind: "process", Title: "Scheduler, scripts and files", Detail: "Scheduled jobs and scripts nobody added (a classic way to keep a router), and .rsc or .npk files you did not upload.",
			Commands: []findings.Command{
				cmd("RouterOS: scheduled jobs", "/system scheduler print detail"),
				cmd("RouterOS: scripts", "/system script print detail"),
				cmd("RouterOS: files", "/file print"),
			}},
		findings.Indicator{Kind: "file", Title: "Proxy, DNS and redirects", Detail: "A SOCKS or web proxy turned on, DNS servers changed, or NAT rules that send traffic somewhere else: signs of a router used by someone else.",
			Commands: []findings.Command{
				cmd("RouterOS: SOCKS and web proxy", "/ip socks print\n/ip proxy print"),
				cmd("RouterOS: DNS and NAT", "/ip dns print\n/ip firewall nat print"),
				cmd("RouterOS: services and the networks they accept", "/ip service print"),
			}},
	)
}

func ciscoChecks(software, cve string) findings.CompromiseCheck {
	return check("Cisco IOS", software, cve,
		findings.Indicator{Kind: "file", Title: "Accounts and configuration changes", Detail: "Local users nobody created, and configuration changes nobody in your team made (the archive log only exists when archive logging is on).",
			Commands: []findings.Command{
				cmd("IOS: local users", "show running-config | include username"),
				cmd("IOS: who is signed in", "show users"),
				cmd("IOS: configuration change log", "show archive log config all"),
				cmd("IOS: sign-ins and changes in the log", "show logging | include LOGIN|CONFIG_I"),
			}},
		findings.Indicator{Kind: "web", Title: "Web interface and open ports", Detail: "The web interface turned on although you do not use it, and ports the device listens on that its configuration does not explain.",
			Commands: []findings.Command{
				cmd("IOS: web interface settings", "show running-config | include ip http"),
				cmd("IOS: listening ports", "show control-plane host open-ports"),
			}},
		findings.Indicator{Kind: "file", Title: "Files on the device", Detail: "Files you did not put on flash or bootflash.",
			Commands: []findings.Command{cmd("IOS: files", "dir flash:\ndir bootflash:")}},
	)
}

func netdeviceChecks(software, cve string) findings.CompromiseCheck {
	return check("Network device", software, cve,
		findings.Indicator{Kind: "file", Title: "Admin accounts", Detail: "In the device's admin pages: administrators and VPN users nobody in your team created, and API keys or SSH keys nobody added."},
		findings.Indicator{Kind: "log", Title: "Admin sign-ins and configuration changes", Detail: "In the device's system or audit log: sign-ins from addresses you do not know, and changes nobody in your team made. Compare the running configuration with your last backup."},
		findings.Indicator{Kind: "file", Title: "Firmware and files", Detail: "A firmware version you did not install, and files or scripts on the device you did not upload."},
	)
}

func genericChecks(software, cve string) findings.CompromiseCheck {
	return check("General", software, cve,
		findings.Indicator{Kind: "file", Title: "Accounts", Detail: "In the software's own user list: administrators, users, API keys and tokens nobody in your team created."},
		findings.Indicator{Kind: "log", Title: "Sign-ins and changes", Detail: "In the software's log: sign-ins at odd hours or from addresses you do not know, and settings changed by nobody in your team."},
		findings.Indicator{Kind: "file", Title: "Files", Detail: "Files in the software's folders changed recently that no update explains, and programs started from temporary folders."},
	)
}

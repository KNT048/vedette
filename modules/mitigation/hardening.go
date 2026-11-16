package mitigation

import (
	"context"
	"fmt"
	"hash/fnv"
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
		if r.Asset != nil && r.Asset.ID != "" {
			// The ports only sharpen the config: a failed read gives the all-inbound config, never a failed finding page (r1 L6).
			in.Open, _ = p.vendors.OpenPorts(ctx, r.Asset.ID)
		}
		in.Detected = map[string]bool{}
		var err error
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
	var tooMany bool
	h.Ports, h.PortsFrom, tooMany = portsFor(fam, in.Open)
	c := cfg{t: t, ports: h.Ports, from: h.PortsFrom, tooMany: tooMany, fam: fam, tag: tagOf(in.Row.CVE)}
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

// tagOf is the finding's part of every object name ("cve-2024-6387"), so two findings on one device never share a policy, rule or
// table and the undo of one never removes the other's (r1 H2). Only letters, digits and dashes.
func tagOf(cve string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(cve) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 || b.Len() > 20 {
		return "finding"
	}
	return b.String()
}

// target is the device address as the configs write it. Only a parsed IP (no zone) goes in (INV-4); anything else is "<IP>".
type target struct {
	ip   string // "10.0.0.5", or "<IP>"
	ok   bool
	v6   bool
	slug string // the address in object names: dots and colons as dashes ("device" without an address)
}

func targetOf(a *findings.AssetView) target {
	if a != nil {
		if addr, err := netip.ParseAddr(a.IP); err == nil && addr.Zone() == "" {
			addr = addr.Unmap()
			s := addr.String()
			return target{ip: s, ok: true, v6: addr.Is6(), slug: strings.NewReplacer(".", "-", ":", "-").Replace(s)}
		}
	}
	return target{ip: "<IP>", slug: "device"}
}

// portsFor picks the ports of the config: the open ports of the device of the family's kind, else (the device is the firewall
// itself) its usual admin ports, else none, which means every new inbound connection. tooMany: more than maxPorts were seen.
func portsFor(fam family, open []OpenPort) ([]findings.HardeningPort, string, bool) {
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
		return out, portsSeen, false
	case len(fam.usual) > 0:
		return slices.Clone(fam.usual), portsUsual, false
	}
	return nil, portsAll, len(out) > maxPorts
}

// serviceName keeps a service name only when it is plain (it is shown on the page, not put in a config).
func serviceName(s string) string {
	if len(s) > 40 {
		return ""
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-/_.", r) {
			return ""
		}
	}
	return s
}

// cfg is what every vendor's config is written from.
type cfg struct {
	t       target
	ports   []findings.HardeningPort
	from    string
	tooMany bool
	fam     family
	tag     string // tagOf the finding's CVE
}

// name is an object name of this finding and device: "vedette-cve-2024-6387-10-0-0-5" plus the suffix.
func (c cfg) name(suffix string) string {
	n := "vedette-" + c.tag + "-" + c.t.slug
	if suffix != "" {
		n += "-" + suffix
	}
	return n
}

// policyName is the FortiGate policy name: at most 35 characters, unique per finding and device (a hash of the device address,
// so IPv6 hosts of one /64 never share one, r1 L7).
func (c cfg) policyName() string {
	if n := fmt.Sprintf("vedette-%s-%08x", c.tag, fnv32(c.t.ip)); len(n) <= 35 {
		return n
	}
	return fmt.Sprintf("vedette-%08x", fnv32(c.t.ip)^fnv32(c.tag))
}

func fnv32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
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

// intro says what the config does and why these ports, in the same words for every vendor. It names the ports Vedette saw and
// their kind, never that the CVE's software answers there (r1 M4: no claim about the CVE, D-21).
func (c cfg) intro(self bool) string {
	var what string
	kind := c.fam.portsAre
	if kind == "" {
		kind = "services"
	}
	switch {
	case c.from == portsSeen:
		what = fmt.Sprintf("Vedette saw these %s open on %s: %s. This config lets only your admin network reach them; the rest of the device is unchanged.", kind, c.t.ip, c.portList())
	case c.from == portsUsual:
		what = fmt.Sprintf("Vedette has not seen which ports the admin pages of %s answer on, so this config uses their usual ports: %s. If you moved an admin page to another port, change it in the config.", c.t.ip, c.portList())
	case c.tooMany:
		what = fmt.Sprintf("Vedette saw more than %d %s open on %s, too many to list, so this config blocks every new connection to the device except from your admin network.", maxPorts, kind, c.t.ip)
	case c.fam.service == nil:
		what = fmt.Sprintf("Vedette has no port of this kind of software to single out on %s, so this config blocks every new connection to the device except from your admin network.", c.t.ip)
	default:
		what = fmt.Sprintf("Vedette has not seen %s open on %s, so this config blocks every new connection to the device except from your admin network.", kind, c.t.ip)
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

// scansNote is the impact on Vedette's own scans (r1 M6), in every side effect.
const scansNote = " Vedette's own scans stop reaching them as well: allow the Vedette box's address too, or the device looks closed to Vedette."

// sideEffect is stated before the person pastes (INV-4), with what stops for whom (r1 M6).
func (c cfg) sideEffect(self bool) string {
	switch {
	case self:
		return "Admins outside the admin network can no longer sign in to the firewall, and a VPN portal on one of these ports stops for everyone outside it. Check the admin network first, or you can lock yourself out." + scansNote
	case c.from == portsAll:
		return "Everything the device serves (websites, mail, shared folders, printing, remote desktop) stops for computers outside the admin network that reach it through this firewall." + scansNote
	}
	s := "Computers outside the admin network can no longer reach these ports of the device through this firewall."
	if c.fam.outage != "" {
		s += " " + c.fam.outage
	}
	return s + scansNote
}

// selfLockout is added where the config may run on the device the admin is signed in to (r1 M3).
const selfLockout = " Run on the device itself, the session you are in stays, but new sign-ins from outside the admin network fail: check the admin network first, or you can lock yourself out."

const verifyByHand = "From a computer outside the admin network, connect to the device on one of the ports: it must fail. From the admin network it must still work."

// fortigateGuide writes the FortiGate CLI: address objects, a service of the ports and a deny policy for everyone but the admin
// network; for a FortiGate's own CVE, local-in policies that keep its admin ports to the admin network. Every object but the
// shared vedette-admin-net carries the finding's tag (r1 H2).
func fortigateGuide(c cfg, self bool) findings.FirewallGuide {
	g := findings.FirewallGuide{Vendor: "fortigate", Label: "FortiGate", Intro: c.intro(self)}
	addr, addrSet, addrKey := "address", "subnet", "srcaddr"
	if c.t.v6 {
		addr, addrSet, addrKey = "address6", "ip6", "srcaddr6"
	}
	admin := fmt.Sprintf("config firewall %s\n    edit \"vedette-admin-net\"\n        set %s %s\n    next\nend", addr, addrSet, findings.AdminNetPlaceholder)
	svcName, service := c.name("ports"), "\"ALL\""
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
	pname := c.policyName()
	undoSvc := ""
	if svc != "" {
		undoSvc = fmt.Sprintf("\nconfig firewall service custom\n    delete %q\nend", svcName)
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
		code += fmt.Sprintf("config firewall %s\n    edit 0\n        set intf \"any\"\n        set srcaddr \"vedette-admin-net\"\n        set dstaddr \"all\"\n        set action accept\n        set service %s\n        set schedule \"always\"\n        set comments %q\n    next\n    edit 0\n        set intf \"any\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action deny\n        set service %s\n        set schedule \"always\"\n        set comments %q\n    next\nend", policy, service, pname, service, pname)
		g.Steps = []findings.CodeStep{{Title: "FortiGate CLI: allow the admin network to the admin ports, deny everyone else", Code: code,
			Note:       "Paste it in the CLI console (the >_ icon at the top of the FortiGate page) or over SSH. The first policy allows the admin network, the second denies the rest; FortiGate checks them in that order.",
			SideEffect: c.sideEffect(true)}}
		trust := "trusthost1"
		if c.t.v6 {
			trust = "ip6-trusthost1"
		}
		g.Alternative = &findings.Alternative{Title: "Or: trusted hosts on each admin account", Intro: "Trusted hosts limit where an admin account may sign in from. Set them on every admin account (show system admin lists them).",
			Steps: []findings.CodeStep{{Title: "FortiGate CLI: trusted host of the admin account", Code: fmt.Sprintf("config system admin\n    edit \"admin\"\n        set %s %s\n    next\nend", trust, findings.AdminNetPlaceholder),
				Note: "Replace admin with the account name; repeat for each account."}}}
		g.Verify = []findings.CodeStep{{Title: "Show the policies", Code: fmt.Sprintf("show firewall %s | grep -f %s", policy, pname), Note: verifyByHand}}
		g.Undo = []findings.CodeStep{{Title: "Delete the two policies and the port list", Code: fmt.Sprintf("config firewall %s\n    delete <ID>\n    delete <ID2>\nend", policy) + undoSvc,
			Note: "Use the IDs the show command above lists for the two policies of " + pname + ". vedette-admin-net stays: other Vedette policies may use it."}}
		return g
	}
	host := c.name("")
	hostSet := c.t.ip + "/32"
	if c.t.v6 {
		hostSet = c.t.ip + "/128"
	}
	dst := "dstaddr"
	if c.t.v6 {
		dst = "dstaddr6"
	}
	code := fmt.Sprintf("config firewall %s\n    edit \"vedette-admin-net\"\n        set %s %s\n    next\n    edit %q\n        set %s %s\n    next\nend\n", addr, addrSet, findings.AdminNetPlaceholder, host, addrSet, hostSet)
	if svc != "" {
		code += svc + "\n"
	}
	// match-vip: a deny policy applies to traffic that reaches the device through a Virtual IP (port forward) only with it, and it
	// was off by default before FortiOS 7.2.4 (r1 H1).
	code += fmt.Sprintf("config firewall policy\n    edit 0\n        set name %q\n        set srcintf \"any\"\n        set dstintf \"any\"\n        set %s \"vedette-admin-net\"\n        set %s-negate enable\n        set %s %q\n        set action deny\n        set service %s\n        set schedule \"always\"\n        set match-vip enable\n        set logtraffic all\n    next\nend",
		pname, addrKey, addrKey, dst, host, service)
	g.Steps = []findings.CodeStep{
		{Title: "FortiGate CLI: deny the device's ports to everyone but the admin network", Code: code,
			Note:       "Paste it in the CLI console (the >_ icon at the top of the FortiGate page) or over SSH. FortiGate adds the policy at the bottom of the list. match-vip makes it apply to traffic that reaches the device through a Virtual IP (port forward) too.",
			SideEffect: c.sideEffect(false)},
		{Title: "Move the policy to the top", Code: fmt.Sprintf("show firewall policy | grep -f %s\nconfig firewall policy\n    move <ID> before <FIRST-ID>\nend", pname),
			Note: "The show command prints the policy with its ID (edit <ID>). <FIRST-ID> is the top policy in Policy & Objects, Firewall Policy. You can also drag the policy to the top there. Until it is above your allow policies it does nothing; when the device is published through a Virtual IP, it must be above that VIP's allow policy."},
	}
	g.Verify = []findings.CodeStep{{Title: "Show the policy", Code: "show firewall policy | grep -f " + pname,
		Note: verifyByHand + " Blocked attempts appear in Log & Report, Forward Traffic."}}
	undo := "config firewall policy\n    delete <ID>\nend" + undoSvc + fmt.Sprintf("\nconfig firewall %s\n    delete %q\nend", addr, host)
	g.Undo = []findings.CodeStep{{Title: "Remove the policy and its objects", Code: undo, Note: "This removes only this finding's policy and objects. vedette-admin-net stays: other Vedette policies may use it."}}
	return g
}

// mikrotikGuide writes RouterOS: an address list of the admin network and drop rules for the device's ports (chain forward), or
// for a MikroTik's own CVE, the router's own ports (chain input). The rules go in front of the first static rule found at paste
// time (no rule numbers, which depend on the last print of the session, r1 M1), and nothing is added while the admin list is
// empty, so a failed list never turns into "drop everyone" (r1 M2).
func mikrotikGuide(c cfg, self bool) findings.FirewallGuide {
	g := findings.FirewallGuide{Vendor: "mikrotik", Label: "MikroTik", Intro: c.intro(self)}
	fw := "/ip firewall"
	if c.t.v6 {
		fw = "/ipv6 firewall"
	}
	id := strings.ToUpper(c.tag)
	comment := fmt.Sprintf("Vedette %s: restrict %s", id, c.t.ip)
	chain, dst := "forward", " dst-address="+c.t.ip
	if self {
		comment = fmt.Sprintf("Vedette %s: restrict admin access", id)
		chain, dst = "input", ""
	}
	var specs []string
	if len(c.ports) == 0 {
		specs = append(specs, " connection-state=new")
	}
	for _, p := range c.protos() {
		specs = append(specs, fmt.Sprintf(" protocol=%s dst-port=%s", p, strings.Join(c.byProto(p), ",")))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s address-list add list=vedette-admin address=%s comment=\"Vedette admin network\"\n{\n", fw, findings.AdminNetPlaceholder)
	fmt.Fprintf(&b, "    :if ([:len [%s address-list find list=vedette-admin]] = 0) do={ :error \"The vedette-admin list is empty: nothing was added.\" }\n", fw)
	fmt.Fprintf(&b, "    :local first [:pick [%s filter find where dynamic=no] 0]\n", fw)
	for _, s := range specs {
		rule := fmt.Sprintf("%s filter add chain=%s action=drop%s src-address-list=!vedette-admin%s comment=%q", fw, chain, dst, s, comment)
		fmt.Fprintf(&b, "    :if ([:len $first] > 0) do={ %s place-before=$first } else={ %s }\n", rule, rule)
	}
	b.WriteString("}")
	g.Steps = []findings.CodeStep{{Title: "RouterOS terminal: drop the ports for everyone but the admin network", Code: b.String(),
		Note:       "Paste it as a whole in a terminal (WinBox, New Terminal, or SSH). The rules go in front of your first filter rule; if the admin list could not be filled, nothing is added.",
		SideEffect: c.sideEffect(self)}}
	if self {
		g.Alternative = &findings.Alternative{Title: "Or: limit the router's services to the admin network", Intro: "RouterOS can limit each of its own services (WinBox, SSH, web, API) to a network.",
			Steps: []findings.CodeStep{{Title: "RouterOS terminal: services only from the admin network", Code: "/ip service set [find] address=" + findings.AdminNetPlaceholder,
				Note: "This replaces the address limits your services already have (/ip service print shows them). With an IPv6 network only, admin access over IPv4 stops."}}}
	}
	g.Verify = []findings.CodeStep{{Title: "Show the rules and their counters", Code: fmt.Sprintf("%s filter print stats where comment=%q", fw, comment),
		Note: "The rules must be listed; if they are not, the paste failed. " + verifyByHand}}
	g.Undo = []findings.CodeStep{{Title: "Remove the rules", Code: fmt.Sprintf("%s filter remove [find comment=%q]", fw, comment), Note: "This removes only this finding's rules. The vedette-admin address list stays: other Vedette rules may use it."}}
	return g
}

// genericGuide writes nftables (and iptables as the other way) for a Linux firewall or the Linux device itself: one table of
// its own per finding and device, so removing it touches nothing else. The input chain drops only new connections, so the
// session of the admin pasting it on the device itself survives (r1 M3).
func genericGuide(c cfg) findings.FirewallGuide {
	g := findings.FirewallGuide{Vendor: "generic", Label: "Linux (nftables)", Intro: c.intro(false) + " The same config works on a Linux firewall or router and on the device itself when it runs Linux."}
	fam, ipt := "ip", "iptables"
	if c.t.v6 {
		fam, ipt = "ip6", "ip6tables"
	}
	table := strings.ReplaceAll(c.name(""), "-", "_")
	match := fmt.Sprintf("%s daddr %s %s saddr != %s", fam, c.t.ip, fam, findings.AdminNetPlaceholder)
	rules := func(input bool) []string {
		ct := ""
		if input || len(c.ports) == 0 {
			ct = " ct state new"
		}
		if len(c.ports) == 0 {
			return []string{match + ct + " drop"}
		}
		var out []string
		for _, p := range c.protos() {
			out = append(out, fmt.Sprintf("%s %s dport { %s }%s drop", match, p, strings.Join(c.byProto(p), ", "), ct))
		}
		return out
	}
	chain := func(hook string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "    chain %s {\n        type filter hook %s priority 0; policy accept;\n", hook, hook)
		if hook == "input" {
			b.WriteString("        iifname \"lo\" accept\n")
		}
		for _, r := range rules(hook == "input") {
			b.WriteString("        " + r + "\n")
		}
		b.WriteString("    }\n")
		return b.String()
	}
	side := c.sideEffect(false) + selfLockout
	code := fmt.Sprintf("sudo nft -f - <<'EOF'\ntable inet %s {\n%s%s}\nEOF", table, chain("forward"), chain("input"))
	g.Steps = []findings.CodeStep{{Title: "nftables: drop the ports for everyone but the admin network", Code: code,
		Note:       "The forward chain filters traffic routed to the device, the input chain traffic to this machine when it is the device. The rules last until the next restart: to keep them, add the table to /etc/nftables.conf.",
		SideEffect: side}}
	var ins, del []string
	comment := "vedette-" + c.tag
	for _, chainName := range []string{"FORWARD", "INPUT"} {
		base := fmt.Sprintf("-d %s ! -s %s", c.t.ip, findings.AdminNetPlaceholder)
		ct := ""
		if chainName == "INPUT" || len(c.ports) == 0 {
			ct = " -m conntrack --ctstate NEW"
		}
		if chainName == "INPUT" {
			base += " ! -i lo"
		}
		var specs []string
		if len(c.ports) == 0 {
			specs = append(specs, base+ct)
		}
		for _, p := range c.protos() {
			specs = append(specs, fmt.Sprintf("%s -p %s -m multiport --dports %s%s", base, p, strings.Join(c.byProto(p), ","), ct))
		}
		for _, s := range specs {
			ins = append(ins, fmt.Sprintf("sudo %s -I %s %s -m comment --comment %s -j DROP", ipt, chainName, s, comment))
			del = append(del, fmt.Sprintf("sudo %s -D %s %s -m comment --comment %s -j DROP", ipt, chainName, s, comment))
		}
	}
	g.Alternative = &findings.Alternative{Title: "Or: iptables", Intro: "For a system that still uses iptables. The rules go first in each chain.",
		Steps: []findings.CodeStep{{Title: "iptables: drop the ports for everyone but the admin network", Code: strings.Join(ins, "\n"), SideEffect: side},
			{Title: "iptables: remove them again", Code: strings.Join(del, "\n")}}}
	g.Verify = []findings.CodeStep{{Title: "Show the table", Code: "sudo nft list table inet " + table, Note: verifyByHand}}
	g.Undo = []findings.CodeStep{{Title: "Remove the table", Code: "sudo nft delete table inet " + table, Note: "This removes only this finding's table."}}
	return g
}

// family is a software family the checks and the ports are written for. Only families the KEV entry names reliably.
type family struct {
	label    string
	self     string                   // the firewall guide that protects the device itself: "fortigate", "mikrotik" or ""
	usual    []findings.HardeningPort // the usual admin ports when the device is the firewall itself
	portsAre string                   // what the ports of the family are, in words ("remote access services")
	outage   string                   // what stops for users when those ports are restricted (r1 M6), "" when nothing more to say
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
		return family{label: "Fortinet FortiOS", self: "fortigate", service: isAdmin, checks: fortiosChecks, portsAre: "admin services",
			usual: []findings.HardeningPort{tcp(22, "ssh"), tcp(80, "http"), tcp(443, "https")}}
	case vendor == "mikrotik" && strings.Contains(product, "routeros"): //nolint:misspell // RouterOS is the product name
		return family{label: "MikroTik RouterOS", self: "mikrotik", service: isAdmin, checks: routerosChecks, portsAre: "admin services",
			usual: []findings.HardeningPort{tcp(21, "ftp"), tcp(22, "ssh"), tcp(23, "telnet"), tcp(80, "www"), tcp(443, "www-ssl"), tcp(8291, "winbox"), tcp(8728, "api"), tcp(8729, "api-ssl")}}
	case vendor == "juniper" && strings.Contains(product, "junos"):
		return family{label: "Juniper Junos OS", service: isAdmin, checks: junosChecks, portsAre: "admin services"}
	case vendor == "cisco" && (strings.HasPrefix(product, "ios") || strings.Contains(product, " ios")) && !strings.Contains(product, "xr"): // r1 L4: IOS XR differs
		return family{label: "Cisco IOS", service: isAdmin, checks: ciscoChecks, portsAre: "admin services"}
	case strings.Contains(product, "openssh"):
		return family{label: "OpenSSH", service: isSSH, checks: opensshChecks, portsAre: "SSH services"}
	case vendor == "microsoft" && hasAny(product, "exchange"):
		return family{label: "Windows web server (IIS)", service: isWeb, checks: iisChecks, portsAre: "web services",
			outage: "Outlook on the web and mail on phones (ActiveSync) stop for every user outside the admin network."}
	case vendor == "microsoft" && hasAny(product, "sharepoint", "internet information services", "iis") || hasAny(vp, "moveit"): // r1 M5: MOVEit runs on IIS
		return family{label: "Windows web server (IIS)", service: isWeb, checks: iisChecks, portsAre: "web services",
			outage: "The website or web application stops for its users outside the admin network."}
	case vendor == "microsoft" || hasAny(vp, "veeam", "solarwinds", "serv-u", "kaseya"): // r1 M5: Windows-only software
		return family{label: "Windows", service: isWindowsRemote, checks: windowsChecks, portsAre: "remote access services",
			outage: "Shared folders, remote desktop and remote management stop for other users outside the admin network."}
	case hasAny(vp, "http server", "httpd", "nginx", "tomcat", "struts", "weblogic", "confluence", "jira", "gitlab", "jenkins", "drupal",
		"wordpress", "joomla", "magento", "coldfusion", "ofbiz", "zimbra", "roundcube", "teamcity", "php", "atlassian"):
		return family{label: "Web server", service: isWeb, checks: webChecks, portsAre: "web services",
			outage: "The website or web application stops for its users outside the admin network: for a public site, restrict only its admin pages instead."}
	case hasAny(vendor, "linux", "canonical", "debian", "red hat", "redhat", "suse", "gnu", "sudo", "polkit") || hasAny(product, "linux", "kernel", "glibc", "polkit"):
		return family{label: "Linux", service: isLinuxRemote, checks: linuxChecks, portsAre: "remote access services"}
	case hasAny(vendor, "fortinet", "juniper", "cisco", "palo alto", "citrix", "ivanti", "pulse secure", "sonicwall", "f5", "zyxel", "d-link",
		"tp-link", "netgear", "draytek", "ubiquiti", "sophos", "watchguard", "array networks", "tenda", "totolink", "mikrotik", "check point") ||
		slices.Contains([]string{"firewall", "router", "switch", "ap"}, kind):
		return family{label: "Network device", service: isAdmin, checks: netdeviceChecks, portsAre: "admin services",
			outage: "A VPN portal on one of these ports stops for its users outside the admin network."}
	}
	return family{label: "General", checks: genericChecks}
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
			Commands: []findings.Command{cmd("Linux: script files changed in the last 30 days", "sudo find /var/www /srv /usr/share/nginx /opt -type f \\( -name '*.php' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.jspx' \\) -mtime -30 -ls 2>/dev/null"),
				cmd("Windows, PowerShell as administrator: script files under C:\\inetpub and the application folders changed in the last 30 days", "Get-ChildItem -Path C:\\inetpub, 'C:\\Program Files', 'C:\\ColdFusion*' -Recurse -Include *.aspx,*.ashx,*.jsp,*.jspx,*.cfm,*.php -File -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) | Format-Table LastWriteTime, FullName")}},
		{Kind: "log", Title: "Web server log", Detail: "On Windows, IIS logs are in C:\\inetpub\\logs\\LogFiles. On Linux the access log is /var/log/apache2/access.log, /var/log/httpd/access_log, /var/log/nginx/access.log, or Tomcat's logs/localhost_access_log. Look for POST requests to script files you do not know, and long encoded parameters.",
			Commands: []findings.Command{cmd("Linux: POST requests to script files", "sudo grep -hE '\"POST [^\"]*\\.(php|phtml|jsp|jspx)' /var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log 2>/dev/null | tail -n 50")}},
		{Kind: "process", Title: "The web server running other programs", Detail: "Programs of the web server's user that are not the web server itself (a shell, curl, wget, a miner).",
			Commands: []findings.Command{cmd("Linux: programs of the web server's user", "ps -eo user,pid,ppid,lstart,cmd | grep -E '^(www-data|apache|nginx|tomcat) ' | grep -vE 'apache2|httpd|nginx|java|php-fpm'")}},
		{Kind: "web", Title: "The application's own administrators and add-ons", Detail: "In the application's admin pages: administrators, API tokens and plugins or extensions nobody in your team added."},
	}
	// r1 M5: the OS is often unknown (ColdFusion, WebLogic run on both), so the commands name their OS.
	return check("Web server", software, cve, append(web, linuxIndicators...)...)
}

func junosChecks(software, cve string) findings.CompromiseCheck {
	return check("Juniper Junos OS", software, cve,
		findings.Indicator{Kind: "log", Title: "Configuration changes and sign-ins", Detail: "Commits nobody in your team made, and sign-ins from addresses you do not know.",
			Commands: []findings.Command{
				cmd("Junos CLI: who committed and when", "show system commit"),
				cmd("Junos CLI: what the last commit changed", "show system rollback 1 compare 0"),
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

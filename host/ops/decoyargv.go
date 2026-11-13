package ops

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The argv of the decoy commands (spec 18, "Tiến trình con"): fixed grammars for ip, with sysctl and
// nft reachable only as "ip netns exec vedette-hp <absolute path> <fixed words>" (they are never
// allowlisted on their own: run outside the namespace, nft would change the box's own firewall).
// Every value is a typed value rendered by a builder below, and validateIP re-checks the whole
// argv, so a value cannot escape its slot (there is no shell) nor start with "-".

const (
	hpNS         = "vedette-hp" // the namespace
	hpTableFirst = 100          // first per-IP routing table
	hpSysctlPath = "/usr/sbin/sysctl"
	hpNftPath    = "/usr/sbin/nft"
	linkNamePre  = "vdh"
	maxMgmtBits  = 30
	minMgmtBits  = 1
	// The ruleset (D-102 (4), D-121, D-466) is rendered from hp/decoys.json: renderRuleset in decoyports.go.
)

// hpSysctls are the settings of the namespace: the four of D-102 (3) and the hygiene of D-121
// (the namespace forwards nothing and has no IPv6), one "sysctl -w" call and one "sysctl -n" to read them back.
var hpSysctls = []string{
	"net.ipv4.conf.all.arp_ignore=1",
	"net.ipv4.conf.all.arp_announce=2",
	"net.ipv4.conf.all.rp_filter=2",
	"net.ipv4.ip_unprivileged_port_start=0",
	"net.ipv4.conf.all.forwarding=0",
	"net.ipv4.conf.default.forwarding=0",
	"net.ipv6.conf.all.disable_ipv6=1",
	"net.ipv6.conf.default.disable_ipv6=1",
}

var (
	linkNameRE = regexp.MustCompile(`^vdh[0-9a-f]{8}$`)
	macLowerRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
)

// linkName is vdh plus the eight hex digits of the IPv4 address.
func linkName(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("%s%02x%02x%02x%02x", linkNamePre, b[0], b[1], b[2], b[3])
}

func tableOK(t int) bool { return t >= hpTableFirst && t < hpTableFirst+32 }

// The builders. Each returns the argv after the program name.

func argvNetnsAdd() []string { return []string{"netns", "add", hpNS} }

func argvLinkAdd(parent, name, mac string) []string {
	return []string{"link", "add", "link", parent, "name", name, "address", mac, "type", "macvlan", "mode", "bridge"}
}

func argvLinkToNS(name string) []string { return []string{"link", "set", name, "netns", hpNS} }
func argvHostLinkDel(name string) []string {
	return []string{"link", "del", name}
}

func inNS(rest ...string) []string { return append([]string{"-n", hpNS}, rest...) }

func argvList() []string { return inNS("-j", "addr", "show") }
func argvAddrAdd(p netip.Prefix, name string) []string {
	return inNS("addr", "add", p.String(), "dev", name)
}
func argvUp(name string) []string        { return inNS("link", "set", name, "up") }
func argvNSLinkDel(name string) []string { return inNS("link", "del", name) }
func argvRouteSubnet(subnet netip.Prefix, name string, src netip.Addr, table int) []string {
	return inNS("route", "replace", subnet.String(), "dev", name, "src", src.String(), "table", strconv.Itoa(table))
}
func argvRouteDefault(gw netip.Addr, name string, table int) []string {
	return inNS("route", "replace", "default", "via", gw.String(), "dev", name, "table", strconv.Itoa(table))
}
func argvRouteFlush(table int) []string {
	return inNS("route", "flush", "table", strconv.Itoa(table))
}
func argvRule(verb string, src netip.Addr, table int) []string {
	return inNS("rule", verb, "from", src.String(), "lookup", strconv.Itoa(table))
}
func argvSysctl() []string {
	return append([]string{"netns", "exec", hpNS, hpSysctlPath, "-w"}, hpSysctls...)
}
func argvSysctlRead() []string {
	a := []string{"netns", "exec", hpNS, hpSysctlPath, "-n"}
	for _, kv := range hpSysctls {
		k, _, _ := strings.Cut(kv, "=")
		a = append(a, k)
	}
	return a
}
func argvLoUp() []string    { return inNS("link", "set", "lo", "up") }
func argvNftLoad() []string { return []string{"netns", "exec", hpNS, hpNftPath, "-f", "-"} }
func argvNftList() []string { return []string{"netns", "exec", hpNS, hpNftPath, "list", "ruleset"} }

// Value checks of the validator.

func plainIP4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s
}

func subnetOK(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4() && p.String() == s && p.Masked() == p && p.Bits() >= minMgmtBits && p.Bits() <= maxMgmtBits
}

func addrPrefixOK(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4() && p.String() == s && p.Bits() >= minMgmtBits && p.Bits() <= maxMgmtBits
}

func tableStr(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && strconv.Itoa(n) == s && tableOK(n)
}

// shape matches an argv against a template: a word starting with "%" names a value kind, every
// other word must be equal.
func shape(args []string, tmpl ...string) bool {
	if len(args) != len(tmpl) {
		return false
	}
	for i, w := range tmpl {
		if len(w) > 0 && w[0] == '%' {
			if !valueOK(w, args[i]) {
				return false
			}
			continue
		}
		if args[i] != w {
			return false
		}
	}
	return true
}

func valueOK(kind, v string) bool {
	switch kind {
	case "%iface":
		return validIfaceName(v)
	case "%name":
		return linkNameRE.MatchString(v)
	case "%mac":
		return macLowerRE.MatchString(v)
	case "%ip":
		return plainIP4(v)
	case "%addr":
		return addrPrefixOK(v)
	case "%subnet":
		return subnetOK(v)
	case "%table":
		return tableStr(v)
	}
	return false
}

// validateIP is the grammar of ip: the decoy commands and nothing else.
func validateIP(args []string) error {
	switch {
	case shape(args, "netns", "add", hpNS),
		shape(args, "link", "add", "link", "%iface", "name", "%name", "address", "%mac", "type", "macvlan", "mode", "bridge"),
		shape(args, "link", "set", "%name", "netns", hpNS),
		shape(args, "link", "del", "%name"),
		shape(args, "-n", hpNS, "-j", "addr", "show"),
		shape(args, "-n", hpNS, "addr", "add", "%addr", "dev", "%name"),
		shape(args, "-n", hpNS, "link", "set", "%name", "up"),
		shape(args, "-n", hpNS, "link", "set", "lo", "up"),
		shape(args, "-n", hpNS, "link", "del", "%name"),
		shape(args, "-n", hpNS, "route", "replace", "%subnet", "dev", "%name", "src", "%ip", "table", "%table"),
		shape(args, "-n", hpNS, "route", "replace", "default", "via", "%ip", "dev", "%name", "table", "%table"),
		shape(args, "-n", hpNS, "route", "flush", "table", "%table"),
		shape(args, "-n", hpNS, "rule", "add", "from", "%ip", "lookup", "%table"),
		shape(args, "-n", hpNS, "rule", "del", "from", "%ip", "lookup", "%table"),
		slices.Equal(args, argvSysctl()),
		slices.Equal(args, argvSysctlRead()),
		slices.Equal(args, argvNftLoad()),
		slices.Equal(args, argvNftList()):
		return nil
	}
	return errors.New("not one of the fixed ip command lines")
}

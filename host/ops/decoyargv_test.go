package ops

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	ip1    = netip.MustParseAddr("192.168.1.50")
	gw1    = netip.MustParseAddr("192.168.1.1")
	sub1   = netip.MustParsePrefix("192.168.1.0/24")
	macStr = "02:11:22:33:44:55"
)

func TestDecoyArgvBuildersAreExactlyTheSpecGrammar(t *testing.T) {
	t.Parallel()
	name := linkName(ip1)
	if name != "vdhc0a80132" {
		t.Fatalf("link name %q", name)
	}
	for _, c := range []struct {
		what string
		got  []string
		want string
	}{
		{"netns add", argvNetnsAdd(), "netns add vedette-hp"},
		{"link add", argvLinkAdd("eth0", name, macStr), "link add link eth0 name vdhc0a80132 address 02:11:22:33:44:55 type macvlan mode bridge"},
		{"to ns", argvLinkToNS(name), "link set vdhc0a80132 netns vedette-hp"},
		{"host del", argvHostLinkDel(name), "link del vdhc0a80132"},
		{"list", argvList(), "-n vedette-hp -j addr show"},
		{"addr", argvAddrAdd(netip.PrefixFrom(ip1, 24), name), "-n vedette-hp addr add 192.168.1.50/24 dev vdhc0a80132"},
		{"up", argvUp(name), "-n vedette-hp link set vdhc0a80132 up"},
		{"ns del", argvNSLinkDel(name), "-n vedette-hp link del vdhc0a80132"},
		{"subnet route", argvRouteSubnet(sub1, name, ip1, 100), "-n vedette-hp route replace 192.168.1.0/24 dev vdhc0a80132 src 192.168.1.50 table 100"},
		{"default route", argvRouteDefault(gw1, name, 131), "-n vedette-hp route replace default via 192.168.1.1 dev vdhc0a80132 table 131"},
		{"flush", argvRouteFlush(100), "-n vedette-hp route flush table 100"},
		{"rule add", argvRule("add", ip1, 100), "-n vedette-hp rule add from 192.168.1.50 lookup 100"},
		{"rule del", argvRule("del", ip1, 100), "-n vedette-hp rule del from 192.168.1.50 lookup 100"},
		{"sysctl", argvSysctl(), "netns exec vedette-hp /usr/sbin/sysctl -w net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2 net.ipv4.conf.all.rp_filter=2 net.ipv4.ip_unprivileged_port_start=0 net.ipv4.conf.all.forwarding=0 net.ipv4.conf.default.forwarding=0 net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1"},
		{"sysctl read", argvSysctlRead(), "netns exec vedette-hp /usr/sbin/sysctl -n net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_announce net.ipv4.conf.all.rp_filter net.ipv4.ip_unprivileged_port_start net.ipv4.conf.all.forwarding net.ipv4.conf.default.forwarding net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6"},
		{"lo up", argvLoUp(), "-n vedette-hp link set lo up"},
		{"nft load", argvNftLoad(), "netns exec vedette-hp /usr/sbin/nft -f -"},
		{"nft list", argvNftList(), "netns exec vedette-hp /usr/sbin/nft list ruleset"},
	} {
		if got := strings.Join(c.got, " "); got != c.want {
			t.Errorf("%s: %q, want %q", c.what, got, c.want)
		}
		if err := validateIP(c.got); err != nil {
			t.Errorf("%s: its own validator refuses it: %v", c.what, err)
		}
	}
}

func TestValidateIPRefusesEverythingElse(t *testing.T) {
	t.Parallel()
	name := linkName(ip1)
	good := argvLinkAdd("eth0", name, macStr)
	mut := func(i int, v string) []string { a := slices.Clone(good); a[i] = v; return a }
	bad := [][]string{
		nil, {}, {"netns"}, {"netns", "add"}, {"netns", "add", "other"}, {"netns", "del", "vedette-hp"}, {"netns", "exec", "vedette-hp", "/bin/sh", "-c", "id"},
		{"netns", "exec", "vedette-hp", "/usr/sbin/nft", "-f", "/etc/passwd"}, {"netns", "exec", "vedette-hp", "/usr/sbin/nft", "flush", "ruleset"},
		{"netns", "exec", "vedette-hp", "/usr/sbin/sysctl", "-w", "kernel.core_pattern=|/x"}, {"netns", "exec", "vedette-hp", "/usr/sbin/sysctl", "-w"},
		append(argvSysctl(), "net.ipv4.ip_forward=1"),
		{"netns", "exec", "-all", "/usr/sbin/nft", "list", "ruleset"},
		mut(3, "-eth0"), mut(3, "eth0 x"), mut(3, ""), mut(5, "eth0"), mut(5, "vdhC0A80132"), mut(5, "vdhc0a8013"), mut(5, "vdhc0a801322"), mut(5, "-n"),
		mut(7, "02:11:22:33:44:5"), mut(7, "02:11:22:33:44:AA"), mut(7, "02-11-22-33-44-55"), mut(7, "-x"),
		mut(9, "veth"), mut(11, "ipvlan"), append(slices.Clone(good), "extra"), good[:len(good)-1],
		{"link", "set", "eth0", "netns", "vedette-hp"}, {"link", "set", name, "netns", "1"}, {"link", "set", name, "netns", "vedette-hp", "up"},
		{"link", "del", "eth0"}, {"link", "del", "lo"}, {"link", "del", name, "x"},
		{"-n", "other", "-j", "addr", "show"}, {"-n", "vedette-hp", "-j", "addr", "show", "dev", "eth0"}, {"-n", "vedette-hp", "addr", "flush"},
		{"-n", "vedette-hp", "addr", "add", "192.168.1.50", "dev", name}, {"-n", "vedette-hp", "addr", "add", "192.168.1.50/0", "dev", name},
		{"-n", "vedette-hp", "addr", "add", "192.168.1.50/33", "dev", name}, {"-n", "vedette-hp", "addr", "add", "192.168.1.50/31", "dev", name},
		{"-n", "vedette-hp", "addr", "add", "::1/64", "dev", name}, {"-n", "vedette-hp", "addr", "add", "192.168.1.050/24", "dev", name},
		{"-n", "vedette-hp", "addr", "add", "192.168.1.50/24", "dev", "eth0"}, {"-n", "vedette-hp", "addr", "add", "-6", "192.168.1.50/24", "dev", name},
		{"-n", "vedette-hp", "link", "set", name, "down"}, {"-n", "vedette-hp", "link", "set", "lo", "down"}, {"-n", "vedette-hp", "link", "set", "eth0", "up"}, append(argvSysctlRead(), "net.ipv4.ip_forward"), {"-n", "vedette-hp", "link", "del", "lo"},
		{"-n", "vedette-hp", "route", "replace", "192.168.1.50/24", "dev", name, "src", "192.168.1.50", "table", "100"}, // host bits set
		{"-n", "vedette-hp", "route", "replace", "192.168.1.0/24", "dev", name, "src", "192.168.1.50", "table", "99"},
		{"-n", "vedette-hp", "route", "replace", "192.168.1.0/24", "dev", name, "src", "192.168.1.50", "table", "132"},
		{"-n", "vedette-hp", "route", "replace", "192.168.1.0/24", "dev", name, "src", "192.168.1.50", "table", "0100"},
		{"-n", "vedette-hp", "route", "replace", "192.168.1.0/24", "dev", name, "src", "192.168.1.50", "table", "main"},
		{"-n", "vedette-hp", "route", "replace", "0.0.0.0/0", "dev", name, "src", "192.168.1.50", "table", "100"},
		{"-n", "vedette-hp", "route", "replace", "default", "via", "192.168.1.1", "dev", name, "table", "255"},
		{"-n", "vedette-hp", "route", "replace", "default", "via", "-1", "dev", name, "table", "100"},
		{"-n", "vedette-hp", "route", "replace", "default", "dev", name, "table", "100"},
		{"-n", "vedette-hp", "route", "add", "default", "via", "192.168.1.1", "dev", name, "table", "100"},
		{"-n", "vedette-hp", "route", "flush", "table", "main"}, {"-n", "vedette-hp", "route", "flush", "all"}, {"-n", "vedette-hp", "route", "flush"},
		{"-n", "vedette-hp", "rule", "flush"}, {"-n", "vedette-hp", "rule", "add", "from", "0.0.0.0/0", "lookup", "100"},
		{"-n", "vedette-hp", "rule", "add", "from", "192.168.1.50", "lookup", "main"}, {"-n", "vedette-hp", "rule", "add", "from", "192.168.1.50", "table", "100"},
		{"-n", "vedette-hp", "rule", "add", "from", "192.168.1.50", "lookup", "100", "prio", "0"},
		{"-b", "-"}, {"-batch", "/etc/passwd"}, {"-force", "link", "del", name}, {"-n", "vedette-hp", "-force", "link", "del", name},
		{"addr", "show"}, {"route", "show"}, {"monitor"}, {"-n", "vedette-hp", "monitor"}, {"-n", "vedette-hp", "netns", "exec", "x"},
		{"-n", "vedette-hp", "exec", "x"}, {"-n", "vedette-hp", "-n", "vedette-hp", "-j", "addr", "show"},
	}
	for _, a := range bad {
		if err := validateIP(a); err == nil {
			t.Errorf("accepted: %q", a)
		}
	}
}

func TestMgmtPrefixBoundsOfTheGrammar(t *testing.T) {
	t.Parallel()
	for bits, want := range map[int]bool{0: false, 1: true, 8: true, 24: true, 30: true, 31: false, 32: false} {
		got := addrPrefixOK(netip.PrefixFrom(ip1, bits).String())
		if got != want {
			t.Errorf("/%d: %v, want %v", bits, got, want)
		}
	}
}

var slotRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:./_@-]*$`)

// templates are the shapes the validator knows, with the value slots as "%kind".
var templates = [][]string{
	{"link", "add", "link", "%iface", "name", "%name", "address", "%mac", "type", "macvlan", "mode", "bridge"},
	{"link", "set", "%name", "netns", hpNS},
	{"link", "del", "%name"},
	{"-n", hpNS, "addr", "add", "%addr", "dev", "%name"},
	{"-n", hpNS, "link", "set", "%name", "up"},
	{"-n", hpNS, "link", "del", "%name"},
	{"-n", hpNS, "route", "replace", "%subnet", "dev", "%name", "src", "%ip", "table", "%table"},
	{"-n", hpNS, "route", "replace", "default", "via", "%ip", "dev", "%name", "table", "%table"},
	{"-n", hpNS, "route", "flush", "table", "%table"},
	{"-n", hpNS, "rule", "add", "from", "%ip", "lookup", "%table"},
	{"-n", hpNS, "rule", "del", "from", "%ip", "lookup", "%table"},
}

// FuzzValidateIP: whatever a value slot holds, an argv the validator accepts has in every slot a
// plain word that does not start with "-" (it can never be read as an option) and has no space,
// NUL, quote or shell character; and the fixed words stay where the grammar puts them.
func FuzzValidateIP(f *testing.F) {
	for _, s := range []string{"eth0", "vdhc0a80132", "02:11:22:33:44:55", "192.168.1.50", "192.168.1.0/24", "192.168.1.50/24", "100", "-1", "-n", "a b", "x\x00y", "$(id)", ";id", "1.2.3.4/8\n", "../x", ""} {
		f.Add(s, 0)
		f.Add(s, 6)
		f.Add(s, 9)
	}
	f.Fuzz(func(t *testing.T, v string, ti int) {
		if ti < 0 {
			ti = -ti
		}
		tmpl := templates[ti%len(templates)]
		for slot := range tmpl {
			if !strings.HasPrefix(tmpl[slot], "%") {
				continue
			}
			args := slices.Clone(tmpl)
			for i, w := range args {
				if strings.HasPrefix(w, "%") {
					args[i] = goodValue(w) // every slot a good value, then one of them the fuzzed one
				}
			}
			args[slot] = v
			if validateIP(args) != nil {
				continue
			}
			for i, w := range tmpl {
				if strings.HasPrefix(w, "%") {
					if !slotRE.MatchString(args[i]) {
						t.Fatalf("accepted a slot %q in %q", args[i], args)
					}
				} else if args[i] != w {
					t.Fatalf("a fixed word moved: %q", args)
				}
			}
		}
	})
}

func goodValue(kind string) string {
	switch kind {
	case "%iface":
		return "eth0"
	case "%name":
		return "vdhc0a80132"
	case "%mac":
		return macStr
	case "%ip":
		return "192.168.1.50"
	case "%addr":
		return "192.168.1.50/24"
	case "%subnet":
		return "192.168.1.0/24"
	}
	return "100"
}

// FuzzDecoyBuilders: from any text that parses as a decoy address, every command line the builders
// make passes the validator, and no word starts with "-" except the fixed options.
func FuzzDecoyBuilders(f *testing.F) {
	for _, s := range []string{"192.168.1.50", "10.0.0.1", "255.255.255.254", "1.2.3.4", "-1.2.3.4", "1.2.3.4 ", "::1", "0.0.0.0"} {
		f.Add(s, uint8(24), uint8(0))
	}
	f.Fuzz(func(t *testing.T, s string, bits, tbl uint8) {
		ip, err := parseDecoyIP(s)
		if err != nil {
			return
		}
		b := int(bits)%maxMgmtBits + 1
		table := hpTableFirst + int(tbl)%32
		pfx := netip.PrefixFrom(ip, b)
		name := linkName(ip)
		key := make([]byte, 32)
		mac := deriveMAC(key, ip, nil).String()
		for _, a := range [][]string{
			argvLinkAdd("eth0", name, mac), argvLinkToNS(name), argvHostLinkDel(name), argvAddrAdd(pfx, name), argvUp(name), argvNSLinkDel(name),
			argvRouteSubnet(pfx.Masked(), name, ip, table), argvRouteDefault(ip, name, table), argvRouteFlush(table),
			argvRule("add", ip, table), argvRule("del", ip, table),
		} {
			if err := validateIP(a); err != nil {
				t.Fatalf("the builders made %q and the validator refuses it: %v", a, err)
			}
			for i, w := range a {
				if strings.HasPrefix(w, "-") && (i >= 3 || (w != "-n" && w != "-j")) {
					t.Fatalf("a word starts with a dash: %q", a)
				}
			}
		}
	})
}

func TestTheRulesetTextIsTheOneTheEffectCheckAccepts(t *testing.T) {
	t.Parallel()
	// The text sent to nft, as nft prints it back (quoted interface, priority name), must pass the check.
	printed := strings.NewReplacer("priority 0", "priority filter", "oif lo", `oif "lo"`, "flush ruleset\n", "").Replace(hpRulesetText)
	if !hasEgressDrop([]byte(printed)) {
		t.Fatalf("the ruleset the host loads is not what its own check accepts:\n%s", printed)
	}
	lines := strings.Split(hpRulesetText, "\n")
	acc, lo, drop := -1, -1, -1
	for i, l := range lines {
		switch strings.TrimSpace(l) {
		case "ct state established,related accept":
			acc = i
		case "oif lo accept":
			lo = i
		case "ct state new drop":
			drop = i
		}
	}
	if acc < 0 || acc >= lo || lo >= drop {
		t.Fatalf("order: established %d, lo %d, drop %d", acc, lo, drop)
	}
	if !strings.HasPrefix(hpRulesetText, "flush ruleset\n") || !strings.Contains(hpRulesetText, "hook forward priority 0; policy drop;") {
		t.Fatal("the load must replace what was there and drop forwarding")
	}
}

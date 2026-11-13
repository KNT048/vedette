package ops

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// D-466: the per-address ports of the decoys in the namespace's input chain.

func dp(proto string, port int) api.DecoyPort { return api.DecoyPort{Proto: proto, Port: port} }

func ports(p ...any) *[]api.DecoyPort {
	out := []api.DecoyPort{}
	for i := 0; i+1 < len(p); i += 2 {
		out = append(out, dp(p[i].(string), p[i+1].(int)))
	}
	return &out
}

func entries() []decoyEntry {
	return []decoyEntry{
		{IP: "192.168.1.100", MAC: "02:00:00:00:00:01", Table: 100, Iface: "eth0", Ports: ports("tcp", 445, "tcp", 3389)},
		{IP: "192.168.1.101", MAC: "02:00:00:00:00:02", Table: 101, Iface: "eth0"},                 // an older core's decoy: every port
		{IP: "192.168.1.102", MAC: "02:00:00:00:00:03", Table: 102, Iface: "eth0", Ports: ports()}, // nothing open
	}
}

// printed is what nft prints for a loaded ruleset: no flush line, priority by name, quoted interfaces.
func printed(text string) string {
	return strings.NewReplacer("flush ruleset\n", "", "priority 0", "priority filter", "oif lo", `oif "lo"`, "iif lo", `iif "lo"`).Replace(text)
}

func TestCanonicalPorts(t *testing.T) {
	t.Parallel()
	got, err := canonicalPorts([]api.DecoyPort{dp("udp", 69), dp("tcp", 3389), dp("tcp", 22)})
	if err != nil || !slices.Equal(got, []api.DecoyPort{dp("tcp", 22), dp("tcp", 3389), dp("udp", 69)}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := canonicalPorts(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	many := make([]api.DecoyPort, api.MaxDecoyPorts+1)
	for i := range many {
		many[i] = api.DecoyPort{Proto: "tcp", Port: i + 1}
	}
	for name, in := range map[string][]api.DecoyPort{
		"proto":     {dp("sctp", 22)},
		"upper":     {dp("TCP", 22)},
		"port 0":    {dp("tcp", 0)},
		"port big":  {dp("tcp", 65536)},
		"negative":  {dp("udp", -1)},
		"duplicate": {dp("tcp", 22), dp("tcp", 22)},
		"too many":  many,
	} {
		if _, err := canonicalPorts(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRenderRulesetPutsEachAddressInItsSet(t *testing.T) {
	t.Parallel()
	text := renderRuleset(entries())
	for _, want := range []string{
		"flush ruleset\ntable inet vedette_hp {\n",
		"\tset open {\n\t\ttype ipv4_addr\n\t\telements = { 192.168.1.101 }\n\t}\n",
		"\tset allow {\n\t\ttype ipv4_addr . inet_proto . inet_service\n\t\telements = { 192.168.1.100 . tcp . 3389, 192.168.1.100 . tcp . 445 }\n\t}\n",
		"\tset touched {\n\t\ttype ipv4_addr . ipv4_addr\n\t\tsize 1024\n\t\tflags dynamic,timeout\n\t\ttimeout 120s\n\t}\n",
		"\t\ttype filter hook input priority 0; policy accept;\n\t\tiif lo accept\n\t\tmeta l4proto { tcp, udp } meta pkttype host ct state new add @touched { ip saddr . ip daddr }\n\t\tct state established,related accept\n\t\tip daddr @open accept\n" +
			"\t\tip daddr . meta l4proto . th dport @allow accept\n\t\tmeta l4proto tcp reject with tcp reset\n\t\tmeta l4proto udp reject\n",
		"\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t\tct state established,related accept\n\t\toif lo accept\n\t\tct state new drop\n\t}\n",
		"\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n}\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the ruleset lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "192.168.1.102") {
		t.Error("an address with an empty allow-list is in a set: it must answer no port")
	}
	// No decoy: two empty sets, no elements line (nft refuses "elements = { }").
	if e := renderRuleset(nil); strings.Contains(e, "elements") {
		t.Fatalf("empty sets carry elements:\n%s", e)
	}
	if !rulesetIs([]byte(printed(text)), entries()) {
		t.Fatalf("the host does not accept its own ruleset as nft prints it:\n%s", printed(text))
	}
}

// realListing is the shape nft 1.x prints: long element lists wrap over lines, protocols may come as numbers.
const realListing = `table inet other {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}
table inet vedette_hp {
	set open {
		type ipv4_addr
		elements = { 192.168.1.101 }
	}

	set allow {
		type ipv4_addr . inet_proto . inet_service
		elements = { 192.168.1.100 . tcp . 445,
			     192.168.1.100 . 6 . 3389 }
	}

	set touched {
		type ipv4_addr . ipv4_addr
		size 1024
		flags dynamic,timeout
		timeout 2m
		elements = { 192.168.1.7 . 192.168.1.100 timeout 2m expires 1m51s,
			     192.168.1.7 . 192.168.1.101 timeout 2m expires 1m52s }
	}

	chain input {
		type filter hook input priority filter; policy accept;
		iif "lo" accept
		meta l4proto { tcp, udp } pkttype host ct state new add @touched { ip saddr . ip daddr }
		ct state established,related accept
		ip daddr @open accept
		ip daddr . meta l4proto . th dport @allow accept
		meta l4proto tcp reject with tcp reset
		meta l4proto udp reject with icmpx port-unreachable
	}

	chain output {
		type filter hook output priority filter; policy accept;
		ct state established,related accept
		oif "lo" accept
		ct state new drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`

func TestRulesetIsReadsTheRealListing(t *testing.T) {
	t.Parallel()
	ours := realListing[strings.Index(realListing, "table inet vedette_hp"):]
	if !rulesetIs([]byte(ours), entries()) {
		t.Fatal("the real listing (wrapped elements, numeric protocol) is not recognised")
	}
	if rulesetIs([]byte(realListing), entries()) {
		t.Fatal("a namespace ruleset with another table was taken for the one the host loaded")
	}
	if !hasEgressDrop([]byte(realListing)) {
		t.Fatal("the egress part of a table with sets is not recognised")
	}
	for name, in := range map[string]string{
		"missing element":   strings.Replace(ours, "192.168.1.100 . tcp . 445,\n\t\t\t     ", "", 1),
		"extra element":     strings.Replace(ours, "192.168.1.101 }", "192.168.1.101, 192.168.1.102 }", 1),
		"other port":        strings.Replace(ours, ". 6 . 3389", ". 6 . 3390", 1),
		"udp for tcp":       strings.Replace(ours, ". tcp . 445", ". udp . 445", 1),
		"service name":      strings.Replace(ours, ". tcp . 445", ". tcp . microsoft-ds", 1),
		"open has allowed":  strings.Replace(ours, "{ 192.168.1.101 }", "{ 192.168.1.100, 192.168.1.101 }", 1),
		"no input chain":    ours[:strings.Index(ours, "\tchain input")] + ours[strings.Index(ours, "\tchain output"):],
		"input accepts all": strings.Replace(ours, "\t\tiif \"lo\" accept\n", "\t\taccept\n\t\tiif \"lo\" accept\n", 1),
		"no tcp reject":     strings.Replace(ours, "\t\tmeta l4proto tcp reject with tcp reset\n", "", 1),
		"input policy drop": strings.Replace(ours, "hook input priority filter; policy accept;\n\t\tiif", "hook input priority filter; policy drop;\n\t\tiif", 1),
		"set flags":         strings.Replace(ours, "\t\ttype ipv4_addr\n", "\t\ttype ipv4_addr\n\t\tflags interval\n", 1),
		"set type":          strings.Replace(ours, "type ipv4_addr\n", "type ipv4_addr . inet_service\n", 1),
		"extra chain":       strings.Replace(ours, "\tchain forward {", "\tchain prerouting {\n\t\ttype filter hook prerouting priority filter; policy accept;\n\t}\n\tchain forward {", 1),
		"extra set":         strings.Replace(ours, "\tset allow {", "\tset more {\n\t\ttype ipv4_addr\n\t}\n\tset allow {", 1),
		"no touched set":    ours[:strings.Index(ours, "\tset touched")] + ours[strings.Index(ours, "\tchain input"):],
		"touched not dyn":   strings.Replace(ours, "flags dynamic,timeout", "flags timeout", 1),
		"touched other":     strings.Replace(ours, "\t\tsize 1024\n", "\t\tsize 1024\n\t\tpolicy memory\n", 1),
		"no touch rule":     strings.Replace(ours, "\t\tmeta l4proto { tcp, udp } pkttype host ct state new add @touched { ip saddr . ip daddr }\n", "", 1),
		"touch rule late":   strings.Replace(strings.Replace(ours, "\t\tmeta l4proto { tcp, udp } pkttype host ct state new add @touched { ip saddr . ip daddr }\n", "", 1), "\t\tmeta l4proto tcp reject", "\t\tmeta l4proto { tcp, udp } pkttype host ct state new add @touched { ip saddr . ip daddr }\n\t\tmeta l4proto tcp reject", 1),
		"dormant":           strings.Replace(ours, "table inet vedette_hp {\n", "table inet vedette_hp {\n\tflags dormant\n", 1),
		"egress gone":       strings.Replace(ours, "\t\tct state new drop\n", "", 1),
	} {
		if rulesetIs([]byte(in), entries()) {
			t.Errorf("%s accepted", name)
		}
	}
	// A set's closing brace does not end the table: the egress part after it is still read.
	setsFirst := "table inet vedette_hp {\n\tset open {\n\t\ttype ipv4_addr\n\t}\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n" +
		"\t\tct state established,related accept\n\t\toif \"lo\" accept\n\t\tct state new drop\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n"
	if !hasEgressDrop([]byte(setsFirst)) {
		t.Fatal("a set before the chains hides the egress drop")
	}
}

func TestTheStateFileKeepsTheAllowList(t *testing.T) {
	t.Parallel()
	good := `{"decoys":[{"ip":"192.168.1.100","mac":"02:00:00:00:00:01","table":100,"iface":"eth0","ports":[{"proto":"tcp","port":22},{"proto":"tcp","port":445}]},` +
		`{"ip":"192.168.1.101","mac":"02:00:00:00:00:02","table":101,"iface":"eth0"},{"ip":"192.168.1.102","mac":"02:00:00:00:00:03","table":102,"iface":"eth0","ports":[]}]}`
	list, err := parseDecoys([]byte(good))
	if err != nil || len(list) != 3 || list[0].Ports == nil || len(*list[0].Ports) != 2 || list[1].Ports != nil || list[2].Ports == nil || len(*list[2].Ports) != 0 {
		t.Fatalf("%+v %v", list, err)
	}
	for name, in := range map[string]string{
		"unsorted":  strings.Replace(good, `{"proto":"tcp","port":22},{"proto":"tcp","port":445}`, `{"proto":"tcp","port":445},{"proto":"tcp","port":22}`, 1),
		"duplicate": strings.Replace(good, `{"proto":"tcp","port":445}`, `{"proto":"tcp","port":22}`, 1),
		"bad proto": strings.Replace(good, `"proto":"tcp","port":22`, `"proto":"icmp","port":22`, 1),
		"port 0":    strings.Replace(good, `"port":22`, `"port":0`, 1),
		"unknown":   strings.Replace(good, `"proto":"tcp","port":22`, `"proto":"tcp","port":22,"x":1`, 1),
		"not list":  strings.Replace(good, `"ports":[]`, `"ports":"all"`, 1),
	} {
		if _, err := parseDecoys([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSameSets(t *testing.T) {
	t.Parallel()
	a := entries()
	b := entries()
	b[0].Iface = "eth1" // a rebuilt link on another card: same ruleset
	if !sameSets(a, b) {
		t.Fatal("the card changes the sets")
	}
	b[0].Ports = ports("tcp", 445)
	if sameSets(a, b) {
		t.Fatal("other ports, same sets")
	}
	if !sameEntry(a[0], entries()[0]) || sameEntry(a[0], b[0]) || sameEntry(a[1], a[2]) {
		t.Fatal("sameEntry")
	}
}

// kien's N100 rule (B2): the decoys never touch the box's network. The ruleset the host loads names one table, inet
// vedette_hp; it is loaded and listed only inside the namespace vedette-hp (its "flush ruleset" empties that namespace's
// ruleset, never the box's own firewall); every address in it is a decoy's; it names no interface but lo and hooks only
// input, output and forward of that namespace (no NAT, no prerouting). The effect check refuses a listing with any other
// table in the namespace.
func TestTheRulesetTouchesOnlyItsOwnTableAndTheDecoys(t *testing.T) {
	t.Parallel()
	list := entries()
	text := renderRuleset(list)
	decoys := map[string]bool{}
	for _, e := range list {
		decoys[e.IP] = true
	}
	tables := regexp.MustCompile(`(?m)^\s*table\s+(.*?)\s*\{`).FindAllStringSubmatch(text, -1)
	if len(tables) != 1 || tables[0][1] != "inet vedette_hp" {
		t.Fatalf("tables in the ruleset: %q", tables)
	}
	for _, l := range strings.Split(text, "\n") {
		if top := strings.TrimSpace(l); l == top && top != "" && top != "}" && top != "flush ruleset" && top != "table inet vedette_hp {" {
			t.Errorf("a top-level statement other than the flush and the table: %q", top)
		}
	}
	for _, a := range regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`).FindAllString(text, -1) {
		if !decoys[a] {
			t.Errorf("the ruleset names %s, which is no decoy", a)
		}
	}
	for _, w := range []string{"iifname", "oifname", "eth0", "nat", "prerouting", "postrouting", "ingress", "masquerade", "dnat", "snat", "redirect"} {
		if strings.Contains(text, w) {
			t.Errorf("the ruleset mentions %q", w)
		}
	}
	if !regexp.MustCompile(`(?m)^\s*iif lo accept$`).MatchString(text) || strings.Count(text, " lo ") != 2 {
		t.Errorf("the only interface named must be lo:\n%s", text)
	}
	for _, a := range [][]string{argvNftLoad(), argvNftList()} {
		if !slices.Equal(a[:3], []string{"netns", "exec", hpNS}) || hpNS != "vedette-hp" {
			t.Errorf("nft runs outside the namespace: %q", a)
		}
	}
	listed := printed(text)
	if !rulesetIs([]byte(listed), list) {
		t.Fatalf("the effect check refuses the ruleset the host loads:\n%s", listed)
	}
	other := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n" + listed
	if rulesetIs([]byte(other), list) {
		t.Fatal("the effect check accepted a namespace ruleset with a table the host did not write")
	}
}

// B2 review H1: the effect check accepts what the real nft 1.1 of Ubuntu 26.04 prints for the ruleset the host loads (captured
// in the lab VM, `ip netns exec vedette-hp nft list ruleset`, 2026-11-13: two Trap IPs, a File server and a NAS), and refuses
// the same listing for any other decoy list.
func TestRulesetIsAcceptsTheRealUbuntu2604Listing(t *testing.T) {
	t.Parallel()
	listed, err := os.ReadFile("testdata/nft-list-ruleset-vedette-hp-ubuntu2604.txt")
	if err != nil {
		t.Fatal(err)
	}
	list := []decoyEntry{
		{IP: "192.168.18.240", MAC: "f8:bc:12:00:00:01", Table: 100, Iface: "enp0s2", Ports: ports("tcp", 445, "tcp", 3389)},
		{IP: "192.168.18.241", MAC: "00:11:32:00:00:01", Table: 101, Iface: "enp0s2", Ports: ports("tcp", 80, "tcp", 445)},
	}
	// The capture predates the touched set (M2): it is refused now, so the host loads the new ruleset over it; its egress part
	// is still read. With the set and the rule printed in, the rest of it is what nft 1.1 prints.
	if rulesetIs(listed, list) || !hasEgressDrop(listed) {
		t.Fatalf("the pre-M2 listing: rulesetIs %v, egress %v", rulesetIs(listed, list), hasEgressDrop(listed))
	}
	listed = []byte(strings.Replace(strings.Replace(string(listed), "\tchain input {", "\tset touched {\n\t\ttype ipv4_addr . ipv4_addr\n\t\tsize 1024\n\t\tflags dynamic,timeout\n\t\ttimeout 2m\n\t}\n\n\tchain input {", 1),
		"\t\tiif \"lo\" accept\n", "\t\tiif \"lo\" accept\n\t\tmeta l4proto { tcp, udp } pkttype host ct state new add @touched { ip saddr . ip daddr }\n", 1))
	if !rulesetIs(listed, list) {
		t.Fatalf("the effect check refuses the real listing with the touched set:\n%s", listed)
	}
	if rulesetIs(listed, list[:1]) || rulesetIs(listed, append(slices.Clone(list), decoyEntry{IP: "192.168.18.242", MAC: "00:50:56:00:00:01", Table: 102, Iface: "enp0s2", Ports: ports("tcp", 22)})) {
		t.Fatal("the real listing was taken for another decoy list")
	}
}

// B2 review L1, H1: the set touched must have the size and timeout the host loads (printed 2m or 120s) and only the flags dynamic
// and timeout; the touch rule is accepted in the forms nft may print (implicit nfproto, numbers, bare pkttype); the ruleset
// without the set (the fallback of loadProven) is its own mode.
func TestTouchedSetAndRuleForms(t *testing.T) {
	t.Parallel()
	list := entries()
	ours := printed(renderRuleset(list))
	if !rulesetIs([]byte(ours), list) {
		t.Fatalf("the host does not accept its own ruleset:\n%s", ours)
	}
	for name, in := range map[string]string{
		"size":    strings.Replace(ours, "size 1024", "size 65535", 1),
		"timeout": strings.Replace(ours, "timeout 120s", "timeout 1h", 1),
		"flags":   strings.Replace(ours, "flags dynamic,timeout", "flags dynamic,timeout,interval", 1),
	} {
		if rulesetIs([]byte(in), list) {
			t.Errorf("%s accepted", name)
		}
	}
	for _, form := range []string{
		"meta nfproto ipv4 meta l4proto { 6, 17 } pkttype host ct state new add @touched { ip saddr . ip daddr }",
		"meta l4proto { tcp, udp } pkttype host ct state new add @touched { ip saddr . ip daddr }",
	} {
		in := strings.Replace(ours, "meta l4proto { tcp, udp } meta pkttype host ct state new add @touched { ip saddr . ip daddr }", form, 1)
		if !rulesetIs([]byte(in), list) {
			t.Errorf("form %q refused", form)
		}
	}
	plain := printed(renderRulesetMode(list, false))
	if strings.Contains(plain, "touched") || !rulesetIsMode([]byte(plain), list, false) || rulesetIsMode([]byte(plain), list, true) || rulesetIsMode([]byte(ours), list, false) {
		t.Fatalf("the modes with and without the set are not told apart:\n%s", plain)
	}
}

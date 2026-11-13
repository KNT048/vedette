package ops

import (
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
		"\t\ttype filter hook input priority 0; policy accept;\n\t\tiif lo accept\n\t\tct state established,related accept\n\t\tip daddr @open accept\n" +
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

	chain input {
		type filter hook input priority filter; policy accept;
		iif "lo" accept
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
	if !rulesetIs([]byte(realListing), entries()) {
		t.Fatal("the real listing (wrapped elements, numeric protocol) is not recognised")
	}
	if !hasEgressDrop([]byte(realListing)) {
		t.Fatal("the egress part of a table with sets is not recognised")
	}
	for name, in := range map[string]string{
		"missing element":   strings.Replace(realListing, "192.168.1.100 . tcp . 445,\n\t\t\t     ", "", 1),
		"extra element":     strings.Replace(realListing, "192.168.1.101 }", "192.168.1.101, 192.168.1.102 }", 1),
		"other port":        strings.Replace(realListing, ". 6 . 3389", ". 6 . 3390", 1),
		"udp for tcp":       strings.Replace(realListing, ". tcp . 445", ". udp . 445", 1),
		"service name":      strings.Replace(realListing, ". tcp . 445", ". tcp . microsoft-ds", 1),
		"open has allowed":  strings.Replace(realListing, "{ 192.168.1.101 }", "{ 192.168.1.100, 192.168.1.101 }", 1),
		"no input chain":    realListing[:strings.Index(realListing, "\tchain input")] + realListing[strings.Index(realListing, "\tchain output"):],
		"input accepts all": strings.Replace(realListing, "\t\tiif \"lo\" accept\n", "\t\taccept\n\t\tiif \"lo\" accept\n", 1),
		"no tcp reject":     strings.Replace(realListing, "\t\tmeta l4proto tcp reject with tcp reset\n", "", 1),
		"input policy drop": strings.Replace(realListing, "hook input priority filter; policy accept;\n\t\tiif", "hook input priority filter; policy drop;\n\t\tiif", 1),
		"set flags":         strings.Replace(realListing, "\t\ttype ipv4_addr\n", "\t\ttype ipv4_addr\n\t\tflags interval\n", 1),
		"set type":          strings.Replace(realListing, "type ipv4_addr\n", "type ipv4_addr . inet_service\n", 1),
		"extra chain":       strings.Replace(realListing, "\tchain forward {", "\tchain prerouting {\n\t\ttype filter hook prerouting priority filter; policy accept;\n\t}\n\tchain forward {", 1),
		"extra set":         strings.Replace(realListing, "\tset allow {", "\tset more {\n\t\ttype ipv4_addr\n\t}\n\tset allow {", 1),
		"dormant":           strings.Replace(realListing, "table inet vedette_hp {\n", "table inet vedette_hp {\n\tflags dormant\n", 1),
		"egress gone":       strings.Replace(realListing, "\t\tct state new drop\n", "", 1),
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

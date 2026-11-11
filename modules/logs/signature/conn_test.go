package signature

import (
	"net/netip"
	"strings"
	"testing"
)

func connOf(t testing.TB, set *Set, kind, line string) (string, []string) {
	t.Helper()
	c := set.Of(kind, line).Conn
	var out []string
	for _, d := range c.Dests {
		out = append(out, d.Kind+":"+d.Value)
	}
	if !c.Local.IsValid() {
		if len(out) != 0 {
			t.Fatalf("destinations without a local device: %+v", c)
		}
		return "", nil
	}
	return c.Local.String(), out
}

const fgTraffic = `date=2026-11-09 time=10:20:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=192.168.10.113 srcport=51234 dstip=45.9.148.20 dstport=443 action="accept" policyid=5`

func TestConnFortiGateTraffic(t *testing.T) {
	set := shipped(t)
	if l, d := connOf(t, set, "fortigate", fgTraffic); l != "192.168.10.113" || len(d) != 1 || d[0] != "ip:45.9.148.20" {
		t.Fatalf("got %q %q", l, d)
	}
	// A device kind with no profile and a kind with another profile never has a connection: there is no free-text reader.
	if l, _ := connOf(t, set, "sophos", fgTraffic); l != "" {
		t.Errorf("a device without a profile read a connection: %q", l)
	}
	if l, _ := connOf(t, set, "mikrotik", fgTraffic); l != "" {
		t.Errorf("another profile read it: %q", l)
	}
}

// Private, special and not-LAN endpoints make no connection (D-213).
func TestConnRefusesPrivateAndSpecial(t *testing.T) {
	set := shipped(t)
	dests := []string{"10.1.1.1", "172.16.5.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "100.64.0.1", "203.0.113.9", "198.51.100.1", "192.0.2.1",
		"198.18.0.1", "240.0.0.1", "255.255.255.255", "0.0.0.0", "::1", "fe80::1", "fc00::1", "2001:db8::1", "::ffff:8.8.8.8", "ff02::1", "64:ff9b::808:808"}
	for _, d := range dests {
		line := strings.Replace(fgTraffic, "dstip=45.9.148.20", "dstip="+d, 1)
		if _, got := connOf(t, set, "fortigate", line); len(got) != 0 {
			t.Errorf("destination %s made %v", d, got)
		}
	}
	for _, src := range []string{"8.8.8.8", "45.9.148.20", "100.64.0.9", "127.0.0.1", "fd00::5", "2606:4700::1", "192.168.10.113%eth0", "192.168.10.113/32", "", "-"} {
		line := strings.Replace(fgTraffic, "srcip=192.168.10.113", "srcip="+src, 1)
		if l, _ := connOf(t, set, "fortigate", line); l != "" {
			t.Errorf("source %q made a connection from %q", src, l)
		}
	}
	// An IPv6 public destination is fine.
	line := strings.Replace(fgTraffic, "dstip=45.9.148.20", "dstip=2606:4700:4700::1111", 1)
	if _, got := connOf(t, set, "fortigate", line); len(got) != 1 || got[0] != "ip:2606:4700:4700::1111" {
		t.Errorf("a public IPv6 destination gave %v", got)
	}
}

// The anti-framing rule: a field counts only when it is written exactly once, outside quotes (D-213, like D-210).
func TestConnAmbiguityGivesNothing(t *testing.T) {
	set := shipped(t)
	cases := map[string]string{
		"the same field twice":      strings.Replace(fgTraffic, "dstport=443", "dstip=45.9.148.20 dstport=443", 1),
		"two values":                strings.Replace(fgTraffic, "dstport=443", "dstip=1.1.1.1 dstport=443", 1),
		"two local fields":          strings.Replace(fgTraffic, "srcport=51234", "srcip=192.168.10.7 srcport=51234", 1),
		"a user field that injects": strings.Replace(fgTraffic, `devname="FW-HQ"`, `devname=FW-HQ dstip=6.6.6.6`, 1),
		"a stray quote":             strings.Replace(fgTraffic, `devname="FW-HQ"`, `devname=FW"HQ`, 1),
		"an unclosed quote":         fgTraffic + ` msg="x`,
		"text after a quote":        strings.Replace(fgTraffic, `devname="FW-HQ"`, `devname="FW-HQ"x`, 1),
		"a quoted word":             strings.Replace(fgTraffic, `devname="FW-HQ"`, `"a dstip=6.6.6.6"`, 1),
	}
	for name, line := range cases {
		if l, d := connOf(t, set, "fortigate", line); l != "" || len(d) != 0 {
			t.Errorf("%s: got %q %v", name, l, d)
		}
	}
	// Text inside a quoted value is never a site: the real field still counts once.
	quoted := strings.Replace(fgTraffic, `devname="FW-HQ"`, `devname="x dstip=6.6.6.6 srcip=10.0.0.9"`, 1)
	if l, d := connOf(t, set, "fortigate", quoted); l != "192.168.10.113" || len(d) != 1 || d[0] != "ip:45.9.148.20" {
		t.Errorf("a quoted value changed the answer: %q %v", l, d)
	}
	// An injected field in a line that has no destination of its own is the only site, and is still read: the format of the device decides
	// what a field is (a firewall quotes its strings), so the guarantee is about duplicates and quotes, not about unquoted free text.
	// Whitespace-only variation and a tab between pairs are the same line.
	if l, _ := connOf(t, set, "fortigate", strings.ReplaceAll(fgTraffic, " srcip", "\tsrcip")); l == "" {
		t.Error("a tab between pairs lost the connection")
	}
}

func TestConnDomains(t *testing.T) {
	set := shipped(t)
	line := func(name string) string {
		return `date=2026-11-09 logid="1501054802" type="utm" subtype="dns" srcip=192.168.10.113 qname="` + name + `" qtype="A" action="pass"`
	}
	for in, want := range map[string]string{"Bad.Example.NET": "bad.example.net", "bad.example.net.": "bad.example.net", "xn--bcher-kva.example": "xn--bcher-kva.example", "a-b.c0.io": "a-b.c0.io"} {
		if _, got := connOf(t, set, "fortigate", line(in)); len(got) != 1 || got[0] != "domain:"+want {
			t.Errorf("%q: got %v", in, got)
		}
	}
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 60) + ".com"
	for _, in := range []string{"", "localhost", "-a.com", "a-.com", "a..com", ".com", "com.", "1.2.3.4", "bücher.example", "a b.com", "a_b.com", "a.com/x", "a.com:80", "[::1]", strings.Repeat("a", 64) + ".com", long + ".x", "a.123", "a\\.com"} {
		if _, got := connOf(t, set, "fortigate", line(in)); len(got) != 0 {
			t.Errorf("%q made %v", in, got)
		}
	}
	// A web filter line gives the address and the name; a name twice gives none at all.
	wf := `logid="0316013056" type="utm" subtype="webfilter" srcip=192.168.10.113 dstip=104.21.5.5 hostname="x.example.org" action="blocked"`
	if _, got := connOf(t, set, "fortigate", wf); len(got) != 2 || got[0] != "ip:104.21.5.5" || got[1] != "domain:x.example.org" {
		t.Errorf("web filter: %v", got)
	}
	if l, _ := connOf(t, set, "fortigate", wf+` hostname="y.example.org"`); l != "" {
		t.Errorf("a host name twice: %q", l)
	}
	// A private destination does not hide the name.
	dns := `logid="1501054802" type="utm" subtype="dns" srcip=192.168.10.113 dstip=192.168.10.1 qname="bad.example.net" action="pass"`
	if _, got := connOf(t, set, "fortigate", dns); len(got) != 1 || got[0] != "domain:bad.example.net" {
		t.Errorf("dns: %v", got)
	}
}

func TestConnMikroTik(t *testing.T) {
	set := shipped(t)
	base := `firewall,info forward: in:ether1 out:ether2, proto TCP (SYN), 192.168.10.113:50922->45.9.148.20:443, len 60`
	if l, d := connOf(t, set, "mikrotik", base); l != "192.168.10.113" || len(d) != 1 || d[0] != "ip:45.9.148.20" {
		t.Fatalf("got %q %v", l, d)
	}
	if l, _ := connOf(t, set, "mikrotik", strings.Replace(base, "in:ether1", "connection-state:new in:ether1", 1)); l == "" {
		t.Error("a new connection lost its connection")
	}
	for name, line := range map[string]string{
		// M2: only the first packet of a connection (TCP with the SYN flag alone, and not marked as an established connection) is the device's own
		// connection; a reply from a port-forwarded server to a listed scanner is not.
		"syn+ack":        strings.Replace(base, "(SYN)", "(SYN,ACK)", 1),
		"ack+psh":        strings.Replace(base, "(SYN)", "(ACK,PSH)", 1),
		"established":    strings.Replace(base, "in:ether1", "connection-state:established in:ether1", 1),
		"related":        strings.Replace(base, "in:ether1", "connection-state:related in:ether1", 1),
		"udp":            `firewall,info fwd: in:lan out:wan, proto UDP, 192.168.10.113:5000->45.9.148.20:53, len 84`,
		"icmp":           `firewall,info fwd: in:lan out:wan, proto ICMP (type 8, code 0), 192.168.10.113->45.9.148.20, len 84`,
		"private dest":   strings.Replace(base, "45.9.148.20:443", "10.0.0.5:443", 1),
		"public source":  strings.Replace(base, "192.168.10.113:50922", "8.8.8.8:50922", 1),
		"a second pair":  base + ` 192.168.10.5:1->6.6.6.6:2`,
		"in the prefix":  `firewall,info x 192.168.10.5:1->6.6.6.6:2 ` + base[len("firewall,info "):],
		"a stray quote":  `firewall,info "` + base[len("firewall,info "):],
		"no proto text":  `firewall,info forward: 192.168.10.113:50922->45.9.148.20:443`,
		"leading zeroes": strings.Replace(base, "45.9.148.20", "045.009.148.020", 1),
	} {
		if l, d := connOf(t, set, "mikrotik", line); l != "" || len(d) != 0 {
			t.Errorf("%s: got %q %v", name, l, d)
		}
	}
}

func TestConnProfileRules(t *testing.T) {
	good := func(rule string) string {
		return `{"id":"x","title":"x","kinds":["x"],"rule":` + rule + `,"samples":[{"line":"a=1 s=192.168.1.1 d=8.8.8.8","signature":"a=1","local":"192.168.1.1","dests":["ip:8.8.8.8"]}]}`
	}
	ok := `{"type":"kv","fields":["a"],"local_field":"s","dest_ip_field":"d"}`
	if _, err := Load(profileFS(map[string]string{"x.json": good(ok)}), "profiles"); err != nil {
		t.Fatalf("a good rule: %v", err)
	}
	for name, rule := range map[string]string{
		"local without a destination": `{"type":"kv","fields":["a"],"local_field":"s"}`,
		"a destination without local": `{"type":"kv","fields":["a"],"dest_ip_field":"d"}`,
		"the same key twice":          `{"type":"kv","fields":["a"],"local_field":"s","dest_ip_field":"s"}`,
		"three host fields":           `{"type":"kv","fields":["a"],"local_field":"s","dest_host_fields":["h1","h2","h3"]}`,
		"a bad key":                   `{"type":"kv","fields":["a"],"local_field":"s s","dest_ip_field":"d"}`,
		"conn_pattern on kv":          `{"type":"kv","fields":["a"],"conn_pattern":"(?P<local>a)(?P<dest>b)"}`,
		"a pattern without dest":      `{"type":"template","prefix":"^(?P<head>x) ","conn_pattern":"(?P<local>a)"}`,
		"fields on template":          `{"type":"template","prefix":"^(?P<head>x) ","local_field":"s"}`,
	} {
		if _, err := Load(profileFS(map[string]string{"x.json": good(rule)}), "profiles"); err == nil {
			t.Errorf("%s loaded", name)
		}
	}
	// A sample that says a connection the rule does not give is refused.
	wrong := strings.Replace(good(ok), `"local":"192.168.1.1"`, `"local":"192.168.1.9"`, 1)
	if _, err := Load(profileFS(map[string]string{"x.json": wrong}), "profiles"); err == nil {
		t.Error("a sample with a wrong connection loaded")
	}
}

func FuzzConn(f *testing.F) {
	set := shipped(f)
	for _, p := range set.profiles {
		for _, s := range p.Samples {
			f.Add(p.Kinds[0], s.Line)
		}
	}
	for _, s := range []string{`srcip=10.0.0.1 dstip=8.8.8.8 dstip=8.8.4.4`, `srcip=10.0.0.1 qname="a.b" "`, `srcip="10.0.0.1"dstip=8.8.8.8`, strings.Repeat(`a=1 `, 400) + `srcip=10.0.0.1 dstip=8.8.8.8`, `hostname=` + strings.Repeat("a.", 200) + `com srcip=10.0.0.1`} {
		f.Add("fortigate", s)
		f.Add("mikrotik", s)
	}
	f.Fuzz(func(t *testing.T, kind, line string) {
		c := set.Of(kind, line).Conn
		if !c.Local.IsValid() {
			if len(c.Dests) != 0 {
				t.Fatalf("destinations without a device from %q", line)
			}
			return
		}
		if !LocalOK(c.Local) || c.Local.Zone() != "" || len(c.Dests) == 0 || len(c.Dests) > MaxDests {
			t.Fatalf("%q gave %+v", line, c)
		}
		for _, d := range c.Dests {
			switch d.Kind {
			case KindIP:
				a, err := netip.ParseAddr(d.Value)
				if err != nil || !PublicDest(a) || a.String() != d.Value {
					t.Fatalf("%q gave the address %q", line, d.Value)
				}
			case KindDomain:
				if v, ok := CleanDomain(d.Value); !ok || v != d.Value || len(v) > 253 {
					t.Fatalf("%q gave the domain %q", line, d.Value)
				}
			default:
				t.Fatalf("kind %q", d.Kind)
			}
		}
	})
}

// M6: only traffic and utm lines have a connection; an event line (an SSL-VPN login failure carries a user name that an attacker writes) never does, whatever
// fields it has or an injected name gives it.
func TestConnFortiGateEventLinesHaveNone(t *testing.T) {
	set := shipped(t)
	ev := `date=2026-11-09 logid="0101039426" type="event" subtype="vpn" level="alert" user="x" srcip=192.168.10.66 dstip=6.6.6.6 a="" action="ssl-login-fail"`
	if l, _ := connOf(t, set, "fortigate", ev); l != "" {
		t.Errorf("an event line made a connection from %q", l)
	}
	for _, typ := range []string{"traffic", "utm"} {
		if l, _ := connOf(t, set, "fortigate", strings.Replace(ev, `type="event"`, `type="`+typ+`"`, 1)); l == "" {
			t.Errorf("type %s has no connection", typ)
		}
	}
	for name, line := range map[string]string{"no type": strings.Replace(ev, ` type="event"`, "", 1), "two types": ev + ` type="traffic"`, "other type": strings.Replace(ev, `"event"`, `"anomaly"`, 1)} {
		if l, _ := connOf(t, set, "fortigate", line); l != "" {
			t.Errorf("%s: %q", name, l)
		}
	}
}

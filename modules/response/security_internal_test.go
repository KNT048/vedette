package response

// Permanent tests of the security review of WP-13a on the internal helpers (D-88 amendment 2026-11-09).

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The ip type refuses what is never a target to block or isolate: 0.0.0.0/8, the reserved 240.0.0.0/4 with the broadcast
// address, and multicast. Ordinary private addresses stay valid (devices on the LAN are targets).
func TestIPTypeRefusesNonTargets(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"255.255.255.255", "0.1.2.3", "0.0.0.0", "240.0.0.1", "239.1.1.1", "::ffff:255.255.255.255", "::ffff:0.1.2.3"} {
		if _, ok := CheckValue(PIP, v); ok {
			t.Errorf("CheckValue(ip, %q) accepted a broadcast, this-network, multicast or reserved address", v)
		}
	}
	for _, v := range []string{"192.168.10.5", "10.0.0.1", "198.51.100.7", "100.64.0.1", "8.8.8.8", "2001:db8::1"} {
		if _, ok := CheckValue(PIP, v); !ok {
			t.Errorf("CheckValue(ip, %q) refused a valid target", v)
		}
	}
	for _, v := range []string{"0.0.0.0/16", "240.0.0.0/16", "255.255.0.0/16"} {
		if _, ok := CheckValue(PCIDR, v); ok {
			t.Errorf("CheckValue(cidr, %q) accepted a reserved range", v)
		}
	}
}

// An interface value lands in an API path: it cannot hold .. or an empty segment (1%2F..%2F..%2Fadmin walks up a path on a
// server that decodes %2F before routing).
func TestInterfaceValuesRefuseDotSegments(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"1/../../admin", "Gi1/0/48/", "Gi1//48", "a/./b", "Gi1..2", "eth0.."} {
		if _, ok := CheckValue(PInterface, v); ok {
			t.Errorf("an interface value %q was accepted", v)
		}
	}
	for _, v := range []string{"Gi1/0/48", "ether1", "1/1/48", "ae0.100", "Te1/0/1:1"} {
		if _, ok := CheckValue(PInterface, v); !ok {
			t.Errorf("an interface value %q was refused", v)
		}
	}
}

// A never-touch domain also protects its parents: blocking corp.example.com blocks login.corp.example.com on a DNS filter. A
// sibling or an unrelated domain that merely ends the same way is not touched.
func TestNeverTouchDomainProtectsParentsAndSubdomains(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		entry, value string
		want         bool
	}{
		{"login.corp.example.com", "corp.example.com", true},
		{"login.corp.example.com", "example.com", true},
		{"corp.example.com", "login.corp.example.com", true},
		{"corp.example.com", "corp.example.com", true},
		{"login.corp.example.com", "mail.corp.example.com", false},
		{"corp.example.com", "notcorp.example.com", false},
		{"corp.example.com", "example.org", false},
	} {
		if got := touches(c.entry, c.value); got != c.want {
			t.Errorf("touches(%q, %q) = %v, want %v", c.entry, c.value, got, c.want)
		}
	}
}

// MAC addresses and port names are never-touch entries too; a kind only matches its own kind.
func TestNeverTouchMACAndInterfaceMatching(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		entry, value string
		want         bool
	}{
		{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", true},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:00", false},
		{"Gi1/0/48", "gi1/0/48", true},
		{"Gi1/0/48", "Gi1/0/4", false},
		{"Gi1/0/48", "192.168.10.1", false},
		{"192.168.10.0/24", "Gi1/0/48", false},
		{"aa:bb:cc:dd:ee:ff", "Gi1/0/48", false},
	} {
		if got := touches(c.entry, c.value); got != c.want {
			t.Errorf("touches(%q, %q) = %v, want %v", c.entry, c.value, got, c.want)
		}
	}
	for _, bad := range []string{"192.168.1.300", "10.0.0.0/33", "2001:db8::/129", "", " ", "1.2.3", "a b"} {
		if _, ok := ValidAllowValue(bad); ok {
			t.Errorf("ValidAllowValue(%q) accepted a mistyped entry", bad)
		}
	}
}

// An API path may not start with "//": a scheme-relative reference would resolve to another host with the connection's credentials.
func TestAPIPathRefusesSchemeRelative(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"//attacker.example/x/{ip}", "///x", "x/y", "/a/../b", "/a?b=1"} {
		if why := ValidateTpl(Tpl{Method: "POST", Path: p}, "Action"); why == "" {
			t.Errorf("the path %q was accepted", p)
		}
	}
	if why := ValidateTpl(Tpl{Method: "POST", Path: "/api/v2/x/{ip}"}, "Action"); why != "" {
		t.Errorf("a plain path was refused: %s", why)
	}
}

// publishable: only public addresses are published (blocklist-format 5).
func TestPublishableAddresses(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{
		"10.0.0.1": false, "172.16.5.5": false, "172.31.255.255": false, "172.32.0.1": true, "192.168.0.1": false, "100.64.0.1": false, "100.127.0.1": false, "100.128.0.1": true,
		"0.0.0.1": false, "127.0.0.1": false, "169.254.0.1": false, "224.0.0.1": false, "240.0.0.1": false, "255.255.255.255": false,
		"198.51.100.7": true, "203.0.113.5": true, "8.8.8.8": true, "fc00::1": false, "fe80::1": false, "ff02::1": false, "::": false, "2001:db8::1": false, "2606:4700::1111": true,
	} {
		if got := publishable(netip.MustParseAddr(v)); got != want {
			t.Errorf("publishable(%s) = %v, want %v", v, got, want)
		}
	}
	if publishable(netip.Addr{}) {
		t.Error("the zero address is publishable")
	}
}

// sourceKey: the rate limit key is the address for IPv4 and the /64 for IPv6, with or without a port or a mapped form.
func TestSourceKey(t *testing.T) {
	t.Parallel()
	for from, want := range map[string]string{
		"192.168.10.5": "192.168.10.5", "192.168.10.5:4431": "192.168.10.5", "::ffff:192.168.10.5": "192.168.10.5",
		"2001:db8:1:2::7": "2001:db8:1:2::/64", "2001:db8:1:2:ffff:ffff:ffff:ffff": "2001:db8:1:2::/64", "[2001:db8:1:2::7]:443": "2001:db8:1:2::/64", "not an address": "not an address",
	} {
		if got := sourceKey(from); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", from, got, want)
		}
	}
}

// The rate limit table is capped: when it is full a source it does not know is refused until old ones age out, and a known
// source keeps its own count.
func TestAllowFetchTableIsCapped(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	s := &Service{fetchTimes: map[string][]time.Time{}, cfg: Config{Clock: func() time.Time { return now }}}
	for i := range maxFetchKeys + 50 {
		s.allowFetch("bad:"+strconv.Itoa(i), 20, true)
	}
	if len(s.fetchTimes) > maxFetchKeys {
		t.Fatalf("the table holds %d keys, the cap is %d", len(s.fetchTimes), maxFetchKeys)
	}
	if !s.allowFetch("bad:0", 20, true) {
		t.Error("a known source lost its place")
	}
	if s.allowFetch("bad:new", 20, true) {
		t.Error("an unknown source was admitted while the table is full")
	}
	now = now.Add(2 * time.Minute)
	if !s.allowFetch("bad:new", 20, true) || len(s.fetchTimes) != 1 {
		t.Errorf("the table did not recover after a minute (%d keys)", len(s.fetchTimes))
	}
}

// L9: every built-in action that can be undone has a rollback that differs from its run step (a rollback that repeats the run
// is no undo); an action with no rollback says so by having none, so it cannot be pre-approved.
func TestBuiltinRollbackDiffersFromRun(t *testing.T) {
	t.Parallel()
	s := &Service{}
	if err := s.loadData(); err != nil {
		t.Fatal(err)
	}
	if len(s.cat) == 0 {
		t.Fatal("no built-in actions")
	}
	for _, a := range s.cat {
		if a.Rollback.Empty() {
			if a.ID == "pf_alias_add" || a.ID == "cisco_save_config" || a.ID == "msg_send" || a.ID == "webhook_call" {
				continue
			}
			t.Errorf("%s has no rollback: if it cannot be undone, list it here on purpose", a.ID)
			continue
		}
		if a.Rollback == a.Run {
			t.Errorf("%s: the rollback is a copy of the run step", a.ID)
		}
		if a.Rollback.Method == a.Run.Method && a.Rollback.Path == a.Run.Path && a.Rollback.Body == a.Run.Body && a.Rollback.CLI == a.Run.CLI {
			t.Errorf("%s: the rollback repeats the run call", a.ID)
		}
	}
}

// Fuzz of the two layers: every typed value that passes CheckValue is free of shell characters, control characters and quotes,
// and Fill never produces a command with a shell character.
func FuzzCheckValueThenFill(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "::ffff:10.0.0.1", "fe80::1%eth0", "a.b", "Gi1/0/1", "x;y", "a\nb", "Kevil.com", "10.0.0.0/8", "1e3", "0x1F", "1/../2", "0.1.2.3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		for _, p := range ParamTypes {
			c, ok := CheckValue(p, v)
			if !ok {
				continue
			}
			if strings.ContainsAny(c, shellChars+"\"'\r\n\t\x00{}") || strings.ContainsFunc(c, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				t.Fatalf("CheckValue(%s, %q) = %q holds a dangerous character", p, v, c)
			}
			if p == PText {
				continue
			}
			out, err := Fill("cmd {"+string(p)+"} x", Values{p: c}, TCLI)
			if err == nil && HasShellChar(out) {
				t.Fatalf("Fill produced %q", out)
			}
		}
	})
}

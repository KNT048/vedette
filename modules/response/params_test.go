package response

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/netguard"
)

func TestCheckValue(t *testing.T) {
	t.Parallel()
	ok := []struct {
		t    ParamType
		in   string
		want string
	}{
		{PIP, "192.168.10.5", "192.168.10.5"}, {PIP, "::ffff:198.51.100.7", "198.51.100.7"}, {PIP, "2001:DB8::1", "2001:db8::1"},
		{PCIDR, "192.168.10.77/24", "192.168.10.0/24"}, {PDomain, "Bad.Example.COM", "bad.example.com"}, {PPort, "0443", "443"}, {PMAC, "3C-22-FB-10-AA-01", "3c:22:fb:10:aa:01"},
		{PVLAN, "4094", "4094"}, {PInterface, "Gi1/0/12", "Gi1/0/12"}, {PID, "2147483647", "2147483647"}, {PName, "NAS-PHOTO_443.x", "NAS-PHOTO_443.x"}, {PText, "Trap touched on PC-HR-01", "Trap touched on PC-HR-01"},
	}
	for _, c := range ok {
		if got, good := CheckValue(c.t, c.in); !good || got != c.want {
			t.Errorf("%s %q = %q, %v; want %q", c.t, c.in, got, good, c.want)
		}
	}
	bad := map[ParamType][]string{
		PIP:        {"", "1.2.3", "1.2.3.4.5", "1.2.3.4; x", "1.2.3.4\n", "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "169.254.1.1", "fe80::1", "fe80::1%eth0", "2130706433", "0x7f.1", " 1.2.3.4", "1.2.3.4/24"},
		PCIDR:      {"", "10.0.0.0/8", "10.0.0.0/15", "10.0.0.0", "0.0.0.0/0", "127.0.0.0/24", "2001:db8::/32", "10.0.0.0/33", "10.0.0.0/24;x"},
		PDomain:    {"", "localhost", "a_b.example", "-a.example", "*.example.com", "1.2.3.4", "example.c", "exämple.com", "a.example.com\n", strings.Repeat("a", 64) + ".com", "a..com"},
		PPort:      {"", "0", "65536", "-1", "80;", "1e3", "８０"},
		PMAC:       {"", "3c:22:fb:10:aa", "3c:22:fb:10:aa:0g", "3c22.fb10.aa01"},
		PVLAN:      {"", "0", "4095", "12 "},
		PInterface: {"", "-Gi1", "Gi1/0/12;", "Gi1 0", strings.Repeat("a", 33), "Gi1\n"},
		PID:        {"", "0", "2147483648", "-5", "1.5", "12345678901"},
		PName:      {"", "-x", "a b", "a\"b", "a;b", "$x", strings.Repeat("a", 65), "a\n"},
		PText:      {"", " x", "a'b", "a\"b", "a;b", "a|b", "a`b", "a$b", "a\nb", "a(b)", "a\\b", "a<b", "a&b", "a!b", "a~b", "a^b", strings.Repeat("a", 81)},
	}
	for typ, l := range bad {
		for _, in := range l {
			if got, good := CheckValue(typ, in); good {
				t.Errorf("%s %q was accepted as %q", typ, in, got)
			}
		}
	}
}

func TestContract_INV14b_EscapeAndFill(t *testing.T) {
	t.Parallel()
	if got := escapeFor(TJSON, "a\"b\\c\n"); got != `a\"b\\c\n` {
		t.Errorf("json: %q", got)
	}
	if got := escapeFor(TURL, "a b/c?d"); got != "a%20b%2Fc%3Fd" {
		t.Errorf("url: %q", got)
	}
	if got := escapeFor(THeader, "a\r\nX-Evil: 1"); strings.ContainsAny(got, "\r\n") || got != "aX-Evil: 1" {
		t.Errorf("header: %q", got)
	}
	v := Values{PIP: "198.51.100.7", PName: "VIP-1"}
	out, err := Fill("config\n edit \"{name}\"\n  set src {ip} {expiry_s}", v, TCLI)
	if err != nil || out != "config\n edit \"VIP-1\"\n  set src 198.51.100.7 <expiry_s>" {
		t.Errorf("fill: %q, %v", out, err)
	}
	// A value that skipped the type check, or is not canonical, never reaches a template.
	for _, bad := range []Values{{PIP: "1.2.3.4; reboot"}, {PIP: "::ffff:1.2.3.4"}, {}} {
		if _, err := Fill("x {ip}", bad, TCLI); err == nil {
			t.Errorf("Fill accepted %v", bad)
		}
	}
	// The path of an API call is escaped per segment.
	if got, _ := Fill("/vip/{name}", Values{PName: "a.b-c"}, TURL); got != "/vip/a.b-c" {
		t.Errorf("path: %q", got)
	}
}

func TestValidateTpl(t *testing.T) {
	t.Parallel()
	good := []Tpl{{CLI: "diagnose user banned-ip add src4 {ip}"}, {Method: "POST", Path: "/api/v2/x/{name}", Body: `{"ip":"{ip}","e":{expiry_s}}`}, {CLI: "config firewall address\n edit \"vedette-{ip}\"\nend"}}
	for _, g := range good {
		if why := ValidateTpl(g, "Action"); why != "" {
			t.Errorf("%+v refused: %s", g, why)
		}
	}
	bad := []Tpl{{}, {CLI: "ping {ip}; reboot"}, {CLI: "a | b"}, {CLI: "echo $(id)"}, {CLI: "a `b`"}, {CLI: "a > b"}, {CLI: "a & b"}, {CLI: "a \\ b"}, {CLI: "a !b"}, {CLI: "a ~b"}, {CLI: "a ^b"}, {CLI: "x (y)"},
		{CLI: "notify {text}"}, {CLI: "x {nope}"}, {Method: "GET", Path: "/a/../b"}, {Method: "GET", Path: "/a?x=1"}, {Method: "TRACE", Path: "/a"}, {Method: "POST", Path: "/a", Body: "{not json"},
		{Method: "POST", Path: "/a", Body: "{}", Headers: "X-A: b\r\nX-B: c"}, {Method: "POST", Path: "a"}, {Path: "/a"}, {Method: "POST"}, {CLI: strings.Repeat("a", 2001)}}
	for _, b := range bad {
		if why := ValidateTpl(b, "Action"); why == "" {
			t.Errorf("%+v was accepted", b)
		}
	}
}

// The data files are valid by the same checks as a customer's action (they are validated when the service starts), and the
// action library does not drift from the copy the GUI mock uses: the only differences are the ones that keep shell
// characters out of the shipped templates (INV-14b) and the pfSense alias rollback that was a copy of its run step (D-88 amendment
// 2026-11-09), listed here.
func TestLibraryMatchesTheMockExceptForShellCharacters(t *testing.T) {
	t.Parallel()
	mock, err := os.ReadFile("../../web/src/features/response/templates/action-templates.sample.json")
	if err != nil {
		t.Skip("the web tree is not here")
	}
	ours, err := os.ReadFile("data/action-templates.json")
	if err != nil {
		t.Fatal(err)
	}
	type lib struct {
		Actions []map[string]any `json:"actions"`
	}
	var a, b lib
	if json.Unmarshal(mock, &a) != nil || json.Unmarshal(ours, &b) != nil || len(a.Actions) != len(b.Actions) {
		t.Fatal("the libraries do not parse or differ in size")
	}
	allowed := map[string]bool{"adguard_block": true, "cisco_save_config": true, "pf_alias_add": true}
	for i := range a.Actions {
		id := a.Actions[i]["id"].(string)
		x, _ := json.Marshal(a.Actions[i])
		y, _ := json.Marshal(b.Actions[i])
		if string(x) != string(y) && !allowed[id] {
			t.Errorf("action %s differs from the GUI mock copy", id)
		}
	}
	rm, _ := os.ReadFile("../../web/src/features/response/templates/rule-templates.sample.json")
	ro, _ := os.ReadFile("data/rule-templates.json")
	if string(rm) != string(ro) {
		t.Error("rule-templates.json differs from the GUI mock copy")
	}
}

func TestForbiddenAddr(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1", "::ffff:127.0.0.1",
		// D-411: the cloud metadata endpoints that are not link-local, and transition forms of a forbidden address (core/netguard)
		"100.100.100.200", "192.0.0.192", "fd00:ec2::254", "fd20:ce::254", "64:ff9b::a9fe:a9fe", "2002:6464:64c8::1", "255.255.255.255"} {
		if !forbiddenAddr(netip.MustParseAddr(a), false) {
			t.Errorf("%s is allowed", a)
		}
	}
	for _, a := range []string{"192.168.10.9", "10.1.1.1", "198.51.100.7", "2001:db8::1"} {
		if forbiddenAddr(netip.MustParseAddr(a), false) {
			t.Errorf("%s is forbidden", a)
		}
	}
	if forbiddenAddr(netip.MustParseAddr("127.0.0.1"), true) || !forbiddenAddr(netip.MustParseAddr("100.100.100.200"), true) {
		t.Error("the loopback switch must open loopback only")
	}
}

// D-411: a webhook URL naming a cloud metadata service or endpoint is refused at save, before any lookup.
func TestCheckWebhookURLRefusesMetadata(t *testing.T) {
	t.Parallel()
	s := &Service{interfaceFn: func() ([]netip.Addr, error) { return nil, nil }}
	for _, u := range []string{"https://metadata.google.internal/computeMetadata/v1/", "https://metadata/", "https://METADATA.GOOG./x", "https://100.100.100.200/latest", "https://[fd00:ec2::254]/latest", "https://[64:ff9b::a9fe:a9fe]/"} {
		if _, err := s.checkWebhookURL(u); err == nil || !strings.Contains(err.Error(), "cloud metadata") {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := s.checkWebhookURL("https://hooks.example.com/x"); err != nil {
		t.Errorf("a public name is refused: %v", err)
	}
}

// D-446 for webhook_call: the machine's address only on Vedette's own ports, core's container and the decoys on every port, loopback
// always; every target while the machine's addresses are not known; the dial-time check judges the same at the dialled port.
func TestWebhookVedetteItself(t *testing.T) {
	t.Parallel()
	known := true
	s := &Service{interfaceFn: func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.88.0.5")}, nil
	}, cfg: Config{
		MachineAddrs: func() ([]netip.Addr, bool) { return []netip.Addr{netip.MustParseAddr("192.168.18.141")}, known },
		SelfAddrs:    func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.18.200")} },
	}}
	for u, own := range map[string]bool{
		"https://192.168.18.141/hook": false, "https://192.168.18.141:5678/hook": false, // another program on the machine
		"https://192.168.18.141:8443/api": true, "https://192.168.18.141:6514/": true,
		"https://10.88.0.5:5678/": true, "https://192.168.18.200/": true, // core's container, a decoy
		"https://127.0.0.1:5678/": true, "https://localhost/": true, "https://[::ffff:192.168.18.141]:8444/": true,
	} {
		_, err := s.checkWebhookURL(u)
		if got := err != nil && err.Error() == netguard.OwnText; got != own || (!own && err != nil) {
			t.Errorf("%s: %v", u, err)
		}
	}
	dial := dialControl(s.refusedTarget)
	if dial("tcp", "192.168.18.141:8443", nil) == nil || dial("tcp", "192.168.18.141:5678", nil) != nil || dial("tcp", "10.88.0.5:5678", nil) == nil {
		t.Error("the dial-time check differs from the save-time check")
	}
	known = false
	if _, err := s.checkWebhookURL("https://192.168.18.50:5678/"); err == nil || dial("tcp", "192.168.18.50:5678", nil) == nil {
		t.Error("unknown machine addresses must refuse every webhook (fail closed, #157)")
	}
}

func TestTouches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		entry, value string
		want         bool
	}{
		{"192.168.10.1", "192.168.10.1", true}, {"192.168.10.1", "192.168.10.2", false}, {"192.168.99.0/24", "192.168.99.7", true}, {"192.168.99.0/24", "192.168.98.7", false},
		{"192.168.10.1", "192.168.10.0/24", true}, {"192.168.10.0/24", "192.168.0.0/16", true}, {"192.168.10.0/24", "192.168.11.0/24", false},
		{"mail.acme.example", "mail.acme.example", true}, {"acme.example", "x.mail.acme.example", true}, {"acme.example", "notacme.example", false}, {"acme.example", "192.168.1.1", false},
	}
	for _, c := range cases {
		if got := touches(c.entry, c.value); got != c.want {
			t.Errorf("touches(%q, %q) = %v", c.entry, c.value, got)
		}
	}
}

func FuzzCheckValue(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "10.0.0.0/24", "a.example.com", "443", "3c:22:fb:10:aa:01", "Gi1/0/1", "x\n", "a;b", "::ffff:1.2.3.4", "0x7f.1", "fe80::1%eth0"} {
		for i := range ParamTypes {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, ti uint8, v string) {
		typ := ParamTypes[int(ti)%len(ParamTypes)]
		got, ok := CheckValue(typ, v)
		if !ok {
			return
		}
		if strings.ContainsAny(got, "\r\n\x00") || HasShellChar(got) || strings.ContainsAny(got, `"'`) {
			t.Fatalf("%s %q accepted as %q", typ, v, got)
		}
		again, ok := CheckValue(typ, got)
		if !ok || again != got {
			t.Fatalf("%s %q: canonical form %q is not stable (%q, %v)", typ, v, got, again, ok)
		}
	})
}

// FuzzRender fuzzes the renderer: any template a customer could save and any value. A template that passes ValidateTpl and a
// value that passes CheckValue never produce a command with a shell character, an extra line, or a JSON body that is not JSON.
func FuzzRender(f *testing.F) {
	f.Add("diagnose user banned-ip add src4 {ip}", uint8(0), "1.2.3.4", uint8(0))
	f.Add("config\n edit \"{name}\"\nend", uint8(8), "VIP-1", uint8(0))
	f.Add(`{"ip":"{ip}","expiry":{expiry_s}}`, uint8(0), "::ffff:1.2.3.4", uint8(1))
	f.Add("x {text}", uint8(9), "hello world", uint8(0))
	f.Fuzz(func(t *testing.T, tmpl string, ti uint8, v string, tr uint8) {
		typ := ParamTypes[int(ti)%len(ParamTypes)]
		val, ok := CheckValue(typ, v)
		if !ok {
			return
		}
		vals := Values{typ: val}
		transport := []Transport{TCLI, TJSON}[int(tr)%2]
		var tpl Tpl
		if transport == TJSON {
			tpl = Tpl{Method: "POST", Path: "/a", Body: tmpl}
		} else {
			tpl = Tpl{CLI: tmpl}
		}
		if ValidateTpl(tpl, "x") != "" {
			// {text} is refused by ValidateTpl; the box actions that use it are checked by the loader, so allow it here by hand
			if typ != PText || strings.Contains(tmpl, "{text}") == false || HasShellChar(tmpl) {
				return
			}
		}
		text := tmpl
		for _, p := range ParamTypes {
			if p != typ {
				text = strings.ReplaceAll(text, "{"+string(p)+"}", "")
			}
		}
		out, err := Fill(text, vals, transport)
		if err != nil {
			return
		}
		switch transport {
		case TCLI:
			chk := out
			for _, r := range RuntimeValues {
				chk = strings.ReplaceAll(chk, "<"+r+">", "")
			}
			if HasShellChar(chk) {
				t.Fatalf("shell character in %q (template %q, value %q)", out, tmpl, val)
			}
			if strings.Count(out, "\n") != strings.Count(text, "\n") {
				t.Fatalf("lines changed: %q -> %q", text, out)
			}
		case TJSON:
			// a value placed inside a JSON string stays inside it, whatever it holds
			body, err := Fill(`{"k":"{`+string(typ)+`}","n":1}`, vals, TJSON)
			var m map[string]any
			if err != nil || json.Unmarshal([]byte(body), &m) != nil || m["k"] != val || m["n"] != float64(1) {
				t.Fatalf("value %q escaped its JSON string: %q, %v", val, body, err)
			}
		}
	})
}

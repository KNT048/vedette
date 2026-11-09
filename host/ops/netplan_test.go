package ops

import (
	"errors"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func staticCfg() NetplanConfig {
	return NetplanConfig{Mgmt: NetplanMgmt{
		Iface: "eth0", Mode: api.NetModeStatic, Address: netip.MustParsePrefix("192.168.10.250/24"), Gateway: netip.MustParseAddr("192.168.10.1"),
		DNS: addrs("192.168.10.1", "1.1.1.1"), Search: []string{"corp.example", "lan"},
	}}
}

func goldenCases() map[string]NetplanConfig {
	span := staticCfg()
	span.SPAN = "eth1"
	return map[string]NetplanConfig{
		"static": staticCfg(),
		"dhcp":   {Mgmt: NetplanMgmt{Iface: "ens3", Mode: api.NetModeDHCP}},
		"span":   span,
		"static_no_gateway_no_dns": {Mgmt: NetplanMgmt{
			Iface: "eno1", Mode: api.NetModeStatic, Address: netip.MustParsePrefix("10.0.0.5/8"),
		}},
		"dhcp_span_dns": {Mgmt: NetplanMgmt{Iface: "eth0", Mode: api.NetModeDHCP, DNS: addrs("9.9.9.9", "2606:4700:4700::1111")}, SPAN: "enp2s0"},
	}
}

func TestNetplanGolden(t *testing.T) {
	t.Parallel()
	for name, cfg := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := renderNetplan(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "netplan_"+name+".yaml")
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // a golden file of this package's testdata
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("rendered text differs from %s:\n%s", path, got)
			}
			back, err := parseNetplan(got)
			if err != nil {
				t.Fatalf("what the host rendered is not read back: %v", err)
			}
			again, _ := renderNetplan(back)
			if string(again) != string(got) {
				t.Fatalf("read-back configuration renders differently:\n%s", again)
			}
		})
	}
}

// Every value that could break out of a YAML scalar, a key or a list is refused before anything is rendered.
func TestNetplanRefusesInjection(t *testing.T) {
	t.Parallel()
	evil := []string{
		"a\nb", "a\rb", "x: y", "a #b", "#a", "{a}", "a{", "&a", "*a", "!a", "|a", ">a", "-a", "- a", "'a", `"a`, "a'b", "a\x00b",
		"a b", "a\tb", "%a", "@a", "`a", "[a]", "a,b", "a;b", "a$b", "../a", "a/b", "", "é", strings.Repeat("a", 65), ".", "..", "-", "?a", ":a", "=a",
	}
	check := func(field string, mutate func(c *NetplanConfig, v string)) {
		for _, v := range evil {
			if v == "" && field == "span.iface" {
				continue // "no SPAN card"
			}
			c := staticCfg()
			c.SPAN = "eth1"
			mutate(&c, v)
			out, err := renderNetplan(c)
			if err == nil || out != nil {
				t.Errorf("%s=%q was rendered:\n%s", field, v, out)
				continue
			}
			var fe *fieldError
			if !errors.As(err, &fe) || !strings.HasPrefix(fe.Field, field) {
				t.Errorf("%s=%q: error %v names the wrong field", field, v, err)
			}
		}
	}
	check("mgmt.iface", func(c *NetplanConfig, v string) { c.Mgmt.Iface = v })
	check("span.iface", func(c *NetplanConfig, v string) { c.SPAN = v })
	check("mgmt.search", func(c *NetplanConfig, v string) { c.Mgmt.Search = []string{v} })
	// An interface name longer than the kernel allows.
	c := staticCfg()
	c.Mgmt.Iface = "abcdefghijklmnop"
	if _, err := renderNetplan(c); err == nil {
		t.Error("a 16-byte interface name was rendered")
	}
	// Values that are not valid at all for their type.
	for name, mut := range map[string]func(*NetplanConfig){
		"mode":              func(c *NetplanConfig) { c.Mgmt.Mode = "static\nx: y" },
		"mode empty":        func(c *NetplanConfig) { c.Mgmt.Mode = "" },
		"same iface":        func(c *NetplanConfig) { c.SPAN = c.Mgmt.Iface },
		"address ipv6":      func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("fd00::5/64") },
		"address mapped":    func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("::ffff:10.0.0.5/120") },
		"address zero":      func(c *NetplanConfig) { c.Mgmt.Address = netip.Prefix{} },
		"address network":   func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("192.168.10.0/24") },
		"address broadcast": func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("192.168.10.255/24") },
		"address loopback":  func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("127.0.0.1/8") },
		"address multicast": func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("224.0.0.1/8") },
		"address /31":       func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("192.168.10.2/31") },
		"address /32":       func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("192.168.10.2/32") },
		"address /7":        func(c *NetplanConfig) { c.Mgmt.Address = netip.MustParsePrefix("10.0.0.5/7") },
		"gateway outside":   func(c *NetplanConfig) { c.Mgmt.Gateway = netip.MustParseAddr("192.168.11.1") },
		"gateway is box":    func(c *NetplanConfig) { c.Mgmt.Gateway = c.Mgmt.Address.Addr() },
		"gateway network":   func(c *NetplanConfig) { c.Mgmt.Gateway = netip.MustParseAddr("192.168.10.0") },
		"gateway ipv6":      func(c *NetplanConfig) { c.Mgmt.Gateway = netip.MustParseAddr("fd00::1") },
		"gateway zoned":     func(c *NetplanConfig) { c.Mgmt.Gateway = netip.MustParseAddr("fe80::1%eth0") },
		"dns loopback":      func(c *NetplanConfig) { c.Mgmt.DNS = addrs("127.0.0.53") },
		"dns unspecified":   func(c *NetplanConfig) { c.Mgmt.DNS = addrs("0.0.0.0") },
		"dns multicast":     func(c *NetplanConfig) { c.Mgmt.DNS = addrs("224.0.0.1") },
		"dns link-local":    func(c *NetplanConfig) { c.Mgmt.DNS = addrs("fe80::1") },
		"dns zoned":         func(c *NetplanConfig) { c.Mgmt.DNS = addrs("fe80::1%eth0") },
		"dns mapped":        func(c *NetplanConfig) { c.Mgmt.DNS = addrs("::ffff:1.1.1.1") },
		"dns zero value":    func(c *NetplanConfig) { c.Mgmt.DNS = []netip.Addr{{}} },
		"dns four":          func(c *NetplanConfig) { c.Mgmt.DNS = addrs("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4") },
		"search seven":      func(c *NetplanConfig) { c.Mgmt.Search = []string{"a", "b", "c", "d", "e", "f", "g"} },
		"dhcp with address": func(c *NetplanConfig) { c.Mgmt.Mode = api.NetModeDHCP },
	} {
		c := staticCfg()
		mut(&c)
		if out, err := renderNetplan(c); err == nil {
			t.Errorf("%s: rendered:\n%s", name, out)
		}
	}
}

// Names that YAML would read as something else than a string are quoted by the encoder, so the file reads back as the same text.
func TestNetplanQuotesScalarsThatLookLikeOtherTypes(t *testing.T) {
	t.Parallel()
	c := staticCfg()
	c.Mgmt.Iface = "on"
	c.SPAN = "123"
	c.Mgmt.Search = []string{"yes", "1e3", "null", "0x10", "true"}
	out, err := renderNetplan(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseNetplan(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if back.Mgmt.Iface != "on" || back.SPAN != "123" || !slices.Equal(back.Mgmt.Search, c.Mgmt.Search) {
		t.Fatalf("read back %+v from\n%s", back, out)
	}
}

// parseNetplan never turns a file the host did not write into a configuration.
func TestParseNetplanRefusesWhatTheHostDidNotRender(t *testing.T) {
	t.Parallel()
	good, _ := renderNetplan(staticCfg())
	for name, text := range map[string]string{
		"empty":            "",
		"hand edited":      strings.Replace(string(good), "1.1.1.1", "8.8.8.8 ", 1),
		"extra key":        strings.Replace(string(good), "version: 2", "version: 2\n  bridges: {}", 1),
		"extra comment":    string(good) + "# edited\n",
		"another renderer": strings.Replace(string(good), "networkd", "NetworkManager", 1),
		"foreign file":     "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n      wakeonlan: true\n",
		"two mgmt cards":   "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    a:\n      dhcp4: true\n    b:\n      dhcp4: true\n",
		"not yaml":         "\x00\x01 {{{",
		"alias bomb":       "a: &a [x,x,x,x]\nb: &b [*a,*a,*a,*a]\nc: [*b,*b,*b,*b]\n",
		"too big":          strings.Repeat("# x\n", maxNetplan),
	} {
		if cfg, err := parseNetplan([]byte(text)); err == nil {
			t.Errorf("%s: parsed as %+v", name, cfg)
		}
	}
}

func FuzzParseNetplan(f *testing.F) {
	for _, c := range goldenCases() {
		b, _ := renderNetplan(c)
		f.Add(b)
	}
	f.Add([]byte("network: {}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfg, err := parseNetplan(b)
		if err != nil {
			return
		}
		again, err := renderNetplan(cfg)
		if err != nil || string(again) != string(b) {
			t.Fatalf("accepted text that is not what the host renders: %q", b)
		}
	})
}

// On CI Linux with netplan installed: the real generator accepts every golden file and brings the
// SPAN card up with no address of any kind.
func TestNetplanGenerateAcceptsTheRenderedYAML(t *testing.T) {
	bin := ""
	for _, p := range []string{"/usr/sbin/netplan", "/usr/bin/netplan"} {
		if _, e := os.Stat(p); e == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("netplan is not installed here")
	}
	// Through the same runner and grammar the host uses (SYS-1): the grammar is what this test exercises.
	runner, err := vexec.NewRunner(slog.New(slog.DiscardHandler), vexec.Binary{Name: binNetplan, Path: bin, Validate: validateNetplan})
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := validateNetplan([]string{"generate", "--root-dir", root}); err != nil {
				t.Fatalf("the argv grammar refuses the test's own root %q: %v", root, err)
			}
			text, _ := renderNetplan(cfg)
			dir := filepath.Join(root, "etc", "netplan")
			if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a directory of the test's own temp root; netplan wants it readable
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, netplanName), text, 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := runner.Run(t.Context(), binNetplan, []string{"generate", "--root-dir", root}, nil)
			if err != nil {
				t.Fatalf("netplan generate: %v\n%s\n%s\n%s", err, res.Stdout, res.Stderr, text)
			}
			if cfg.SPAN == "" {
				return
			}
			nets, _ := filepath.Glob(filepath.Join(root, "run", "systemd", "network", "*"+cfg.SPAN+"*.network"))
			if len(nets) != 1 {
				t.Fatalf("no .network file for the SPAN card: %v", nets)
			}
			b, _ := os.ReadFile(nets[0])
			if !strings.Contains(string(b), "LinkLocalAddressing=no") || strings.Contains(string(b), "DHCP=") && !strings.Contains(string(b), "DHCP=no") {
				t.Fatalf("the SPAN card is not address-free:\n%s", b)
			}
		})
	}
}

func TestValidateNetplanArgv(t *testing.T) {
	t.Parallel()
	ok := [][]string{{"generate", "--root-dir", "/tmp/x"}, {"generate", "--root-dir", "/private/tmp/a-b_c.d/root"}}
	for _, a := range ok {
		if err := validateNetplan(a); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	no := [][]string{
		nil, {"generate"}, {"apply"}, {"try"}, {"generate", "--root-dir"}, {"generate", "--root-dir", "/"}, {"generate", "--root-dir", "/tmp"},
		{"generate", "--root-dir", "tmp/x"}, {"generate", "--root-dir", "/tmp/../etc"}, {"generate", "--root-dir", "/tmp/x/.."}, {"generate", "--root-dir", "/tmp/./x"},
		{"generate", "--root-dir", "/tmp//x"}, {"generate", "--root-dir", "/tmp/x/"}, {"generate", "--root-dir", "/etc/x"}, {"generate", "--root-dir", "/run/x"},
		{"generate", "--root-dir", "/usr/x"}, {"generate", "--root-dir", "/var/x"}, {"generate", "--root-dir", "/tmp/a b"}, {"generate", "--root-dir", "/tmp/a\nb"},
		{"generate", "--root-dir", "/tmp/a;id"}, {"generate", "--root-dir", "/tmp/$x"}, {"generate", "--root-dir", "/tmp/\x00"}, {"generate", "--root-dir", "-x/y"},
		{"generate", "--root-dir", "/tmp/x", "extra"}, {"--root-dir", "/tmp/x", "generate"}, {"generate", "--root-dir=/tmp/x"}, {"generate", "/tmp/x", "--root-dir"},
		{"generate", "--root-dir", "/tmp/" + strings.Repeat("a", 300)},
	}
	for _, a := range no {
		if err := validateNetplan(a); err == nil {
			t.Errorf("%q was accepted", a)
		}
	}
}

// --- CheckBackend ---------------------------------------------------------------------------------

func newNetOps(t *testing.T) (*Ops, string) {
	t.Helper()
	base, err := os.MkdirTemp("", "nt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	state := filepath.Join(base, "state")
	for _, d := range []string{root, state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	o, err := NewWithDeps(Config{StateDir: state, OwnerUID: os.Getuid()}, Deps{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return o, root
}

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckBackend(t *testing.T) {
	t.Parallel()
	good := func(t *testing.T) (*Ops, string) {
		o, root := newNetOps(t)
		put(t, root, "usr/sbin/netplan", "#!/bin/sh\n")
		return o, root
	}
	want := func(t *testing.T, o *Ops, wantRefused bool) {
		t.Helper()
		r := o.CheckBackend()
		if wantRefused != (r != nil) {
			t.Fatalf("CheckBackend = %v, want refused=%v", r, wantRefused)
		}
		if r != nil && (r.Status != 412 || r.Code != "net_backend_unsupported") {
			t.Fatalf("refusal %d %s", r.Status, r.Code)
		}
	}
	t.Run("nothing else", func(t *testing.T) { o, _ := good(t); want(t, o, false) })
	t.Run("only ours in /etc and /run", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "etc/netplan/90-vedette.yaml", "x")
		put(t, root, "run/netplan/90-vedette.yaml", "x")
		want(t, o, false)
	})
	t.Run("files that are not yaml are not netplan files", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "etc/netplan/README", "x")
		put(t, root, "etc/netplan/50.yaml.bak", "x")
		put(t, root, "etc/netplan/50.YAML", "x")
		want(t, o, false)
	})
	t.Run("netplan missing", func(t *testing.T) { o, _ := newNetOps(t); want(t, o, true) })
	t.Run("netplan is a directory", func(t *testing.T) {
		o, root := newNetOps(t)
		if err := os.MkdirAll(filepath.Join(root, "usr/sbin/netplan"), 0o750); err != nil {
			t.Fatal(err)
		}
		want(t, o, true)
	})
	for _, dir := range []string{"etc/netplan", "run/netplan", "lib/netplan"} {
		t.Run("other yaml in "+dir, func(t *testing.T) {
			o, root := good(t)
			put(t, root, dir+"/50-cloud-init.yaml", "network: {}")
			want(t, o, true)
		})
	}
	t.Run("a foreign file next to ours", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "etc/netplan/90-vedette.yaml", "x")
		put(t, root, "run/netplan/01-other.yaml", "x")
		want(t, o, true)
	})
	t.Run("our name in /lib is foreign", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "lib/netplan/90-vedette.yaml", "x")
		want(t, o, true)
	})
	t.Run("a symlink at our file name", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "elsewhere/real.yaml", "x")
		if err := os.MkdirAll(filepath.Join(root, "etc/netplan"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "elsewhere/real.yaml"), filepath.Join(root, "etc/netplan/90-vedette.yaml")); err != nil {
			t.Fatal(err)
		}
		want(t, o, true)
	})
	t.Run("a directory at our file name", func(t *testing.T) {
		o, root := good(t)
		if err := os.MkdirAll(filepath.Join(root, "run/netplan/90-vedette.yaml"), 0o750); err != nil {
			t.Fatal(err)
		}
		want(t, o, true)
	})
	t.Run("a symlink for the directory itself", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "elsewhere/x", "x")
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "elsewhere"), filepath.Join(root, "etc/netplan")); err != nil {
			t.Fatal(err)
		}
		want(t, o, true)
	})
	t.Run("the other files are never read", func(t *testing.T) {
		o, root := good(t)
		put(t, root, "etc/netplan/50-cloud-init.yaml", "x")
		if err := os.Chmod(filepath.Join(root, "etc/netplan/50-cloud-init.yaml"), 0); err != nil {
			t.Fatal(err)
		}
		want(t, o, true) // would fail with a permission error, not a refusal, if it were opened
	})
}

// netplan generate is not in the production runner (slice 3-3 review): the grammar checks the --root-dir string only, and a path that is
// a symlink to "/" passes it. Slice 3-4 brings it back with a directory the host creates itself; until then no production argv names netplan.
func TestProductionRunnerHasNoNetplan(t *testing.T) {
	t.Parallel()
	o, _ := newNetOps(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "root")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{link, "/tmp/x/y"} {
		if _, err := o.runner.Run(t.Context(), binNetplan, []string{"generate", "--root-dir", root}, nil); err == nil {
			t.Fatalf("the production runner ran netplan generate --root-dir %s", root)
		}
	}
	if _, ok := prodPaths[binNetplan]; ok {
		t.Fatal("prodPaths names a netplan binary")
	}
}

package ops

// Properties of the netplan renderer: a value never changes the YAML structure, a scalar a YAML reader takes for
// another type is quoted, and every configuration reads back as itself.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/host/api"
)

// Names that a YAML 1.1 or 1.2 reader resolves to something other than a string when they are plain.
var trickyNames = []string{
	"on", "off", "yes", "no", "y", "n", "Y", "N", "ON", "Off", "NO", "true", "False", "null", "Null", "NULL",
	"0755", "0o17", "0b101", "0x1F", "1_000", "1e3", "1E3", "1.5", "1.", "123", "0", "00", "nan", "NaN", "inf", "Inf",
	"Infinity", "2001-12-14", "2001-12-14t21", "1-2", "a.b", "a@b", "a_b", "x..", "eth0@if5",
}

// Every tricky name, as an interface, a SPAN card and a search domain, is quoted so that a generic YAML
// decoder sees the same string, and the file reads back as exactly the typed configuration.
func TestNetplanQuotesEveryYAML11Scalar(t *testing.T) {
	t.Parallel()
	for _, n := range trickyNames {
		c := staticCfg()
		c.Mgmt.Iface = n
		c.SPAN = "span0"
		if n == "span0" {
			c.SPAN = "span1"
		}
		c.Mgmt.Search = []string{n}
		out, err := renderNetplan(c)
		if err != nil {
			if validIfaceName(n) && dnsNameRE.MatchString(n) {
				t.Errorf("%q: valid name refused: %v", n, err)
			}
			continue
		}
		genericShape(t, out, c)
		back, err := parseNetplan(out)
		if err != nil {
			t.Errorf("%q: not read back: %v\n%s", n, err, out)
			continue
		}
		if back.Mgmt.Iface != n || !slices.Equal(back.Mgmt.Search, []string{n}) {
			t.Errorf("%q: read back as iface %q search %v", n, back.Mgmt.Iface, back.Mgmt.Search)
		}
	}
}

// genericShape decodes the rendered text into untyped YAML and checks the structure: exactly the
// keys the host meant, every interface key a string equal to the name, every search domain a string.
func genericShape(t *testing.T, out []byte, c NetplanConfig) {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal(out, &n); err != nil {
		t.Fatalf("rendered text is not YAML: %v\n%s", err, out)
	}
	var walk func(*yaml.Node)
	walk = func(x *yaml.Node) {
		if x.Anchor != "" || x.Kind == yaml.AliasNode {
			t.Errorf("anchor or alias in rendered text:\n%s", out)
		}
		if x.Kind == yaml.ScalarNode && x.Tag != "!!str" && x.Tag != "!!int" && x.Tag != "!!bool" {
			t.Errorf("scalar %q has tag %s:\n%s", x.Value, x.Tag, out)
		}
		for _, k := range x.Content {
			walk(k)
		}
	}
	walk(&n)
	var g map[string]any
	if err := yaml.Unmarshal(out, &g); err != nil {
		t.Fatal(err)
	}
	netw, ok := g["network"].(map[string]any)
	if !ok || len(g) != 1 {
		t.Fatalf("top level %v", g)
	}
	eths, ok := netw["ethernets"].(map[string]any)
	if !ok {
		t.Fatalf("ethernets %T", netw["ethernets"])
	}
	want := []string{c.Mgmt.Iface}
	if c.SPAN != "" {
		want = append(want, c.SPAN)
	}
	var got []string
	for k := range eths {
		got = append(got, k)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("interface keys %q, want %q:\n%s", got, want, out)
	}
	mg, _ := eths[c.Mgmt.Iface].(map[string]any)
	if ns, ok := mg["nameservers"].(map[string]any); ok {
		if s, ok := ns["search"].([]any); ok {
			for i, v := range s {
				if str, ok := v.(string); !ok || str != c.Mgmt.Search[i] {
					t.Errorf("search[%d] decodes as %T %v, want %q", i, v, v, c.Mgmt.Search[i])
				}
			}
		}
	}
}

// Unicode separators, BOM, NEL, invalid UTF-8, control bytes and over-long values never render.
func TestNetplanRefusesUnicodeAndLongValues(t *testing.T) {
	t.Parallel()
	evil := []string{
		"eth0\u2028x", "eth0\u2029x", "eth0\u0085x", "\ufeffeth0", "eth0\ufeff", "eth\u00a0", "eth0\x7f", "eth0\x1b",
		"eth0\xff", "\xc0\xaf", "eth0\u200b", "eth0\r", "eth0\n", "eth0\t", strings.Repeat("a", 16), strings.Repeat("a", 4096),
	}
	for _, v := range evil {
		for name, mut := range map[string]func(*NetplanConfig){
			"iface":  func(c *NetplanConfig) { c.Mgmt.Iface = v },
			"span":   func(c *NetplanConfig) { c.SPAN = v },
			"search": func(c *NetplanConfig) { c.Mgmt.Search = []string{v + strings.Repeat("a", 60)} },
		} {
			c := staticCfg()
			mut(&c)
			if out, err := renderNetplan(c); err == nil {
				t.Errorf("%s=%q rendered:\n%s", name, v, out)
			}
		}
	}
}

// Round-trip property: random valid configurations render, read back to the same typed values, and
// re-render to the same bytes; the generic YAML shape matches the typed values.
func TestNetplanRoundTripProperty(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(3, 3)) //nolint:gosec // a fixed seed: a reproducible test, not a secret
	alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	tail := alpha + "_.@-"
	name := func(maxLen int) string {
		if r.IntN(4) == 0 {
			return trickyNames[r.IntN(len(trickyNames))]
		}
		b := []byte{alpha[r.IntN(len(alpha))]}
		for range r.IntN(maxLen) {
			b = append(b, tail[r.IntN(len(tail))])
		}
		return string(b)
	}
	rbytes := func() (b [16]byte) {
		binary.LittleEndian.PutUint64(b[:8], r.Uint64())
		binary.LittleEndian.PutUint64(b[8:], r.Uint64())
		return b
	}
	addr4 := func() netip.Addr {
		for {
			rb := rbytes()
			a := netip.AddrFrom4([4]byte{1 + rb[0]%222, rb[1], rb[2], rb[3]})
			if unicast4(a) {
				return a
			}
		}
	}
	tried := 0
	for range 4000 {
		var c NetplanConfig
		c.Mgmt.Iface = name(14)
		if r.IntN(2) == 0 {
			c.Mgmt.Mode = api.NetModeDHCP
		} else {
			c.Mgmt.Mode = api.NetModeStatic
			c.Mgmt.Address = netip.PrefixFrom(addr4(), 8+r.IntN(23))
			if r.IntN(2) == 0 {
				m := c.Mgmt.Address.Masked().Addr().As4()
				m[3] |= 1 + rbytes()[0]%2 // usually a host address of the subnet
				c.Mgmt.Gateway = netip.AddrFrom4(m)
			}
		}
		for range r.IntN(4) {
			if r.IntN(2) == 0 {
				c.Mgmt.DNS = append(c.Mgmt.DNS, addr4())
			} else {
				b := rbytes()
				b[0] = 0x20
				c.Mgmt.DNS = append(c.Mgmt.DNS, netip.AddrFrom16(b))
			}
		}
		for range r.IntN(7) {
			s := name(14)
			if r.IntN(3) == 0 {
				s += "." + name(20)
			}
			c.Mgmt.Search = append(c.Mgmt.Search, s)
		}
		if r.IntN(2) == 0 {
			c.SPAN = name(14)
		}
		out, err := renderNetplan(c)
		if err != nil {
			continue // invalid by the rules (gateway outside the subnet, same card twice...)
		}
		tried++
		genericShape(t, out, c)
		back, err := parseNetplan(out)
		if err != nil {
			t.Fatalf("rendered text not read back: %v\n%+v\n%s", err, c, out)
		}
		norm := func(x NetplanConfig) string {
			if len(x.Mgmt.Search) == 0 {
				x.Mgmt.Search = nil
			}
			if len(x.Mgmt.DNS) == 0 {
				x.Mgmt.DNS = nil
			}
			return fmt.Sprintf("%#v", x)
		}
		if norm(back) != norm(c) {
			t.Fatalf("read back differs:\n got %s\nwant %s\n%s", norm(back), norm(c), out)
		}
		again, _ := renderNetplan(back)
		if !bytes.Equal(again, out) {
			t.Fatalf("re-render differs")
		}
		if !bytes.HasPrefix(out, []byte(netplanHeader)) || bytes.ContainsAny(out, "&*!|>%\t\r") {
			t.Fatalf("unexpected YAML indicator in:\n%s", out)
		}
		for _, ch := range string(out) {
			if ch > 0x7e {
				t.Fatalf("non-ASCII byte in:\n%s", out)
			}
		}
	}
	if tried < 500 {
		t.Fatalf("only %d valid configurations generated", tried)
	}
}

// parseNetplan's read path is bounded before the read: a file far over the cap is not read whole.
// (readNetplanFile reads through LimitReader(maxNetplan+1); this pins that a 10 MiB file is refused.)
func TestReadNetplanFileIsBounded(t *testing.T) {
	t.Parallel()
	o, root := newNetOps(t)
	good, _ := renderNetplan(staticCfg())
	big := append(append([]byte{}, good...), bytes.Repeat([]byte("# x\n"), 10<<18)...)
	if err := os.MkdirAll(filepath.Join(root, "etc/netplan"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/netplan", netplanName), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.readNetplanConfig(); ok {
		t.Fatal("an oversized file was accepted")
	}
}

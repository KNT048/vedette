package honeypot

import (
	"encoding/hex"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/content/oui"
)

// INV-5: the network and broadcast addresses are never usable, for any prefix, not only ones whose host part starts at an even
// octet (#270: `|` and `-` share a precedence level, so lastAddr of 192.168.1.0/24 came out as 192.168.0.255).
func TestUsableRefusesNetworkAndBroadcast(t *testing.T) {
	cases := []struct {
		prefix, ip string
		want       bool
	}{
		{"192.168.1.0/24", "192.168.1.255", false},
		{"192.168.1.0/24", "192.168.1.0", false},
		{"192.168.1.0/24", "192.168.1.254", true},
		{"192.168.1.0/24", "192.168.0.255", false},
		{"192.168.10.0/24", "192.168.10.255", false},
		{"10.1.3.0/23", "10.1.3.255", false},
		{"10.1.2.0/23", "10.1.3.255", false},
		{"10.1.2.0/23", "10.1.2.255", true},
		{"172.16.5.64/26", "172.16.5.127", false},
		{"172.16.5.64/26", "172.16.5.126", true},
		{"10.0.0.0/8", "10.255.255.255", false},
		{"10.0.0.0/8", "10.255.255.254", true},
		{"192.168.1.4/30", "192.168.1.7", false},
		{"192.168.1.4/30", "192.168.1.6", true},
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		if got := usable(p, netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("usable(%s, %s) = %v, want %v (lastAddr %s)", c.prefix, c.ip, got, c.want, lastAddr(p))
		}
	}
}

// presets.go and web/src/features/honeypot/presets.ts are the same data (D-466): the form fills what the box checks.
func TestPresetsMatchTheGUI(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../web/src/features/honeypot/presets.ts")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	presetRE := regexp.MustCompile(`\{ id: '(\w+)', services: \[([^\]]*)\], vendor: (?:null|'(\w+)'), kinds: \[[^\]]*\], example: '([\w-]+)' \}`)
	got := presetRE.FindAllStringSubmatch(src, -1)
	if len(got) != len(presets) {
		t.Fatalf("%d presets in presets.ts, %d in presets.go", len(got), len(presets))
	}
	for i, m := range got {
		p := presets[i]
		var svcs []ServiceName
		for _, q := range regexp.MustCompile(`'(\w+)'`).FindAllStringSubmatch(m[2], -1) {
			svcs = append(svcs, ServiceName(q[1]))
		}
		if string(p.id) != m[1] || !slices.Equal(p.services, svcs) || p.vendor != m[3] || p.example != m[4] {
			t.Errorf("preset %d: go %+v, ts %q", i, p, m[0])
		}
	}
	vendorRE := regexp.MustCompile(`\{ id: '(\w+)', oui: '([0-9A-F:]+)' \}`)
	vs := vendorRE.FindAllStringSubmatch(src, -1)
	if len(vs) != len(vendors) {
		t.Fatalf("%d vendors in presets.ts, %d in presets.go", len(vs), len(vendors))
	}
	for i, m := range vs {
		if v := vendors[i]; v.id != m[1] || v.oui != strings.ToLower(strings.ReplaceAll(m[2], ":", "")) {
			t.Errorf("vendor %d: go %+v, ts %q", i, v, m[0])
		}
	}
	for _, p := range presets {
		if _, ok := vendorOUI(p.vendor); p.vendor != "" && !ok {
			t.Errorf("preset %s names an unknown vendor %s", p.id, p.vendor)
		}
	}
}

// Each vendor's MAC prefix is registered to that vendor in the D-83 table: a scanner on the LAN shows the vendor the owner picked.
func TestVendorOUIsBelongToTheVendor(t *testing.T) {
	t.Parallel()
	for _, v := range vendors {
		b, err := hex.DecodeString(v.oui + "000000")
		if err != nil || len(b) != 6 {
			t.Fatalf("%s: bad oui %q", v.id, v.oui)
		}
		got, ok := oui.Lookup([6]byte(b))
		if !ok || !strings.Contains(strings.ToLower(got), strings.ToLower(v.name)) {
			t.Errorf("%s: %s is registered to %q, want %q", v.id, v.oui, got, v.name)
		}
		if mv := macVendor(v.oui[:2] + ":" + v.oui[2:4] + ":" + v.oui[4:] + ":01:02:03"); mv == nil || *mv != got {
			t.Errorf("%s: macVendor %v", v.id, mv)
		}
	}
	if macVendor("06:b7:36:4f:54:67") != nil || macVendor("nonsense") != nil {
		t.Error("a locally administered or broken MAC has a vendor")
	}
}

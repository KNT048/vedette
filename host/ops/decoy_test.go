package ops

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"net/netip"
)

func TestParseOUI(t *testing.T) {
	t.Parallel()
	for in, want := range map[string][3]byte{"001A2B": {0x00, 0x1a, 0x2b}, "f0def1": {0xf0, 0xde, 0xf1}} {
		v, ok, err := parseOUI(in)
		if err != nil || !ok || v != want {
			t.Errorf("%q: %v %v %v", in, v, ok, err)
		}
	}
	if _, ok, err := parseOUI(""); ok || err != nil {
		t.Errorf("empty: %v %v", ok, err)
	}
	for _, in := range []string{
		"01005E", // multicast
		"030000", // multicast and local
		"020000", // locally administered
		"FE0000", // local (bit 1 set)
		"00:1A:2B", "001A2", "001A2B0", "00 1A2B", "0x1A2B", "GG1A2B", "-01A2B", "００1A2B", "001A2B\n",
	} {
		if _, _, err := parseOUI(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestDeriveMAC(t *testing.T) {
	t.Parallel()
	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)
	seen := map[string]bool{}
	for i := range 200 {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i), byte(i * 7)})
		m := deriveMAC(k1, ip, nil)
		if len(m) != 6 || m[0]&0x02 == 0 || m[0]&0x01 != 0 {
			t.Fatalf("%s: bits of %s", ip, m)
		}
		if deriveMAC(k1, ip, nil).String() != m.String() {
			t.Fatalf("not stable for %s", ip)
		}
		if deriveMAC(k2, ip, nil).String() == m.String() {
			t.Fatalf("another key gave the same MAC for %s", ip)
		}
		seen[m.String()] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d distinct MACs in 200", len(seen))
	}
	oui := [3]byte{0x00, 0x1a, 0x2b}
	ip := netip.MustParseAddr("192.168.1.50")
	m := deriveMAC(k1, ip, &oui)
	if !strings.HasPrefix(m.String(), "00:1a:2b:") || m[0]&0x03 != 0 {
		t.Fatalf("oui mac %s", m)
	}
	if m2 := deriveMAC(k1, ip, nil); m2[3] == m[3] && m2[4] == m[4] && m2[5] == m[5] && m2[0] == m[0] {
		// the default MAC and the OUI one are different constructions; they share no tail by design of the first 3 bytes only
		t.Log("same tail by chance")
	}
	if deriveMAC(k1, ip, &oui).String() != m.String() {
		t.Fatal("oui mac not stable")
	}
}

func TestMACKeyIsCreatedOnceAndRefusesLiesAboutTheFile(t *testing.T) {
	t.Parallel()
	o, _ := newNetOps(t)
	k1, err := o.loadMACKey()
	if err != nil || len(k1) != 32 {
		t.Fatalf("%v %v", k1, err)
	}
	path := filepath.Join(o.cfg.StateDir, "hp", "mac.key")
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	k2, err := o.loadMACKey()
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("the key changed: %v", err)
	}
	if bytes.Equal(k1, make([]byte, 32)) {
		t.Fatal("all-zero key")
	}
	// Another installation: another key.
	o2, _ := newNetOps(t)
	if k3, _ := o2.loadMACKey(); bytes.Equal(k1, k3) {
		t.Fatal("two installs share a key")
	}
	// Wrong permissions: refused, and not replaced.
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // the test makes the file readable by the group on purpose
		t.Fatal(err)
	}
	if _, err := o.loadMACKey(); err == nil {
		t.Fatal("mode 640 accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// A wrong length: refused, not regenerated.
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.loadMACKey(); err == nil {
		t.Fatal("a short key was accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != "short" { //nolint:gosec // a path of the test's own temp dir
		t.Fatal("the bad key was replaced")
	}
	// A symlink is refused and its target is untouched.
	target := filepath.Join(o.cfg.StateDir, "elsewhere")
	if err := os.WriteFile(target, k1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := o.loadMACKey(); err == nil {
		t.Fatal("a symlink was followed")
	}
	// A directory is not a key.
	_ = os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := o.loadMACKey(); err == nil {
		t.Fatal("a directory was accepted")
	}
}

func goodDecoys() string {
	return `{"decoys":[{"ip":"10.0.0.50","mac":"02:11:22:33:44:55","table":100,"iface":"eth0"},` +
		`{"ip":"10.0.0.51","mac":"02:11:22:33:44:56","table":101,"iface":"eth0"}]}`
}

func TestParseDecoysIsStrict(t *testing.T) {
	t.Parallel()
	l, err := parseDecoys([]byte(goodDecoys()))
	if err != nil || len(l) != 2 {
		t.Fatalf("%v %v", l, err)
	}
	if l, err := parseDecoys([]byte(`{"decoys":[]}`)); err != nil || len(l) != 0 {
		t.Fatalf("%v %v", l, err)
	}
	bad := map[string]string{
		"trailing":       goodDecoys() + "{}",
		"unknown field":  strings.Replace(goodDecoys(), `"table":100`, `"table":100,"x":1`, 1),
		"unknown top":    `{"decoys":[],"x":1}`,
		"not json":       `nope`,
		"null entry":     `{"decoys":[null]}`,
		"v6":             strings.Replace(goodDecoys(), "10.0.0.50", "fd00::1", 1),
		"mapped v4":      strings.Replace(goodDecoys(), "10.0.0.50", "::ffff:10.0.0.50", 1),
		"leading zero":   strings.Replace(goodDecoys(), "10.0.0.50", "010.0.0.50", 1),
		"loopback":       strings.Replace(goodDecoys(), "10.0.0.50", "127.0.0.1", 1),
		"multicast mac":  strings.Replace(goodDecoys(), "02:11:22:33:44:55", "03:11:22:33:44:55", 1),
		"upper mac":      strings.Replace(goodDecoys(), "02:11:22:33:44:55", "02:11:22:33:44:AA", 1),
		"short mac":      strings.Replace(goodDecoys(), "02:11:22:33:44:55", "02:11:22:33:44", 1),
		"table low":      strings.Replace(goodDecoys(), `"table":100`, `"table":99`, 1),
		"table high":     strings.Replace(goodDecoys(), `"table":100`, `"table":132`, 1),
		"table twice":    strings.Replace(goodDecoys(), `"table":101`, `"table":100`, 1),
		"ip twice":       strings.Replace(goodDecoys(), "10.0.0.51", "10.0.0.50", 1),
		"mac twice":      strings.Replace(goodDecoys(), "44:56", "44:55", 1),
		"iface option":   strings.Replace(goodDecoys(), `"eth0"`, `"-eth0"`, 1),
		"iface space":    strings.Replace(goodDecoys(), `"eth0"`, `"eth 0"`, 1),
		"iface too long": strings.Replace(goodDecoys(), `"eth0"`, `"abcdefghijklmnopq"`, 1),
	}
	for name, in := range bad {
		if _, err := parseDecoys([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the size cap and the count cap
	if _, err := parseDecoys(bytes.Repeat([]byte(" "), maxDecoysFile+1)); err == nil {
		t.Error("an oversized file was accepted")
	}
	var b strings.Builder
	b.WriteString(`{"decoys":[`)
	for i := range 33 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"ip":"10.0.1.` + itoa(i+1) + `","mac":"02:00:00:00:00:` + hex2(i) + `","table":` + itoa(100+i%32) + `,"iface":"eth0"}`)
	}
	b.WriteString(`]}`)
	if _, err := parseDecoys([]byte(b.String())); err == nil {
		t.Error("33 decoys accepted")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
func hex2(i int) string { return fmt.Sprintf("%02x", i) }

func TestReadDecoysRefusesALinkAndSetsAnInvalidFileAside(t *testing.T) {
	t.Parallel()
	o, _ := newNetOps(t)
	if l, err := o.readDecoys(); err != nil || l != nil {
		t.Fatalf("missing file: %v %v", l, err)
	}
	if err := o.saveDecoys([]decoyEntry{{IP: "10.0.0.50", MAC: "02:11:22:33:44:55", Table: 100, Iface: "eth0"}}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(o.decoysPath()); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if l, err := o.readDecoys(); err != nil || len(l) != 1 {
		t.Fatalf("%v %v", l, err)
	}
	// hostile content: set aside by the writer's loader, the reader only refuses
	if err := os.WriteFile(o.decoysPath(), []byte(`{"decoys":[{"ip":"1.2.3.4 -x"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.readDecoys(); err == nil {
		t.Fatal("hostile file read")
	}
	l, q, err := o.loadDecoys()
	if err != nil || !q || len(l) != 0 {
		t.Fatalf("%v %v %v", l, q, err)
	}
	if _, err := os.Stat(o.decoysPath() + ".invalid"); err != nil {
		t.Fatalf("not set aside: %v", err)
	}
	// a symlink in place of the file is not followed
	target := filepath.Join(o.cfg.StateDir, "x.json")
	if err := os.WriteFile(target, []byte(goodDecoys()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, o.decoysPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := o.readDecoys(); err == nil {
		t.Fatal("a symlink was followed")
	}
}

func TestFreeTableIsTheLowestFreeAndStable(t *testing.T) {
	t.Parallel()
	var l []decoyEntry
	for i := range 32 {
		tbl, ok := freeTable(l)
		if !ok || tbl != 100+i {
			t.Fatalf("step %d: %d %v", i, tbl, ok)
		}
		l = append(l, decoyEntry{Table: tbl})
	}
	if _, ok := freeTable(l); ok {
		t.Fatal("a 33rd table")
	}
	// removing the middle one frees exactly its table; the others keep theirs
	l = append(l[:5], l[6:]...)
	if tbl, ok := freeTable(l); !ok || tbl != 105 {
		t.Fatalf("%d %v", tbl, ok)
	}
}

func TestRefusalFor(t *testing.T) {
	t.Parallel()
	m := mgmtNet{Iface: "eth0", Prefix: netip.MustParsePrefix("192.168.1.50/24"), Gateway: netip.MustParseAddr("192.168.1.1")}
	host := []netip.Addr{netip.MustParseAddr("192.168.1.50"), netip.MustParseAddr("192.168.1.77")}
	for ip, want := range map[string]string{
		"192.168.1.100": "", "192.168.1.2": "", "192.168.1.254": "",
		"192.168.2.100": "ip_not_in_mgmt_subnet", "10.0.0.1": "ip_not_in_mgmt_subnet",
		"192.168.1.0": "ip_is_network", "192.168.1.255": "ip_is_broadcast", "192.168.1.1": "ip_is_gateway",
		"192.168.1.50": "ip_is_host", "192.168.1.77": "ip_is_host",
	} {
		if got, _ := m.refusalFor(netip.MustParseAddr(ip), host); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	// no gateway: the gateway address is just an address
	m.Gateway = netip.Addr{}
	if got, _ := m.refusalFor(netip.MustParseAddr("192.168.1.1"), host); got != "" {
		t.Errorf("no gateway: %q", got)
	}
	// a /31 and a /30 leave no free host or a few
	m31 := mgmtNet{Iface: "eth0", Prefix: netip.MustParsePrefix("10.0.0.1/31")}
	for _, ip := range []string{"10.0.0.0", "10.0.0.1"} {
		if got, _ := m31.refusalFor(netip.MustParseAddr(ip), nil); got == "" {
			t.Errorf("/31 %s accepted", ip)
		}
	}
}

func TestHasEgressDrop(t *testing.T) {
	t.Parallel()
	good := "table inet vedette_hp {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state established,related accept\n\t\tct state new drop\n\t}\n}\n"
	if !hasEgressDrop([]byte(good)) {
		t.Fatal("the real listing is not recognised")
	}
	if !hasEgressDrop([]byte(strings.Replace(good, "established,related", "{ established, related }", 1))) {
		t.Fatal("the braces form is not recognised")
	}
	for name, in := range map[string]string{
		"empty":                 "",
		"no drop":               strings.Replace(good, "\t\tct state new drop\n", "", 1),
		"accept only":           strings.Replace(good, "ct state new drop", "ct state new accept", 1),
		"drop first":            "table inet vedette_hp {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state new drop\n\t\tct state established,related accept\n\t}\n}\n",
		"other table":           strings.Replace(good, "vedette_hp", "other", 1),
		"other family":          strings.Replace(good, "inet", "ip", 1),
		"not output":            strings.Replace(good, "hook output", "hook input", 1),
		"no hook":               strings.Replace(good, "\t\ttype filter hook output priority filter; policy accept;\n", "", 1),
		"drop in a later table": strings.Replace(good, "\t\tct state new drop\n\t}\n}\n", "\t}\n}\ntable inet other {\n\tchain output {\n\t\tct state new drop\n\t}\n}\n", 1),
	} {
		// "drop first": the drop before the accept would kill the replies, so the order counts
		if hasEgressDrop([]byte(in)) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCheckNSFile(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*Ops, string) {
		o, root := newNetOps(t)
		o.d.IsNsfs = func(*os.File) (bool, error) { return true, nil }
		return o, filepath.Join(root, "run/netns")
	}
	t.Run("absent", func(t *testing.T) {
		o, _ := setup(t)
		if p, err := o.checkNSFile(); p || err != nil {
			t.Fatalf("%v %v", p, err)
		}
	})
	t.Run("directory without the file", func(t *testing.T) {
		o, dir := setup(t)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if p, err := o.checkNSFile(); p || err != nil {
			t.Fatalf("%v %v", p, err)
		}
	})
	t.Run("a good one", func(t *testing.T) {
		o, dir := setup(t)
		mustWrite(t, dir, "vedette-hp")
		if p, err := o.checkNSFile(); !p || err != nil {
			t.Fatalf("%v %v", p, err)
		}
	})
	t.Run("not nsfs", func(t *testing.T) {
		o, dir := setup(t)
		o.d.IsNsfs = func(*os.File) (bool, error) { return false, nil }
		mustWrite(t, dir, "vedette-hp")
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("an ordinary file was accepted")
		}
	})
	t.Run("a symlink at the name", func(t *testing.T) {
		o, dir := setup(t)
		mustWrite(t, dir, "real")
		if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "vedette-hp")); err != nil {
			t.Fatal(err)
		}
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("a symlink was accepted")
		}
	})
	t.Run("a symlink dangling", func(t *testing.T) {
		o, dir := setup(t)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/proc/self/ns/net", filepath.Join(dir, "vedette-hp")); err != nil {
			t.Fatal(err)
		}
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("a symlink to the host namespace was accepted")
		}
	})
	t.Run("a directory at the name", func(t *testing.T) {
		o, dir := setup(t)
		if err := os.MkdirAll(filepath.Join(dir, "vedette-hp"), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("a directory was accepted")
		}
	})
	t.Run("run/netns is a symlink", func(t *testing.T) {
		o, dir := setup(t)
		other := filepath.Join(filepath.Dir(dir), "other")
		mustWrite(t, other, "vedette-hp")
		if err := os.Symlink(other, dir); err != nil {
			t.Fatal(err)
		}
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("a symlinked /run/netns was accepted")
		}
	})
	t.Run("run/netns is writable by others", func(t *testing.T) {
		o, dir := setup(t)
		mustWrite(t, dir, "vedette-hp")
		if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the test makes the directory world-writable on purpose
			t.Fatal(err)
		}
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("a world-writable /run/netns was accepted")
		}
	})
	t.Run("a FIFO does not block", func(t *testing.T) {
		o, dir := setup(t)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := mkfifo(filepath.Join(dir, "vedette-hp")); err != nil {
			t.Skip("no mkfifo")
		}
		if _, err := o.checkNSFile(); err == nil {
			t.Fatal("a FIFO was accepted")
		}
	})
}

func mustWrite(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// FuzzParseDecoys: whatever the bytes are, what parseDecoys accepts is a list a command line can be
// built from: canonical IPv4 unicast addresses, lowercase unicast MACs, a table of 100 to 131 and a
// card name, each unique, at most 32; and building the argv of each entry passes the ip grammar.
func FuzzParseDecoys(f *testing.F) {
	f.Add([]byte(goodDecoys()))
	f.Add([]byte(`{"decoys":[]}`))
	f.Add([]byte(`{"decoys":[{"ip":"10.0.0.50","mac":"02:11:22:33:44:55","table":100,"iface":"-n"}]}`))
	f.Add([]byte(`{"decoys":[{"ip":"10.0.0.50","mac":"02:11:22:33:44:55","table":100,"iface":"eth0"}]}{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		list, err := parseDecoys(b)
		if err != nil {
			return
		}
		if len(list) > 32 {
			t.Fatalf("%d entries", len(list))
		}
		seen := map[string]bool{}
		for _, e := range list {
			ip, perr := parseDecoyIP(e.IP)
			if perr != nil || seen[e.IP] || !tableOK(e.Table) || !validIfaceName(e.Iface) || !macLowerRE.MatchString(e.MAC) {
				t.Fatalf("accepted a bad entry %+v", e)
			}
			seen[e.IP] = true
			name := linkName(ip)
			for _, a := range [][]string{argvLinkAdd(e.Iface, name, e.MAC), argvRule("add", ip, e.Table), argvRouteFlush(e.Table)} {
				if err := validateIP(a); err != nil {
					t.Fatalf("entry %+v gives an argv the grammar refuses: %q", e, a)
				}
			}
		}
	})
}

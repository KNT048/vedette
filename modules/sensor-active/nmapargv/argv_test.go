package nmapargv

import (
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func addrs(t testing.TB, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestBuild(t *testing.T) {
	t.Parallel()
	one := addrs(t, "192.168.10.20")
	tests := []struct {
		name    string
		kind    Kind
		rate    int
		targets []netip.Addr
		want    []string
	}{
		{"sweep", Sweep, 50, addrs(t, "192.168.10.1", "192.168.10.2"),
			[]string{"--privileged", "-sn", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1", "192.168.10.2"}},
		{"normal", Normal, 100, one,
			[]string{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", "100", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}},
		{"versions: no -O, the same two scripts (D-504)", Versions, 25, one,
			[]string{"--privileged", "-sS", "-sV", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", "25", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}},
		{"gentle ignores the rate given: 1 packet per second, no -sV", Gentle, 500, one,
			[]string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.20"}},
		{"gentle with titles (D-511): the gentle line plus http-title and ssl-cert, each capped at 20 s", GentleTitles, 500, one,
			[]string{"--privileged", "-sS", "--script", "http-title,ssl-cert", "--script-timeout", "20s", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.20"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Build(tt.kind, tt.rate, tt.targets)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("argv = %q\nwant   %q", got, tt.want)
			}
			if err := Validate(got); err != nil {
				t.Fatalf("the validator rejects what the builder made: %v", err)
			}
		})
	}
	// The gentle line never carries OS detection, version detection (which runs the "version" NSE scripts) or
	// a script (D-45, FORBID-6).
	g, _ := Build(Gentle, 10, one)
	for _, a := range g {
		if a == "-O" || a == "-sV" || strings.HasPrefix(a, "--script") || strings.HasPrefix(a, "--version") || a == "-A" || a == "-sC" {
			t.Fatalf("gentle argv has %q", a)
		}
	}
}

func TestBuildRefuses(t *testing.T) {
	t.Parallel()
	many := make([]netip.Addr, MaxBatch+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
	}
	for name, c := range map[string]struct {
		rate    int
		targets []netip.Addr
	}{
		"no target":         {10, nil},
		"too many targets":  {10, many},
		"rate 0":            {0, many[:1]},
		"rate over 1000":    {1001, many[:1]},
		"IPv6 target":       {10, addrs(t, "fd00::1")},
		"zero value target": {10, []netip.Addr{{}}},
		"public target":     {10, addrs(t, "8.8.8.8")},
		"loopback":          {10, addrs(t, "127.0.0.1")},
	} {
		if _, err := Build(Normal, c.rate, c.targets); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Build(Kind(9), 10, many[:1]); err == nil {
		t.Error("unknown kind accepted")
	}
}

// The four shapes written out apart from the code under test (INV-4, SYS-2; versions: D-501).
var (
	shapeSweep    = []string{"--privileged", "-sn", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1"}
	shapeNormal   = []string{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", "100", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}
	shapeGentle   = []string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"}
	shapeVersions = []string{"--privileged", "-sS", "-sV", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", "25", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.40"}
	shapeTitles   = []string{"--privileged", "-sS", "--script", "http-title,ssl-cert", "--script-timeout", "20s", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.50"}
)

// INV-4, SYS-2: the validator accepts exactly three command shapes, with only the rate (of sweep and normal)
// and the targets variable. Anything else is rejected, including flags that are individually harmless: a
// missing -n would let nmap resolve names, a missing --max-rate would run at full speed, and mixing the gentle
// and the normal flags would run -O on a fragile device.
func TestValidate(t *testing.T) {
	t.Parallel()
	with := func(base []string, extra ...string) []string { return append(slices.Clone(base), extra...) }
	swap := func(base []string, from, to string) []string {
		out := slices.Clone(base)
		out[slices.Index(out, from)] = to
		return out
	}
	drop := func(base []string, tokens ...string) []string {
		return slices.DeleteFunc(slices.Clone(base), func(a string) bool { return slices.Contains(tokens, a) })
	}
	bad := map[string][]string{
		"empty":                                {},
		"no privileged":                        drop(shapeNormal, "--privileged"),
		"aggressive":                           with(shapeNormal[:len(shapeNormal)-3], "-A", "-oX", "-", "192.168.10.20"),
		"script":                               {"--privileged", "-sS", "--script", "vuln", "-oX", "-", "192.168.10.1"},
		"script=":                              {"--privileged", "-sS", "--script=vuln", "-oX", "-", "192.168.10.1"},
		"default scripts":                      {"--privileged", "-sS", "-sC", "-oX", "-", "192.168.10.1"},
		"another script list":                  swap(shapeNormal, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "rdp-ntlm-info,smb-os-discovery"),
		"script list reordered":                swap(shapeNormal, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "http-ntlm-info,rdp-ntlm-info,http-title,ssl-cert"),
		"script category":                      swap(shapeVersions, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "safe"),
		"script wildcard":                      swap(shapeVersions, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "*-ntlm-info"),
		"script list without the flag":         drop(shapeNormal, "--script"),
		"normal without its scripts":           drop(shapeNormal, "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert"),
		"output to a file":                     {"--privileged", "-sS", "-oN", "/tmp/x", "-oX", "-", "192.168.10.1"},
		"xml to a file":                        swap(shapeNormal, "-", "/tmp/x"),
		"input list":                           {"--privileged", "-sS", "-iL", "/etc/hosts", "-oX", "-", "192.168.10.1"},
		"no xml":                               {"--privileged", "-sn", "-n", "--max-rate", "50", "192.168.10.1"},
		"sweep without -n (reverse DNS)":       drop(shapeSweep, "-n"),
		"sweep without --max-rate":             drop(shapeSweep, "--max-rate", "50"),
		"normal without --max-rate":            drop(shapeNormal, "--max-rate", "100"),
		"normal without -n":                    drop(shapeNormal, "-n"),
		"normal without --host-timeout":        drop(shapeNormal, "--host-timeout", "30m"),
		"normal with the gentle host timeout":  swap(shapeNormal, "30m", "15m"),
		"normal with all ports":                swap(shapeNormal, "1000", "65535"),
		"-sS without --top-ports":              drop(shapeNormal, "--top-ports", "1000"),
		"sweep with service detection":         with(shapeSweep[:4], "-sV", "--max-rate", "50", "-oX", "-", "192.168.10.1"),
		"sweep with the normal flags added":    {"--privileged", "-sn", "-sV", "-O", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1"},
		"gentle with -sV (version scripts)":    {"--privileged", "-sS", "-sV", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"},
		"gentle with --version-intensity":      {"--privileged", "-sS", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"},
		"gentle flags mixed with -O at 1000":   {"--privileged", "-sS", "-sV", "-O", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1000", "--top-ports", "1000", "-oX", "-", "192.168.10.30"},
		"gentle at a rate above 1":             swap(swap(shapeGentle, "--max-rate", "--max-rate"), "1", "5"),
		"gentle with -O":                       with([]string{"--privileged", "-sS", "-O"}, shapeGentle[2:]...),
		"duplicate flag":                       with([]string{"--privileged", "-sn", "-sn"}, shapeSweep[2:]...),
		"flags in another order":               {"--privileged", "-n", "-sn", "--max-rate", "50", "-oX", "-", "192.168.10.1"},
		"rate 0":                               swap(shapeSweep, "50", "0"),
		"rate 1001":                            swap(shapeSweep, "50", "1001"),
		"rate with a sign":                     swap(shapeSweep, "50", "+5"),
		"rate with a zero":                     swap(shapeSweep, "50", "05"),
		"rate missing":                         {"--privileged", "-sn", "-n", "--max-rate"},
		"timing 5":                             swap(shapeGentle, "-T2", "-T5"),
		"no target":                            shapeSweep[:len(shapeSweep)-1],
		"flag after the targets":               with(shapeSweep, "-A"),
		"hostname":                             with(shapeSweep[:len(shapeSweep)-1], "example.com"),
		"cidr":                                 with(shapeSweep[:len(shapeSweep)-1], "192.168.10.0/24"),
		"range":                                with(shapeSweep[:len(shapeSweep)-1], "192.168.10.1-5"),
		"leading zero":                         with(shapeSweep[:len(shapeSweep)-1], "192.168.10.01"),
		"IPv6":                                 with(shapeSweep[:len(shapeSweep)-1], "fd00::1"),
		"mapped IPv6":                          with(shapeSweep[:len(shapeSweep)-1], "::ffff:192.168.10.1"),
		"zone":                                 with(shapeSweep[:len(shapeSweep)-1], "fe80::1%eth0"),
		"duplicate target":                     with(shapeSweep, "192.168.10.1"),
		"shell":                                with(shapeSweep[:len(shapeSweep)-1], "192.168.10.1;id"),
		"empty token":                          with(shapeSweep, ""),
		"versions without --host-timeout":      drop(shapeVersions, "--host-timeout", "30m"),
		"versions without --max-rate":          drop(shapeVersions, "--max-rate", "25"),
		"gentle titles with the NTLM scripts":  swap(shapeTitles, "http-title,ssl-cert", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert"),
		"gentle titles with a script category": swap(shapeTitles, "http-title,ssl-cert", "default"),
		"gentle titles without script timeout": drop(shapeTitles, "--script-timeout", "20s"),
		"gentle titles with a longer timeout":  swap(shapeTitles, "20s", "5m"),
		"gentle titles at a rate above 1":      func() []string { a := slices.Clone(shapeTitles); a[slices.Index(a, "--max-rate")+1] = "5"; return a }(),
		"gentle titles with -sV":               with([]string{"--privileged", "-sS", "-sV"}, shapeTitles[2:]...),
		"versions with -O after -sV":           {"--privileged", "-sS", "-sV", "-n", "-O", "--max-rate", "25", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.40"},
	}
	for name, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
	for name, argv := range map[string][]string{"sweep": shapeSweep, "normal": shapeNormal, "gentle": shapeGentle, "versions": shapeVersions, "gentle_titles": shapeTitles, "two targets": with(shapeSweep, "192.168.10.2")} {
		if err := Validate(argv); err != nil {
			t.Errorf("%s: a good argv is rejected: %v", name, err)
		}
	}
	base := slices.Clone(shapeSweep[:len(shapeSweep)-1])
	over := make([]string, MaxBatch+1)
	for i := range over {
		over[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String()
	}
	if err := Validate(with(base, over...)); err == nil {
		t.Error("more than MaxBatch targets accepted")
	}
	if err := Validate(with(base, over[:MaxBatch]...)); err != nil {
		t.Errorf("MaxBatch targets rejected: %v", err)
	}
}

// L1: lan_ranges can only be RFC 1918 or RFC 6598 shared address space ranges (D-461), so no legitimate argv names a
// public (the rest of 100/8 too), loopback, link-local, multicast, reserved, broadcast or unspecified address, and the
// validator refuses them all.
func TestValidateRefusesNonPrivateTargets(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"8.8.8.8", "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "240.0.0.1", "127.0.0.1", "169.254.1.1", "100.63.255.255", "100.128.0.0", "100.1.2.3", "172.15.0.1", "172.32.0.1", "192.169.0.1", "11.0.0.1"} {
		argv := slices.Clone(shapeSweep[:len(shapeSweep)-1])
		if err := Validate(append(argv, target)); err == nil {
			t.Errorf("accepted target %s, which no confirmed LAN range can contain", target)
		}
	}
	for _, target := range []string{"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.0.1", "100.64.0.1", "100.65.254.7", "100.127.255.254"} {
		argv := slices.Clone(shapeSweep[:len(shapeSweep)-1])
		if err := Validate(append(argv, target)); err != nil {
			t.Errorf("refused the private target %s: %v", target, err)
		}
	}
}

// private is the oracle's own idea of RFC 1918 and RFC 6598 (100.64-127.x, D-461), not netip's or localnet's.
var private = regexp.MustCompile(`^(10\.([0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3})$`)

// shapeOracle knows the four shapes and nothing else: the flags before "-oX" must be one of them, with the
// rate of sweep, normal and versions written as plain digits between 1 and 1000.
func shapeOracle(flags []string) bool {
	rate := regexp.MustCompile(`^([1-9][0-9]{0,2}|1000)$`)
	withRate := func(shape []string, at int) bool {
		want := shape[:slices.Index(shape, "-oX")]
		return len(flags) == len(want) && rate.MatchString(flags[at]) &&
			slices.Equal(flags[:at], want[:at]) && slices.Equal(flags[at+1:], want[at+1:])
	}
	return withRate(shapeSweep, 4) || withRate(shapeNormal, 8) || withRate(shapeVersions, 7) || slices.Equal(flags, shapeGentle[:slices.Index(shapeGentle, "-oX")]) ||
		slices.Equal(flags, shapeTitles[:slices.Index(shapeTitles, "-oX")])
}

func FuzzValidate(f *testing.F) {
	for _, s := range [][]string{
		shapeSweep, shapeNormal, shapeGentle, shapeVersions, shapeTitles,
		{"--privileged", "-sn", "-n", "--max-rate", "1000", "-oX", "-", "10.0.0.1", "10.0.0.2"},
		{"--privileged", "-A", "-oX", "-", "10.0.0.1"},
		{"--privileged", "-sS", "--script", "vuln", "-oX", "-", "10.0.0.1"},
	} {
		f.Add(strings.Join(s, "\n"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		argv := strings.Split(joined, "\n")
		if Validate(argv) != nil {
			return
		}
		i := slices.Index(argv, "-oX")
		if i < 0 || i+1 >= len(argv) || argv[i+1] != "-" || !shapeOracle(argv[:i]) {
			t.Fatalf("accepted an argv that is not one of the five shapes: %q", argv)
		}
		targets := argv[i+2:]
		if len(targets) < 1 || len(targets) > MaxBatch {
			t.Fatalf("accepted %d targets: %q", len(targets), argv)
		}
		seen := map[string]bool{}
		for _, a := range targets {
			if !private.MatchString(a) || seen[a] {
				t.Fatalf("accepted target %q (not private, or twice) in %q", a, argv)
			}
			seen[a] = true
		}
	})
}

func TestParseInvertsBuild(t *testing.T) {
	t.Parallel()
	ts := addrs(t, "192.168.10.1", "10.0.0.7")
	for _, c := range []struct {
		kind Kind
		rate int
		want int
	}{{Sweep, 50, 50}, {Normal, 1000, 1000}, {Gentle, 500, 1}, {GentleTitles, 500, 1}} {
		argv, err := Build(c.kind, c.rate, ts)
		if err != nil {
			t.Fatal(err)
		}
		k, r, got, err := Parse(argv)
		if err != nil || k != c.kind || r != c.want || !reflect.DeepEqual(got, ts) {
			t.Errorf("%s: Parse = %v %d %v %v", c.kind.Name(), k, r, got, err)
		}
		if kk, ok := KindOf(c.kind.Name()); !ok || kk != c.kind {
			t.Errorf("KindOf(%q) = %v %v", c.kind.Name(), kk, ok)
		}
	}
	if _, _, _, err := Parse([]string{"-A", "-oX", "-", "10.0.0.1"}); err == nil {
		t.Error("Parse accepted an argv Validate refuses")
	}
	if _, ok := KindOf("aggressive"); ok {
		t.Error("KindOf accepted an unknown shape")
	}
}

// FuzzParseBuild: for every argv Validate accepts, Parse finds the kind, rate and targets it was built from, and Build makes the
// same argv again. The dispatcher turns the argv core checked into a job and the worker builds it back: this is the guarantee
// that nothing is lost or invented on the way (L8).
func FuzzParseBuild(f *testing.F) {
	for _, s := range [][]string{
		shapeSweep, shapeNormal, shapeGentle, shapeVersions, shapeTitles,
		{"--privileged", "-sn", "-n", "--max-rate", "1000", "-oX", "-", "10.0.0.1", "10.0.0.2"},
		{"--privileged", "-sn", "-n", "--max-rate", "1", "-oX", "-", "172.16.0.1"},
	} {
		f.Add(strings.Join(s, "\n"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		argv := strings.Split(joined, "\n")
		if Validate(argv) != nil {
			return
		}
		kind, rate, targets, err := Parse(argv)
		if err != nil {
			t.Fatalf("Parse refuses an argv Validate accepts: %q: %v", argv, err)
		}
		got, err := Build(kind, rate, targets)
		if err != nil || !slices.Equal(got, argv) {
			t.Fatalf("Build(Parse(a)) != a:\n a = %q\n b = %q (%v)", argv, got, err)
		}
		if _, ok := KindOf(kind.Name()); !ok {
			t.Fatalf("kind %v has no name", kind)
		}
	})
}

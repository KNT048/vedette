package sensoractive

import (
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func addrs(t testing.TB, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestBuildNmapArgs(t *testing.T) {
	t.Parallel()
	one := addrs(t, "192.168.10.20")
	tests := []struct {
		name    string
		kind    scanKind
		rate    int
		targets []netip.Addr
		want    []string
	}{
		{"sweep", kindSweep, 50, addrs(t, "192.168.10.1", "192.168.10.2"),
			[]string{"--privileged", "-sn", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1", "192.168.10.2"}},
		{"normal", kindNormal, 100, one,
			[]string{"--privileged", "-sS", "-sV", "-O", "-n", "--max-rate", "100", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}},
		{"gentle ignores the rate given: 1 packet per second, no -sV", kindGentle, 500, one,
			[]string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.20"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := buildNmapArgs(tt.kind, tt.rate, tt.targets)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("argv = %q\nwant   %q", got, tt.want)
			}
			if err := ValidateNmapArgs(got); err != nil {
				t.Fatalf("the validator rejects what the builder made: %v", err)
			}
		})
	}
	// The gentle line never carries OS detection, version detection (which runs the "version" NSE scripts) or
	// a script (D-45, FORBID-6).
	g, _ := buildNmapArgs(kindGentle, 10, one)
	for _, a := range g {
		if a == "-O" || a == "-sV" || strings.HasPrefix(a, "--script") || strings.HasPrefix(a, "--version") || a == "-A" || a == "-sC" {
			t.Fatalf("gentle argv has %q", a)
		}
	}
}

func TestBuildNmapArgsRefuses(t *testing.T) {
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
		if _, err := buildNmapArgs(kindNormal, c.rate, c.targets); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := buildNmapArgs(scanKind(9), 10, many[:1]); err == nil {
		t.Error("unknown kind accepted")
	}
}

// The three shapes written out apart from the code under test (INV-4, SYS-2).
var (
	shapeSweep  = []string{"--privileged", "-sn", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1"}
	shapeNormal = []string{"--privileged", "-sS", "-sV", "-O", "-n", "--max-rate", "100", "--top-ports", "1000", "--host-timeout", "30m", "-oX", "-", "192.168.10.20"}
	shapeGentle = []string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"}
)

// INV-4, SYS-2: the validator accepts exactly three command shapes, with only the rate (of sweep and normal)
// and the targets variable. Anything else is rejected, including flags that are individually harmless: a
// missing -n would let nmap resolve names, a missing --max-rate would run at full speed, and mixing the gentle
// and the normal flags would run -O on a fragile device.
func TestValidateNmapArgs(t *testing.T) {
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
		"empty":                               {},
		"no privileged":                       drop(shapeNormal, "--privileged"),
		"aggressive":                          with(shapeNormal[:len(shapeNormal)-3], "-A", "-oX", "-", "192.168.10.20"),
		"script":                              {"--privileged", "-sS", "--script", "vuln", "-oX", "-", "192.168.10.1"},
		"script=":                             {"--privileged", "-sS", "--script=vuln", "-oX", "-", "192.168.10.1"},
		"default scripts":                     {"--privileged", "-sS", "-sC", "-oX", "-", "192.168.10.1"},
		"output to a file":                    {"--privileged", "-sS", "-oN", "/tmp/x", "-oX", "-", "192.168.10.1"},
		"xml to a file":                       swap(shapeNormal, "-", "/tmp/x"),
		"input list":                          {"--privileged", "-sS", "-iL", "/etc/hosts", "-oX", "-", "192.168.10.1"},
		"no xml":                              {"--privileged", "-sn", "-n", "--max-rate", "50", "192.168.10.1"},
		"sweep without -n (reverse DNS)":      drop(shapeSweep, "-n"),
		"sweep without --max-rate":            drop(shapeSweep, "--max-rate", "50"),
		"normal without --max-rate":           drop(shapeNormal, "--max-rate", "100"),
		"normal without -n":                   drop(shapeNormal, "-n"),
		"normal without --host-timeout":       drop(shapeNormal, "--host-timeout", "30m"),
		"normal with the gentle host timeout": swap(shapeNormal, "30m", "15m"),
		"normal with all ports":               swap(shapeNormal, "1000", "65535"),
		"-sS without --top-ports":             drop(shapeNormal, "--top-ports", "1000"),
		"sweep with service detection":        with(shapeSweep[:4], "-sV", "--max-rate", "50", "-oX", "-", "192.168.10.1"),
		"sweep with the normal flags added":   {"--privileged", "-sn", "-sV", "-O", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1"},
		"gentle with -sV (version scripts)":   {"--privileged", "-sS", "-sV", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"},
		"gentle with --version-intensity":     {"--privileged", "-sS", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"},
		"gentle flags mixed with -O at 1000":  {"--privileged", "-sS", "-sV", "-O", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1000", "--top-ports", "1000", "-oX", "-", "192.168.10.30"},
		"gentle at a rate above 1":            swap(swap(shapeGentle, "--max-rate", "--max-rate"), "1", "5"),
		"gentle with -O":                      with([]string{"--privileged", "-sS", "-O"}, shapeGentle[2:]...),
		"duplicate flag":                      with([]string{"--privileged", "-sn", "-sn"}, shapeSweep[2:]...),
		"flags in another order":              {"--privileged", "-n", "-sn", "--max-rate", "50", "-oX", "-", "192.168.10.1"},
		"rate 0":                              swap(shapeSweep, "50", "0"),
		"rate 1001":                           swap(shapeSweep, "50", "1001"),
		"rate with a sign":                    swap(shapeSweep, "50", "+5"),
		"rate with a zero":                    swap(shapeSweep, "50", "05"),
		"rate missing":                        {"--privileged", "-sn", "-n", "--max-rate"},
		"timing 5":                            swap(shapeGentle, "-T2", "-T5"),
		"no target":                           shapeSweep[:len(shapeSweep)-1],
		"flag after the targets":              with(shapeSweep, "-A"),
		"hostname":                            with(shapeSweep[:len(shapeSweep)-1], "example.com"),
		"cidr":                                with(shapeSweep[:len(shapeSweep)-1], "192.168.10.0/24"),
		"range":                               with(shapeSweep[:len(shapeSweep)-1], "192.168.10.1-5"),
		"leading zero":                        with(shapeSweep[:len(shapeSweep)-1], "192.168.10.01"),
		"IPv6":                                with(shapeSweep[:len(shapeSweep)-1], "fd00::1"),
		"mapped IPv6":                         with(shapeSweep[:len(shapeSweep)-1], "::ffff:192.168.10.1"),
		"zone":                                with(shapeSweep[:len(shapeSweep)-1], "fe80::1%eth0"),
		"duplicate target":                    with(shapeSweep, "192.168.10.1"),
		"shell":                               with(shapeSweep[:len(shapeSweep)-1], "192.168.10.1;id"),
		"empty token":                         with(shapeSweep, ""),
	}
	for name, argv := range bad {
		if err := ValidateNmapArgs(argv); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
	for name, argv := range map[string][]string{"sweep": shapeSweep, "normal": shapeNormal, "gentle": shapeGentle, "two targets": with(shapeSweep, "192.168.10.2")} {
		if err := ValidateNmapArgs(argv); err != nil {
			t.Errorf("%s: a good argv is rejected: %v", name, err)
		}
	}
	base := slices.Clone(shapeSweep[:len(shapeSweep)-1])
	over := make([]string, MaxBatch+1)
	for i := range over {
		over[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String()
	}
	if err := ValidateNmapArgs(with(base, over...)); err == nil {
		t.Error("more than MaxBatch targets accepted")
	}
	if err := ValidateNmapArgs(with(base, over[:MaxBatch]...)); err != nil {
		t.Errorf("MaxBatch targets rejected: %v", err)
	}
}

// L1: lan_ranges can only be RFC 1918 ranges, so no legitimate argv names a public, loopback, link-local,
// shared (CGNAT), multicast, reserved, broadcast or unspecified address, and the validator refuses them all.
func TestValidateNmapArgsRefusesNonPrivateTargets(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"8.8.8.8", "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "240.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "11.0.0.1"} {
		argv := slices.Clone(shapeSweep[:len(shapeSweep)-1])
		if err := ValidateNmapArgs(append(argv, target)); err == nil {
			t.Errorf("accepted target %s, which no confirmed LAN range can contain", target)
		}
	}
	for _, target := range []string{"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.0.1"} {
		argv := slices.Clone(shapeSweep[:len(shapeSweep)-1])
		if err := ValidateNmapArgs(append(argv, target)); err != nil {
			t.Errorf("refused the private target %s: %v", target, err)
		}
	}
}

// private is the oracle's own idea of RFC 1918, not netip's.
var private = regexp.MustCompile(`^(10\.([0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})$`)

// shapeOracle knows the three shapes and nothing else: the flags before "-oX" must be one of them, with the
// rate of sweep and normal written as plain digits between 1 and 1000.
func shapeOracle(flags []string) bool {
	rate := regexp.MustCompile(`^([1-9][0-9]{0,2}|1000)$`)
	withRate := func(shape []string, at int) bool {
		want := shape[:slices.Index(shape, "-oX")]
		return len(flags) == len(want) && rate.MatchString(flags[at]) &&
			slices.Equal(flags[:at], want[:at]) && slices.Equal(flags[at+1:], want[at+1:])
	}
	return withRate(shapeSweep, 4) || withRate(shapeNormal, 6) || slices.Equal(flags, shapeGentle[:slices.Index(shapeGentle, "-oX")])
}

func FuzzValidateNmapArgs(f *testing.F) {
	for _, s := range [][]string{
		shapeSweep, shapeNormal, shapeGentle,
		{"--privileged", "-sn", "-n", "--max-rate", "1000", "-oX", "-", "10.0.0.1", "10.0.0.2"},
		{"--privileged", "-A", "-oX", "-", "10.0.0.1"},
		{"--privileged", "-sS", "--script", "vuln", "-oX", "-", "10.0.0.1"},
	} {
		f.Add(strings.Join(s, "\n"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		argv := strings.Split(joined, "\n")
		if ValidateNmapArgs(argv) != nil {
			return
		}
		i := slices.Index(argv, "-oX")
		if i < 0 || i+1 >= len(argv) || argv[i+1] != "-" || !shapeOracle(argv[:i]) {
			t.Fatalf("accepted an argv that is not one of the three shapes: %q", argv)
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

func FuzzParseNmapXML(f *testing.F) {
	for _, name := range []string{"sweep.xml", "device.xml", "fragile.xml"} {
		b, err := os.ReadFile("testdata/" + name) //nolint:gosec // fixed fixture names
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>`))
	f.Add([]byte(`<!DOCTYPE nmaprun [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>`))
	f.Add([]byte(`<nmaprun><host><status state="up"/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		hosts, err := parseNmapXML(data)
		if err != nil {
			if hosts != nil {
				t.Fatal("hosts returned with an error")
			}
			return
		}
		if len(hosts) > maxXMLHosts {
			t.Fatalf("%d hosts", len(hosts))
		}
		for _, h := range hosts {
			if !h.addr.IsValid() || !h.addr.Is4() {
				t.Fatalf("host address %v", h.addr)
			}
			for _, s := range []string{h.vendor, h.hostname} {
				if s != "" && text(s) != s {
					t.Fatalf("stored string not clean: %q", s)
				}
			}
			if h.mac != "" && !macRE.MatchString(h.mac) {
				t.Fatalf("mac %q", h.mac)
			}
			if len(h.ports) > maxPortsPerHost || len(h.matches) > maxOSMatches {
				t.Fatal("limit exceeded")
			}
		}
	})
}

func TestWindow(t *testing.T) {
	t.Parallel()
	at := func(day, hour, minute int) time.Time { return time.Date(2026, 11, day, hour, minute, 0, 0, time.Local) } // 9 Nov 2026 is a Monday
	weekdays := Settings{Days: []int{1, 2, 3, 4, 5}, From: "23:00", To: "05:00"}
	wed := Settings{Days: []int{3}, From: "01:00", To: "05:00"}
	tests := []struct {
		name    string
		st      Settings
		t       time.Time
		in      bool
		wantEnd time.Time
	}{
		{"crossing: Monday 23:30 starts Monday's window", weekdays, at(9, 23, 30), true, at(10, 5, 0)},
		{"crossing: Tuesday 04:59 is still Monday's window", weekdays, at(10, 4, 59), true, at(10, 5, 0)},
		{"crossing: Tuesday 05:00 is closed", weekdays, at(10, 5, 0), false, time.Time{}},
		{"crossing: Saturday 02:00 belongs to Friday's window", weekdays, at(14, 2, 0), true, at(14, 5, 0)},
		{"crossing: Saturday 23:30 has no window (Saturday is not listed)", weekdays, at(14, 23, 30), false, time.Time{}},
		{"crossing: Monday 02:00 has none (Sunday is not listed)", weekdays, at(9, 2, 0), false, time.Time{}},
		{"crossing: Monday 22:59 is before the window", weekdays, at(9, 22, 59), false, time.Time{}},
		{"same day: starts at From", wed, at(11, 1, 0), true, at(11, 5, 0)},
		{"same day: one minute before", wed, at(11, 0, 59), false, time.Time{}},
		{"same day: ends at To", wed, at(11, 5, 0), false, time.Time{}},
		{"same day: other day", wed, at(12, 2, 0), false, time.Time{}},
		{"Sunday is day 7", Settings{Days: []int{7}, From: "10:00", To: "11:00"}, at(15, 10, 30), true, at(15, 11, 0)},
		{"From equals To is no window", Settings{Days: []int{1}, From: "10:00", To: "10:00"}, at(9, 10, 0), false, time.Time{}},
		{"bad time is no window", Settings{Days: []int{1}, From: "25:00", To: "10:00"}, at(9, 9, 0), false, time.Time{}},
		{"no days is no window", Settings{From: "01:00", To: "05:00"}, at(9, 2, 0), false, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, end, ok := tt.st.window(tt.t)
			if ok != tt.in {
				t.Fatalf("in window = %v, want %v", ok, tt.in)
			}
			if ok && !end.Equal(tt.wantEnd) {
				t.Fatalf("window end = %v, want %v", end, tt.wantEnd)
			}
		})
	}
}

func TestWalker(t *testing.T) {
	t.Parallel()
	collect := func(ranges ...string) []string {
		var out []string
		w := newWalker(prefixes(ranges), netip.Addr{})
		for a, ok := w.next(); ok; a, ok = w.next() {
			out = append(out, a.String())
		}
		return out
	}
	tests := []struct {
		name   string
		ranges []string
		want   []string
	}{
		{"/29 has six hosts, no network or broadcast", []string{"192.168.10.0/29"}, []string{"192.168.10.1", "192.168.10.2", "192.168.10.3", "192.168.10.4", "192.168.10.5", "192.168.10.6"}},
		{"/31 and /32 keep every address", []string{"192.168.10.8/31", "192.168.10.20/32"}, []string{"192.168.10.8", "192.168.10.9", "192.168.10.20"}},
		{"a repeated range yields once", []string{"192.168.10.0/30", "192.168.10.0/30"}, []string{"192.168.10.1", "192.168.10.2"}},
		{"ranges are walked in ascending order", []string{"192.168.11.0/30", "192.168.10.0/30"}, []string{"192.168.10.1", "192.168.10.2", "192.168.11.1", "192.168.11.2"}},
		{"a range inside another yields once", []string{"192.168.10.0/29", "192.168.10.0/30"}, []string{"192.168.10.1", "192.168.10.2", "192.168.10.3", "192.168.10.4", "192.168.10.5", "192.168.10.6"}},
		{"IPv6 and junk are skipped", []string{"fd00::/64", "nope", "192.168.10.0/30"}, []string{"192.168.10.1", "192.168.10.2"}},
		{"the last address of the space does not loop", []string{"255.255.255.254/31"}, []string{"255.255.255.254", "255.255.255.255"}},
		{"nothing", nil, nil},
	}
	for _, tt := range tests {
		got := collect(tt.ranges...)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// The sweep cursor: a walker started after an address yields only what follows it, across ranges.
func TestWalkerResumesAfterTheCursor(t *testing.T) {
	t.Parallel()
	ps := prefixes([]string{"192.168.10.0/29", "192.168.20.0/30"})
	for after, want := range map[string][]string{
		"192.168.10.3": {"192.168.10.4", "192.168.10.5", "192.168.10.6", "192.168.20.1", "192.168.20.2"},
		"192.168.10.6": {"192.168.20.1", "192.168.20.2"},
		"192.168.10.0": {"192.168.10.1", "192.168.10.2", "192.168.10.3", "192.168.10.4", "192.168.10.5", "192.168.10.6", "192.168.20.1", "192.168.20.2"},
		"192.168.15.1": {"192.168.20.1", "192.168.20.2"}, // between ranges (a range was removed since)
		"192.168.20.2": nil,
		"192.168.30.1": nil,
		"10.0.0.1":     {"192.168.10.1", "192.168.10.2", "192.168.10.3", "192.168.10.4", "192.168.10.5", "192.168.10.6", "192.168.20.1", "192.168.20.2"},
	} {
		var got []string
		w := newWalker(ps, netip.MustParseAddr(after))
		for a, ok := w.next(); ok; a, ok = w.next() {
			got = append(got, a.String())
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("after %s: got %v, want %v", after, got, want)
		}
	}
}

// The in-memory scope is the inventory's rule (SYS-7): inside a range, outside every exclusion; the estimate
// counts what a sweep covers.
func TestScope(t *testing.T) {
	t.Parallel()
	st := Settings{LANRanges: []string{"192.168.10.0/24", "10.0.0.0/30", "fd00::/64"}, Exclusions: []string{"192.168.10.0/28", "192.168.10.200", "10.0.0.0/8", "junk"}}
	for ip, want := range map[string]bool{
		"192.168.10.1": false, "192.168.10.16": true, "192.168.10.200": false, "192.168.10.201": true,
		"192.168.11.1": false, "10.0.0.1": false, "172.16.0.1": false, "::ffff:192.168.10.20": true,
	} {
		if got := st.InScope(netip.MustParseAddr(ip)); got != want {
			t.Errorf("InScope(%s) = %v, want %v", ip, got, want)
		}
	}
	if got, want := newScope(st).count(), 256-16-1; got != want {
		t.Errorf("count = %d, want %d", got, want)
	}
	if got := (Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"10.0.0.0/16"}, Days: []int{1}, From: "01:00", To: "05:00", Rate: 2}).sweepWarning(); got == "" {
		t.Error("65536 addresses at 2 packets/s in 4 hours: no warning")
	}
	if got := (Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"10.0.0.0/24"}, Days: []int{1}, From: "01:00", To: "05:00", Rate: 10}).sweepWarning(); got != "" {
		t.Errorf("a /24 at 10 packets/s fits: %q", got)
	}
}

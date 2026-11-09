package sensoractive

import (
	"net/netip"
	"os"
	"reflect"
	"regexp"
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
			[]string{"--privileged", "-sS", "-sV", "-O", "-n", "--max-rate", "100", "--top-ports", "1000", "-oX", "-", "192.168.10.20"}},
		{"gentle ignores the rate given: 1 packet per second", kindGentle, 500, one,
			[]string{"--privileged", "-sS", "-sV", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--top-ports", "100", "-oX", "-", "192.168.10.20"}},
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
	// The gentle line never carries OS detection or a script (D-45, FORBID-6).
	g, _ := buildNmapArgs(kindGentle, 10, one)
	for _, a := range g {
		if a == "-O" || strings.HasPrefix(a, "--script") || a == "-A" || a == "-sC" {
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
	} {
		if _, err := buildNmapArgs(kindNormal, c.rate, c.targets); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := buildNmapArgs(scanKind(9), 10, many[:1]); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestValidateNmapArgs(t *testing.T) {
	t.Parallel()
	base := []string{"--privileged", "-sS", "-sV", "-n", "--max-rate", "10", "-oX", "-"}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }
	bad := map[string][]string{
		"empty":                  {},
		"no privileged":          {"-sS", "-oX", "-", "10.0.0.1"},
		"aggressive":             {"--privileged", "-sS", "-A", "-oX", "-", "10.0.0.1"},
		"script":                 {"--privileged", "-sS", "--script", "vuln", "-oX", "-", "10.0.0.1"},
		"script=":                {"--privileged", "-sS", "--script=vuln", "-oX", "-", "10.0.0.1"},
		"default scripts":        {"--privileged", "-sS", "-sC", "-oX", "-", "10.0.0.1"},
		"output to a file":       {"--privileged", "-sS", "-oN", "/tmp/x", "-oX", "-", "10.0.0.1"},
		"xml to a file":          {"--privileged", "-sS", "-oX", "/tmp/x", "10.0.0.1"},
		"input list":             {"--privileged", "-sS", "-iL", "/etc/hosts", "-oX", "-", "10.0.0.1"},
		"no xml":                 {"--privileged", "-sS", "10.0.0.1"},
		"no scan type":           {"--privileged", "-n", "-oX", "-", "10.0.0.1"},
		"sweep with service":     {"--privileged", "-sn", "-sV", "-oX", "-", "10.0.0.1"},
		"duplicate flag":         {"--privileged", "-sS", "-sS", "-oX", "-", "10.0.0.1"},
		"rate 0":                 {"--privileged", "-sS", "--max-rate", "0", "-oX", "-", "10.0.0.1"},
		"rate 1001":              {"--privileged", "-sS", "--max-rate", "1001", "-oX", "-", "10.0.0.1"},
		"rate with a sign":       {"--privileged", "-sS", "--max-rate", "+5", "-oX", "-", "10.0.0.1"},
		"rate with a zero":       {"--privileged", "-sS", "--max-rate", "05", "-oX", "-", "10.0.0.1"},
		"rate missing":           {"--privileged", "-sS", "--max-rate"},
		"all ports":              {"--privileged", "-sS", "--top-ports", "65535", "-oX", "-", "10.0.0.1"},
		"intensity 9":            {"--privileged", "-sS", "--version-intensity", "9", "-oX", "-", "10.0.0.1"},
		"timing 5":               {"--privileged", "-sS", "-T5", "-oX", "-", "10.0.0.1"},
		"no target":              with(),
		"flag after the targets": with("10.0.0.1", "-A"),
		"hostname":               with("example.com"),
		"cidr":                   with("10.0.0.0/24"),
		"range":                  with("10.0.0.1-5"),
		"leading zero":           with("10.0.0.01"),
		"IPv6":                   with("fd00::1"),
		"mapped IPv6":            with("::ffff:10.0.0.1"),
		"zone":                   with("fe80::1%eth0"),
		"duplicate target":       with("10.0.0.1", "10.0.0.1"),
		"shell":                  with("10.0.0.1;id"),
		"empty token":            with(""),
	}
	for name, argv := range bad {
		if err := ValidateNmapArgs(argv); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
	if err := ValidateNmapArgs(with("10.0.0.1", "10.0.0.2")); err != nil {
		t.Errorf("a good argv is rejected: %v", err)
	}
	over := make([]string, MaxBatch+1)
	for i := range over {
		over[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String()
	}
	if err := ValidateNmapArgs(with(over...)); err == nil {
		t.Error("more than MaxBatch targets accepted")
	}
	if err := ValidateNmapArgs(with(over[:MaxBatch]...)); err != nil {
		t.Errorf("MaxBatch targets rejected: %v", err)
	}
}

// allowedToken is the oracle of the fuzz test, written apart from the validator: every token of an accepted
// argv must be a fixed flag, a small integer (a flag's value), "-" or a dotted IPv4 address.
var allowedToken = regexp.MustCompile(`^(--privileged|-sn|-sS|-sV|-O|-n|-T2|--max-rate|--top-ports|--version-intensity|--max-retries|-oX|-|[0-9]{1,4}|((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9]))$`)

func FuzzValidateNmapArgs(f *testing.F) {
	for _, s := range [][]string{
		{"--privileged", "-sn", "-n", "--max-rate", "50", "-oX", "-", "192.168.10.1"},
		{"--privileged", "-sS", "-sV", "-O", "-n", "--max-rate", "100", "--top-ports", "1000", "-oX", "-", "192.168.10.20"},
		{"--privileged", "-sS", "-sV", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--top-ports", "100", "-oX", "-", "192.168.10.20"},
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
		for _, a := range argv {
			if !allowedToken.MatchString(a) {
				t.Fatalf("accepted a token that is not allowed: %q in %q", a, argv)
			}
		}
		if argv[0] != "--privileged" || len(argv) > 64+16 {
			t.Fatalf("accepted a malformed shape: %q", argv)
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
		w := newWalker(prefixes(ranges))
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
		{"two ranges in order", []string{"192.168.11.0/30", "192.168.10.0/30"}, []string{"192.168.11.1", "192.168.11.2", "192.168.10.1", "192.168.10.2"}},
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

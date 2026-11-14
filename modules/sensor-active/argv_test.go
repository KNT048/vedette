package sensoractive

import (
	"net/netip"
	"os"
	"reflect"
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
	if got := (Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"10.0.0.0/16"}, Days: []int{1}, From: "01:00", To: "05:00", Rate: 2}).sweepWarning(nil); got == "" {
		t.Error("65536 addresses at 2 packets/s in 4 hours: no warning")
	}
	if got := (Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"10.0.0.0/24"}, Days: []int{1}, From: "01:00", To: "05:00", Rate: 10}).sweepWarning(nil); got != "" {
		t.Errorf("a /24 at 10 packets/s fits: %q", got)
	}
	// D-523: 65536 addresses at 50 packets/s in the 23:00-05:00 window. On the box's own network (one ARP request each) that is
	// 22 minutes and fits; behind a router (17 packets or more each) it is over six hours and does not. A mixed scope charges
	// each part its own cost, and the exclusions come off both.
	wide := Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"10.0.0.0/16"}, Days: []int{1}, From: "23:00", To: "05:00", Rate: 50}
	if got := wide.sweepWarning([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/16")}); got != "" {
		t.Errorf("a local /16 at 50 packets/s fits: %q", got)
	}
	want := "a sweep of about 65536 addresses (0 on the box's own networks at one packet each, 65536 behind a router at 17 or more) at 50 packets/s needs at least 6h11m0s but a window lasts 6h0m0s; one pass will take several days"
	if got := wide.sweepWarning([]netip.Prefix{netip.MustParsePrefix("192.168.1.10/24")}); got != want {
		t.Errorf("sweepWarning = %q", got)
	}
	wide.Exclusions = []string{"10.0.1.0/24"}
	want = "a sweep of about 65280 addresses (256 on the box's own networks at one packet each, 65024 behind a router at 17 or more) at 50 packets/s needs at least 6h9m0s but a window lasts 6h0m0s; one pass will take several days"
	if got := wide.sweepWarning([]netip.Prefix{netip.MustParsePrefix("10.0.0.7/24"), netip.MustParsePrefix("10.0.1.7/24")}); got != want {
		t.Errorf("mixed scope: sweepWarning = %q", got)
	}
}

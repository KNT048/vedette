package sensoractive

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// D-501: what a device scan records from nmap's output (kind, OS, software with CPE) and, when it records no software, exactly
// why. The fixtures are hand-written in the shape of real nmap 7.94 output for each kind of device; no network is scanned.
func TestIdentifiedFromRealOutputShapes(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.168.10.20")
	for _, c := range []struct {
		file   string
		gentle bool
		kind   string   // the kind observation, "" for none
		cpes   []string // CPEs of the software recorded, in order
		found  []string // lines of Found
		why    string
	}{
		{file: "iphone.xml", kind: "iot", cpes: []string{"cpe:/o:apple:iphone_os:15", "cpe:/o:apple:iphone_os:16"},
			found: []string{"Operating system: Apple iOS 15.0 - 16.1 (Darwin 21.0.0 - 22.1.0)", "Type: iot", "Software: Apple iOS 15.0 - 16.1 (Darwin 21.0.0 - 22.1.0)"}},
		{file: "windows.xml", kind: "pc", cpes: []string{"", "", "", "cpe:/o:microsoft:windows_10:1607"},
			found: []string{"Operating system: Microsoft Windows 10 1607", "Type: pc", "Software: Microsoft Windows RPC", "Software: Microsoft Windows netbios-ssn",
				"Software: Microsoft Terminal Services", "Software: Microsoft Windows 10 1607"}},
		{file: "device.xml", kind: "server", cpes: []string{"cpe:/a:openbsd:openssh:8.9p1", "cpe:/a:apache:http_server:2.4.52", "", "cpe:/o:linux:linux_kernel:5"},
			found: []string{"Operating system: Linux 5.4 - 5.15", "Type: server", "Software: OpenSSH 8.9p1", "Software: Apache httpd 2.4.52", "Software: Squid http proxy 5.7", "Software: Linux 5.4 - 5.15"}},
		{file: "fortigate.xml", kind: "firewall", cpes: []string{"", "cpe:/o:fortinet:fortios:7.2"},
			found: []string{"Operating system: Fortinet FortiGate-60F firewall (FortiOS 7.2)", "Type: firewall", "Software: FortiGate firewall http config", "Software: Fortinet FortiGate-60F firewall (FortiOS 7.2)"}},
		{file: "printer.xml", why: WhyOSUnsure},
		{file: "noversion.xml", why: WhyNoVersion},
		{file: "filtered.xml", why: WhyFiltered},
		{file: "closed.xml", why: WhyNoOpenPorts},
		{file: "down.xml", why: WhyHostDown},
		{file: "timedout.xml", why: WhyTimedOut},
		{file: "fragile.xml", gentle: true, why: WhyGentleOnly},
	} {
		t.Run(c.file, func(t *testing.T) {
			t.Parallel()
			all, err := parseNmapXML(fixture(t, c.file))
			if err != nil {
				t.Fatal(err)
			}
			hosts := onlyTargets(all, []netip.Addr{ip, netip.MustParseAddr("192.168.10.30")}) // fragile.xml is the printer at .30
			addr := ip
			if c.file == "fragile.xml" {
				addr = netip.MustParseAddr("192.168.10.30")
			}
			found, why := identified(hosts, addr, c.gentle)
			if why != c.why || strings.Join(found, "\n") != strings.Join(c.found, "\n") {
				t.Errorf("identified = %q, %q\nwant %q, %q", found, why, c.found, c.why)
			}
			var kind string
			var cpes []string
			if i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == addr }); i >= 0 {
				for _, o := range deviceObservations(hosts[i]) {
					if o.Field == observe.Kind {
						kind = o.Value
					}
				}
				if !c.gentle {
					for _, s := range softwareOf(hosts[i]) {
						cpes = append(cpes, s.CPE)
					}
				}
			}
			if kind != c.kind || !slices.Equal(cpes, c.cpes) {
				t.Errorf("kind %q software CPEs %q, want %q %q", kind, cpes, c.kind, c.cpes)
			}
		})
	}
}

// Walk 1 W1-7: a FortiGate becomes maker Fortinet (nmap's MAC table), OS FortiOS with the version nmap gives (7.2) and type firewall.
// With no sure fingerprint, the OS its admin page names (cpe:/o:fortinet:fortios) is still recorded as its OS row.
func TestFortiGateIsIdentified(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "fortigate.xml"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[observe.Field]string{}
	for _, o := range deviceObservations(hosts[0]) {
		got[o.Field] = o.Value
	}
	if got[observe.Vendor] != "Fortinet" || got[observe.OS] != "Fortinet FortiGate-60F firewall (FortiOS 7.2)" || got[observe.Kind] != "firewall" {
		t.Errorf("observations = %v", got)
	}
	var os []string
	for _, s := range softwareOf(hosts[0]) {
		if strings.HasPrefix(s.CPE, "cpe:/o:") {
			os = append(os, s.Vendor+"|"+s.Product+"|"+s.Version)
		}
	}
	if !slices.Equal(os, []string{"fortinet|fortios|7.2"}) {
		t.Errorf("OS software = %v, want fortinet|fortios|7.2", os)
	}
	unsure := hosts[0]
	unsure.matches = nil // the fingerprint failed: the service's OS CPE stands in, without a version
	os = nil
	for _, s := range softwareOf(unsure) {
		if strings.HasPrefix(s.CPE, "cpe:/o:") {
			os = append(os, s.Vendor+"|"+s.Product+"|"+s.Version)
		}
	}
	if !slices.Equal(os, []string{"fortinet|fortios|"}) {
		t.Errorf("OS software without a fingerprint = %v", os)
	}
}

// An OS guess below minOSAccuracy is not recorded: not as the OS, not as a kind, not as software (a wrong OS gives wrong findings).
func TestUnsureOSGuessIsNotRecorded(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "printer.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range deviceObservations(hosts[0]) {
		if o.Field == observe.OS || o.Field == observe.Kind {
			t.Errorf("recorded %s=%q from an 84%% guess", o.Field, o.Value)
		}
	}
	if sw := softwareOf(hosts[0]); len(sw) != 0 {
		t.Errorf("software from an 84%% guess: %v", sw)
	}
	if hosts[0].closed != 997 || hosts[0].filtered != 0 {
		t.Errorf("closed %d filtered %d, want 997 and 0", hosts[0].closed, hosts[0].filtered)
	}
}

// D-501: Scan now's identification of a device the person picked. A device discovery scans normally keeps the normal scan; a
// fragile one gets only the gentle scan (D-45); one whose kind is unknown gets the normal scan at a quarter of the rate (the pick
// is the consent); a refusal of origin, address or scope is passed on and nothing runs.
func TestPickedPlan(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		dec  Decision
		kind nmapargv.Kind
		rate int
		why  string
	}{
		{"classified", Decision{Allowed: true, Rate: 100, Reason: "ok"}, nmapargv.Normal, 100, ""},
		{"unknown, first scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true}, nmapargv.Normal, 25, ""},
		{"unknown, after its gentle scan", Decision{Reason: reasonUnclassifiedPassive, Unclassified: true}, nmapargv.Normal, 25, ""},
		{"fragile, first scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Fragile: true}, nmapargv.Gentle, 1, ""},
		{"fragile and unknown", Decision{Reason: reasonFragilePassive, Fragile: true, Unclassified: true}, nmapargv.Gentle, 1, ""},
		{"never, first scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}, nmapargv.Gentle, 1, ""},
		{"never", Decision{Reason: "regular_scan_never"}, 0, 0, "regular_scan_never"},
		{"by hand", Decision{Reason: "declared_by_hand", Unclassified: true}, 0, 0, "declared_by_hand"},
		{"out of scope", Decision{Reason: "out_of_scope"}, 0, 0, "out_of_scope"},
	} {
		kind, rate, why := pickedPlan(c.dec, 100)
		if kind != c.kind || rate != c.rate || why != c.why {
			t.Errorf("%s: %v %d %q, want %v %d %q", c.name, kind, rate, why, c.kind, c.rate, c.why)
		}
	}
}

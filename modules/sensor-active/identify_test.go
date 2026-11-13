package sensoractive

import (
	"fmt"
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
		// The OS of a fingerprint is a guess: one row per OS without the generation (iOS 15 and 16 are one row), never a version.
		{file: "iphone.xml", kind: "iot", cpes: []string{"cpe:/o:apple:iphone_os"},
			found: []string{"Operating system: Apple iOS 15.0 - 16.1 (Darwin 21.0.0 - 22.1.0)", "Type: iot"}, why: WhyOSGuess},
		// W3-5: "Microsoft Windows RPC" and the other banners with no version are open services, not software.
		{file: "windows.xml", kind: "pc", cpes: []string{"cpe:/o:microsoft:windows_10"},
			found: []string{"Operating system: Microsoft Windows 10 1607", "Type: pc"}, why: WhyOSGuess},
		// W3-4, D-504: the versions shape (no -O) on a Windows 11 PC: RDP's NTLM answer names the release and the build; the row
		// carries that version but no match keys (Guess), as the monthly update level is not in it.
		{file: "windows11.xml", kind: "pc", cpes: []string{"cpe:/o:microsoft:windows"},
			found: []string{"Operating system: Microsoft Windows 11 23H2 (build 22631)", "Type: pc"}, why: WhyOSNoPatch},
		// Linux "general purpose" gives no kind (review H2): Linux also runs embedded and OT devices.
		{file: "device.xml", cpes: []string{"cpe:/a:openbsd:openssh:8.9p1", "cpe:/a:apache:http_server:2.4.52", "", "cpe:/o:linux:linux_kernel"},
			found: []string{"Operating system: Linux 5.4 - 5.15", "Software: OpenSSH 8.9p1", "Software: Apache httpd 2.4.52", "Software: Squid http proxy 5.7"}},
		{file: "fortigate.xml", kind: "firewall", cpes: []string{"cpe:/o:fortinet:fortios"},
			found: []string{"Operating system: Fortinet FortiGate-60F firewall (FortiOS 7.2)", "Type: firewall"}, why: WhyOSGuess},
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
	osRows := func(h host) []string {
		var out []string
		for _, s := range softwareOf(h) {
			if strings.HasPrefix(s.CPE, "cpe:/o:") {
				out = append(out, fmt.Sprintf("%s|%s|%s|%s|guess=%v", s.Vendor, s.Product, s.Version, s.CPE, s.Guess))
			}
		}
		return out
	}
	// Review H1: "7.2" is the OS generation of the fingerprint, never a version; the row is a guess and gets no match keys.
	if got := osRows(hosts[0]); !slices.Equal(got, []string{"fortinet|fortios||cpe:/o:fortinet:fortios|guess=true"}) {
		t.Errorf("OS software = %v", got)
	}
	unsure := hosts[0]
	unsure.matches = nil // the fingerprint failed and the service gave no version: no OS row at all
	if got := osRows(unsure); len(got) != 0 {
		t.Errorf("OS software without a fingerprint = %v, want none", got)
	}
	unsure.ports = slices.Clone(unsure.ports)
	unsure.ports[1].version = "7.2.5" // -sV read the version from the service: that row is real, and matched
	if got := osRows(unsure); !slices.Equal(got, []string{"fortinet|fortios|7.2.5|cpe:/o:fortinet:fortios|guess=false"}) {
		t.Errorf("OS software from a versioned service = %v", got)
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
		{"unknown, first scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true}, nmapargv.Versions, 25, ""},
		{"unknown, after its gentle scan", Decision{Reason: reasonUnclassifiedPassive, Unclassified: true}, nmapargv.Versions, 25, ""},
		{"fragile, first scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Fragile: true}, nmapargv.Gentle, 1, ""},
		{"fragile and unknown", Decision{Reason: reasonFragilePassive, Fragile: true, Unclassified: true}, nmapargv.Gentle, 1, ""},
		{"never, before its gentle scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true, Never: true}, 0, 0, "regular_scan_never"},
		{"never, fragile", Decision{Reason: reasonFragilePassive, Fragile: true, Never: true}, 0, 0, "regular_scan_never"},
		{"never", Decision{Reason: "regular_scan_never", Never: true}, 0, 0, "regular_scan_never"},
		{"another first gentle scan", Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}, nmapargv.Gentle, 1, ""},
		{"by hand", Decision{Reason: "declared_by_hand", Unclassified: true}, 0, 0, "declared_by_hand"},
		{"out of scope", Decision{Reason: "out_of_scope"}, 0, 0, "out_of_scope"},
	} {
		kind, rate, why := pickedPlan(c.dec, 100)
		if kind != c.kind || rate != c.rate || why != c.why {
			t.Errorf("%s: %v %d %q, want %v %d %q", c.name, kind, rate, why, c.kind, c.rate, c.why)
		}
	}
}

// D-504: the NTLM answer is untrusted text from the device. Only the two NTLM scripts of an open port are read, only a version of the
// form major.minor.build and a plain computer name are kept, a value longer than maxElemLen is dropped, and the parse never fails
// the batch for a script.
func TestNTLMAnswerIsReadFailClosed(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "windows11.xml"))
	if err != nil {
		t.Fatal(err)
	}
	// the closed port's http-ntlm-info (6.1.7601, "forged") and the open port's smb-os-discovery are ignored
	if got := hosts[0].ntlm; got != (ntlmInfo{version: "10.0.22631", dnsName: "DESKTOP-K7Q2M1", nbName: "DESKTOP-K7Q2M1"}) {
		t.Fatalf("ntlm = %+v", got)
	}
	doc := func(elems string) []byte {
		return []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.10.20" addrtype="ipv4"/><ports>` +
			`<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/><script id="rdp-ntlm-info" output="">` +
			elems + `</script></port></ports></host></nmaprun>`)
	}
	for name, c := range map[string]struct {
		elems string
		want  ntlmInfo
	}{
		"build with revision":   {`<elem key="Product_Version">10.0.22631.4317</elem>`, ntlmInfo{}},
		"not a version":         {`<elem key="Product_Version">Windows 11</elem>`, ntlmInfo{}},
		"leading text":          {`<elem key="Product_Version">x10.0.22631</elem>`, ntlmInfo{}},
		"too long":              {`<elem key="Product_Version">10.0.` + strings.Repeat("1", 300) + `</elem>`, ntlmInfo{}},
		"name with a space":     {`<elem key="DNS_Computer_Name">evil name</elem>`, ntlmInfo{}},
		"name with a bidi mark": {"<elem key=\"NetBIOS_Computer_Name\">PC‮EXE</elem>", ntlmInfo{}},
		"other key":             {`<elem key="OS">10.0.22631</elem>`, ntlmInfo{}},
		"the first value wins":  {`<elem key="Product_Version">10.0.20348</elem><elem key="Product_Version">6.1.7601</elem>`, ntlmInfo{version: "10.0.20348"}},
		"DNS name before NetBIOS": {`<elem key="NetBIOS_Computer_Name">SRV1</elem><elem key="DNS_Computer_Name">srv1.corp.example</elem>`,
			ntlmInfo{dnsName: "srv1.corp.example", nbName: "SRV1"}},
	} {
		hosts, err := parseNmapXML(doc(c.elems))
		if err != nil {
			t.Errorf("%s: the batch failed: %v", name, err)
			continue
		}
		if hosts[0].ntlm != c.want {
			t.Errorf("%s: ntlm = %+v, want %+v", name, hosts[0].ntlm, c.want)
		}
	}
}

// D-504: the Windows release a build names, client or server, and what each records. A build only Windows Server has, or a domain
// controller (88 and 389 open), is a server; a version with a build the table does not know still says Windows, never a guess.
func TestWindowsFromNTLM(t *testing.T) {
	t.Parallel()
	ports := func(ns ...int) []portInfo {
		var out []portInfo
		for _, n := range ns {
			out = append(out, portInfo{number: n, proto: "tcp", name: "x"})
		}
		return out
	}
	for _, c := range []struct {
		version string
		ports   []int
		display string
		kind    string
	}{
		{"10.0.22631", []int{3389}, "Microsoft Windows 11 23H2 (build 22631)", "pc"},
		{"10.0.19045", []int{3389}, "Microsoft Windows 10 22H2 (build 19045)", "pc"},
		{"10.0.26100", []int{3389}, "Microsoft Windows 11 24H2 (build 26100)", "pc"},
		{"10.0.26100", []int{88, 389, 3389}, "Microsoft Windows Server 2025 (build 26100)", "server"},
		{"10.0.20348", []int{3389}, "Microsoft Windows Server 2022 (build 20348)", "server"},
		{"10.0.17763", []int{88, 389}, "Microsoft Windows Server 2019 (build 17763)", "server"},
		{"10.0.27000", []int{3389}, "Microsoft Windows 11 (build 27000)", "pc"},
		{"10.0.15000", []int{3389}, "Microsoft Windows (build 15000)", "pc"},
		{"6.1.7601", []int{3389}, "Microsoft Windows 7 (build 7601)", "pc"},
		{"6.3.9600", []int{88, 389}, "Microsoft Windows Server 2012 R2 (build 9600)", "server"},
		{"5.1.2600", []int{3389}, "Microsoft Windows (build 2600)", "pc"},
	} {
		h := host{addr: netip.MustParseAddr("192.168.10.20"), ports: ports(c.ports...), ntlm: ntlmInfo{version: c.version, nbName: "PC1"}}
		got := map[observe.Field]string{}
		for _, o := range deviceObservations(h) {
			got[o.Field] = o.Value
		}
		if got[observe.OS] != c.display || got[observe.Kind] != c.kind || got[observe.Hostname] != "PC1" {
			t.Errorf("%s %v: observations %v, want %q %q", c.version, c.ports, got, c.display, c.kind)
		}
		sw := softwareOf(h)
		if len(sw) != 1 || sw[0].Display != c.display || sw[0].Version != c.version || !sw[0].Guess || sw[0].Vendor != "microsoft" {
			t.Errorf("%s: software %+v, want one Guess row with the version", c.version, sw)
		}
	}
}

// D-504: with no NTLM answer and no sure fingerprint, RPC (135) and SMB (445) together give the type at a passive hint's rank, and
// never an OS: the walk's .49 without RDP. One of the two alone gives nothing.
func TestWindowsPortRuleGivesOnlyTheType(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "windows11.xml"))
	if err != nil {
		t.Fatal(err)
	}
	h := hosts[0]
	h.ntlm = ntlmInfo{}
	var kinds []string
	for _, o := range deviceObservations(h) {
		switch o.Field {
		case observe.Kind:
			kinds = append(kinds, fmt.Sprintf("%s@%.2f", o.Value, o.Confidence))
		case observe.OS:
			t.Errorf("the port rule recorded an OS: %q", o.Value)
		}
	}
	if !slices.Equal(kinds, []string{"pc@0.40"}) {
		t.Errorf("kinds = %v, want pc at 0.4", kinds)
	}
	if sw := softwareOf(h); len(sw) != 0 {
		t.Errorf("software from the port rule: %+v", sw)
	}
	if _, why := identified([]host{h}, h.addr, false); why != WhyNoVersion {
		t.Errorf("why = %q, want %q", why, WhyNoVersion)
	}
	h.ports = slices.DeleteFunc(slices.Clone(h.ports), func(p portInfo) bool { return p.number == 135 })
	for _, o := range deviceObservations(h) {
		if o.Field == observe.Kind {
			t.Errorf("445 alone gave the type %q", o.Value)
		}
	}
}

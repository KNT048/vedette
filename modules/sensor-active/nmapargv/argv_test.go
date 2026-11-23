package nmapargv

import (
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
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
			[]string{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", "50", "--stats-every", "5s", "-oX", "-", "192.168.10.1", "192.168.10.2"}},
		{"normal", Normal, 100, one,
			[]string{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "-n", "--max-rate", "100", "--max-retries", "3", "--top-ports", "1000", "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}},
		{"versions: no -O, the same two scripts", Versions, 25, one,
			[]string{"--privileged", "-sS", "-sV", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "-n", "--max-rate", "25", "--max-retries", "3", "--top-ports", "1000", "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}},
		{"gentle ignores the rate given: 1 packet per second, no -sV", Gentle, 500, one,
			[]string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}},
		{"gentle with titles: the gentle line plus http-title and ssl-cert, each capped at 20 s", GentleTitles, 500, one,
			[]string{"--privileged", "-sS", "--script", "http-title,ssl-cert,http-hp-ilo-info,vmware-version", "--script-timeout", "20s", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}},
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
	// a script (FORBID-6).
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
	if _, err := Build(Kind(99), 10, many[:1]); err == nil {
		t.Error("unknown kind accepted")
	}
}

// The six shapes written out apart from the code under test (INV-4, SYS-2).
var (
	shapeSweep    = []string{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", "50", "--stats-every", "5s", "-oX", "-", "192.168.10.1"}
	shapeNormal   = []string{"--privileged", "-sS", "-sV", "-O", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "-n", "--max-rate", "100", "--max-retries", "3", "--top-ports", "1000", "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}
	shapeGentle   = []string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "--stats-every", "5s", "-oX", "-", "192.168.10.30"}
	shapeVersions = []string{"--privileged", "-sS", "-sV", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "-n", "--max-rate", "25", "--max-retries", "3", "--top-ports", "1000", "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.40"}
	shapeTitles   = []string{"--privileged", "-sS", "--script", "http-title,ssl-cert,http-hp-ilo-info,vmware-version", "--script-timeout", "20s", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "--stats-every", "5s", "-oX", "-", "192.168.10.50"}
	// The ports written out here are those of modules/scan/commonports (TestExternalVersionsCoverTheSurfaceList).
	externalPorts = "21,22,23,25,53,80,81,88,102,110,111,135,139,143,179,389,443,445,465,502,515,554,587,631,636,873,993,995,1080,1194,1433,1521,1723,1883,2049,2082,2083,2086,2087,2222,2375,2376,2379,3000,3128,3306,3389,4443,4899,5000,5001,5060,5061,5432,5601,5672,5900,5901,5938,5984,5985,5986,6379,6443,7001,7002,7547,8000,8006,8008,8009,8080,8081,8088,8089,8090,8123,8291,8443,8728,8729,8834,8880,8883,8888,9000,9042,9090,9100,9200,9443,10000,10250,10443,11211,11443,27017,34567,37777"
	// The external discovery: SYN only, nmap's own 1000 most common TCP ports, no -sV.
	shapeExternal = []string{"--privileged", "-sS", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "2m", "--top-ports", "1000", "--stats-every", "5s", "-oX", "-", "8.8.8.8"}
	// The external -sV run: the fixed list (the surface list and the reviewed admin ports) and one open port the discovery found
	// outside it (50000).
	shapeExternalVersions = []string{"--privileged", "-sS", "-sV", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "3m", "-p", plainPorts(append(slices.Clone(ExtraPortNumbers), 50000)), "--stats-every", "5s", "-oX", "-", "8.8.8.8"}
	// The run after a normal or versions scan over the surface list and the reviewed admin ports.
	shapeExtra = []string{"--privileged", "-sS", "-sV", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "-n", "--max-rate", "100",
		"--max-retries", "3", "-p", ExtraPorts, "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}
	// The weekly scan of every port of a LAN device that is not fragile.
	shapeAllPorts = []string{"--privileged", "-sS", "-n", "--max-rate", "100", "--max-retries", "1", "-p-", "--host-timeout", "90m", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}
	// The -sV follow-up of the weekly scan on the open ports the normal scan does not cover.
	shapePortVersions = []string{"--privileged", "-sS", "-sV", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "-n", "--max-rate", "50",
		"--max-retries", "3", "-p", "22222,40000", "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.20"}
	// The two full shapes of a target whose testing terms are accepted.
	shapeFull = []string{"--privileged", "-sS", "-sV", "--version-all", "-Pn", "-n", "-p-", "--script", FullScripts,
		"--script-timeout", "5m", "--max-rate", "300", "--max-retries", "2", "--host-timeout", "60m", "--stats-every", "5s", "-oX", "-", "8.8.8.8"}
	shapeDisruptive = []string{"--privileged", "-sS", "-sV", "--version-all", "-Pn", "-n", "-p-", "--script", DisruptiveScripts,
		"--script-timeout", "5m", "--max-rate", "300", "--max-retries", "2", "--host-timeout", "60m", "--stats-every", "5s", "-oX", "-", "8.8.8.8"}
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
		"aggressive":                           with(shapeNormal[:len(shapeNormal)-3], "-A", "--stats-every", "5s", "-oX", "-", "192.168.10.20"),
		"script":                               {"--privileged", "-sS", "--script", "vuln", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
		"script=":                              {"--privileged", "-sS", "--script=vuln", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
		"default scripts":                      {"--privileged", "-sS", "-sC", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
		"another script list":                  swap(shapeNormal, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "rdp-ntlm-info,smb-os-discovery"),
		"script list reordered":                swap(shapeNormal, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "http-ntlm-info,rdp-ntlm-info,http-title,ssl-cert"),
		"script category":                      swap(shapeVersions, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "safe"),
		"script wildcard":                      swap(shapeVersions, "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version", "*-ntlm-info"),
		"script list without the flag":         drop(shapeNormal, "--script"),
		"normal without its scripts":           drop(shapeNormal, "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version"),
		"output to a file":                     {"--privileged", "-sS", "-oN", "/tmp/x", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
		"xml to a file":                        swap(shapeNormal, "-", "/tmp/x"),
		"input list":                           {"--privileged", "-sS", "-iL", "/etc/hosts", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
		"no xml":                               {"--privileged", "-sn", "-n", "--max-rate", "50", "192.168.10.1"},
		"sweep without -n (reverse DNS)":       drop(shapeSweep, "-n"),
		"sweep without --max-rate":             drop(shapeSweep, "--max-rate", "50"),
		"normal without --max-rate":            drop(shapeNormal, "--max-rate", "100"),
		"normal without -n":                    drop(shapeNormal, "-n"),
		"normal without --host-timeout":        drop(shapeNormal, "--host-timeout", "30m"),
		"normal with the gentle host timeout":  swap(shapeNormal, "30m", "15m"),
		"normal with all ports":                swap(shapeNormal, "1000", "65535"),
		"extra with another port list":         swap(shapeExtra, ExtraPorts, ExtraPorts+",31337"),
		"extra with -O":                        with(shapeExtra[:3], append([]string{"-O"}, shapeExtra[3:]...)...),
		"extra on a public address":            swap(shapeExtra, "192.168.10.20", "8.8.8.8"),
		"all_ports over its rate":              swap(shapeAllPorts, "100", "101"),
		"all_ports with -O":                    with(shapeAllPorts[:3], append([]string{"-O"}, shapeAllPorts[3:]...)...),
		"all_ports with -sV":                   with(shapeAllPorts[:2], append([]string{"-sV"}, shapeAllPorts[2:]...)...),
		"all_ports with more retries":          swap(shapeAllPorts, "1", "3"),
		"port_versions with 21 ports":          swap(shapePortVersions, "22222,40000", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21"),
		"port_versions unsorted":               swap(shapePortVersions, "22222,40000", "40000,22222"),
		"port_versions repeated":               swap(shapePortVersions, "22222,40000", "22222,22222"),
		"port_versions a range":                swap(shapePortVersions, "22222,40000", "1-65535"),
		"port_versions port 0":                 swap(shapePortVersions, "22222,40000", "0,22"),
		"port_versions leading zero":           swap(shapePortVersions, "22222,40000", "022"),
		"port_versions two targets":            with(shapePortVersions, "192.168.10.21"),
		"port_versions public":                 swap(shapePortVersions, "192.168.10.20", "8.8.8.8"),
		"port_versions with -O":                with(shapePortVersions[:3], append([]string{"-O"}, shapePortVersions[3:]...)...),
		"all_ports on a public address":        swap(shapeAllPorts, "192.168.10.20", "8.8.8.8"),
		"-sS without --top-ports":              drop(shapeNormal, "--top-ports", "1000"),
		"normal without --max-retries":         drop(shapeNormal, "--max-retries", "3"),
		"normal with more retries":             swap(shapeNormal, "3", "10"),
		"versions without --max-retries":       drop(shapeVersions, "--max-retries", "3"),
		"sweep with the default probes only":   drop(shapeSweep, "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443"),
		"sweep with a SYN port added":          swap(shapeSweep, "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100,502"),
		"sweep with a UDP probe":               with(shapeSweep[:2], append([]string{"-PU53"}, shapeSweep[2:]...)...),
		"sweep with service detection":         with(shapeSweep[:4], "-sV", "--max-rate", "50", "--stats-every", "5s", "-oX", "-", "192.168.10.1"),
		"sweep with the normal flags added":    {"--privileged", "-sn", "-sV", "-O", "-n", "--max-rate", "50", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
		"gentle with -sV (version scripts)":    {"--privileged", "-sS", "-sV", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "--stats-every", "5s", "-oX", "-", "192.168.10.30"},
		"gentle with --version-intensity":      {"--privileged", "-sS", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "--stats-every", "5s", "-oX", "-", "192.168.10.30"},
		"gentle flags mixed with -O at 1000":   {"--privileged", "-sS", "-sV", "-O", "--version-intensity", "0", "-n", "-T2", "--max-retries", "1", "--max-rate", "1000", "--top-ports", "1000", "--stats-every", "5s", "-oX", "-", "192.168.10.30"},
		"gentle at a rate above 1":             swap(swap(shapeGentle, "--max-rate", "--max-rate"), "1", "5"),
		"gentle with -O":                       with([]string{"--privileged", "-sS", "-O"}, shapeGentle[2:]...),
		"duplicate flag":                       with([]string{"--privileged", "-sn", "-sn"}, shapeSweep[2:]...),
		"flags in another order":               {"--privileged", "-n", "-sn", "--max-rate", "50", "--stats-every", "5s", "-oX", "-", "192.168.10.1"},
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
		"gentle titles with the NTLM scripts":  swap(shapeTitles, "http-title,ssl-cert,http-hp-ilo-info,vmware-version", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version"),
		"gentle titles with a script category": swap(shapeTitles, "http-title,ssl-cert,http-hp-ilo-info,vmware-version", "default"),
		"gentle titles without script timeout": drop(shapeTitles, "--script-timeout", "20s"),
		"gentle titles with a longer timeout":  swap(shapeTitles, "20s", "5m"),
		"gentle titles at a rate above 1":      func() []string { a := slices.Clone(shapeTitles); a[slices.Index(a, "--max-rate")+1] = "5"; return a }(),
		"gentle titles with -sV":               with([]string{"--privileged", "-sS", "-sV"}, shapeTitles[2:]...),
		"versions with -O after -sV":           {"--privileged", "-sS", "-sV", "-n", "-O", "--max-rate", "25", "--max-retries", "3", "--top-ports", "1000", "--host-timeout", "30m", "--stats-every", "5s", "-oX", "-", "192.168.10.40"},
	}
	for name, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
	for name, argv := range map[string][]string{"sweep": shapeSweep, "normal": shapeNormal, "gentle": shapeGentle, "versions": shapeVersions, "gentle_titles": shapeTitles, "external": shapeExternal, "external -sV": shapeExternalVersions, "external_full": shapeFull, "external_disruptive": shapeDisruptive, "all_ports": shapeAllPorts, "extra_ports": shapeExtra, "port_versions": shapePortVersions, "all_ports slower": swap(shapeAllPorts, "100", "50"), "two targets": with(shapeSweep, "192.168.10.2")} {
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

// L1: lan_ranges can only be RFC 1918 or RFC 6598 shared address space ranges, so no legitimate argv names a
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

// private is the oracle's own idea of RFC 1918 and RFC 6598 (100.64-127.x), not netip's or localnet's.
var private = regexp.MustCompile(`^(10\.([0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3})$`)

// shapeOracle knows the six shapes and nothing else: the flags before "-oX" must be one of them, with the
// rate of sweep, normal and versions written as plain digits between 1 and 1000.
func shapeOracle(flags []string) bool {
	rate := regexp.MustCompile(`^([1-9][0-9]{0,2}|1000)$`)
	withRate := func(shape []string, at int) bool {
		want := shape[:slices.Index(shape, "--stats-every")]
		return len(flags) == len(want) && rate.MatchString(flags[at]) &&
			slices.Equal(flags[:at], want[:at]) && slices.Equal(flags[at+1:], want[at+1:])
	}
	at := func(shape []string) int { return slices.Index(shape, "--max-rate") + 1 }
	allPortsRate := regexp.MustCompile(`^([1-9][0-9]?|100)$`) // all_ports: at most 100
	if a := at(shapeAllPorts); len(flags) > a && allPortsRate.MatchString(flags[a]) && withRate(shapeAllPorts, a) {
		return true
	}
	if portVersionsOracle(flags) {
		return true
	}
	return withRate(shapeSweep, at(shapeSweep)) || withRate(shapeExtra, at(shapeExtra)) || withRate(shapeNormal, at(shapeNormal)) || withRate(shapeVersions, at(shapeVersions)) || slices.Equal(flags, shapeGentle[:slices.Index(shapeGentle, "--stats-every")]) ||
		slices.Equal(flags, shapeTitles[:slices.Index(shapeTitles, "--stats-every")]) || externalOracle(flags)
}

// portVersionsOracle: the port_versions shape with any rate 1..1000 and 1..20 ascending ports written as plain decimals.
func portVersionsOracle(flags []string) bool {
	want := shapePortVersions[:slices.Index(shapePortVersions, "--stats-every")]
	if len(flags) != len(want) {
		return false
	}
	ri, pi := slices.Index(want, "--max-rate")+1, slices.Index(want, "-p")+1
	for i := range want {
		if i != ri && i != pi && flags[i] != want[i] {
			return false
		}
	}
	if !regexp.MustCompile(`^([1-9][0-9]{0,2}|1000)$`).MatchString(flags[ri]) || !regexp.MustCompile(`^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4}){0,19}$`).MatchString(flags[pi]) {
		return false
	}
	last := 0
	for _, p := range strings.Split(flags[pi], ",") {
		n, _ := strconv.Atoi(p)
		if n <= last || n > 65535 {
			return false
		}
		last = n
	}
	return true
}

// externalOracle: the flags are one of the shapes whose target is public (the external discovery, its -sV run, external_full,
// external_disruptive).
func externalOracle(flags []string) bool {
	return externalVersionsOracle(flags) ||
		slices.ContainsFunc([][]string{shapeExternal, shapeFull, shapeDisruptive}, func(s []string) bool { return slices.Equal(flags, s[:slices.Index(s, "--stats-every")]) })
}

// externalVersionsOracle: the external -sV run with ascending plain-decimal ports that hold every port of the fixed list and at
// most 40 others.
func externalVersionsOracle(flags []string) bool {
	want := shapeExternalVersions[:slices.Index(shapeExternalVersions, "--stats-every")]
	if len(flags) != len(want) {
		return false
	}
	pi := slices.Index(want, "-p") + 1
	for i := range want {
		if i != pi && flags[i] != want[i] {
			return false
		}
	}
	if !regexp.MustCompile(`^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*$`).MatchString(flags[pi]) {
		return false
	}
	last, extra, fixed := 0, 0, 0
	for _, p := range strings.Split(flags[pi], ",") {
		n, _ := strconv.Atoi(p)
		if n <= last || n > 65535 {
			return false
		}
		last = n
		if slices.Contains(ExtraPortNumbers, n) {
			fixed++
		} else {
			extra++
		}
	}
	return fixed == len(ExtraPortNumbers) && extra <= 40
}

// plainPorts writes ports as a comma-separated -p value, sorted.
func plainPorts(ns []int) string {
	ns = slices.Clone(ns)
	slices.Sort(ns)
	ss := make([]string, len(ns))
	for i, n := range ns {
		ss[i] = strconv.Itoa(n)
	}
	return strings.Join(ss, ",")
}

// public is the oracle's own idea of a public IPv4 address: dotted decimal without leading zeros, outside 0/8, 10/8, 100.64/10,
// 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24 and 224/3.
func public(s string) bool {
	if !regexp.MustCompile(`^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$`).MatchString(s) {
		return false
	}
	var o [4]int
	for i, p := range strings.Split(s, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
		o[i] = n
	}
	a, b, c := o[0], o[1], o[2]
	switch {
	case a == 0 || a == 10 || a == 127 || a >= 224:
		return false
	case a == 100 && b >= 64 && b <= 127, a == 169 && b == 254, a == 172 && b >= 16 && b <= 31, a == 192 && b == 168, a == 198 && (b == 18 || b == 19):
		return false
	case a == 192 && b == 0 && (c == 0 || c == 2), a == 192 && b == 88 && c == 99, a == 198 && b == 51 && c == 100, a == 203 && b == 0 && c == 113:
		return false
	}
	return true
}

func FuzzValidate(f *testing.F) {
	for _, s := range [][]string{
		shapeSweep, shapeNormal, shapeGentle, shapeVersions, shapeTitles, shapeExternal, shapeExternalVersions, shapeFull, shapeDisruptive, shapeAllPorts, shapeExtra, shapePortVersions,
		append(slices.Clone(shapeExternal[:len(shapeExternal)-1]), "192.168.1.1"),
		append(slices.Clone(shapeExternal), "1.1.1.1"),
		{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", "1000", "--stats-every", "5s", "-oX", "-", "10.0.0.1", "10.0.0.2"},
		{"--privileged", "-A", "--stats-every", "5s", "-oX", "-", "10.0.0.1"},
		{"--privileged", "-sS", "--script", "vuln", "--stats-every", "5s", "-oX", "-", "10.0.0.1"},
	} {
		f.Add(strings.Join(s, "\n"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		argv := strings.Split(joined, "\n")
		if Validate(argv) != nil {
			return
		}
		i := slices.Index(argv, "--stats-every") // #830: the progress flag and -oX - end the flag part, in that order
		if i < 0 || i+3 >= len(argv) || argv[i+1] != StatsEvery || argv[i+2] != "-oX" || argv[i+3] != "-" || !shapeOracle(argv[:i]) {
			t.Fatalf("accepted an argv that is not one of the six shapes: %q", argv)
		}
		targets := argv[i+4:]
		if portVersionsOracle(argv[:i]) && len(targets) != 1 {
			t.Fatalf("accepted port_versions with targets %q", targets)
		}
		if externalOracle(argv[:i]) { // One public address, never a local one, never two
			if len(targets) != 1 || !public(targets[0]) || private.MatchString(targets[0]) {
				t.Fatalf("accepted the external shape with targets %q", targets)
			}
			return
		}
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
	}{{Sweep, 50, 50}, {Normal, 1000, 1000}, {Gentle, 500, 1}, {GentleTitles, 500, 1}, {External, ExternalRate, ExternalRate}, {ExternalFull, FullRate, FullRate}, {ExternalDisruptive, FullRate, FullRate}} {
		ts := ts
		if c.kind.IsExternal() {
			ts = addrs(t, "8.8.8.8")
		}
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
	if _, _, _, err := Parse([]string{"-A", "--stats-every", "5s", "-oX", "-", "10.0.0.1"}); err == nil {
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
		shapeSweep, shapeNormal, shapeGentle, shapeVersions, shapeTitles, shapeExternal, shapeExternalVersions, shapeFull, shapeDisruptive, shapeAllPorts, shapeExtra, shapePortVersions,
		{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", "1000", "--stats-every", "5s", "-oX", "-", "10.0.0.1", "10.0.0.2"},
		{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", "1", "--stats-every", "5s", "-oX", "-", "172.16.0.1"},
	} {
		f.Add(strings.Join(s, "\n"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		argv := strings.Split(joined, "\n")
		if Validate(argv) != nil {
			return
		}
		kind, rate, ports, targets, err := ParseFor(argv)
		if err != nil {
			t.Fatalf("Parse refuses an argv Validate accepts: %q: %v", argv, err)
		}
		got, err := BuildFor(kind, rate, ports, targets)
		if err != nil || !slices.Equal(got, argv) {
			t.Fatalf("Build(Parse(a)) != a:\n a = %q\n b = %q (%v)", argv, got, err)
		}
		if _, ok := KindOf(kind.Name()); !ok {
			t.Fatalf("kind %v has no name", kind)
		}
	})
}

// The external shape is two runs on one public address at the fixed rate, with no -O and no script: the discovery (SYN only,
// nmap's own --top-ports 1000, no port list of Vedette's) and the -sV run over the fixed list plus at most 40 open ports the
// discovery found outside it. It is the only shape besides the full ones that names a public address, and only one.
func TestExternalShape(t *testing.T) {
	t.Parallel()
	got, err := Build(External, ExternalRate, addrs(t, "8.8.8.8"))
	if err != nil || !slices.Equal(got, shapeExternal) {
		t.Fatalf("argv = %q %v\nwant   %q", got, err, shapeExternal)
	}
	ports, err := ExternalVersionPorts([]int{22, 443, 50000})
	if err != nil {
		t.Fatal(err)
	}
	gotV, err := BuildFor(External, ExternalRate, ports, addrs(t, "8.8.8.8"))
	if err != nil || !slices.Equal(gotV, shapeExternalVersions) {
		t.Fatalf("argv = %q %v\nwant   %q", gotV, err, shapeExternalVersions)
	}
	for _, argv := range [][]string{got, gotV} {
		for _, a := range argv {
			if a == "-O" || strings.HasPrefix(a, "--script") || a == "-A" || a == "-sC" || strings.HasPrefix(a, "--version") || a == "-sU" || a == "-p-" {
				t.Fatalf("external argv has %q", a)
			}
		}
	}
	if slices.Contains(got, "-sV") || slices.Contains(got, "-p") {
		t.Fatalf("the discovery reads versions or names ports: %q", got)
	}
	for _, argv := range [][]string{shapeExternal, shapeExternalVersions} {
		k, rate, p, ts, err := ParseFor(argv)
		if err != nil || k != External || rate != ExternalRate || len(ts) != 1 || ts[0].String() != "8.8.8.8" {
			t.Fatalf("ParseFor(%q) = %v %d %v %v %v", argv, k, rate, p, ts, err)
		}
		if again, err := BuildFor(k, rate, p, ts); err != nil || !slices.Equal(again, argv) {
			t.Fatalf("BuildFor(ParseFor) = %q %v", again, err)
		}
	}
	for name, c := range map[string]struct {
		rate    int
		targets []netip.Addr
	}{
		"another rate":          {101, addrs(t, "8.8.8.8")},
		"a slower rate":         {10, addrs(t, "8.8.8.8")},
		"two targets":           {ExternalRate, addrs(t, "8.8.8.8", "1.1.1.1")},
		"no target":             {ExternalRate, nil},
		"a private target":      {ExternalRate, addrs(t, "192.168.1.1")},
		"a CGNAT target":        {ExternalRate, addrs(t, "100.64.0.1")},
		"a documentation range": {ExternalRate, addrs(t, "203.0.113.5")},
		"loopback":              {ExternalRate, addrs(t, "127.0.0.1")},
		"link-local (metadata)": {ExternalRate, addrs(t, "169.254.169.254")},
		"mapped IPv6":           {ExternalRate, addrs(t, "::ffff:8.8.8.8")},
		"IPv6":                  {ExternalRate, addrs(t, "2001:4860:4860::8888")},
		"multicast":             {ExternalRate, addrs(t, "224.0.0.1")},
	} {
		if _, err := Build(External, c.rate, c.targets); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := BuildFor(External, c.rate, ports, c.targets); err == nil {
			t.Errorf("%s: the -sV run accepted", name)
		}
	}
	with := func(base []string, extra ...string) []string { return append(slices.Clone(base), extra...) }
	set := func(base []string, i int, v string) []string { a := slices.Clone(base); a[i] = v; return a }
	vp := slices.Index(shapeExternalVersions, "-p") + 1
	tooMany := slices.Clone(ExtraPortNumbers)
	for p := range 41 {
		tooMany = append(tooMany, 50000+p)
	}
	bad := map[string][]string{
		"two public targets":             with(shapeExternal, "1.1.1.1"),
		"a private target":               set(shapeExternal, len(shapeExternal)-1, "192.168.10.1"),
		"a public target in a LAN shape": with(shapeSweep[:len(shapeSweep)-1], "8.8.8.8"),
		"more top ports":                 set(shapeExternal, slices.Index(shapeExternal, "--top-ports")+1, "5000"),
		"discovery with -sV":             with([]string{"--privileged", "-sS", "-sV"}, shapeExternal[2:]...),
		"no -Pn":                         slices.DeleteFunc(slices.Clone(shapeExternal), func(a string) bool { return a == "-Pn" }),
		"another rate":                   set(shapeExternal, slices.Index(shapeExternal, "--max-rate")+1, "1000"),
		"a longer host timeout":          set(shapeExternal, slices.Index(shapeExternal, "--host-timeout")+1, "30m"),
		"with -O":                        with([]string{"--privileged", "-sS", "-O"}, shapeExternal[2:]...),
		"with scripts":                   with([]string{"--privileged", "-sS", "--script", "vuln"}, shapeExternal[2:]...),
		"-sV: every port":                set(shapeExternalVersions, vp, "1-65535"),
		"-sV: ranges":                    set(shapeExternalVersions, vp, ExtraPorts),
		"-sV: the surface list only":     set(shapeExternalVersions, vp, externalPorts),
		"-sV: a fixed port missing":      set(shapeExternalVersions, vp, plainPorts(ExtraPortNumbers[1:])),
		"-sV: 41 ports outside the list": set(shapeExternalVersions, vp, plainPorts(tooMany)),
		"-sV: a port twice":              set(shapeExternalVersions, vp, plainPorts(append(slices.Clone(ExtraPortNumbers), 22))),
		"-sV: a port above 65535":        set(shapeExternalVersions, vp, plainPorts(append(slices.Clone(ExtraPortNumbers), 65536))),
		"-sV: a private target":          set(shapeExternalVersions, len(shapeExternalVersions)-1, "192.168.10.1"),
		"-sV: two targets":               with(shapeExternalVersions, "1.1.1.1"),
		"-sV: another rate":              set(shapeExternalVersions, slices.Index(shapeExternalVersions, "--max-rate")+1, "300"),
		"-sV: a longer host timeout":     set(shapeExternalVersions, slices.Index(shapeExternalVersions, "--host-timeout")+1, "30m"),
		"-sV: with scripts":              with([]string{"--privileged", "-sS", "-sV", "--script", "vuln"}, shapeExternalVersions[3:]...),
	}
	for name, argv := range bad {
		if err := Validate(argv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ExternalVersionPorts(tooMany[len(ExtraPortNumbers):]); err == nil {
		t.Error("ExternalVersionPorts took 41 open ports outside the fixed list")
	}
	if k, ok := KindOf("external"); !ok || k != External {
		t.Fatal("KindOf(external)")
	}
}

// The -sV run always names the surface scan's list, the one list of modules/scan/commonports, written out above apart from the
// code, so the default scan of the public IP probes it whatever nmap's top ports are.
func TestExternalVersionsCoverTheSurfaceList(t *testing.T) {
	t.Parallel()
	ports, err := ExternalVersionPorts(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range strings.Split(externalPorts, ",") {
		n, _ := strconv.Atoi(p)
		if !slices.Contains(ports, n) {
			t.Errorf("port %d of the surface list is not in the -sV run", n)
		}
	}
	if !slices.Equal(ports, ExtraPortNumbers) {
		t.Fatalf("ExternalVersionPorts(nil) = %v", ports)
	}
}

// The two full shapes are built, validated and parsed back exactly as written above, with one public target at FullRate;
// anything else in their place is refused: a LAN target, two targets, another rate, the other shape's script expression or a
// mix of the two, a script argument, a port list instead of -p-.
func TestFullShapes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		kind  Kind
		shape []string
	}{{ExternalFull, shapeFull}, {ExternalDisruptive, shapeDisruptive}} {
		got, err := Build(c.kind, FullRate, addrs(t, "8.8.8.8"))
		if err != nil || !slices.Equal(got, c.shape) {
			t.Fatalf("%s: argv = %q %v\nwant   %q", c.kind.Name(), got, err, c.shape)
		}
		if k, r, ts, err := Parse(got); err != nil || k != c.kind || r != FullRate || len(ts) != 1 || ts[0].String() != "8.8.8.8" {
			t.Fatalf("%s: Parse = %v %d %v %v", c.kind.Name(), k, r, ts, err)
		}
		if k, ok := KindOf(c.kind.Name()); !ok || k != c.kind || !k.IsFull() || !k.IsExternal() || ExternalRateOf(k) != FullRate {
			t.Fatalf("KindOf(%q) = %v %v", c.kind.Name(), k, ok)
		}
		for name, b := range map[string]struct {
			rate    int
			targets []netip.Addr
		}{"a LAN target": {FullRate, addrs(t, "192.168.1.1")}, "two targets": {FullRate, addrs(t, "8.8.8.8", "1.1.1.1")}, "another rate": {ExternalRate, addrs(t, "8.8.8.8")}} {
			if _, err := Build(c.kind, b.rate, b.targets); err == nil {
				t.Errorf("%s: Build accepted %s", c.kind.Name(), name)
			}
		}
		set := func(i int, v string) []string { a := slices.Clone(c.shape); a[i] = v; return a }
		at := func(flag string) int { return slices.Index(c.shape, flag) + 1 }
		for name, argv := range map[string][]string{
			"a LAN target":       set(len(c.shape)-1, "192.168.10.1"),
			"two targets":        append(slices.Clone(c.shape), "1.1.1.1"),
			"another rate":       set(at("--max-rate"), "1000"),
			"a mixed expression": set(at("--script"), "(default or safe or vuln or dos) and not (brute or external or broadcast)"),
			"external scripts":   set(at("--script"), "(default or safe or vuln or external) and not (dos or brute or broadcast)"),
			"a script name":      set(at("--script"), "vulners"),
			"with --script-args": append(append(slices.Clone(c.shape[:at("--script")+1]), "--script-args", "vulns.showall"), c.shape[at("--script")+1:]...),
			"a port list":        set(slices.Index(c.shape, "-p-"), "-p1-1024"),
			"a longer timeout":   set(at("--host-timeout"), "120m"),
		} {
			if err := Validate(argv); err == nil {
				t.Errorf("%s: Validate accepted %s: %q", c.kind.Name(), name, argv)
			}
		}
	}
	// Each shape's expression in the other's flags is the other shape, never a third one: swapping them changes the kind.
	swapped := slices.Clone(shapeFull)
	swapped[slices.Index(swapped, "--script")+1] = DisruptiveScripts
	if k, _, _, err := Parse(swapped); err != nil || k != ExternalDisruptive {
		t.Fatalf("swapped expression = %v %v", k, err)
	}
	if External.IsFull() || !External.IsExternal() || Normal.IsExternal() || ExternalRateOf(External) != ExternalRate {
		t.Fatal("IsFull/IsExternal")
	}
}

// The sweep sends 17 probes a round to an address behind a router: ICMP echo and timestamp, 13 SYNs, 2 ACKs.
func TestSweepProbes(t *testing.T) {
	t.Parallel()
	f, _ := Flags(Sweep, 50)
	n := 0
	for _, a := range f {
		switch {
		case a == "-PE", a == "-PP":
			n++
		case strings.HasPrefix(a, "-PS"), strings.HasPrefix(a, "-PA"):
			n += len(strings.Split(a[3:], ","))
		}
	}
	if n != 17 || SweepProbes != n {
		t.Fatalf("SweepProbes = %d, the flags send %d", SweepProbes, n)
	}
}

// No shape ever turns on what nmap's guides keep off fragile devices and printers: --allports (version detection then
// probes TCP 9100 too, where some printers print what they are sent), -A or -sC (the "default" script category), a script
// category or wildcard, or a script argument. Every --script value is a fixed list of the scripts named in this package, except
// the two full shapes of the box's own public IP, whose value is exactly their fixed category expression, written out here.
func TestNoShapeWidensScripts(t *testing.T) {
	t.Parallel()
	named := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	allowed := map[string]bool{}
	for _, n := range strings.Split(Scripts+","+TitleScripts, ",") {
		allowed[n] = true
	}
	expr := map[Kind]string{
		ExternalFull:       FullScripts,
		ExternalDisruptive: DisruptiveScripts,
	}
	for _, k := range kinds {
		rate := 50
		if k.IsExternal() {
			rate = ExternalRateOf(k)
		}
		f, err := Flags(k, rate)
		if err != nil {
			t.Fatal(err)
		}
		for i, a := range f {
			switch {
			case a == "--allports", a == "-A", a == "-sC", a == "--script-args", a == "--script-args-file", a == "--script-updatedb",
				strings.HasPrefix(a, "--script="), strings.HasPrefix(a, "--version-intensity"):
				t.Errorf("%s has %q", k.Name(), a)
			case strings.HasPrefix(a, "--version-all"): // M2-7: every probe on a port nothing matched, only in the deep scans of the box's own IP
				if !k.IsFull() || a != "--version-all" {
					t.Errorf("%s has %q", k.Name(), a)
				}
			case a == "--script" && k.IsFull():
				if f[i+1] != expr[k] {
					t.Errorf("%s: --script %q is not its fixed expression", k.Name(), f[i+1])
				}
			case a == "--script":
				for _, n := range strings.Split(f[i+1], ",") {
					if !named.MatchString(n) || !allowed[n] || slices.Contains([]string{"default", "safe", "discovery", "version", "vuln", "intrusive", "all"}, n) {
						t.Errorf("%s: script %q is not one of the fixed scripts", k.Name(), n)
					}
				}
			}
		}
	}
}

// #830: every shape ends with --stats-every StatsEvery -oX -; another interval, the flag missing, moved or doubled is refused.
func TestStatsEveryIsFixed(t *testing.T) {
	i := slices.Index(shapeNormal, "--stats-every")
	flags, tail := shapeNormal[:i], shapeNormal[i+4:]
	for name, argv := range map[string][]string{
		"missing":       slices.Concat(flags, []string{"-oX", "-"}, tail),
		"faster":        slices.Concat(flags, []string{"--stats-every", "1ms", "-oX", "-"}, tail),
		"after -oX":     slices.Concat(flags, []string{"-oX", "-", "--stats-every", "5s"}, tail),
		"twice":         slices.Concat(flags, []string{"--stats-every", "5s", "--stats-every", "5s", "-oX", "-"}, tail),
		"among flags":   slices.Concat([]string{"--stats-every", "5s"}, flags, []string{"-oX", "-"}, tail),
		"with -v added": slices.Concat(flags, []string{"-v", "--stats-every", "5s", "-oX", "-"}, tail),
	} {
		if Validate(argv) == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
	if err := Validate(shapeNormal); err != nil {
		t.Fatal(err)
	}
}

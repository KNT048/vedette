package sensoractive

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/observe"
)

// nmapCeiling keeps every confidence below 1: nmap guesses, it does not know (INV-8). The inventory ranks a
// value by its source first, so a value a person typed or an agent reported still wins.
const nmapCeiling = 0.95

const maxSoftware = 200

// The bounds of the service list the inventory accepts (inventory INV-23, D-350): nmap's normal scan reads its top 1000 ports.
const (
	maxServices   = 1000
	maxSvcName    = 100
	maxSvcVersion = 100
)

// accuracyConf scales nmap's accuracy (0..100) to a confidence below 1.
func accuracyConf(acc int) float64 { return float64(clamp(acc, 0, 100)) / 100 * nmapCeiling }

// serviceConf scales nmap's service conf (1..10; 0 when absent) to a confidence below 1.
func serviceConf(conf int) float64 {
	if conf == 0 {
		return 0.5 * nmapCeiling
	}
	return float64(clamp(conf, 1, 10)) / 10 * nmapCeiling
}

// minOSAccuracy is the lowest accuracy of nmap's OS guess that is recorded (D-501). nmap prints a guess below 100 only when no
// fingerprint matched exactly; under 85 its own manual calls such guesses unreliable, and a wrong OS gives wrong findings.
const minOSAccuracy = 85

// kindOf maps nmap's device type (osclass type) to an inventory kind; types with no clear kind give "". Phones (nmap's phone, VoIP
// phone, PDA) and media devices are iot, as the catalog files iOS and Android, until the inventory has a phone kind (D-501).
func kindOf(t string) string {
	switch strings.ToLower(t) {
	case "router", "broadband router":
		return "router"
	case "firewall":
		return "firewall"
	case "switch":
		return "switch"
	case "wap":
		return "ap"
	case "printer", "print server":
		return "printer"
	case "webcam":
		return "camera"
	case "storage-misc":
		return "nas"
	case "phone", "voip phone", "voip adapter", "pda", "media device", "power-device":
		return "iot"
	}
	return ""
}

// generalKind is the kind a "general purpose" match suggests from its OS (D-501): Windows is a pc (a server when its name says so),
// iOS and Android a phone (iot). Nothing else: Linux, the BSDs and Unix also run embedded and OT devices, so such a guess must not
// lift a device out of "unknown, careful"; macOS stays unknown too. It is a hint, recorded below the confidence of a device type.
func generalKind(c osClass, name string) string {
	if !strings.EqualFold(c.typ, "general purpose") {
		return ""
	}
	switch strings.ToLower(c.family) {
	case "windows":
		if strings.Contains(strings.ToLower(name), "server") {
			return "server"
		}
		return "pc"
	case "ios", "android":
		return "iot"
	}
	return ""
}

// winRelease names the Windows release of an NTLM version (D-504): client and server releases can share one build (14393, 17763,
// 26100), so both names are kept; "" when that build has no such release.
type winRelease struct{ client, server string }

// windowsBuilds maps the build of a Windows 10.0 version to its release: the feature updates and the Server releases Microsoft
// publishes (https://learn.microsoft.com/en-us/windows/release-health/release-information,
// https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information,
// https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info).
var windowsBuilds = map[string]winRelease{
	"10240": {"Windows 10 1507", ""}, "10586": {"Windows 10 1511", ""}, "14393": {"Windows 10 1607", "Windows Server 2016"},
	"15063": {"Windows 10 1703", ""}, "16299": {"Windows 10 1709", ""}, "17134": {"Windows 10 1803", ""},
	"17763": {"Windows 10 1809", "Windows Server 2019"}, "18362": {"Windows 10 1903", ""}, "18363": {"Windows 10 1909", ""},
	"19041": {"Windows 10 2004", ""}, "19042": {"Windows 10 20H2", ""}, "19043": {"Windows 10 21H1", ""}, "19044": {"Windows 10 21H2", ""},
	"19045": {"Windows 10 22H2", ""}, "20348": {"", "Windows Server 2022"}, "22000": {"Windows 11 21H2", ""},
	"22621": {"Windows 11 22H2", ""}, "22631": {"Windows 11 23H2", ""}, "26100": {"Windows 11 24H2", "Windows Server 2025"},
	"26200": {"Windows 11 25H2", ""},
}

// windowsMinor maps the major.minor of an older Windows version to its release.
var windowsMinor = map[string]winRelease{
	"6.0": {"Windows Vista", "Windows Server 2008"}, "6.1": {"Windows 7", "Windows Server 2008 R2"},
	"6.2": {"Windows 8", "Windows Server 2012"}, "6.3": {"Windows 8.1", "Windows Server 2012 R2"},
}

// winOS is the Windows the device named in its NTLM challenge (D-504).
type winOS struct {
	display string // "Microsoft Windows 11 23H2 (build 22631)"
	version string // "10.0.22631": the release, without the monthly update revision
	server  bool
}

// windowsOf reads the Windows version a device put in its NTLM challenge (rdp-ntlm-info, http-ntlm-info). It is the device's own
// answer, not a fingerprint guess, so it names the release (feature update) exactly; it never carries the monthly update revision
// (UBR), so the patch level stays unknown. A server is a build only Windows Server has, or a domain controller (Kerberos 88 and
// LDAP 389 open); otherwise a build shared by both is the client release.
func windowsOf(h host) (winOS, bool) {
	v := h.ntlm.version
	if v == "" {
		return winOS{}, false
	}
	parts := strings.Split(v, ".")
	rel, ok := windowsMinor[parts[0]+"."+parts[1]]
	if parts[0] == "10" && parts[1] == "0" {
		rel, ok = windowsBuilds[parts[2]]
		if !ok && len(parts[2]) == 5 && parts[2] >= "22000" {
			rel, ok = winRelease{"Windows 11", ""}, true
		}
	}
	server := rel.client == "" && rel.server != "" || openTCP(h, 88) && openTCP(h, 389)
	name := rel.client
	if server {
		name = cmp.Or(rel.server, "Windows Server")
	}
	if !ok || name == "" {
		name = "Windows"
	}
	return winOS{display: "Microsoft " + name + " (build " + parts[2] + ")", version: v, server: server}, true
}

// openTCP says whether TCP port n is open on the host.
func openTCP(h host, n int) bool {
	return slices.ContainsFunc(h.ports, func(p portInfo) bool { return p.proto == "tcp" && p.number == n })
}

// windowsByPorts is the port rule of D-504: RPC (135) and SMB (445) open together is a Windows computer. Without an NTLM answer or
// a sure fingerprint it gives only the type, at the rank of a passive hint, never an OS or a version; a domain controller's
// Kerberos and LDAP make it a server.
func windowsByPorts(h host) (kind string, ok bool) {
	if !openTCP(h, 135) || !openTCP(h, 445) {
		return "", false
	}
	if openTCP(h, 88) && openTCP(h, 389) {
		return "server", true
	}
	return "pc", true
}

// Confidences of what D-504 records: the device's own NTLM answer is as sure as nmap gets; its type below that, like a device type;
// the port rule at the rank of a passive hint (a DHCP option 60 OS hint is 0.4).
const (
	ntlmKindConf = nmapCeiling * 0.8
	portKindConf = 0.4
)

// best returns the OS match with the highest accuracy (the first on a tie).
func (h host) best() (osMatch, bool) {
	var b osMatch
	found := false
	for _, m := range h.matches {
		if m.name != "" && (!found || m.accuracy > b.accuracy) {
			b, found = m, true
		}
	}
	return b, found
}

// sure is best when its accuracy reaches minOSAccuracy: the only OS guess that is recorded.
func (h host) sure() (osMatch, bool) {
	m, ok := h.best()
	return m, ok && m.accuracy >= minOSAccuracy
}

// sweepObservations is what a host discovery run says about a host: that it exists, by its MAC, and who made
// the network card. A host with no MAC (not on this segment) gives nothing the inventory can key a device on.
func sweepObservations(h host) []observe.Observation {
	if h.mac == "" {
		return nil
	}
	hint := observe.AssetHint{IP: h.addr, MAC: h.mac}
	out := []observe.Observation{{AssetHint: hint, Field: observe.MAC, Value: h.mac, Source: observe.Nmap, Confidence: 0.9}}
	if h.vendor != "" {
		out = append(out, observe.Observation{AssetHint: hint, Field: observe.Vendor, Value: h.vendor, Source: observe.Nmap, Confidence: 0.6})
	}
	return out
}

// deviceObservations is what a service scan says about a device that the inventory already knows by IP.
func deviceObservations(h host) []observe.Observation {
	hint := observe.AssetHint{IP: h.addr}
	var out []observe.Observation
	add := func(f observe.Field, v string, c float64) {
		if v != "" {
			out = append(out, observe.Observation{AssetHint: hint, Field: f, Value: v, Source: observe.Nmap, Confidence: c})
		}
	}
	add(observe.Hostname, cmp.Or(h.hostname, h.ntlm.name()), 0.6)
	add(observe.Vendor, h.vendor, 0.6)
	if w, ok := windowsOf(h); ok { // the device's own answer outranks nmap's fingerprint guess (D-504)
		add(observe.OS, w.display, nmapCeiling)
		kind := "pc"
		if w.server {
			kind = "server"
		}
		add(observe.Kind, kind, ntlmKindConf)
		return out
	}
	kind := ""
	if m, ok := h.sure(); ok {
		add(observe.OS, m.name, accuracyConf(m.accuracy))
		for _, c := range m.classes {
			if k := kindOf(c.typ); k != "" {
				add(observe.Kind, k, accuracyConf(min(m.accuracy, c.accuracy))*0.8)
				kind = k
				break
			}
		}
		for _, c := range m.classes {
			if k := generalKind(c, m.name); k != "" && kind == "" {
				add(observe.Kind, k, accuracyConf(min(m.accuracy, c.accuracy))*0.6)
				kind = k
			}
		}
	}
	if k, ok := windowsByPorts(h); ok && kind == "" {
		add(observe.Kind, k, portKindConf)
	}
	return out
}

// cpeParts splits "cpe:/a:vendor:product:version:..." into its parts; underscores become spaces, which is
// how the CISA list writes products ("http server"). ok is false when the URI has no vendor or product.
func cpeParts(c string) (part, vendor, product, version string, ok bool) {
	f := strings.Split(strings.TrimPrefix(c, "cpe:/"), ":")
	if len(f) < 3 || f[1] == "" || f[2] == "" || strings.ContainsAny(c, `%\`) {
		return "", "", "", "", false
	}
	clean := func(s string) string { return strings.ReplaceAll(s, "_", " ") }
	if len(f) > 3 {
		version = f[3]
	}
	return f[0], clean(f[1]), clean(f[2]), version, true
}

// softwareOf lists what the scan says runs on the host: one entry per service that -sV read a version of (from its CPE, else from
// its product name), and the OS: the Windows of the device's NTLM answer (D-504), else per OS CPE of the best match when it is sure
// (minOSAccuracy), else per OS CPE a service names with a version. A service with no version is a banner, not software ("Microsoft
// Windows RPC"): it stays in the open services only (W3-5), so it never adds a row that has nothing to compare.
func softwareOf(h host) []observe.Software {
	var out []observe.Software
	seen := map[string]bool{}
	add := func(s observe.Software) {
		k := strings.ToLower(s.Vendor + "\x00" + s.Product + "\x00" + s.Version)
		if !seen[k] && len(out) < maxSoftware && text(s.Display) != "" && text(s.Vendor) != "" && text(s.Product) != "" && len(s.Version) <= 100 {
			seen[k] = true
			out = append(out, s)
		}
	}
	for _, p := range h.ports {
		conf := serviceConf(p.conf)
		var withCPE bool
		for _, c := range p.cpes {
			part, vendor, product, version, ok := cpeParts(c)
			if !ok || part != "a" {
				continue
			}
			withCPE = true
			if p.version != "" {
				version = p.version
			}
			if version == "" {
				continue
			}
			display := strings.TrimSpace(p.product + " " + version)
			if p.product == "" {
				display = strings.TrimSpace(vendor + " " + product + " " + version)
			}
			add(observe.Software{Display: display, Vendor: vendor, Product: product, Version: version, CPE: c, Confidence: conf})
		}
		if !withCPE && p.product != "" && p.version != "" {
			// ponytail: no CPE, so the vendor is not known; the product name stands for both. A CPE-to-vendor table is the upgrade.
			add(observe.Software{Display: strings.TrimSpace(p.product + " " + p.version), Vendor: p.product, Product: p.product, Version: p.version, Confidence: conf * 0.8})
		}
	}
	if w, ok := windowsOf(h); ok {
		// The release is the device's own answer, but the build without its monthly revision cannot be placed in a vendor range
		// (NVD ends Windows ranges at a revision, 10.0.22631.4317): with match keys it would flag every Windows flaw of that release
		// as affected. So it is stored with its version and no match keys (Guess) until a person adds Windows with its full
		// version on the device page (D-504).
		product, cpe := "windows", "cpe:/o:microsoft:windows"
		if w.server {
			product, cpe = "windows server", "cpe:/o:microsoft:windows_server"
		}
		add(observe.Software{Display: w.display, Vendor: "microsoft", Product: product, Version: w.version, CPE: cpe, Confidence: nmapCeiling, Guess: true})
		return out
	}
	m, ok := h.sure()
	if !ok { // no sure OS fingerprint: the OS a service names is the OS row, only with the version -sV read from that service (D-501)
		for _, p := range h.ports {
			for _, c := range p.cpes {
				if part, vendor, product, _, ok := cpeParts(c); ok && part == "o" && p.version != "" {
					add(observe.Software{Display: strings.TrimSpace(vendor + " " + product + " " + p.version), Vendor: vendor, Product: product, Version: p.version, CPE: cpeBase(c), Confidence: serviceConf(p.conf) * 0.8})
				}
			}
		}
	}
	if ok {
		// The OS of a fingerprint is a guess, and the version in its CPE is the OS generation (iphone_os:15, linux_kernel:5,
		// fortios:7.2), not a release: the row keeps the name for display, has no version and no match keys (Guess), so it never
		// becomes a flood of product-only findings (Windows: 175 CISA entries). A person confirms it by adding the OS with its
		// version on the device page (D-501).
		conf := accuracyConf(m.accuracy)
		for _, c := range m.classes {
			for _, cpe := range c.cpes {
				if part, vendor, product, _, ok := cpeParts(cpe); ok && part == "o" {
					add(observe.Software{Display: m.name, Vendor: vendor, Product: product, CPE: cpeBase(cpe), Confidence: min(conf, accuracyConf(c.accuracy)), Guess: true})
				}
			}
		}
	}
	return out
}

// cpeBase is a CPE 2.2 URI cut to part, vendor and product ("cpe:/o:apple:iphone_os:15" -> "cpe:/o:apple:iphone_os"): what nmap
// knows of an OS fingerprint without the generation, which is no version.
func cpeBase(c string) string {
	f := strings.SplitN(strings.TrimPrefix(c, "cpe:/"), ":", 4)
	if len(f) < 3 {
		return c
	}
	return "cpe:/" + f[0] + ":" + f[1] + ":" + f[2]
}

// servicesOf lists the open ports of the host for the inventory (D-350): tcp and udp only (the inventory has no other protocol),
// at most maxServices. A name or version longer than the inventory keeps is left out, so one long banner does not refuse the
// device's whole list; texts are already printable (text).
func servicesOf(h host) []observe.Service {
	out := []observe.Service{}
	for _, p := range h.ports {
		if len(out) == maxServices {
			break
		}
		if p.number < 1 || (p.proto != "tcp" && p.proto != "udp") {
			continue
		}
		s := observe.Service{Port: p.number, Proto: p.proto, Name: p.name, Product: p.product, Version: p.version, Confidence: serviceConf(p.conf)}
		if utf8.RuneCountInString(s.Name) > maxSvcName {
			s.Name = ""
		}
		if utf8.RuneCountInString(s.Version) > maxSvcVersion {
			s.Version = ""
		}
		out = append(out, s)
	}
	return out
}

// Why a device scan recorded no software with a version (Identification.Why, D-501), in nmap's terms. Without it the vulnerability
// scan has nothing to compare with the KEV list. IdentifyDevice also passes the inventory's refusal reasons (box, declared_by_hand,
// no_ip, out_of_scope, scope_not_confirmed, regular_scan_never, scanning_off) and its own WhyBusy and WhyUnavailable.
const (
	WhyHostDown    = "host_down"         // no answer at all: off, asleep, gone, or a firewall drops even the ARP/ping
	WhyNoOpenPorts = "no_open_ports"     // answered, but every port tried was closed
	WhyFiltered    = "filtered"          // answered, but the probes were dropped (every port filtered)
	WhyNoVersion   = "no_version"        // open ports, but no service named its product and version, and no usable OS guess
	WhyOSGuess     = "os_unconfirmed"    // only nmap's OS guess: recorded and shown, never matched until a person adds it
	WhyOSUnsure    = "os_low_confidence" // as no_version, and nmap's OS guess was below minOSAccuracy
	WhyOSNoPatch   = "os_no_patch_level" // the device named its Windows release (NTLM), not its monthly update level (D-504)
	WhyGentleOnly  = "gentle_only"       // fragile: only the gentle scan ran (no -sV, no -O), which never records software
	WhyTimedOut    = "timed_out"         // nmap's host timeout ended the scan before it printed ports
	WhyBusy        = "busy"              // discovery was running nmap; one nmap at a time, so nothing ran
	WhyUnavailable = "unavailable"       // nmap is not available (the worker in the scan container)
)

// maxFound bounds the lines of Identification.Found.
const maxFound = 20

// identified says in words what a device scan recorded about ip, and why no software was recorded when none was (D-501). It reads
// the same functions recordDevice records from, so it says what was stored, not what nmap printed.
func identified(hosts []host, ip netip.Addr, gentle bool) (found []string, why string) {
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if i < 0 {
		return nil, WhyHostDown
	}
	h := hosts[i]
	for _, o := range deviceObservations(h) {
		switch o.Field {
		case observe.Kind:
			found = append(found, "Type: "+o.Value)
		case observe.OS:
			found = append(found, "Operating system: "+o.Value)
		}
	}
	switch {
	case h.timedOut:
		return found, WhyTimedOut
	case gentle:
		return found, WhyGentleOnly
	}
	sw := softwareOf(h)
	for j, s := range sw {
		line := "Software: " + s.Display
		switch {
		case s.Guess, slices.Contains(found, line): // the guessed OS is the "Operating system" line already
		case len(found) == maxFound-1 && j < len(sw)-1:
			found = append(found, fmt.Sprintf("Software: %d more, on the device page", len(sw)-j))
			return found, ""
		default:
			found = append(found, line)
		}
	}
	switch {
	case slices.ContainsFunc(sw, func(s observe.Software) bool { return !s.Guess && s.Version != "" }):
		return found, ""
	case len(h.ports) == 0 && h.filtered > 0 && h.filtered >= h.closed:
		return found, WhyFiltered
	case len(h.ports) == 0:
		return found, WhyNoOpenPorts
	case h.ntlm.version != "":
		return found, WhyOSNoPatch
	case slices.ContainsFunc(sw, func(s observe.Software) bool { return s.Guess }):
		return found, WhyOSGuess
	}
	if m, ok := h.best(); ok && m.accuracy < minOSAccuracy {
		return found, WhyOSUnsure
	}
	return found, WhyNoVersion
}

// onlyTargets keeps the hosts whose address nmap was asked about (INV-1: a host nmap reports from outside the
// list is never recorded, whatever the XML says).
func onlyTargets(hosts []host, targets []netip.Addr) []host {
	return slices.DeleteFunc(slices.Clone(hosts), func(h host) bool { return !slices.Contains(targets, h.addr) })
}

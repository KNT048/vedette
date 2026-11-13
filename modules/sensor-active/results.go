package sensoractive

import (
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

// generalKind is the kind a "general purpose" match suggests from its OS (D-501): Windows is a pc unless its name says server, macOS
// a pc, iOS and Android a phone (iot), the Unix family a server. It is a hint: recorded below the confidence of a device type.
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
	case "mac os x", "macos":
		return "pc"
	case "ios", "android":
		return "iot"
	case "linux", "freebsd", "openbsd", "netbsd", "solaris", "unix", "aix", "hp-ux":
		return "server"
	}
	return ""
}

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
	add(observe.Hostname, h.hostname, 0.6)
	add(observe.Vendor, h.vendor, 0.6)
	if m, ok := h.sure(); ok {
		add(observe.OS, m.name, accuracyConf(m.accuracy))
		kind := ""
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

// softwareOf lists what the scan says runs on the host: one entry per service (from its CPE, else from its
// product name) and per OS CPE of the best match when it is sure (minOSAccuracy), else per OS CPE a service names. A service with
// neither product nor CPE gives nothing.
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
			display := strings.TrimSpace(p.product + " " + version)
			if p.product == "" {
				display = strings.TrimSpace(vendor + " " + product + " " + version)
			}
			add(observe.Software{Display: display, Vendor: vendor, Product: product, Version: version, CPE: c, Confidence: conf})
		}
		if !withCPE && p.product != "" {
			// ponytail: no CPE, so the vendor is not known; the product name stands for both. A CPE-to-vendor table is the upgrade.
			add(observe.Software{Display: strings.TrimSpace(p.product + " " + p.version), Vendor: p.product, Product: p.product, Version: p.version, Confidence: conf * 0.8})
		}
	}
	m, ok := h.sure()
	if !ok { // no sure OS fingerprint: the OS a service names (FortiGate's admin page says cpe:/o:fortinet:fortios) is the OS row (D-501)
		for _, p := range h.ports {
			for _, c := range p.cpes {
				if part, vendor, product, version, ok := cpeParts(c); ok && part == "o" {
					add(observe.Software{Display: strings.TrimSpace(vendor + " " + product + " " + version), Vendor: vendor, Product: product, Version: version, CPE: c, Confidence: serviceConf(p.conf) * 0.8})
				}
			}
		}
	}
	if ok {
		conf := accuracyConf(m.accuracy)
		for _, c := range m.classes {
			for _, cpe := range c.cpes {
				if part, vendor, product, version, ok := cpeParts(cpe); ok && part == "o" {
					add(observe.Software{Display: m.name, Vendor: vendor, Product: product, Version: version, CPE: cpe, Confidence: min(conf, accuracyConf(c.accuracy))})
				}
			}
		}
	}
	return out
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

// Why a device scan recorded no software (Identification.Why, D-501), in nmap's terms. With no software the vulnerability scan
// has nothing to compare with the KEV list. IdentifyDevice also passes the inventory's refusal reasons (box, declared_by_hand,
// no_ip, out_of_scope, scope_not_confirmed, regular_scan_never, scanning_off) and its own WhyBusy and WhyUnavailable.
const (
	WhyHostDown    = "host_down"         // no answer at all: off, asleep, gone, or a firewall drops even the ARP/ping
	WhyNoOpenPorts = "no_open_ports"     // answered, but every port tried was closed
	WhyFiltered    = "filtered"          // answered, but the probes were dropped (every port filtered)
	WhyNoVersion   = "no_version"        // open ports, but no service named its product, and no usable OS guess
	WhyOSUnsure    = "os_low_confidence" // as no_version, and nmap's OS guess was below minOSAccuracy
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
		case slices.Contains(found, line): // two CPEs of one OS match (iOS 15 and 16) are two rows with one name
		case len(found) == maxFound-1 && j < len(sw)-1:
			found = append(found, fmt.Sprintf("Software: %d more, on the device page", len(sw)-j))
			return found, ""
		default:
			found = append(found, line)
		}
	}
	switch {
	case len(sw) > 0:
		return found, ""
	case len(h.ports) == 0 && h.filtered > 0 && h.filtered >= h.closed:
		return found, WhyFiltered
	case len(h.ports) == 0:
		return found, WhyNoOpenPorts
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

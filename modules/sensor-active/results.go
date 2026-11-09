package sensoractive

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/observe"
)

// nmapCeiling keeps every confidence below 1: nmap guesses, it does not know (INV-8). The inventory ranks a
// value by its source first, so a value a person typed or an agent reported still wins.
const nmapCeiling = 0.95

const maxSoftware = 200

// accuracyConf scales nmap's accuracy (0..100) to a confidence below 1.
func accuracyConf(acc int) float64 { return float64(clamp(acc, 0, 100)) / 100 * nmapCeiling }

// serviceConf scales nmap's service conf (1..10; 0 when absent) to a confidence below 1.
func serviceConf(conf int) float64 {
	if conf == 0 {
		return 0.5 * nmapCeiling
	}
	return float64(clamp(conf, 1, 10)) / 10 * nmapCeiling
}

// kindOf maps nmap's device type (osclass type) to an inventory kind; types with no clear kind give "".
func kindOf(t string) string {
	switch strings.ToLower(t) {
	case "router":
		return "router"
	case "firewall":
		return "firewall"
	case "switch":
		return "switch"
	case "wap":
		return "ap"
	case "printer":
		return "printer"
	case "webcam":
		return "camera"
	case "storage-misc":
		return "nas"
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
	if m, ok := h.best(); ok {
		add(observe.OS, m.name, accuracyConf(m.accuracy))
		for _, c := range m.classes {
			if k := kindOf(c.typ); k != "" {
				add(observe.Kind, k, accuracyConf(min(m.accuracy, c.accuracy))*0.8)
				break
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
// product name) and per OS CPE of the best match. A service with neither product nor CPE gives nothing.
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
	if m, ok := h.best(); ok {
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

// onlyTargets keeps the hosts whose address nmap was asked about (INV-1: a host nmap reports from outside the
// list is never recorded, whatever the XML says).
func onlyTargets(hosts []host, targets []netip.Addr) []host {
	return slices.DeleteFunc(slices.Clone(hosts), func(h host) bool { return !slices.Contains(targets, h.addr) })
}

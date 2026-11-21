package sensoractive

import (
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/versionscheme"
)

// What a device states about itself without a login (INV-25): the firmware version a device's web interface or API gives anyone. A
// scan reads it with nmap's own scripts (nmapargv.Scripts, nmapargv.TitleScripts: http-hp-ilo-info, vmware-version), so no packet
// of ours is new. The statement is the device's own words, not a guess: it becomes an OS observation (source nmap, ranked above
// nmap's fingerprint guess and below SNMP, an agent and a person, inventory INV-44) and a software row with the CPE NVD names the
// product by (a CPE 2.3 string: the matcher compares the update attribute too), so the vulnerability matcher compares it.

// statedFirmware is one statement: the OS line the device page shows, and the software row the matcher compares.
type statedFirmware struct {
	os string
	sw observe.Software
}

var (
	iloGenRE    = regexp.MustCompile(`\biLO ([2-7])\b`)
	iloFirmware = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{2,3}(?:\.[0-9]{1,4})?$`)
	esxiVersion = regexp.MustCompile(`^(?:6\.[0-9]|7\.0|8\.0)(?:\.[0-9]{1,2})?$`)
	esxiBuildRE = regexp.MustCompile(`^[0-9]{5,9}$`)
	esxiName    = regexp.MustCompile(`^VMware ESXi$`)
)

// iloVendor is the vendor NVD names an iLO generation's firmware by: iLO 2, 3 and 4 as "hp", 5 and later as "hpe"
// (cpe:2.3:o:hp:integrated_lights-out_4_firmware, cpe:2.3:o:hpe:integrated_lights-out_5_firmware; NVD CPE dictionary, 2026-11-18).
func iloVendor(gen string) string {
	if gen >= "5" {
		return "hpe"
	}
	return "hp"
}

// statedFirmware lists what the host stated on its ports to the self-statement scripts, each value checked against the shape it
// must have (a page that says anything else gives nothing).
func (h host) statedFirmware() []statedFirmware {
	var out []statedFirmware
	for _, s := range h.says {
		var f statedFirmware
		var ok bool
		switch s.script {
		case "http-hp-ilo-info":
			f, ok = iloFirmwareOf(s)
		case "vmware-version":
			f, ok = esxiOf(s)
		}
		if ok {
			out = append(out, f)
		}
	}
	return out
}

func iloFirmwareOf(s selfSays) (statedFirmware, bool) {
	m := iloGenRE.FindStringSubmatch(s.field("ILOType"))
	ver := s.field("ILOFirmware")
	if m == nil || !iloFirmware.MatchString(ver) {
		return statedFirmware{}, false
	}
	gen := m[1]
	product := "integrated lights-out " + gen + " firmware"
	display := "HPE iLO " + gen + " firmware " + ver
	cpe := "cpe:2.3:o:" + iloVendor(gen) + ":integrated_lights-out_" + gen + "_firmware:" + ver + ":*:*:*:*:*:*:*"
	return statedFirmware{os: display, sw: observe.Software{Display: display, Vendor: iloVendor(gen), Product: product, Version: ver, CPE: cpe, Confidence: nmapCeiling}}, true
}

// esxiOf reads vmware-version's "Server version" ("VMware ESXi 8.0.3") and "Build" ("24022510"). vCenter answers the same call with
// another name and is not an ESXi host: no row. A build in esxi-builds.json (read through core/versionscheme, the ESXi scheme's build
// table) names the release as NVD does (8.0, update_3), so the
// row is matched; a build that is not listed (or one that belongs to another version than the host states) is shown with the version
// the host stated and no CPE, and never matched.
func esxiOf(s selfSays) (statedFirmware, bool) {
	prefix, ver, ok := cutLast(strings.TrimSpace(s.field("Server version")))
	if !ok || !esxiName.MatchString(prefix) || !esxiVersion.MatchString(ver) {
		return statedFirmware{}, false
	}
	build := s.field("Build")
	if !esxiBuildRE.MatchString(build) {
		return statedFirmware{}, false // without its build the line could not be told from a fingerprint name (observe.SelfStatedBasis)
	}
	stated := statedFirmware{os: "VMware ESXi " + ver + " (build " + build + ")", sw: observe.Software{Vendor: "vmware", Product: "esxi", Version: ver, Confidence: nmapCeiling, Guess: true}}
	stated.sw.Display = stated.os
	if b, known := versionscheme.ESXiBuild(build); known && strings.HasPrefix(ver, b.Version) {
		rel := b.Name
		stated.os = "VMware " + rel + " (build " + build + ")"
		stated.sw = observe.Software{Display: stated.os, Vendor: "vmware", Product: "esxi", Version: b.Version, CPE: "cpe:2.3:o:vmware:esxi:" + b.Version + ":" + b.Update + ":*:*:*:*:*:*", Confidence: nmapCeiling}
	}
	return stated, true
}

// cutLast splits "VMware ESXi 8.0.3" at its last space.
func cutLast(s string) (before, after string, ok bool) {
	i := strings.LastIndexByte(s, ' ')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// statedSoftware is the software rows of what the host stated about itself (statedFirmware).
func statedSoftware(h host) []observe.Software {
	var out []observe.Software
	for _, f := range h.statedFirmware() {
		out = append(out, f.sw)
	}
	return out
}

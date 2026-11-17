package findings

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/oui"
)

// The operating system a network device states about itself is software the matcher compares (#910 phase 1):
// content/catalog/network-os.json maps each statement ("JUNOS 15.1R7.9", "FortiOS 7.0.1", "Cisco IOS XE 17.3.1",
// "RouterOS 6.48", "Cisco IOS 15.2(4)M3") to the NVD product (juniper:junos, fortinet:fortios, cisco:ios_xe,
// MikroTik's RouterOS, cisco:ios), the CISA KEV keys that name it, and the version scheme that orders it. One table, one rule:
// a new OS is a row of data, not code.

// The version schemes of network-os.json.
const (
	schemeJunos  = "junos"  // Juniper's maintenance trains (junosEval, junosListed)
	schemeDotted = "dotted" // numbers with an optional letter ("7.0.1", "17.3.1a"): the generic comparison
	schemeNone   = "none"   // not orderable (classic Cisco IOS "15.2(4)M3"): never compared (#910 phase 2)
)

// Which statement counts (review r1 H1, L1 of #919): the device's answer to Vedette's own SNMP read of its address (Asset.SNMPOS)
// always, and it always wins: an LLDP frame can carry another device's MAC as its chassis id. Only a row with lldp_oui also
// reads an LLDP statement (Asset.StatedOS), and only when the device gave no SNMP answer and its network card is that vendor's
// (lldpCard).

// osRow is one row of network-os.json.
type osRow struct {
	Display   string   `json:"display"`
	Vendor    string   `json:"vendor"`
	Product   string   `json:"product"`
	CPE       string   `json:"cpe"` // part:vendor:product, "o:fortinet:fortios"
	Statement string   `json:"statement"`
	LLDPOUI   string   `json:"lldp_oui"` // the IEEE vendor of the card an LLDP statement must come with; "" = SNMP only
	Scheme    string   `json:"scheme"`
	KevKeys   []string `json:"kev_keys"`
	re        *regexp.Regexp
}

var osRows, osRowsErr = loadNetworkOS(catalogdata.NetworkOS)

// loadNetworkOS reads network-os.json; on an error it returns the rows read so far (TestNetworkOS_DataIsValid fails on it).
func loadNetworkOS(data []byte) ([]osRow, error) {
	var f struct {
		OS []osRow `json:"os"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	out := make([]osRow, 0, len(f.OS))
	for _, r := range f.OS {
		re, err := regexp.Compile(r.Statement)
		if err != nil {
			return out, fmt.Errorf("network-os.json %q: statement: %w", r.Display, err)
		}
		if re.NumSubexp() < 1 {
			return out, fmt.Errorf("network-os.json %q: the statement's group 1 is the version", r.Display)
		}
		if r.Scheme != schemeJunos && r.Scheme != schemeDotted && r.Scheme != schemeNone {
			return out, fmt.Errorf("network-os.json %q: scheme %q", r.Display, r.Scheme)
		}
		if _, err := ParseCPE(r.cpe23()); err != nil || strings.Count(r.CPE, ":") != 2 {
			return out, fmt.Errorf("network-os.json %q: cpe %q", r.Display, r.CPE)
		}
		if r.Display == "" || r.Vendor == "" || r.Product == "" || len(r.KevKeys) == 0 {
			return out, fmt.Errorf("network-os.json %q: display, vendor, product and kev_keys are required", r.Display)
		}
		for i, k := range r.KevKeys {
			r.KevKeys[i] = NormalizeKevKey(k)
		}
		r.re = re
		out = append(out, r)
	}
	return out, nil
}

// cpe23 is the row's NVD product as a CPE of any version: the identity PR 1's NVD path (viaNVD, rowVendors) reads.
func (d osRow) cpe23() string { return "cpe:2.3:" + d.CPE + ":*:*:*:*:*:*:*:*" }

// dottedRe is a version the dotted scheme orders: two to four numbers, an optional letter ("17.3.1a").
var dottedRe = regexp.MustCompile(`^\d{1,4}(?:\.\d{1,4}){1,3}[a-z]?$`)

// reads says whether the row's scheme orders version ver against NVD's.
func (d osRow) reads(ver string) bool {
	switch d.Scheme {
	case schemeJunos:
		_, ok := junosParse(ver)
		return ok
	case schemeDotted:
		ver = OSVersion(ver)
		return dottedRe.MatchString(ver) && versionKnown(ver)
	}
	return false
}

// own says whether a recorded row's KEV key names this OS itself (one of its keys, not the vendor's "Multiple Products").
func (d osRow) own(k string) bool {
	k = NormalizeKevKey(k)
	return !multiKey(k) && slices.Contains(d.KevKeys, k)
}

// multiKey says whether a normalised KEV key is a vendor's "Multiple Products".
func multiKey(k string) bool {
	_, p, _ := strings.Cut(k, "|")
	return isMultiProduct(p)
}

// osSoftwareID is the software id of the row a device's own OS gives (deviceSoftware): no inventory row has it.
func osSoftwareID(assetID string) string { return "os:" + assetID }

// deviceOS is the row the OS the device states gives (network-os.json): its first row whose statement is the whole value the
// device states, through the source the row allows (from). Never nmap's OS guess: "Juniper Junos OS 12.1 - 15.1" or
// "Juniper JUNOS 10.4R1.9 (EX4200 switch)" are not statements, even when they won the device's OS field (review M2 of #703).
// orderable is false when the row's scheme cannot order the version (scheme none, or a version it does not read, "7.14rc1"):
// that row is never compared, only listed (MatchResult.NotComparable). ok is false when the device states no such OS, when its
// own agent reports another OS (the agent's reading wins), or when a row a person, an agent or a scan recorded for the OS
// decides instead: one keyed to it with a version the scheme reads, or, for a version that is not orderable, any one keyed to
// it (it gives what it gives today).
func deviceOS(a Asset) (os Software, orderable, ok bool) {
	for _, d := range osRows {
		text := a.SNMPOS
		if text == "" && d.LLDPOUI != "" && lldpCard(a.MAC, d.LLDPOUI) {
			text = a.StatedOS
		}
		m := d.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if a.AgentOS != "" && !d.re.MatchString(a.AgentOS) {
			return Software{}, false, false
		}
		orderable = d.reads(m[1])
		for _, s := range a.Software {
			if slices.ContainsFunc(s.KevKeys, d.own) && versionGiven(s.Version) && (!orderable || d.reads(s.Version)) {
				return Software{}, false, false // "15.1" or "JUNOS 15.1R7.9" typed by a person is not a Junos version: the stated one decides (review L2)
			}
		}
		os = Software{ID: osSoftwareID(a.ID), Display: d.Display, Vendor: d.Vendor, Product: d.Product, Version: m[1],
			KevKeys: slices.Clone(d.KevKeys), CPE: d.cpe23()}
		if a.SNMPOS != "" && text == a.SNMPOS {
			os.Source = "snmp" // the device's own SNMP answer (platformOS, knownVersion); an LLDP-stated Junos keeps no source
		}
		return os, orderable, true
	}
	return Software{}, false, false
}

// deviceSoftware is the software the matcher reads for a device: its inventory rows and, when the device states a network OS
// with a version its scheme orders (deviceOS), one row for that OS. A recorded row of the OS without a readable version, all of
// whose KEV keys are the OS row's, gives way to it: the device's own version decides instead of "add the version" (review M3 of
// #703).
func deviceSoftware(a Asset) []Software {
	return withoutCoveredWindows(deviceOSSoftware(a)) // The agent's Windows release row covers a person's "Windows 11"
}

func deviceOSSoftware(a Asset) []Software {
	os, orderable, ok := deviceOS(a)
	if !ok {
		return a.Software
	}
	out := make([]Software, 0, len(a.Software)+1)
	for _, s := range a.Software {
		covered, own := len(s.KevKeys) > 0, false
		for _, k := range s.KevKeys {
			k = NormalizeKevKey(k)
			covered, own = covered && slices.Contains(os.KevKeys, k), own || !multiKey(k)
		}
		if covered && own { // a FortiGate picked in the catalog (fortinet|fortios, fortinet|multiple products) without a version
			continue
		}
		out = append(out, s)
	}
	if !orderable { // listed only (MatchResult.NotComparable); the covered row without a version gave way all the same (review r1 M2)
		return out
	}
	return append(out, os)
}

// lldpCard says whether an LLDP statement counts for the device: its MAC at its address (Asset.MAC) has an IEEE OUI of vendor,
// or it has none: a device known only through LLDP frames (no address, so no MAC at one) is the frame's own record, where a forged
// frame makes a device that is not there but silences nothing; a frame forged with another device's MAC as its chassis id lands on
// that device, whose card the vendor did not make.
func lldpCard(mac, vendor string) bool {
	if mac == "" {
		return true
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	v, ok := oui.Lookup([6]byte(hw))
	return ok && v == vendor
}

// NotComparable is an exploited CVE of the network OS a device states whose version Vedette cannot order against NVD's (#910
// phase 1: classic Cisco IOS "15.2(4)M3"): no finding and no "add the version" item, but not silent either: the "could not be
// checked" list shows it with reason not_comparable.
type NotComparable struct {
	CVE        string
	SoftwareID string // the OS row's id (osSoftwareID)
	Software   string // its display, "Cisco IOS"
	Version    string // the version as the device states it, "15.2(4)M3"
	Reason     string // NotComparableScheme or NotComparableOtherProduct
}

// The reasons of a NotComparable item.
const (
	// NotComparableScheme: the OS's version has no order Vedette compares (scheme none, or a version the scheme does not read).
	NotComparableScheme = "scheme"
	// NotComparableOtherProduct: CISA's key names the OS but NVD's list names only another product (CVE-2018-0171 for IOS XE).
	NotComparableOtherProduct = "nvd_other_product"
)

// notComparable lists the entries of vulns the device's not-orderable OS row would be compared with: those whose key names it
// (keyedTo) and, for the vendor's "Multiple Products", only those whose NVD list names its product.
func notComparable(os Software, vulns []Vuln) []NotComparable {
	in := newSWInfo(os, "")
	var out []NotComparable
	seen := map[string]bool{}
	for _, v := range vulns {
		if !ValidCVE(v.CVE) || seen[v.CVE] || !keyedTo(os, v) || isMultiProduct(v.Product) && !listsRow(in, v) {
			continue
		}
		seen[v.CVE] = true
		out = append(out, NotComparable{CVE: v.CVE, SoftwareID: os.ID, Software: clean(os.Display), Version: clean(os.Version), Reason: NotComparableScheme})
	}
	return out
}

// listsRow says whether an entry of NVD's list for v names the row's own product (its CPE, name or alias).
func listsRow(in swInfo, v Vuln) bool {
	for _, af := range v.Affected {
		if c, err := af.cpe(); err == nil {
			if own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids); own {
				return true
			}
		}
	}
	return false
}

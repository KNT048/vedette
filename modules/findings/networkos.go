package findings

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/oui"
	"github.com/knt048/vedette/core/productid"
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
			r.KevKeys[i] = productid.NormalizeKey(k)
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

// osScheme is the version scheme of the network OS that NVD configuration c names (its part, vendor and product are a row's
// cpe), "" when it names none.
func osScheme(c CPE) string {
	id := cpeProductID(c)
	if id == "" {
		return ""
	}
	for _, d := range osRows {
		if strings.EqualFold(d.CPE, id) {
			return d.Scheme
		}
	}
	return ""
}

// dottedTrainRe is the numbers a version text starts with, followed by anything but a digit: "15.2" of "15.2(6)e0a", "15.6.3"
// of "15.6.3m1", "5.2.0" of "5.2.0.base", "17.9.1" of "17.9.1y1".
var dottedTrainRe = regexp.MustCompile(`^(\d{1,4}(?:\.\d{1,4}){0,3})(?:[^\d.]|\.[^\d]|$)`)

// dottedTrain is the numbers a version text starts with (dottedTrainRe).
func dottedTrain(s string) ([]uint64, bool) {
	m := dottedTrainRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return nil, false
	}
	var out []uint64
	for _, p := range strings.Split(m[1], ".") {
		n, _ := strconv.ParseUint(p, 10, 64) // at most 4 digits, by the pattern
		out = append(out, n)
	}
	return out, true
}

// trainCmp orders a version against every version that starts with the numbers b: by the first of their common numbers that
// differs ("17.3.1" is after every "15.2…"). ok is false when they share every common number ("16.12.1" and "16.12.1z1",
// "17.3" and "17.3.1a"): the train is the same, and its build is what NVD does not give in a form Vedette orders.
func trainCmp(v, b []uint64) (int, bool) {
	if otherNumbering(v[0], b[0]) {
		return 0, false
	}
	for i := range min(len(v), len(b)) {
		if c := cmp.Compare(v[i], b[i]); c != 0 {
			return c, true
		}
	}
	return 0, false
}

// otherNumbering says whether two first numbers may be one release under two numberings, which no order compares: IOS XE 2.x
// and 3.x carry classic IOS numbers 12.x and 15.x ("3.6.4E" is IOS "15.2(2)E4", and NVD lists IOS XE at both), so neither is
// before the other. IOS XE 16 and later, FortiOS and RouterOS use one numbering.
func otherNumbering(a, b uint64) bool {
	old := func(n uint64) bool { return n < 4 }
	ios := func(n uint64) bool { return n >= 10 && n <= 15 }
	return old(a) && ios(b) || ios(a) && old(b)
}

// dottedListGuess says whether a No for exact NVD row c (with range r: none) rests only on dottedDecide reading the row by its
// train: the generic comparison alone did not rule version ver out ("16.12.1z1", "17.9.1x1", "5.2.0.base" do not read). Such a
// row is one of an enumeration NVD writes partly in forms Vedette does not order, and its enumerations leave releases out
// (CVE-2025-20352 lists IOS XE from 17.6 and affects every release): no finding from it, but no proof either.
func dottedListGuess(c CPE, r VersionRange, ver string) bool {
	lit, ok := c.Version.Literal()
	if !ok || !r.IsZero() || c.Update.Kind != Any || osScheme(c) != schemeDotted {
		return false
	}
	row := VersionRange{StartIncl: lit, EndIncl: lit}
	t := row.Contains(ver)
	if t == No {
		t = looseExact(row, ver)
	}
	return t != No
}

// dottedAfter says whether version ver is after every version NVD entry c (range r) names: after its end bound, or after its
// exact version, by the generic order or, when that does not read, by the train (trainCmp). A range with no end is never passed.
func dottedAfter(c CPE, r VersionRange, ver string) bool {
	bound, incl := r.EndExcl, false
	if r.IsZero() {
		lit, ok := c.Version.Literal()
		if !ok {
			return false
		}
		bound, incl = lit, true
	} else if bound == "" {
		bound, incl = r.EndIncl, true
	}
	if bound == "" {
		return false
	}
	cmpTo, known := compareBound(ver, bound)
	if !known {
		v, okV := dottedTrain(ver)
		b, okB := dottedTrain(bound)
		if !okV || !okB {
			return false
		}
		if cmpTo, known = trainCmp(v, b); !known {
			return false
		}
	}
	return cmpTo > 0 || !incl && cmpTo == 0
}

// dottedDecide is, for a network OS of the dotted scheme, the answer t of the generic comparison for an NVD configuration that
// did not say Yes, read by the numbers each version starts with (trainCmp). It never says Yes:
//   - a range the generic comparison left Unknown because a bound is not in a form it orders: No when the version is outside
//     by those numbers (IOS XE 17.3.1 is after every "up to 15.2(6)e0a"); a bound of the version's own train ("16.12" with
//     16.12.1z1 beside 16.12.4) or of another numbering (otherNumbering) stays Unknown;
//   - an exact version: No when the numbers it starts with differ ("17.9.1y1" and "5.2.0.base" are not 17.9.4), Unknown when
//     they do not, whatever the generic comparison said: "17.5.1" or "17.5.1a" does not prove 17.5.1c outside, because NVD's
//     enumerations leave rebuilds out (CVE-2025-20352 lists 17.5.1 and 17.5.1a and affects all of 17.5).
//
// A version that is not of the scheme's form keeps t.
func dottedDecide(t Tri, r VersionRange, exact bool, ver string) Tri {
	ver = strings.ToLower(OSVersion(ver))
	if t == Yes || !dottedRe.MatchString(ver) || !exact && t == No {
		return t
	}
	v, _ := dottedTrain(ver)
	if exact {
		b, ok := dottedTrain(r.StartIncl)
		if !ok {
			return t // "denali-16.3.4": the generic comparison reads it, or nothing does
		}
		if c, ok := trainCmp(v, b); ok && c != 0 {
			return No
		}
		return Unknown
	}
	outside := func(bound string, in func(int) bool) bool {
		if bound == "" {
			return false
		}
		c, known := compareBound(ver, bound)
		if !known {
			b, ok := dottedTrain(bound)
			if !ok {
				return false
			}
			if c, known = trainCmp(v, b); !known {
				return false
			}
		}
		return !in(c)
	}
	if outside(r.StartIncl, func(c int) bool { return c >= 0 }) || outside(r.StartExcl, func(c int) bool { return c > 0 }) ||
		outside(r.EndIncl, func(c int) bool { return c <= 0 }) || outside(r.EndExcl, func(c int) bool { return c < 0 }) {
		return No
	}
	return Unknown
}

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
	k = productid.NormalizeKey(k)
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
		text := statedText(a, d)
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
			KevKeys: slices.Clone(d.KevKeys), CPE: d.cpe23(), stated: true}
		os.SeenAt = a.StatedOSAt
		if a.SNMPOS != "" && text == a.SNMPOS {
			os.Source = "snmp" // the device's own SNMP answer (platformOS, knownVersion); an LLDP-stated Junos keeps no source
			os.SeenAt = a.SNMPOSAt
		}
		return os, orderable, true
	}
	return Software{}, false, false
}

// statedText is what the device states about its OS that row d may read: its answer to Vedette's own SNMP read always, else, for a
// row with lldp_oui, its LLDP statement when its network card is that vendor's (lldpCard).
func statedText(a Asset, d osRow) string {
	if a.SNMPOS == "" && d.LLDPOUI != "" && lldpCard(a.MAC, d.LLDPOUI) {
		return a.StatedOS
	}
	return a.SNMPOS
}

// statedRow says row s holds the very release of the network OS the device states about itself (statedText, as deviceOS reads it):
// a row of that OS (its KEV key or its CPE's product) whose version is the stated one, while no agent of the device reports another
// OS. The passive sensor writes the release of a switch's LLDP statement as a row of its own ("JUNOS 15.1R7.9" gives Junos OS
// 15.1R7.9); that row, not deviceOS's, is then the one compared, and its version is the device's own word, not a banner's.
func statedRow(a Asset, s Software) bool {
	ver := strings.TrimSpace(s.Version)
	if ver == "" {
		return false
	}
	id := ""
	if c, err := ParseCPE(s.CPE); s.CPE != "" && err == nil {
		id = cpeProductID(c)
	}
	for _, d := range osRows {
		if !slices.ContainsFunc(s.KevKeys, d.own) && (id == "" || !strings.EqualFold(id, d.CPE)) {
			continue
		}
		m := d.re.FindStringSubmatch(statedText(a, d))
		if m == nil || a.AgentOS != "" && !d.re.MatchString(a.AgentOS) {
			continue
		}
		if strings.EqualFold(m[1], ver) {
			return true
		}
	}
	return false
}

// cpeProductID is a CPE's part, vendor and product as network-os.json writes them ("o:juniper:junos"), "" when one is not a value.
func cpeProductID(c CPE) string {
	part, okP := c.Part.Literal()
	vendor, okV := c.Vendor.Literal()
	product, okR := c.Product.Literal()
	if !okP || !okV || !okR {
		return ""
	}
	return part + ":" + vendor + ":" + product
}

// withStated is rows with every row that holds the release the device states (statedRow) marked as its own word (Software.stated).
// rows itself is never changed: a marked copy comes back when one is marked.
func withStated(a Asset, rows []Software) []Software {
	if a.SNMPOS == "" && a.StatedOS == "" {
		return rows
	}
	var out []Software
	for i, s := range rows {
		if trustedReading(s) || !statedRow(a, s) {
			continue
		}
		if out == nil {
			out = slices.Clone(rows)
		}
		out[i].stated = true
	}
	if out == nil {
		return rows
	}
	return out
}

// deviceSoftware is the software every surface reads for a device: its inventory rows (inventory's MatchInput gives only the
// effective row of each software, inventory INV-50; findings never ranks sources itself) and, when the device states a network OS
// with a version its scheme orders (deviceOS), one row for that OS. A recorded row of the OS without a readable version, all of
// whose KEV keys are the OS row's, gives way to it: the device's own version decides instead of "add the version" (review M3 of
// #703).
func deviceSoftware(a Asset) []Software {
	return withoutCoveredWindows(deviceOSSoftware(a)) // The agent's Windows release row covers a person's "Windows 11"
}

func deviceOSSoftware(a Asset) []Software {
	rows := withStated(a, a.Software)
	os, orderable, ok := deviceOS(a)
	if !ok {
		return rows
	}
	out := make([]Software, 0, len(rows)+1)
	for _, s := range rows {
		covered, own := len(s.KevKeys) > 0, false
		for _, k := range s.KevKeys {
			k = productid.NormalizeKey(k)
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

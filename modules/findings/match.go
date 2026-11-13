package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Basis says how a finding was established.
type Basis string

// The three bases of a finding (INV-2).
const (
	BasisScan    Basis = "scan"    // a safe scan template confirmed it
	BasisVersion Basis = "version" // the known version is inside the affected range
	BasisProduct Basis = "product" // only the product matches; version unknown or not checked
)

// Confidence by basis. product/vendor-only values are the mock's (match.ts).
// ConfVersion is a proposal: DATA_MODEL 5.2 says "at least 0.7" for version;
// it sits between a bare product match (0.5) and a scan confirmation (>= 0.95).
const (
	ConfVendorOnly = 0.3
	ConfProduct    = 0.5
	ConfVersion    = 0.7
	ConfScan       = 0.95
)

// Severity is the level given at creation.
type Severity string

// The severities the matcher assigns (INV-5). Critical and high only for a version inside the affected range;
// a match whose version could not be compared is medium (D-500).
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
)

// Software is one inventory software row of an asset.
type Software struct {
	ID, Display, Vendor, Product, Version string
	// KevKeys are the KEV keys the inventory matched this software to
	// ("vendorproject|product", see NormalizeKevKey).
	KevKeys []string
	// CPE is an optional CPE 2.3 string of the software; a malformed one is ignored.
	CPE string
}

// Asset is what the matcher needs to know about a device.
type Asset struct {
	ID    string
	Name  string // hostname, or the IP when there is none
	OS    string // current operating system as inventory folds it ("Ubuntu 26.04.1 LTS", LLDP "JUNOS 15.1R7.9"); "" when unknown
	Model string // the model the device states ("EX4200-48T"); "" when unknown (D-510: Juniper series)
	// StatedOS is the OS the device states itself (LLDP or SNMP system description, "JUNOS 15.1R7.9"), even when another
	// source's value won OS; "" when none (D-510: deviceSoftware reads it, never nmap's guess).
	StatedOS string
	Software []Software
}

// Affected is one NVD cpeMatch entry (vulnerable=true) of a CVE.
type Affected struct {
	CPE   string // CPE 2.3 criteria; a malformed one is ignored
	Range VersionRange
}

// Vuln is a KEV entry with the optional NVD affected configurations.
type Vuln struct {
	CVE        string
	Vendor     string // KEV vendorProject
	Product    string // KEV product
	Name       string // KEV vulnerabilityName: it names the Juniper series a Junos flaw is about (D-510)
	Ransomware bool
	EPSS       float64   // 0 when unknown
	DateAdded  time.Time // when CISA added the entry to KEV; zero when unknown (Reconcile treats that as backlog)
	Affected   []Affected
}

// Evidence is the explanation shown with a finding.
type Evidence struct {
	Summary   string
	Template  string // scan template id, only for basis scan
	Request   string
	Response  string
	CheckedAt time.Time
}

// Match is a finding the matcher would create (status is always suspected).
type Match struct {
	CVE             string
	SoftwareID      string
	SoftwareDisplay string
	Basis           Basis
	Confidence      float64
	Severity        Severity
	Evidence        Evidence
}

// MatchResult separates what is new from what the asset already has, so the
// caller knows which pairs to create and which only to touch (idempotent by
// (asset_id, cve), INV-6).
type MatchResult struct {
	New      []Match
	Existing []Match // pair already present (open or closed): never recreated or reopened
	// NeedVersion lists, per software, the exploited CVEs of its product that cannot be checked because the
	// software has no usable version (D-500): one item for the device, not one finding per CVE.
	NeedVersion []VersionNeeded
	// NotAffected lists the CVEs the device has a finding for that the matcher proves do not apply (D-530): every
	// software of the entry's product has a readable version outside every NVD range (or its OS release is not one
	// the entry lists), none needs a version, none matches. Evidence.Summary is the sentence that closes the finding.
	NotAffected []Match
	// Unlisted lists the CVEs the device has a finding for whose "Multiple Products" entry NVD lists only other products
	// (D-505): no finding, and no proof either (NVD's list can lag the vendor's advisory), so the finding stays open for a
	// person. Evidence.Summary is the sentence of its no_longer_matches history row.
	Unlisted []Match
	// Retired lists the Unlisted CVEs that are settled (D-506): NVD names none of the device's software of that vendor and
	// CISA added the entry at least SettledKEV ago, so NVD's list has had a year to follow the advisory. The current
	// matcher would not create such a finding on a fresh device either: the service closes an open one of basis product
	// (never version, scan or a person's) with Evidence.Summary as its note. Each one is also in Unlisted.
	Retired []Match
}

// SettledKEV is how long a "Multiple Products" entry must have been in KEV before NVD's product list for it is taken as
// settled, so that an old product finding NVD's list leaves out may close by itself (D-506). Recent entries keep D-505:
// open at medium with the note, because NVD's list lags the vendor's advisory in the months after publication.
const SettledKEV = 365 * 24 * time.Hour

// VersionNeeded is a software whose product is on the exploited list but whose version is missing or unreadable.
type VersionNeeded struct {
	SoftwareID, Software string
	Version              string   // as stored; "" when missing
	CVEs                 []string // the CVEs that the version would decide, in list order, each once
}

// NormalizeKevKey normalises a KEV key to "vendorproject|product": each part
// trimmed and lower-cased, exactly as feeds builds the key.
func NormalizeKevKey(key string) string {
	v, p, _ := strings.Cut(key, "|")
	return KevKey(v, p)
}

// KevKey builds the KEV key from vendorProject and product.
func KevKey(vendor, product string) string {
	return strings.ToLower(strings.TrimSpace(vendor)) + "|" + strings.ToLower(strings.TrimSpace(product))
}

func isMultiProduct(product string) bool {
	return strings.EqualFold(strings.TrimSpace(product), "multiple products")
}

// ValidCVE reports whether s matches ^CVE-\d{4}-\d{4,}$.
func ValidCVE(s string) bool {
	rest, ok := strings.CutPrefix(s, "CVE-")
	if !ok {
		return false
	}
	year, seq, ok := strings.Cut(rest, "-")
	if !ok || len(year) != 4 || len(seq) < 4 {
		return false
	}
	for _, part := range []string{year, seq} {
		for i := 0; i < len(part); i++ {
			if !isDigit(part[i]) {
				return false
			}
		}
	}
	return true
}

// MatchAsset matches the asset's software against the KEV entries. have holds
// the CVEs the asset already has a finding for (any status). Vulns with an
// invalid CVE id are skipped. Per CVE at most one match is produced, the
// strongest one (version before product, then input order).
//
// Per software: the KEV key must match (or, for "Multiple products", the vendor; then
// only an NVD entry naming the software itself can give a finding, D-505).
// Then the NVD configurations decide (D-500): the version inside a range gives
// basis version, outside every applicable range gives no finding, a given
// version that cannot be compared (no NVD data, a scheme Vedette cannot read,
// such as Cisco "15.2(4)M3") gives basis product at severity medium. A software
// with no version at all (missing, a placeholder such as "0", or words without a
// number such as "latest") gives no finding for an undecided CVE: the CVE is
// counted in the software's NeedVersion item instead, unless NVD lists every
// version of the product as affected (then basis product, medium).
func MatchAsset(a Asset, vulns []Vuln, have map[string]bool, now time.Time) MatchResult {
	var res MatchResult
	seen := make(map[string]bool, len(vulns))
	need := map[string]int{} // software id -> index in res.NeedVersion
	sws := deviceSoftware(a) // its rows, and the network OS it states with its version (D-510)
	infos := make([]swInfo, len(sws))
	for i, s := range sws {
		infos[i] = newSWInfo(s, a.OS)
	}
	for _, v := range vulns {
		if !ValidCVE(v.CVE) || seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		var best, proved, unlisted *Match
		unproved := false    // a software of this product with a No that proves nothing, or one that needs a version
		othersOnly := true   // every software keyed to the entry is one NVD's list leaves out (D-506)
		var unnamed []string // their names, for the D-506 sentence
		for i, s := range sws {
			m, out := matchOne(a, s, infos[i], v, now)
			if out != outNone && (out != outRuledOut || m.Evidence.Summary == "") {
				othersOnly = false
			}
			switch out {
			case outNotAffected:
				if proved == nil {
					proved = &m
				}
			case outRuledOut:
				unproved = true
				if m.Evidence.Summary != "" {
					if unlisted == nil {
						unlisted = &m
					}
					if !slices.Contains(unnamed, m.SoftwareDisplay) {
						unnamed = append(unnamed, m.SoftwareDisplay)
					}
				}
			case outMatch:
				if best == nil || rank(m.Basis) > rank(best.Basis) {
					best = &m
				}
			case outNeedVersion:
				unproved = true
				i, ok := need[s.ID]
				if !ok {
					i = len(res.NeedVersion)
					need[s.ID] = i
					res.NeedVersion = append(res.NeedVersion, VersionNeeded{SoftwareID: s.ID, Software: clean(s.Display), Version: clean(s.Version)})
				}
				if c := res.NeedVersion[i].CVEs; len(c) == 0 || c[len(c)-1] != v.CVE {
					res.NeedVersion[i].CVEs = append(c, v.CVE)
				}
			}
		}
		if best == nil {
			switch {
			case !have[v.CVE]:
			case proved != nil && !unproved: // D-530: only a proof for every software of the product
				res.NotAffected = append(res.NotAffected, *proved)
			case unlisted != nil:
				res.Unlisted = append(res.Unlisted, *unlisted)
				if othersOnly && isMultiProduct(v.Product) && settled(v, now) { // D-506 is about "Multiple Products" only (not D-510's series)
					r := *unlisted
					r.Evidence.Summary = fmt.Sprintf("Closed by Vedette: CISA lists %s for several %s products; NVD names %s, not %s (settled: CISA added it over a year ago). Vedette checks it again whenever NVD's data for it changes.",
						v.CVE, clean(v.Vendor), nvdProducts(v.Vendor, v.Affected), orList(unnamed))
					res.Retired = append(res.Retired, r)
				}
			}
			continue
		}
		if have[v.CVE] {
			res.Existing = append(res.Existing, *best)
		} else {
			res.New = append(res.New, *best)
		}
	}
	return res
}

// settled reports whether CISA added v to KEV at least SettledKEV before now (D-506); an unknown date is never settled.
func settled(v Vuln, now time.Time) bool {
	return !v.DateAdded.IsZero() && !v.DateAdded.After(now.Add(-SettledKEV))
}

// outcome of one software against one KEV entry.
type outcome uint8

const (
	outNone        outcome = iota // not this product, or a version outside every range
	outMatch                      // a finding
	outNeedVersion                // this product, but only a version would tell
	outRuledOut                   // this product, ruled out without a proof about the version (keeps a finding open)
	outNotAffected                // this product, and its version is proved outside every range (D-530)
)

// nvdProducts names the products of NVD entries for a sentence: "fusion, horizon client, remote console", the first three
// in list order and how many more. Only the vendor's own products are named when NVD lists any (a Fortinet entry may also
// list a Siemens product that embeds it).
func nvdProducts(vendor string, afs []Affected) string {
	var names, own []string
	seen := map[string]bool{}
	for _, af := range afs {
		c, err := ParseCPE(af.CPE)
		if err != nil {
			continue
		}
		p, ok := c.Product.Literal()
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		names = append(names, strings.ReplaceAll(p, "_", " "))
		if cv, _ := c.Vendor.Literal(); norm(cv) == norm(vendor) {
			own = append(own, names[len(names)-1])
		}
	}
	if len(own) > 0 {
		names = own
	}
	if len(names) > 3 {
		return clean(strings.Join(names[:3], ", ")) + fmt.Sprintf(" and %d more", len(names)-3)
	}
	return clean(strings.Join(names, ", "))
}

func rank(b Basis) int {
	switch b {
	case BasisProduct:
		return 1
	case BasisVersion:
		return 2
	case BasisScan:
		return 3
	}
	return 0
}

// keyedTo reports whether the software's KEV keys match the entry: its key, or for "Multiple Products" its vendor.
func keyedTo(s Software, v Vuln) bool {
	if strings.Contains(v.Vendor, "|") || strings.Contains(v.Product, "|") {
		return false // the key separator cannot be part of a KEV vendor or product
	}
	multi := isMultiProduct(v.Product)
	vendorPrefix := strings.ToLower(strings.TrimSpace(v.Vendor)) + "|"
	key := KevKey(v.Vendor, v.Product)
	for _, k := range s.KevKeys {
		k = NormalizeKevKey(k)
		if multi && strings.HasPrefix(k, vendorPrefix) || !multi && k == key {
			return true
		}
	}
	return false
}

func matchOne(a Asset, s Software, in swInfo, v Vuln, now time.Time) (Match, outcome) {
	if !keyedTo(s, v) {
		return Match{}, outNone
	}
	if named, out := otherSeries(a.Model, v); out { // D-510: CISA names other Juniper series than the device's model; no proof about the version
		note := fmt.Sprintf("CISA lists %s for Juniper %s only; this device's model is %s. Check the vendor advisory and close it if it does not apply.", v.CVE, orList(named), clean(a.Model))
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outRuledOut
	}
	multi := isMultiProduct(v.Product)
	tri, within, every, proof := decide(in, v, multi)
	switch {
	case tri == No && proof == proofNone:
		if multi && listsOthersOnly(in, v) { // D-505: no proof (NVD's list can lag the advisory); the person reads why
			note := fmt.Sprintf("NVD lists %s for %s, not %s; check the vendor advisory and close it if it does not apply.", nvdProducts(v.Vendor, v.Affected), v.CVE, clean(s.Display))
			return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outRuledOut
		}
		return Match{}, outRuledOut
	case tri == No:
		note := fmt.Sprintf("Not affected: version %s of %s is outside every version range NVD lists for %s. Vedette closed this by itself and reopens it if a later match says the device is affected.", clean(in.ver), clean(s.Display), v.CVE)
		if proof == proofOS {
			note = fmt.Sprintf("Not affected: %s lists only operating-system releases other than this device's (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.", v.CVE, clean(a.OS))
		}
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outNotAffected
	case tri == Unknown && !in.given && !every:
		return Match{}, outNeedVersion // D-500: one "add the version" item per software, not one finding per CVE
	}
	sw := clean(s.Display)
	if s.Version != "" {
		sw += " " + clean(s.Version)
	}
	name := clean(a.Name)
	m := Match{
		CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Basis: BasisProduct, Confidence: ConfProduct,
		Severity: SeverityMedium,
	}
	switch {
	case tri == Yes:
		m.Basis, m.Confidence, m.Severity = BasisVersion, ConfVersion, SeverityHigh
		if v.Ransomware || v.EPSS >= 0.5 {
			m.Severity = SeverityCritical
		}
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. Its version is inside the range affected by %s (%s); no scan has confirmed it yet, so this is only suspected.", name, sw, v.CVE, clean(within.String()))
	case every && !in.given:
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. NVD lists every version of it as affected by %s; no scan has confirmed it yet, so this is only suspected.", name, sw, v.CVE)
	case multi:
		m.Confidence = ConfVendorOnly
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. CISA lists this flaw for several %s products; check the advisory to see whether yours is one of them.", name, sw, clean(v.Vendor))
	default:
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. Vedette has not checked whether this version is in the affected range; compare it with the vendor advisory or run a scan.", name, sw)
	}
	m.Evidence.CheckedAt = now
	return m, outMatch
}

// decide evaluates the NVD configurations for one software. Yes carries the
// range that matched; No means every applicable configuration rules it out and
// nothing was undecidable; Unknown covers "no applicable configuration", an
// unparseable or unidentifiable entry, and anything not comparable. Only a
// definite No drops a KEV match. given says whether the software has a version at
// all (versionGiven); an Unknown without one is "add the version".
// swInfo is what the matcher derives once per software.
type swInfo struct {
	cpe    CPE
	hasCPE bool
	ver    string     // the version, or the CPE's when the software has none
	given  bool       // ver says something about the version (versionGiven); it may still be unreadable
	ids    []identity // the software's own names: inventory vendor/product and its aliases (cpeAliases)
	// os and osVer: the device's operating system as an NVD product ("canonical:ubuntu_linux", "26.04.1"), when known.
	os    identity
	osVer string
}

func newSWInfo(s Software, osName string) swInfo {
	var in swInfo
	in.os, in.osVer = osIdentity(osName)
	if s.CPE != "" {
		if c, err := ParseCPE(s.CPE); err == nil {
			in.cpe, in.hasCPE = c, true
		}
	}
	in.ver = s.Version
	if in.ver == "" && in.hasCPE {
		in.ver, _ = in.cpe.Version.Literal()
	}
	in.given = versionGiven(in.ver)
	if n := (identity{vendor: norm(s.Vendor), product: norm(s.Product)}); n.ok() {
		in.ids = append(append(in.ids, n), cpeAliases[n]...)
	}
	return in
}

// listsOthersOnly reports whether every NVD entry of v is readable and names another product than the software (D-505).
func listsOthersOnly(in swInfo, v Vuln) bool {
	for _, af := range v.Affected {
		c, err := ParseCPE(af.CPE)
		if err != nil {
			return false
		}
		if own, known := appliesTo(c, in.cpe, in.hasCPE, in.ids); own || !known {
			return false
		}
	}
	return len(v.Affected) > 0
}

// decide evaluates the NVD configurations of v for one software. every is true when an applicable entry names every
// version of the product (no range, version and update ANY, nothing pinned the software contradicts): then the answer
// does not depend on the version, so a software without one is not sent to "add the version" (D-500).
//
// An entry applies when it names the software's own identity (its CPE, name or alias) or the KEV entry's own vendor
// and product. Only the first can prove: a No on an entry found by the KEV key alone is Unknown, and so is any
// answer from an entry that lists releases of a distribution the software itself is (a catalog "Ubuntu Linux 22.04"
// row keyed to the kernel), because a release is not the version of the package the CVE is about (review N1).
//
// proof says what a No rests on (D-530): proofRange when every applicable entry rules the readable version out,
// proofOS when the entry lists only releases of the device's own distribution and not its release, proofNone for a
// "Multiple Products" entry without NVD data or whose NVD list names only other products (D-505): no finding, and nothing
// closes, because NVD's list for such an entry can lag the vendor's advisory.
func decide(in swInfo, v Vuln, multi bool) (t Tri, within VersionRange, every bool, proof proofKind) {
	var key []identity // the KEV entry's own vendor and product: it finds the entry, but a No on it alone proves nothing
	if n := (identity{vendor: norm(v.Vendor), product: norm(v.Product)}); !multi && n.ok() {
		key = []identity{n}
	}
	result := No
	applicable, undecidable := false, false
	var yes *VersionRange // the widest range the version is inside: the one that explains the finding and names its fix (D-488)
	jv, isJ := junosParse(in.ver)
	junosSeen := false // a Junos NVD row decided (junosEval): its exact rows say what a missing update means (D-510)
	var jrows []junosVer
	for _, af := range v.Affected {
		c, err := ParseCPE(af.CPE)
		if err != nil || c.Part.Kind == NA {
			undecidable = true // cannot tell which product this entry is about
			continue
		}
		own, known := appliesTo(c, in.cpe, in.hasCPE, in.ids)
		byKey, _ := appliesTo(c, CPE{}, false, key)
		if !own && !byKey {
			undecidable = undecidable || !known
			continue
		}
		applicable = true
		if isJ && isJunos(c) {
			junosSeen = true
			if row, ok := junosRow(c, af.Range); ok {
				jrows = append(jrows, row)
			}
		}
		t, r := evalAffected(c, af.Range, in.ver, in.cpe, in.hasCPE)
		if t != No && af.Range.IsZero() && everyVersion(c) {
			every = true
		}
		switch {
		case !own && t == No:
			t = Unknown // matched by the KEV key alone: the version may be of something else, so no proof (review N1)
		case !byKey && distroRelease(c):
			// The software is a distribution ("Ubuntu Linux 22.04", keyed to the kernel) and the entry lists releases
			// of it that shipped an affected package: the release is not the version of that package, so it neither
			// proves nor rules out (review N1; a kernel CVE stays a product finding, medium).
			t = Unknown
		}
		switch t {
		case Yes:
			if yes == nil || widerEnd(r, *yes) {
				yes = &r
			}
		case Unknown:
			result = Unknown
		case No:
		}
	}
	if yes != nil {
		return Yes, *yes, every, proofNone
	}
	if !applicable && in.osVer != "" && osRulesOut(v, in) {
		p := proofNone
		if versionKnown(in.osVer) {
			p = proofOS
		}
		return No, VersionRange{}, false, p // the entry names only operating-system releases, and not this device's (D-500)
	}
	if !applicable && multi {
		// CISA's "Multiple Products" names no product: only NVD's list can tie the entry to this software (D-505, W3-7).
		switch {
		case len(v.Affected) == 0:
			return No, VersionRange{}, false, proofNone // NVD lists no product yet: a vendor-wide guess is noise, and proves nothing
		case undecidable:
			return Unknown, VersionRange{}, every, proofNone // an entry that may be about this software (vendor or product ANY)
		}
		return No, VersionRange{}, false, proofNone // NVD lists other products only: no finding, but no proof (its list can lag the advisory)
	}
	if !applicable || undecidable && result == No {
		return Unknown, VersionRange{}, every, proofNone
	}
	if junosSeen && result == No { // NVD's Junos lists have gaps: a missing update is not a proof (review H1 of #703)
		t, w, proved := junosListed(jv, jrows)
		switch {
		case t != No:
			return t, w, every, proofNone
		case proved:
			return No, VersionRange{}, every, proofRange
		}
		return No, VersionRange{}, every, proofNone
	}
	if pv, ok := parseVersion(in.ver); result == No && ok && !isPlaceholder(in.ver) && pv.q.class >= 0 {
		return No, VersionRange{}, every, proofRange // a pre-release ("2.0.0-rc1") near a bound proves nothing (review L5)
	}
	return result, VersionRange{}, every, proofNone
}

// proofKind is what a No of decide rests on (D-530): only proofRange and proofOS close a finding.
type proofKind uint8

const (
	proofNone  proofKind = iota // no No, or a No that proves nothing about the version
	proofRange                  // the readable version is outside every applicable NVD entry
	proofOS                     // the entry lists only releases of the device's distribution, not its release
)

// everyVersion reports whether configuration c names the product with nothing else pinned: every version, update,
// edition, language and target.
func everyVersion(c CPE) bool {
	f := c.fields()
	for _, a := range f[3:] { // version and everything after it
		if a.Kind != Any {
			return false
		}
	}
	return true
}

// identity is a normalised vendor and product; prefix (aliases only) matches every product that starts with it.
type identity struct {
	vendor, product string
	prefix          bool
}

func (i identity) ok() bool { return i.vendor != "" && i.product != "" }

func (i identity) matches(vendor, product string) bool {
	if i.vendor != vendor {
		return false
	}
	if i.prefix {
		return strings.HasPrefix(product, i.product)
	}
	return i.product == product
}

// norm keeps only [a-z0-9] so "Photo Station" equals "photo_station".
func norm(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// appliesTo says whether configuration c is about this software. known is false
// when c names its vendor or product with ANY, NA or a wildcard and the software
// has no CPE to settle it: such an entry may be about this software.
func appliesTo(c, sw CPE, hasSW bool, ids []identity) (match, known bool) {
	if hasSW && c.SameProduct(sw) {
		return true, true
	}
	cv, okV := c.Vendor.Literal()
	cp, okP := c.Product.Literal()
	if !okV || !okP {
		return false, false
	}
	cv, cp = norm(cv), norm(cp)
	for _, i := range ids {
		if i.matches(cv, cp) {
			return true, true
		}
	}
	return false, true
}

// versionKnown reports whether ver is a real, comparable version.
func versionKnown(ver string) bool {
	_, ok := parseVersion(ver)
	return ok && !isPlaceholder(ver)
}

// versionGiven reports whether ver says anything about the version: not empty, not a placeholder ("0", "0.0.0") and
// with at least one digit ("latest", "unknown", "n/a" say nothing). A given version may still be unreadable (Cisco
// "15.2(4)M3"): that is "cannot compare" (a product finding, medium), not "add the version" (D-500, review H1).
func versionGiven(ver string) bool {
	ver = strings.TrimSpace(ver)
	return strings.ContainsAny(ver, "0123456789") && !isPlaceholder(ver) && len(ver) <= maxVersionLen
}

// evalAffected evaluates one configuration CPE (with its NVD range) against the
// software. Everything the software side cannot confirm (an unknown version, a
// pinned update, edition, language or target the software does not carry) can
// only lower Yes to Unknown, never produce No.
func evalAffected(c CPE, r VersionRange, ver string, sw CPE, hasSW bool) (Tri, VersionRange) {
	if t, jr, ok := junosEval(c, r, ver); ok { // D-510: "15.1R7.9" is 15.1R7, an X train is a release of its own
		if t = pinnedAttrs(c, sw, hasSW, t); t == No {
			return No, r
		}
		return t, jr
	}
	exact := false
	if r.IsZero() {
		switch c.Version.Kind {
		case Any: // every version
		case Value:
			lit, ok := c.Version.Literal()
			if !ok {
				return Unknown, r
			}
			r = VersionRange{StartIncl: lit, EndIncl: lit}
			exact = true
		default:
			return Unknown, r
		}
	} else if c.Version.Kind != Any {
		return Unknown, r // a range next to a concrete version: contradictory data
	}
	var t Tri
	if et, ok := officeEdition(c, r, exact, ver); ok {
		t = et
	} else if schemeClash(r, ver) {
		t = Unknown // "2016" against "16.0.1", "1607" against "10.0.14393": two ways of writing versions
	} else if c.Update.Kind == Any {
		t = r.Contains(ver)
		if t == No && exact {
			t = looseExact(r, ver)
		}
	} else {
		t = evalUpdate(c, r, ver, sw, hasSW)
	}
	if t == Yes && !versionKnown(ver) {
		t = Unknown // "all versions" does not make an unknown version a version match
	}
	if exact && t != Yes && c.Update.Kind == Any && sameVersionText(r.StartIncl, ver) {
		t = Yes // the exact version NVD lists, character for character: Cisco "15.2(4)m3" needs no ordering
	}
	if t = pinnedAttrs(c, sw, hasSW, t); t == No {
		return No, r
	}
	return t, r
}

// looseExact softens a No for an exact-version configuration whose update is ANY:
// ANY covers every update, so the software "8.9p1" may be configuration "8.9".
func looseExact(r VersionRange, ver string) Tri {
	pv, ok := parseVersion(ver)
	if !ok || pv.q.class == 0 {
		return No
	}
	if r.Contains(relString(pv)) == Yes {
		return Unknown
	}
	return No
}

// evalUpdate handles a configuration pinned to an update ("8.9:p1", "2.0:beta1").
// The software side must carry the update, either as the CPE update attribute or
// as a qualifier of its version string ("8.9p1", "2.0-beta1"); otherwise Unknown.
func evalUpdate(c CPE, r VersionRange, ver string, sw CPE, hasSW bool) Tri {
	pv, ok := parseVersion(ver)
	if !ok || isPlaceholder(ver) {
		return Unknown
	}
	if r.Contains(relString(pv)) == No {
		return No // the release itself is outside ("2016" against "2000:sr1"): the update does not matter (D-500)
	}
	if pv.tail != "" {
		return Unknown
	}
	if c.Update.Kind == NA && !hasSW { // "1.9.17:-" is the release with no update: "1.9.17p2" is not it (D-500)
		if pv.q.class != 0 {
			return No
		}
		return r.Contains(ver)
	}
	if hasSW && sw.Update.Kind == Value && pv.q.class == 0 {
		if !attrMatch(c.Update, sw.Update) {
			return No
		}
		return r.Contains(ver)
	}
	cu, ok := c.Update.Literal()
	if !ok {
		return Unknown
	}
	cq, ctail, ok := parseQual(strings.ToLower(cu))
	if !ok || ctail != "" {
		return Unknown
	}
	if pv.q.class == 0 {
		if cq.class < 0 {
			return No // a plain "7.0.0" is the release, not the pre-release "7.0:rc1" (D-500, W2-11)
		}
		return Unknown // a plain "8.9" may be "8.9p1": the patch level is often left out
	}
	if cq != pv.q {
		if cq.class == pv.q.class && cq.sub == pv.q.sub && (cq.num == 0 || pv.q.num == 0) {
			return Unknown // same kind of update, one without a number: "beta" may be "beta1"
		}
		return No // "h1" is not "h2", Junos "r2-s1" is not "r2" (D-500)
	}
	return r.Contains(relString(pv))
}

// pinnedAttrs checks the attributes the software side rarely carries (edition,
// language, software edition, target software/hardware, other). A pinned value
// the software contradicts gives No; one it does not carry lowers Yes to Unknown.
func pinnedAttrs(c, sw CPE, hasSW bool, t Tri) Tri {
	cfa := c.fields()
	cf := cfa[5:]
	var sf []*Attr
	if hasSW {
		sfa := sw.fields()
		sf = sfa[5:]
	}
	for i, a := range cf {
		if a.Kind == Any {
			continue
		}
		if hasSW {
			if attrMatch(*a, *sf[i]) {
				continue
			}
			if sf[i].Kind == Value {
				return No
			}
		}
		if t == Yes {
			t = Unknown
		}
	}
	return t
}

// clean removes control characters and caps the length: names, versions and
// ranges come from agents and feeds (untrusted) and end up in evidence text.
func clean(s string) string {
	var sb strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if n++; n > 120 {
			sb.WriteString("...")
			break
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// widerEnd says range a ends later than b; a range with no end is the widest, and a tie keeps b.
func widerEnd(a, b VersionRange) bool {
	end := func(r VersionRange) string { return cmp.Or(r.EndExcl, r.EndIncl) }
	ea, eb := end(a), end(b)
	if ea == "" || eb == "" {
		return ea == "" && eb != ""
	}
	c, ok := compareBound(ea, eb)
	return ok && c > 0
}

// orList joins names for a sentence: "A", "A or B", "A, B or C".
func orList(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

package findings

import (
	"fmt"
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

// The severities the matcher assigns (INV-5).
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
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
	ID       string
	Name     string // hostname, or the IP when there is none
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
// Per software: the KEV key must match (or, for "Multiple products", the vendor).
// Then the NVD configurations decide: the version inside a range gives basis
// version, outside every applicable range gives no finding, anything that cannot
// be decided gives basis product. Without applicable configurations the answer
// is product.
func MatchAsset(a Asset, vulns []Vuln, have map[string]bool, now time.Time) MatchResult {
	var res MatchResult
	seen := make(map[string]bool, len(vulns))
	for _, v := range vulns {
		if !ValidCVE(v.CVE) || seen[v.CVE] {
			continue
		}
		var best *Match
		for _, s := range a.Software {
			m, ok := matchOne(a, s, v, now)
			if ok && (best == nil || rank(m.Basis) > rank(best.Basis)) {
				best = &m
			}
		}
		if best == nil {
			continue
		}
		seen[v.CVE] = true
		if have[v.CVE] {
			res.Existing = append(res.Existing, *best)
		} else {
			res.New = append(res.New, *best)
		}
	}
	return res
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

func matchOne(a Asset, s Software, v Vuln, now time.Time) (Match, bool) {
	multi := isMultiProduct(v.Product)
	vendorPrefix := strings.ToLower(strings.TrimSpace(v.Vendor)) + "|"
	key := KevKey(v.Vendor, v.Product)
	if strings.Contains(v.Vendor, "|") || strings.Contains(v.Product, "|") {
		return Match{}, false // the key separator cannot be part of a KEV vendor or product
	}
	keyed := false
	for _, k := range s.KevKeys {
		k = NormalizeKevKey(k)
		if multi && strings.HasPrefix(k, vendorPrefix) || !multi && k == key {
			keyed = true
			break
		}
	}
	if !keyed {
		return Match{}, false
	}
	tri, within := decide(s, v, multi)
	if tri == No {
		return Match{}, false
	}
	sw := clean(s.Display)
	if s.Version != "" {
		sw += " " + clean(s.Version)
	}
	name := clean(a.Name)
	m := Match{
		CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Basis: BasisProduct, Confidence: ConfProduct,
		Severity: SeverityHigh,
	}
	if v.Ransomware || v.EPSS >= 0.5 {
		m.Severity = SeverityCritical
	}
	switch {
	case tri == Yes:
		m.Basis, m.Confidence = BasisVersion, ConfVersion
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. Its version is inside the range affected by %s (%s); no scan has confirmed it yet, so this is only suspected.", name, sw, v.CVE, clean(within.String()))
	case multi:
		m.Confidence = ConfVendorOnly
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. CISA lists this flaw for several %s products; check the advisory to see whether yours is one of them.", name, sw, clean(v.Vendor))
	default:
		m.Evidence.Summary = fmt.Sprintf("%s runs %s. Vedette has not checked whether this version is in the affected range; compare it with the vendor advisory or run a scan.", name, sw)
	}
	m.Evidence.CheckedAt = now
	return m, true
}

// decide evaluates the NVD configurations for one software. Yes carries the
// range that matched; No means every applicable configuration rules it out and
// nothing was undecidable; Unknown covers "no applicable configuration", an
// unparseable or unidentifiable entry, and anything not comparable. Only a
// definite No drops a KEV match.
func decide(s Software, v Vuln, multi bool) (Tri, VersionRange) {
	var swCPE CPE
	hasCPE := false
	if s.CPE != "" {
		if c, err := ParseCPE(s.CPE); err == nil {
			swCPE, hasCPE = c, true
		}
	}
	ver := s.Version
	if ver == "" && hasCPE {
		ver, _ = swCPE.Version.Literal()
	}
	var ids []identity
	if n := (identity{norm(s.Vendor), norm(s.Product)}); n.ok() {
		ids = append(ids, n)
	}
	if !multi {
		if n := (identity{norm(v.Vendor), norm(v.Product)}); n.ok() {
			ids = append(ids, n)
		}
	}
	result := No
	applicable, undecidable := false, false
	for _, af := range v.Affected {
		c, err := ParseCPE(af.CPE)
		if err != nil || c.Part.Kind == NA {
			undecidable = true // cannot tell which product this entry is about
			continue
		}
		match, known := appliesTo(c, swCPE, hasCPE, ids)
		if !match {
			undecidable = undecidable || !known
			continue
		}
		applicable = true
		t, r := evalAffected(c, af.Range, ver, swCPE, hasCPE)
		switch t {
		case Yes:
			return Yes, r
		case Unknown:
			result = Unknown
		case No:
		}
	}
	if !applicable || undecidable && result == No {
		return Unknown, VersionRange{}
	}
	return result, VersionRange{}
}

type identity struct{ vendor, product string }

func (i identity) ok() bool { return i.vendor != "" && i.product != "" }

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
		if i.vendor == cv && i.product == cp {
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

// evalAffected evaluates one configuration CPE (with its NVD range) against the
// software. Everything the software side cannot confirm (an unknown version, a
// pinned update, edition, language or target the software does not carry) can
// only lower Yes to Unknown, never produce No.
func evalAffected(c CPE, r VersionRange, ver string, sw CPE, hasSW bool) (Tri, VersionRange) {
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
	if c.Update.Kind == Any {
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
	if !ok || pv.tail != "" || isPlaceholder(ver) {
		return Unknown
	}
	if hasSW && sw.Update.Kind == Value && pv.q.class == 0 {
		if !attrMatch(c.Update, sw.Update) {
			return No
		}
		return r.Contains(ver)
	}
	cu, ok := c.Update.Literal()
	if !ok || pv.q.class == 0 {
		return Unknown
	}
	cq, ctail, ok := parseQual(strings.ToLower(cu))
	if !ok || ctail != "" {
		return Unknown
	}
	if cq != pv.q {
		if cq.class == pv.q.class && cq.sub == pv.q.sub {
			return Unknown // same kind of update, numbers differ: "beta" may be "beta1"
		}
		return No
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

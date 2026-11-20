package feeds

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// CVE.org affected versions. NVD lags: an exploited CVE CISA adds today often has no NVD configuration for days,
// so findings can only say "product match". The CNA (most often the vendor) publishes the affected versions in its CVE
// record, and the CVE Program mirrors every record to the public cvelistV5 repository. For the CISA KEV CVEs NVD gave no
// usable ranges, the box reads that record and turns its affected versions into the same rows nvd-kev writes. Only the
// CVE ID is in a request (the file's path).
const (
	// CVEOrgMaxBytes bounds one record (the largest Linux kernel records are a few hundred kB).
	CVEOrgMaxBytes = 2 << 20
	// cveOrgMaxProducts and cveOrgMaxVersions make the conversion fail closed on a hostile record.
	cveOrgMaxProducts = 500
	cveOrgMaxVersions = 2000
	cveOrgMaxName     = 200
)

// CVEOrgRecordURL is the address of one record under base (the cves directory of cvelistV5):
// base/<year>/<number/1000>xxx/<CVE>.json, as the repository lays them out ("CVE-2024-3400" -> "2024/3xxx").
func CVEOrgRecordURL(base, cve string) (string, error) {
	if err := CheckURL(base); err != nil {
		return "", err
	}
	if strings.ContainsAny(base, "?#") {
		return "", fail(ErrInvalidURL, "The CVE.org address must not carry a query string.")
	}
	if !cveRE.MatchString(cve) {
		return "", fail(ErrBadSample, "%s is not a CVE ID.", quoteVal(cve))
	}
	year, num, _ := strings.Cut(strings.TrimPrefix(cve, "CVE-"), "-")
	n, err := strconv.Atoi(num)
	if err != nil {
		return "", fail(ErrBadSample, "%s is not a CVE ID.", quoteVal(cve))
	}
	return strings.TrimRight(strings.TrimSpace(base), "/") + "/" + year + "/" + strconv.Itoa(n/1000) + "xxx/" + cve + ".json", nil
}

// What a CVE.org record gave for one CVE.
const (
	CVEOrgRanges     = "ranges"      // affected versions of CISA's product
	CVEOrgNoMatch    = "no_match"    // the record names other products than CISA's entry (or CISA names several)
	CVEOrgNoVersions = "no_versions" // CISA's product is there, without an affected version (status unknown)
	CVEOrgUnusable   = "unusable"    // versions Vedette cannot turn into ranges safely (git commits, holes, wildcards)
	CVEOrgRejected   = "rejected"    // the CVE ID was rejected: no product is affected
)

// CVEOrgResult is the conversion of one record.
type CVEOrgResult struct {
	Outcome string
	Rows    []AffectedRow // only with CVEOrgRanges
	// Complete: every matched CNA product says what a version it does not list is (defaultStatus "unaffected", or
	// "affected" with nothing unaffected), so a version outside every row is not affected. Without it the list may skip
	// branches the CNA did not assess: findings may raise a match on its rows but never close one by them.
	Complete bool
	// Published is the day the record says the CVE was published (cveMetadata.datePublished, "2024-02-09"), "" when it gives none or
	// one that is not a date; findings' age rule reads it for a KEV CVE NVD gives no day for. Set for every
	// outcome but rejected.
	Published string
}

// cveOrgSkipVendors are the vendors whose NVD rows findings reads with a comparator of their own: CNA versions written
// another way would reach the generic one and could close an affected device (review H1 of F6a). Juniper: Junos
// "21.4R3-S5"; Microsoft: Office editions and Windows builds; Citrix: builds written "13.1-49.13" or "13.1.49.13"
// (review R2-M1 of F6a).
var cveOrgSkipVendors = map[string]bool{"juniper": true, "microsoft": true, "citrix": true}

type cveRecord struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	Meta        struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Affected []cnaAffected `json:"affected"`
		} `json:"cna"`
	} `json:"containers"`
}

type cnaAffected struct {
	Vendor        string       `json:"vendor"`
	Product       string       `json:"product"`
	DefaultStatus string       `json:"defaultStatus"`
	Versions      []cnaVersion `json:"versions"`
	Platforms     []string     `json:"platforms"`
	Modules       []string     `json:"modules"`
}

type cnaVersion struct {
	Version         string  `json:"version"`
	Status          string  `json:"status"`
	LessThan        *string `json:"lessThan"`
	LessThanOrEqual *string `json:"lessThanOrEqual"`
	VersionType     string  `json:"versionType"`
	Changes         []struct {
		At     string `json:"at"`
		Status string `json:"status"`
	} `json:"changes"`
}

// ParseCVERecord reads one CVE JSON 5.x record of cve and converts the affected versions the CNA gives for the CISA KEV
// entry's vendor and product into NVD-shaped rows. It invents nothing, and when in doubt it skips the CVE
// (CVEOrgUnusable: no rows, findings keeps its product match):
//   - only a CNA product whose vendor and product clearly are CISA's (productid.NormVendor, productid.NormProduct) is read; a record
//     that names only others, or a KEV entry for "Multiple Products", is CVEOrgNoMatch; a vendor of cveOrgSkipVendors
//     is CVEOrgUnusable;
//   - the rows' CPE carries CISA's own vendor and product (normalised, the names findings already matches the entry by),
//     never a guessed NVD dictionary name;
//   - "affected" versions become ranges: version + lessThan = [version, lessThan), + lessThanOrEqual = [version, x], a
//     version alone is that exact version, a start of "0", "*" or "n/a" is no start, lessThanOrEqual "*" is no end;
//   - git commits, wildcards, text ("all", "< 2.4"), a reversed range, a status change or an "unaffected" version inside
//     an affected range (a hotfix hole), "affected except the listed versions", or an entry limited to platforms or
//     modules make the whole CVE CVEOrgUnusable: findings must never decide on half the list.
//
// A record that is not CVE JSON 5.x (one JSON value, nothing after it), is not cve's, or is larger than CVEOrgMaxBytes
// fails the parse.
func ParseCVERecord(data []byte, cve, kevVendor, kevProduct string) (CVEOrgResult, error) {
	if len(data) > CVEOrgMaxBytes {
		return CVEOrgResult{}, fail(ErrTooLarge, "The CVE.org record is larger than %d MB.", CVEOrgMaxBytes>>20)
	}
	var r cveRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return CVEOrgResult{}, fail(ErrBadSample, "The CVE.org record is not CVE JSON 5.")
	}
	if r.DataType != "CVE_RECORD" || !strings.HasPrefix(r.DataVersion, "5.") || r.Meta.ID != cve {
		return CVEOrgResult{}, fail(ErrBadSample, "The CVE.org record is not CVE JSON 5 for %s.", cve)
	}
	switch r.Meta.State {
	case "REJECTED":
		return CVEOrgResult{Outcome: CVEOrgRejected}, nil
	case "PUBLISHED":
	default:
		return CVEOrgResult{}, fail(ErrBadSample, "The CVE.org record of %s has an unknown state.", cve)
	}
	res := parseCVEAffected(r, kevVendor, kevProduct)
	res.Published = cveDay(r.Meta.Published)
	return res, nil
}

// cveDay is the day of a CVE JSON 5 timestamp ("2024-02-09T00:15:08.123Z", or a day alone), "" when it is not one.
func cveDay(ts string) string {
	if len(ts) < 10 {
		return ""
	}
	d, err := time.Parse(time.DateOnly, ts[:10])
	if err != nil || d.Year() < 1999 || len(ts) > 10 && ts[10] != 'T' {
		return ""
	}
	return ts[:10]
}

// parseCVEAffected converts the CNA's affected versions of a published record (ParseCVERecord).
func parseCVEAffected(r cveRecord, kevVendor, kevProduct string) CVEOrgResult {
	aff := r.Containers.CNA.Affected
	if len(aff) > cveOrgMaxProducts {
		return CVEOrgResult{Outcome: CVEOrgUnusable}
	}
	vk, pk := productid.NormVendor(kevVendor), productid.NormProduct(kevProduct, kevVendor)
	cpeVendor, cpeProduct := productid.Norm(kevVendor), productid.Norm(kevProduct)
	if vk == "" || pk == "" || cpeProduct == "multipleproducts" {
		return CVEOrgResult{Outcome: CVEOrgNoMatch}
	}
	matched, complete := false, true
	var rows []AffectedRow
	for _, a := range aff {
		if len(a.Vendor) > cveOrgMaxName || len(a.Product) > cveOrgMaxName || productid.NormVendor(a.Vendor) != vk || productid.NormProduct(a.Product, a.Vendor) != pk {
			continue
		}
		matched = true
		if cveOrgSkipVendors[vk] {
			return CVEOrgResult{Outcome: CVEOrgUnusable}
		}
		got, all, ok := cnaRows(a, cpeVendor, cpeProduct)
		if !ok {
			return CVEOrgResult{Outcome: CVEOrgUnusable}
		}
		complete = complete && all
		for _, g := range got {
			if !containsRow(rows, g) {
				rows = append(rows, g)
			}
		}
	}
	switch {
	case !matched:
		return CVEOrgResult{Outcome: CVEOrgNoMatch}
	case len(rows) == 0:
		return CVEOrgResult{Outcome: CVEOrgNoVersions}
	}
	return CVEOrgResult{Outcome: CVEOrgRanges, Rows: rows, Complete: complete}
}

// cnaSpan is one affected range of a CNA product, as read ("" = no bound).
type cnaSpan struct {
	start, end string
	incl       bool
}

// cnaRows converts the versions of one CNA product; ok false: they cannot be ranges without guessing. complete says
// whether the product states the status of the versions it does not list.
func cnaRows(a cnaAffected, vendor, product string) (rows []AffectedRow, complete, ok bool) {
	if len(a.Versions) > cveOrgMaxVersions || len(a.Platforms) > 0 || len(a.Modules) > 0 {
		return nil, false, false // only some platforms or modules: the rows would name every device of the product
	}
	cpe := func(version string) string {
		return "cpe:2.3:*:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
	}
	if strings.EqualFold(a.DefaultStatus, "affected") { // versions not listed are affected
		for _, v := range a.Versions {
			if strings.EqualFold(v.Status, "unaffected") {
				return nil, false, false // everything but these versions: not a list of ranges
			}
		}
		return []AffectedRow{{CPE: cpe("*")}}, true, true // every version is affected
	}
	var spans []cnaSpan
	var fixed []string // the unaffected versions the product lists
	for _, v := range a.Versions {
		start := strings.TrimSpace(v.Version)
		switch strings.ToLower(v.Status) {
		case "affected":
		case "unaffected":
			if cnaVersionOK(start) && start != "0" {
				fixed = append(fixed, start)
			}
			continue
		default: // "unknown" says nothing
			continue
		}
		if strings.EqualFold(v.VersionType, "git") || v.LessThan != nil && v.LessThanOrEqual != nil {
			return nil, false, false
		}
		end, incl := "", false
		switch {
		case v.LessThan != nil:
			end = *v.LessThan
		case v.LessThanOrEqual != nil:
			end, incl = *v.LessThanOrEqual, true
		}
		for _, c := range v.Changes {
			if c.At != end || !strings.EqualFold(c.Status, "unaffected") { // a status change inside the range (a hotfix): holes
				return nil, false, false
			}
		}
		if v.LessThan == nil && v.LessThanOrEqual == nil {
			if !cnaVersionOK(start) || start == "0" {
				return nil, false, false
			}
			rows = append(rows, AffectedRow{CPE: cpe(cpeEscape(start))})
			spans = append(spans, cnaSpan{start: start, end: start, incl: true})
			continue
		}
		r := AffectedRow{CPE: cpe("*")}
		switch {
		case incl && end == "*": // "and every later version"
			end = ""
		case !cnaVersionOK(end):
			return nil, false, false
		case incl:
			r.EndIncl = end
		default:
			r.EndExcl = end
		}
		switch strings.ToLower(start) {
		case "", "0", "*", "n/a", "unspecified": // "affected below the end"
			start = ""
		default:
			if !cnaVersionOK(start) {
				return nil, false, false
			}
			r.StartIncl = start
		}
		if start != "" && end != "" { // a reversed, empty or unordered range is a typo, not data (review M1)
			c, ok := cmpLead(start, end)
			if !ok || c > 0 || c == 0 && (start != end || !incl) { // equal numbers, other texts ("3.0.5-h2" to "3.0.5-h1"): no order to trust
				return nil, false, false
			}
		}
		rows = append(rows, r)
		spans = append(spans, cnaSpan{start: start, end: end, incl: incl})
	}
	for _, f := range fixed { // an unaffected version inside an affected range: a backported fix the rows cannot say (review M2)
		for _, sp := range spans {
			if within(f, sp) {
				return nil, false, false
			}
		}
	}
	for _, r := range rows {
		if badAffected(r) != "" {
			return nil, false, false
		}
	}
	return rows, strings.EqualFold(a.DefaultStatus, "unaffected"), true
}

// within says whether version v may lie in sp; a comparison it cannot make (the leading numbers are equal but the
// texts differ, or one has none) counts as inside: when in doubt, skip.
func within(v string, sp cnaSpan) bool {
	if sp.start != "" {
		if c, ok := cmpLead(v, sp.start); ok && c < 0 {
			return false
		}
	}
	if sp.end != "" {
		c, ok := cmpLead(v, sp.end)
		switch {
		case ok && c > 0:
			return false
		case ok && c == 0 && v == sp.end:
			return sp.incl
		}
	}
	return true
}

// cmpLead compares the leading dotted numbers of two versions ("10.2.9-h1" -> 10.2.9; a missing part is 0). ok is false
// when either starts with no number; 0 means the numbers are equal (the rest of the texts may still differ).
func cmpLead(a, b string) (int, bool) {
	x, okA := leadNums(a)
	y, okB := leadNums(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < max(len(x), len(y)); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func leadNums(s string) ([]int, bool) {
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.') {
		end++
	}
	var out []int
	for _, part := range strings.Split(strings.TrimRight(s[:end], "."), ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

// cnaVersionOK accepts a version that can be compared: printable, with a digit, no blanks, no wildcard or comparison
// ("3.x", "< 2.4", "all", "n/a" are refused).
func cnaVersionOK(s string) bool {
	if s == "" || len(s) > nvdMaxVersion || !printableASCII(s) || !strings.ContainsAny(s, "0123456789") || strings.ContainsAny(s, " *?<>=,;\"'`\\") {
		return false
	}
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' }) {
		if strings.EqualFold(seg, "x") {
			return false
		}
	}
	return true
}

// cpeEscape quotes the characters a CPE 2.3 formatted string cannot carry plainly ("15.2(4)M3" -> "15.2\(4\)M3").
func cpeEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !isAlnumByte(b) && b != '_' && b != '.' && b != '-' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

func isAlnumByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func containsRow(rows []AffectedRow, r AffectedRow) bool {
	for _, x := range rows {
		if x == r {
			return true
		}
	}
	return false
}

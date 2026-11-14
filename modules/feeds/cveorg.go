package feeds

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// CVE.org affected versions (D-556). NVD lags: an exploited CVE CISA adds today often has no NVD configuration for days,
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
}

type cveRecord struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	Meta        struct {
		ID    string `json:"cveId"`
		State string `json:"state"`
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
// entry's vendor and product into NVD-shaped rows (D-556). It invents nothing:
//   - only a CNA product whose vendor and product clearly are CISA's (cnaVendorKey, cnaProductKey) is read; a record
//     that names only others, or a KEV entry for "Multiple Products", is CVEOrgNoMatch;
//   - the rows' CPE carries CISA's own vendor and product (normalised, the names findings already matches the entry by),
//     never a guessed NVD dictionary name;
//   - "affected" versions become ranges: version + lessThan = [version, lessThan), + lessThanOrEqual = [version, x], a
//     version alone is that exact version, a start of "0" or "*" is no start, lessThanOrEqual "*" is no end;
//   - a product whose versions cannot be ranges without guessing (git commits, wildcards, text such as "all", changes
//     inside a range, everything affected except listed versions) makes the whole CVE CVEOrgUnusable: findings must never
//     decide on half the list.
//
// A record that is not CVE JSON 5.x, is not cve's, or is larger than CVEOrgMaxBytes fails the parse.
func ParseCVERecord(data []byte, cve, kevVendor, kevProduct string) (CVEOrgResult, error) {
	if len(data) > CVEOrgMaxBytes {
		return CVEOrgResult{}, fail(ErrTooLarge, "The CVE.org record is larger than %d MB.", CVEOrgMaxBytes>>20)
	}
	var r cveRecord
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&r); err != nil {
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
	aff := r.Containers.CNA.Affected
	if len(aff) > cveOrgMaxProducts {
		return CVEOrgResult{Outcome: CVEOrgUnusable}, nil
	}
	vk, pk := cnaVendorKey(kevVendor), cnaProductKey(kevProduct, kevVendor)
	cpeVendor, cpeProduct := normKey(kevVendor), normKey(kevProduct)
	if vk == "" || pk == "" || cpeProduct == "multipleproducts" {
		return CVEOrgResult{Outcome: CVEOrgNoMatch}, nil
	}
	matched := false
	var rows []AffectedRow
	for _, a := range aff {
		if len(a.Vendor) > cveOrgMaxName || len(a.Product) > cveOrgMaxName || cnaVendorKey(a.Vendor) != vk || cnaProductKey(a.Product, a.Vendor) != pk {
			continue
		}
		matched = true
		got, ok := cnaRows(a, cpeVendor, cpeProduct)
		if !ok {
			return CVEOrgResult{Outcome: CVEOrgUnusable}, nil
		}
		for _, g := range got {
			if !containsRow(rows, g) {
				rows = append(rows, g)
			}
		}
	}
	switch {
	case !matched:
		return CVEOrgResult{Outcome: CVEOrgNoMatch}, nil
	case len(rows) == 0:
		return CVEOrgResult{Outcome: CVEOrgNoVersions}, nil
	}
	return CVEOrgResult{Outcome: CVEOrgRanges, Rows: rows}, nil
}

// cnaRows converts the versions of one CNA product; ok false: they cannot be ranges without guessing.
func cnaRows(a cnaAffected, vendor, product string) (rows []AffectedRow, ok bool) {
	if len(a.Versions) > cveOrgMaxVersions {
		return nil, false
	}
	cpe := func(version string) string {
		return "cpe:2.3:*:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
	}
	if strings.EqualFold(a.DefaultStatus, "affected") { // versions not listed are affected
		for _, v := range a.Versions {
			if strings.EqualFold(v.Status, "unaffected") {
				return nil, false // everything but these versions: not a list of ranges
			}
		}
		return []AffectedRow{{CPE: cpe("*")}}, true // every version is affected
	}
	for _, v := range a.Versions {
		if !strings.EqualFold(v.Status, "affected") { // unaffected adds no range; unknown says nothing
			continue
		}
		if strings.EqualFold(v.VersionType, "git") || v.LessThan != nil && v.LessThanOrEqual != nil {
			return nil, false
		}
		end, incl := "", false
		switch {
		case v.LessThan != nil:
			end = *v.LessThan
		case v.LessThanOrEqual != nil:
			end, incl = *v.LessThanOrEqual, true
		}
		for _, c := range v.Changes {
			if c.At != end { // a status change inside the range (a hotfix that fixes it): the range has holes
				return nil, false
			}
		}
		start := strings.TrimSpace(v.Version)
		if v.LessThan == nil && v.LessThanOrEqual == nil {
			if !cnaVersionOK(v.Version) || start == "0" {
				return nil, false
			}
			rows = append(rows, AffectedRow{CPE: cpe(cpeEscape(v.Version))})
			continue
		}
		r := AffectedRow{CPE: cpe("*")}
		switch {
		case incl && end == "*": // "and every later version"
		case !cnaVersionOK(end):
			return nil, false
		case incl:
			r.EndIncl = end
		default:
			r.EndExcl = end
		}
		switch strings.ToLower(start) {
		case "", "0", "*", "n/a", "unspecified": // "affected below the end"
		default:
			if !cnaVersionOK(start) {
				return nil, false
			}
			r.StartIncl = start
		}
		rows = append(rows, r)
	}
	for _, r := range rows {
		if badAffected(r) != "" {
			return nil, false
		}
	}
	return rows, true
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

// normKey keeps only [a-z0-9], as findings compares names ("Palo Alto Networks" -> "paloaltonetworks").
func normKey(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// vendorSuffixes are the company words a CNA adds to a vendor CISA writes without them ("Progress Software Corporation"
// is CISA's "Progress", "Juniper Networks" its "Juniper").
var vendorSuffixes = map[string]bool{
	"inc": true, "incorporated": true, "corp": true, "corporation": true, "co": true, "company": true, "ltd": true,
	"limited": true, "llc": true, "gmbh": true, "ag": true, "se": true, "sa": true, "plc": true, "software": true,
	"foundation": true, "technologies": true, "technology": true, "systems": true, "networks": true,
}

// cnaVendorKey is a vendor without its trailing company words, normalised.
func cnaVendorKey(s string) string {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') })
	for len(words) > 1 && vendorSuffixes[words[len(words)-1]] {
		words = words[:len(words)-1]
	}
	return strings.Join(words, "")
}

// cnaProductKey is a product normalised, without the vendor's name in front ("Apache HTTP Server" of "Apache Software
// Foundation" and CISA's "HTTP Server" of "Apache" are both "httpserver").
func cnaProductKey(product, vendor string) string {
	p := normKey(product)
	for _, v := range []string{cnaVendorKey(vendor), normKey(vendor)} {
		if v != "" && len(p) > len(v) && strings.HasPrefix(p, v) {
			return p[len(v):]
		}
	}
	return p
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

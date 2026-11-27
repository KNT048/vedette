package feeds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The NVD CVE API 2.0 decoder. One decoder reads every NVD answer the box asks for (the exploited-list selector ?hasKev of nvd-kev,
// the date windows and the whole-set walk of nvd-recent, one CVE by id) and writes one catalogue (writeNVDRecords). Nothing of the
// customer is in a request: only a page index, a date window, or the id of a CVE a public list names.
const (
	// NVDPageSize keeps one hasKev answer under MaxBodyBytes: the largest 100 consecutive KEV records measured 1.9 MB on 2026-11-13
	// (one record alone is 1 MB), against 3.1 MB for 200.
	NVDPageSize = 100
	// nvdMaxPages bounds one pull of nvd-kev (1,779 KEV CVEs were 18 pages on 2026-11-13).
	nvdMaxPages = 60
	// nvdIncrementalDays: NVD accepts at most 120 days between lastModStartDate and lastModEndDate; a box whose last good pull of
	// nvd-kev is older starts over with a full pull.
	nvdIncrementalDays = 100
	// nvdMaxRowsPerCVE and the field limits make the parser fail closed on a hostile answer.
	nvdMaxRowsPerCVE = 20_000
	nvdMaxCPE        = 500
	nvdMaxVersion    = 100
	// nvdMaxStatus caps NVD's vulnStatus ("Awaiting Analysis", "Deferred", ...).
	nvdMaxStatus = 40
	// nvdMaxDescription caps the description kept (runes): the catalogue keeps a summary, not a document.
	nvdMaxDescription = 4000
	// nvdMaxPlatforms caps the operating systems kept for one configuration's condition.
	nvdMaxPlatforms = 20
	// nvdMaxAnswer caps one answer the parser reads (the largest page the box asks for is RecentPageSize records).
	nvdMaxAnswer = 32_000_000
)

// nvdPause is the wait between two requests: without an API key NVD allows 5 requests in a rolling 30 s window and asks clients to
// sleep 6 s between requests (https://nvd.nist.gov/developers/start-here). A var for the tests.
var nvdPause = 6 * time.Second

// AffectedRow is one vulnerable CPE match entry of a CVE: the CPE 2.3 criteria and its version range (empty bounds are absent).
type AffectedRow struct {
	CPE                                    string
	StartIncl, StartExcl, EndIncl, EndExcl string
	// AffectedOnly and VendorList say how far a CVE record row read for matching speaks (Range.AffectedOnly, Range.VendorList); both
	// false for NVD's rows.
	AffectedOnly, VendorList bool
}

// NVDRecord is one CVE as NVD's record gives it, as the catalogue keeps it.
type NVDRecord struct {
	CVE                     string
	Published, LastModified time.Time
	Status                  string // NVD's vulnStatus ("Analyzed", "Deferred", "Rejected" …)
	Description             string // NVD's English description, capped
	Metrics                 []Metric
	Affected                []AffectedRow // the vulnerable entries of nodes that are not negated
	// Platforms is, per entry of Affected, the operating systems ("microsoft:windows", vendor and product of the CPE) of NVD's "running
	// on" condition of its configuration (an AND of the vulnerable entries with non-vulnerable operating-system entries); nil for an
	// entry without one.
	Platforms [][]string
	// CWE is the weaknesses NVD lists ("CWE-787"), NVD's own and the ones it carries from the CNA and CISA's ADP, in NVD's order,
	// without repeats; NVD's placeholders ("NVD-CWE-Other", "NVD-CWE-noinfo") are not weaknesses and are left out.
	CWE []string
	// Refs is the references NVD lists, with NVD's tags in the words of the CVE record ("Vendor Advisory" is vendor-advisory:
	// nvdTag), source "nvd". NVD tags the references when it analyses a CVE; before that they carry none.
	Refs []RecordRef
}

// RefsNVD is the source of a reference NVD lists (feeds_cve_ref.source); the CVE record's are OriginCNA and OriginADP.
const RefsNVD = "nvd"

// nvdTagWords are NVD's reference tags whose CVE record word is not the tag itself, lower case with dashes.
var nvdTagWords = map[string]string{"us-government-resource": "government-resource", "press/media-coverage": "media-coverage", "tool-signature": "signature"}

// nvdTag is an NVD reference tag in the CVE record's words: "Vendor Advisory" is vendor-advisory, "US Government Resource" is
// government-resource, so one vocabulary names a reference whichever source tagged it.
func nvdTag(t string) string {
	w := strings.ToLower(strings.Join(strings.Fields(t), "-"))
	if r, ok := nvdTagWords[w]; ok {
		return r
	}
	return w
}

// Tagged says whether NVD gave any of the references a tag: NVD has analysed them.
func (r NVDRecord) Tagged() bool {
	return slices.ContainsFunc(r.Refs, func(x RecordRef) bool { return len(x.Tags) > 0 })
}

// CVSS is the picked score of the record (PickCVSS).
func (r NVDRecord) CVSS() (CVSS, bool) { return PickCVSS(r.Metrics) }

// NVDPage is one parsed answer of the NVD CVE API 2.0.
type NVDPage struct {
	Total, Returned int // totalResults, and the records in this answer
	Records         []NVDRecord
	Stats
}

// NVDPageURL builds one request of the exploited-list selector: base?hasKev&resultsPerPage=N&startIndex=I, plus the lastMod window
// for an incremental pull (from and to non-zero).
func NVDPageURL(base string, start int, from, to time.Time) (string, error) {
	if err := nvdBase(base); err != nil {
		return "", err
	}
	u := strings.TrimSpace(base) + "?hasKev&resultsPerPage=" + strconv.Itoa(NVDPageSize) + "&startIndex=" + strconv.Itoa(start)
	if !from.IsZero() && !to.IsZero() {
		u += "&lastModStartDate=" + from.UTC().Format(tsLayout) + "&lastModEndDate=" + to.UTC().Format(tsLayout)
	}
	return u, nil
}

// RecentPageURL builds one request of a date window: base?pubStartDate=…&pubEndDate=… (byPublished, the fill of the window) or
// lastModStartDate=…&lastModEndDate=… (an update), &resultsPerPage=size&startIndex=start.
func RecentPageURL(base string, byPublished bool, from, to time.Time, start, size int) (string, error) {
	if err := nvdBase(base); err != nil {
		return "", err
	}
	a, b := "lastModStartDate", "lastModEndDate"
	if byPublished {
		a, b = "pubStartDate", "pubEndDate"
	}
	return fmt.Sprintf("%s?%s=%s&%s=%s&resultsPerPage=%d&startIndex=%d", strings.TrimSpace(base), a, from.UTC().Format(tsLayout), b, to.UTC().Format(tsLayout), size, start), nil
}

// WalkPageURL builds one request of the walk over the whole NVD set: base?resultsPerPage=size&startIndex=start.
func WalkPageURL(base string, start, size int) (string, error) {
	if err := nvdBase(base); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", strings.TrimSpace(base), size, start), nil
}

// CVEIDURL builds the request of one CVE's record: base?cveId=CVE-…. Only for a CVE a public list names (an exploited-list entry or
// a signal), never for one only the customer's devices make interesting.
func CVEIDURL(base, cve string) (string, error) {
	if err := nvdBase(base); err != nil {
		return "", err
	}
	if !cveRE.MatchString(cve) || len(cve) > 32 {
		return "", fail(ErrBadSample, "%s is not a CVE ID.", quoteVal(cve))
	}
	return strings.TrimSpace(base) + "?cveId=" + cve, nil
}

func nvdBase(base string) error {
	if err := CheckURL(base); err != nil {
		return err
	}
	if strings.ContainsAny(base, "?#") {
		return fail(ErrInvalidURL, "The NVD address must not carry a query string.")
	}
	return nil
}

// nvdAnswer is one NVD answer; each record is decoded on its own (nvdRecordJSON), so one record of the wrong shape is rejected alone
// instead of failing the whole page.
type nvdAnswer struct {
	TotalResults    *int              `json:"totalResults"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type nvdRecordJSON struct {
	CVE struct {
		ID           string `json:"id"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		VulnStatus   string `json:"vulnStatus"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics        json.RawMessage `json:"metrics"`    // decoded on its own: metricsOf
		Weaknesses     json.RawMessage `json:"weaknesses"` // decoded on its own: weaknessesOf
		References     json.RawMessage `json:"references"` // decoded on its own: referencesOf
		Configurations []struct {
			Operator string `json:"operator"`
			Nodes    []struct {
				Negate   bool `json:"negate"`
				CPEMatch []struct {
					Vulnerable bool   `json:"vulnerable"`
					Criteria   string `json:"criteria"`
					StartIncl  string `json:"versionStartIncluding"`
					StartExcl  string `json:"versionStartExcluding"`
					EndIncl    string `json:"versionEndIncluding"`
					EndExcl    string `json:"versionEndExcluding"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

// nvdTime reads NVD's timestamps ("2026-08-01T03:16:25.307", UTC, sometimes with a Z).
func nvdTime(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(strings.TrimSpace(s), "Z"))
	return t.UTC(), err == nil
}

// metricsOf decodes a record's `metrics` on its own: a malformed value (a string score, a number for a vector, an array) leaves that
// record without a score; the record, its affected versions and its dates are still accepted.
func metricsOf(raw json.RawMessage) []Metric {
	var m cvssMetrics
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return metricsFrom(m)
}

// weaknessesOf decodes a record's `weaknesses` on its own: a malformed value leaves the record without weaknesses, nothing more.
func weaknessesOf(raw json.RawMessage) []string {
	var ws []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &ws) != nil {
		return nil
	}
	var out []string
	for _, w := range ws {
		for _, d := range w.Description {
			if v := strings.TrimSpace(d.Value); cweRE.MatchString(v) && !slices.Contains(out, v) && len(out) < recordMaxCWE {
				out = append(out, v)
			}
		}
	}
	return out
}

// referencesOf decodes a record's `references` on its own, within the caps of a CVE record's (addRef); a malformed value leaves the
// record without references.
func referencesOf(raw json.RawMessage) []RecordRef {
	var rs []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &rs) != nil {
		return nil
	}
	var out []RecordRef
	for _, r := range rs {
		tags := make([]string, 0, len(r.Tags))
		for _, t := range r.Tags {
			tags = append(tags, nvdTag(t))
		}
		out = addRef(out, r.URL, tags, RefsNVD)
	}
	return out
}

// ParseNVD reads one NVD CVE API 2.0 answer. A record with a bad id, dates or status is rejected and counted, as is one with an
// unusable vulnerable entry (a criteria that is not a CPE 2.3 name, a version too long or not printable): fail closed, a CVE that
// lost an entry is dropped whole, so findings never decide on half a configuration. A damaged answer fails the parse.
func ParseNVD(data []byte) (NVDPage, error) {
	if len(data) > nvdMaxAnswer {
		return NVDPage{}, fail(ErrTooLarge, "The NVD answer is larger than %d MB; Vedette would skip it.", nvdMaxAnswer/1_000_000)
	}
	var a nvdAnswer
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&a); err != nil || a.TotalResults == nil || *a.TotalResults < 0 {
		return NVDPage{}, fail(ErrBadSample, "The NVD answer is not the CVE API 2.0 format.")
	}
	out := NVDPage{Total: *a.TotalResults, Returned: len(a.Vulnerabilities), Records: make([]NVDRecord, 0, len(a.Vulnerabilities))}
	tl := newTally()
	for i, raw := range a.Vulnerabilities {
		row := i + 1
		var v nvdRecordJSON
		if err := json.Unmarshal(raw, &v); err != nil {
			tl.reject(row, "the record is not an NVD CVE record")
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(v.CVE.ID))
		pub, okP := nvdTime(v.CVE.Published)
		mod, okM := nvdTime(v.CVE.LastModified)
		status := strings.TrimSpace(v.CVE.VulnStatus)
		switch {
		case !cveRE.MatchString(id) || len(id) > 32:
			tl.reject(row, "id: %s is not a CVE ID", quoteVal(v.CVE.ID))
			continue
		case !okP || !okM:
			tl.reject(row, "%s: the dates are not NVD timestamps", id)
			continue
		case status == "" || len(status) > nvdMaxStatus || !printableASCII(status):
			tl.reject(row, "%s: vulnStatus %s is not usable", id, quoteVal(status))
			continue
		}
		rec := NVDRecord{CVE: id, Published: pub, LastModified: mod, Status: status, Metrics: metricsOf(v.CVE.Metrics), Affected: []AffectedRow{},
			CWE: weaknessesOf(v.CVE.Weaknesses), Refs: referencesOf(v.CVE.References)}
		for _, d := range v.CVE.Descriptions {
			if strings.EqualFold(strings.TrimSpace(d.Lang), "en") {
				rec.Description = cleanDescription(d.Value)
				break
			}
		}
		bad := ""
	entries:
		for _, c := range v.CVE.Configurations {
			var plats []string // the "running on" operating systems of an AND configuration
			if strings.EqualFold(c.Operator, "AND") {
				for _, n := range c.Nodes {
					for _, m := range n.CPEMatch {
						if p, ok := platformOf(m.Criteria); ok && !m.Vulnerable && !n.Negate && !slices.Contains(plats, p) && len(plats) < nvdMaxPlatforms {
							plats = append(plats, p)
						}
					}
				}
			}
			for _, n := range c.Nodes {
				if n.Negate {
					continue
				}
				for _, m := range n.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					r := AffectedRow{CPE: m.Criteria, StartIncl: m.StartIncl, StartExcl: m.StartExcl, EndIncl: m.EndIncl, EndExcl: m.EndExcl}
					if bad = badAffected(r); bad != "" || len(rec.Affected) >= nvdMaxRowsPerCVE {
						if bad == "" {
							bad = "more than " + strconv.Itoa(nvdMaxRowsPerCVE) + " entries"
						}
						break entries
					}
					rec.Affected = append(rec.Affected, r)
					rec.Platforms = append(rec.Platforms, plats)
				}
			}
		}
		if bad != "" {
			tl.reject(row, "%s: %s", id, bad)
			continue
		}
		tl.Accepted++
		out.Records = append(out.Records, rec)
	}
	out.Stats = tl.stats()
	return out, nil
}

// cleanDescription is a description as the catalogue keeps it: valid UTF-8, no control characters but line breaks, trimmed, at most
// nvdMaxDescription runes.
func cleanDescription(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > nvdMaxDescription {
		s = string([]rune(s)[:nvdMaxDescription-1]) + "…"
	}
	return s
}

// platformOf is "vendor:product" of an operating-system CPE ("cpe:2.3:o:microsoft:windows:-:…" gives "microsoft:windows"); false for
// another part or a name that is not plain printable text.
func platformOf(cpe string) (string, bool) {
	rest, ok := strings.CutPrefix(cpe, "cpe:2.3:o:")
	if !ok || len(cpe) > nvdMaxCPE {
		return "", false
	}
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[0] == "*" || !printableASCII(parts[0]+parts[1]) {
		return "", false
	}
	return parts[0] + ":" + parts[1], true
}

func badAffected(r AffectedRow) string {
	if !strings.HasPrefix(r.CPE, "cpe:2.3:") || len(r.CPE) > nvdMaxCPE || !printableASCII(r.CPE) {
		return "criteria is not a CPE 2.3 name"
	}
	for _, v := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl} {
		if len(v) > nvdMaxVersion || !printableASCII(v) {
			return fmt.Sprintf("version %s is not usable", quoteVal(v))
		}
	}
	return ""
}

func printableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// cpeParts is the part, vendor and product of a CPE 2.3 name, lower case ("cpe:2.3:a:apache:http_server:…" gives "a", "apache",
// "http_server"); empty strings for a name that is not one.
func cpeParts(cpe string) (part, vendor, product string) {
	rest, ok := strings.CutPrefix(cpe, "cpe:2.3:")
	if !ok {
		return "", "", ""
	}
	f := strings.SplitN(rest, ":", 4)
	if len(f) < 3 || len(f[0]) != 1 {
		return "", "", ""
	}
	return strings.ToLower(f[0]), strings.ToLower(f[1]), strings.ToLower(f[2])
}

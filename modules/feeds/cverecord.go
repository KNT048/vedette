package feeds

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// CVE records. The CVE Program publishes every CVE record (CVE JSON 5) in its public cvelistV5 repository: the CNA's own words
// (most often the vendor's: affected versions, title, solutions, workarounds, references with tags, weaknesses) and the ADPs'
// additions (CISA's Vulnrichment: SSVC decision points, CWE, CPE names; suppliers' own affected lists). NVD lags behind the CNA,
// often by weeks, and defers most CVEs: the record is the first and often the only structured statement of which versions are
// affected. ParseCVERecord reads one record whole; recordRanges turns its affected lists into catalogue ranges.
const (
	// RecordMaxBytes bounds one record. The largest records (Linux kernel, products with thousands of builds) are a few MB;
	// a larger one is skipped and counted, never read.
	RecordMaxBytes = 4 << 20
	// recordMaxContainers bounds the ADP containers of one record (a handful in practice).
	recordMaxContainers = 20
	// recordMaxEntries and recordMaxVersions make the range conversion fail closed on a hostile record.
	recordMaxEntries  = 500
	recordMaxVersions = 2000
	recordMaxName     = 200
	// recordMaxRefs, recordMaxTags and recordMaxURL bound the references kept of one CVE.
	recordMaxRefs = 200
	recordMaxTags = 10
	recordMaxURL  = 500
	// recordMaxCWE bounds the weaknesses kept of one CVE.
	recordMaxCWE = 20
	// Text caps, as the catalogue columns hold them.
	recordMaxTitle = 500
	recordMaxText  = 4000
)

// CVERecordURL is the address of one record under base (the cves directory of cvelistV5):
// base/<year>/<number/1000>xxx/<CVE>.json, as the repository lays them out ("CVE-2024-3400" -> "2024/3xxx"). Only the CVE ID is in
// the request.
func CVERecordURL(base, cve string) (string, error) {
	if err := CheckURL(base); err != nil {
		return "", err
	}
	if strings.ContainsAny(base, "?#") {
		return "", fail(ErrInvalidURL, "The CVE record address must not carry a query string.")
	}
	year, n, ok := cveParts(cve)
	if !ok {
		return "", fail(ErrBadSample, "%s is not a CVE ID.", quoteVal(cve))
	}
	return strings.TrimRight(strings.TrimSpace(base), "/") + "/" + year + "/" + strconv.Itoa(n/1000) + "xxx/" + cve + ".json", nil
}

// cveParts is the year and number of a CVE ID.
func cveParts(cve string) (year string, n int, ok bool) {
	if !cveRE.MatchString(cve) || len(cve) > 32 {
		return "", 0, false
	}
	year, num, _ := strings.Cut(strings.TrimPrefix(cve, "CVE-"), "-")
	n, err := strconv.Atoi(num)
	return year, n, err == nil
}

// The states of a CVE record.
const (
	RecordPublished = "PUBLISHED"
	RecordRejected  = "REJECTED"
)

// CVERecord is what Vedette keeps of one CVE record.
type CVERecord struct {
	CVE   string
	State string // RecordPublished or RecordRejected
	// Assigner is the CNA's short name ("oracle", "vmware"): the vendor of an affected entry that names none.
	Assigner  string
	Published time.Time // cveMetadata.datePublished; zero when the record gives none or one that is not a time
	Updated   time.Time // cveMetadata.dateUpdated
	// Title is the CNA's title; Description its English description; Solution and Workaround the English text of its solutions
	// and workarounds (several joined by a blank line). Each capped at the catalogue's column size, control characters removed.
	Title, Description   string
	Solution, Workaround string
	CWE                  []string // "CWE-787", the CNA's then the ADPs', in that order, without repeats
	// SSVC is CISA's decision points (Vulnrichment): exploitation none|poc|active, automatable yes|no, technical impact
	// partial|total. Empty when no ADP gave them.
	SSVC   SSVC
	Refs   []RecordRef
	Ranges []Range // the affected versions Vedette can compare (recordRanges); CVE and Origin set
	// Skipped is the affected entries whose versions could not be read without guessing (git commits, wildcards, text, holes);
	// their product has no range from this record.
	Skipped int
	// StatedDropped is the products of Skipped whose versions are not kept as the vendor states them either: more rows than
	// recordMaxStatedProduct, or past recordMaxStated for the record.
	StatedDropped int

	// asOf is the time an archive's copy is current as of (the daily list's midnight, the end of a day of changes), stored as the record's
	// read time so it never claims a change logged after it; zero: read by ID now.
	asOf time.Time
}

// SSVC is CISA's SSVC decision points for a CVE, lower case as stored ("" = not given).
type SSVC struct{ Exploitation, Automatable, Impact string }

// RecordRef is one reference of a record: its URL, the tags its publisher gave it (vendor-advisory, patch, mitigation, exploit …)
// and who gave it (cna or adp).
type RecordRef struct {
	URL    string
	Tags   []string
	Source string
}

type rawRecord struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	Meta        struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Assigner  string `json:"assignerShortName"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA rawContainer   `json:"cna"`
		ADP []rawContainer `json:"adp"`
	} `json:"containers"`
}

type rawContainer struct {
	Provider struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Title        string         `json:"title"`
	Descriptions []rawLangValue `json:"descriptions"`
	Affected     []cnaAffected  `json:"affected"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWE string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Solutions   []rawLangValue `json:"solutions"`
	Workarounds []rawLangValue `json:"workarounds"`
	Metrics     []struct {
		Other *struct {
			Type    string `json:"type"`
			Content struct {
				Options []map[string]any `json:"options"`
			} `json:"content"`
		} `json:"other"`
	} `json:"metrics"`
}

type rawLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cnaAffected struct {
	Vendor        string       `json:"vendor"`
	Product       string       `json:"product"`
	DefaultStatus string       `json:"defaultStatus"`
	Versions      []cnaVersion `json:"versions"`
	Platforms     []string     `json:"platforms"`
	CPEs          []string     `json:"cpes"`
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

// ParseCVERecord reads one CVE JSON 5.x record of cve. A record that is not CVE JSON 5.x (one JSON value, nothing after it), is not
// cve's, has another state than published or rejected, or is larger than RecordMaxBytes fails the parse. A rejected record keeps only
// its state: no product is affected. Everything else is read as the record gives it, within the caps above, and the affected lists
// become ranges only where they can be compared without guessing (recordRanges).
func ParseCVERecord(data []byte, cve string) (CVERecord, error) {
	if len(data) > RecordMaxBytes {
		return CVERecord{}, fail(ErrTooLarge, "The CVE record is larger than %d MB.", RecordMaxBytes>>20)
	}
	var r rawRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return CVERecord{}, fail(ErrBadSample, "The CVE record is not CVE JSON 5.")
	}
	if r.DataType != "CVE_RECORD" || !strings.HasPrefix(r.DataVersion, "5.") || r.Meta.ID != cve || !cveRE.MatchString(cve) {
		return CVERecord{}, fail(ErrBadSample, "The CVE record is not CVE JSON 5 for %s.", quoteVal(cve))
	}
	if len(r.Containers.ADP) > recordMaxContainers {
		return CVERecord{}, fail(ErrBadSample, "The CVE record of %s has more than %d ADP containers.", cve, recordMaxContainers)
	}
	out := CVERecord{CVE: cve, State: r.Meta.State, Assigner: recordWord(r.Meta.Assigner), Published: recordTime(r.Meta.Published),
		Updated: recordTime(r.Meta.Updated)}
	switch r.Meta.State {
	case RecordRejected:
		return out, nil
	case RecordPublished:
	default:
		return CVERecord{}, fail(ErrBadSample, "The CVE record of %s has an unknown state.", cve)
	}
	cna := r.Containers.CNA
	out.Title = clipText(recordLine(cna.Title), recordMaxTitle)
	out.Description = clipText(english(cna.Descriptions, false), recordMaxText)
	out.Solution = clipText(english(cna.Solutions, true), recordMaxText)
	out.Workaround = clipText(english(cna.Workarounds, true), recordMaxText)
	containers := append([]rawContainer{cna}, r.Containers.ADP...)
	for i, c := range containers {
		src := OriginCNA
		if i > 0 {
			src = OriginADP
		}
		for _, pt := range c.ProblemTypes {
			for _, d := range pt.Descriptions {
				if cweRE.MatchString(d.CWE) && !slices.Contains(out.CWE, d.CWE) && len(out.CWE) < recordMaxCWE {
					out.CWE = append(out.CWE, d.CWE)
				}
			}
		}
		for _, ref := range c.References {
			out.Refs = addRef(out.Refs, ref.URL, ref.Tags, src)
		}
		if i > 0 && out.SSVC == (SSVC{}) {
			out.SSVC = ssvcOf(c)
		}
	}
	out.Ranges, out.Skipped, out.StatedDropped = recordRanges(cve, out.Assigner, cna.Affected, r.Containers.ADP)
	return out, nil
}

var cweRE = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)

// recordTime is a CVE JSON 5 timestamp ("2024-02-09T00:15:08.123Z", "2024-02-09T00:15:08", or a day alone), zero when it is not one.
func recordTime(ts string) time.Time {
	ts = strings.TrimSpace(ts)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", time.DateOnly} {
		if t, err := time.Parse(layout, ts); err == nil && t.Year() >= 1999 && t.Year() < 2200 {
			return t.UTC()
		}
	}
	return time.Time{}
}

// english is the English values of a list (lang "en" or "en-…"); all of them joined by a blank line when all, else the first.
func english(vs []rawLangValue, all bool) string {
	var parts []string
	for _, v := range vs {
		l := strings.ToLower(strings.TrimSpace(v.Lang))
		if l != "en" && !strings.HasPrefix(l, "en-") && !strings.HasPrefix(l, "en_") {
			continue
		}
		if t := recordText(v.Value); t != "" && !slices.Contains(parts, t) {
			parts = append(parts, t)
			if !all {
				break
			}
		}
	}
	return strings.Join(parts, "\n\n")
}

// recordText drops control characters other than new lines and tabs, and trims each end.
func recordText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == 0xFEFF {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
}

// recordLine is a text on one line, blanks collapsed.
func recordLine(s string) string { return strings.Join(strings.Fields(recordText(s)), " ") }

// clipText cuts s to at most n bytes at a rune boundary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}

// recordWord is a short identifier of a record (a short name, a version type, an SSVC value), lower case, [a-z0-9_-] only; "" when it
// is anything else or longer than 40 bytes.
func recordWord(s string) string {
	const n = 40
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > n {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return ""
		}
	}
	return s
}

// addRef adds one reference: an http(s) address of printable ASCII within recordMaxURL, its tags as words (recordWord). The same
// address twice keeps the first source and the tags of both.
func addRef(refs []RecordRef, u string, tags []string, src string) []RecordRef {
	u = strings.TrimSpace(u)
	if len(refs) >= recordMaxRefs || len(u) > recordMaxURL || !printableASCII(u) || strings.ContainsAny(u, " \"'<>\\`") ||
		!strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") || len(u) <= len("https://") {
		return refs
	}
	i := slices.IndexFunc(refs, func(r RecordRef) bool { return r.URL == u })
	if i < 0 {
		refs = append(refs, RecordRef{URL: u, Tags: []string{}, Source: src})
		i = len(refs) - 1
	}
	for _, t := range tags {
		if w := recordWord(t); w != "" && !slices.Contains(refs[i].Tags, w) && len(refs[i].Tags) < recordMaxTags {
			refs[i].Tags = append(refs[i].Tags, w)
		}
	}
	return refs
}

// ssvcOf reads CISA's SSVC decision points from an ADP container's metrics ({"other": {"type": "ssvc", "content": {"options":
// [{"Exploitation": "none"}, {"Automatable": "no"}, {"Technical Impact": "total"}]}}}).
func ssvcOf(c rawContainer) SSVC {
	var s SSVC
	for _, m := range c.Metrics {
		if m.Other == nil || !strings.EqualFold(m.Other.Type, "ssvc") {
			continue
		}
		for _, o := range m.Other.Content.Options {
			for k, v := range o {
				w := recordWord(strings.ReplaceAll(str(v), " ", "_"))
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "exploitation":
					s.Exploitation = w
				case "automatable":
					s.Automatable = w
				case "technical impact":
					s.Impact = w
				}
			}
		}
		return s
	}
	return s
}

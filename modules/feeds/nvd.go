package feeds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// NVD affected versions of the exploited list (D-500). The box asks the NVD CVE API 2.0 for the CVEs CISA lists
// (?hasKev), NVDPageSize per request, and keeps each CVE's vulnerable CPE match entries (criteria + version range)
// so that findings can compare a device's version with the versions a CVE affects. Nothing of the customer is in a
// request: only the page index and, after the first full pull, the date of the previous pull.
const (
	// NVDPageSize keeps one answer under MaxBodyBytes: the largest 100 consecutive KEV records measured 1.9 MB
	// on 2026-11-13 (one record alone is 1 MB), against 3.1 MB for 200.
	NVDPageSize = 100
	// nvdMaxPages bounds one pull (1,779 KEV CVEs were 18 pages on 2026-11-13).
	nvdMaxPages = 60
	// nvdIncrementalDays: NVD accepts at most 120 days between lastModStartDate and lastModEndDate; a box whose
	// last good pull is older starts over with a full pull.
	nvdIncrementalDays = 100
	// nvdMaxRowsPerCVE and the field limits make the parser fail closed on a hostile answer.
	nvdMaxRowsPerCVE = 20_000
	nvdMaxCPE        = 500
	nvdMaxVersion    = 100
)

// nvdPause is the wait between two requests: without an API key NVD allows 5 requests in a rolling 30 s window and
// asks clients to sleep 6 s between requests (https://nvd.nist.gov/developers/start-here). A var for the tests.
var nvdPause = 6 * time.Second

// AffectedRow is one vulnerable CPE match entry of a CVE: the CPE 2.3 criteria and its NVD version range
// (empty bounds are absent).
type AffectedRow struct {
	CPE                                    string
	StartIncl, StartExcl, EndIncl, EndExcl string
}

// NVDPage is one parsed answer of the NVD CVE API 2.0.
type NVDPage struct {
	Total    int                      // totalResults
	Returned int                      // records in this answer
	Affected map[string][]AffectedRow // CVE -> vulnerable entries; a CVE with none is present with an empty list
	// Published is the day NVD published each accepted CVE ("2017-03-14", D-615); a record without a readable date is absent.
	Published map[string]string
	// CVSS is the base score of each accepted CVE (INV-28: newest version, NVD's own before the CNA's); a CVE without one is absent.
	CVSS map[string]CVSS
	Stats
}

// CVSS is the CVSS base score of a CVE as NVD's record gives it (INV-28): the newest version present, NVD's own ("Primary")
// before the CNA's ("Secondary"). The band (Low … Critical) follows from Score by FIRST's table, so it is not kept.
type CVSS struct {
	Score   float64 // 0.0 … 10.0
	Version string  // "4.0", "3.1", "3.0" or "2.0" (only when NVD has nothing newer); "" for a row nvd-recent stored before migration 0015
	Source  string  // "nvd" (Primary) or "cna" (Secondary); "" as Version
	Vector  string  // NVD's vector string of that score ("CVSS:3.1/AV:N/…", v2 "AV:N/AC:L/…"); "" when none usable or as Version (FIRST asks that a
	// score be shown with its vector)
}

// NVDPageURL builds the request for one page: base?hasKev&resultsPerPage=N&startIndex=I, plus the lastMod window
// for an incremental pull (from and to non-zero).
func NVDPageURL(base string, start int, from, to time.Time) (string, error) {
	if err := CheckURL(base); err != nil {
		return "", err
	}
	if strings.ContainsAny(base, "?#") {
		return "", fail(ErrInvalidURL, "The NVD address must not carry a query string.")
	}
	u := strings.TrimSpace(base) + "?hasKev&resultsPerPage=" + strconv.Itoa(NVDPageSize) + "&startIndex=" + strconv.Itoa(start)
	if !from.IsZero() && !to.IsZero() {
		const layout = "2006-01-02T15:04:05.000Z"
		u += "&lastModStartDate=" + from.UTC().Format(layout) + "&lastModEndDate=" + to.UTC().Format(layout)
	}
	return u, nil
}

type nvdAnswer struct {
	TotalResults    *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID             string      `json:"id"`
			Published      string      `json:"published"`
			Metrics        cvssMetrics `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
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
	} `json:"vulnerabilities"`
}

// ParseNVD reads one NVD CVE API 2.0 answer. Only vulnerable entries of nodes that are not negated are kept. A
// record with a bad CVE id, or an entry with a criteria that is not a CPE 2.3 name or a version that is too long
// or not printable, is rejected and counted (fail closed: a CVE that lost an entry is dropped whole, so findings
// never decide on half a configuration). A damaged answer fails the parse.
func ParseNVD(data []byte) (NVDPage, error) {
	if len(data) > MaxBodyBytes {
		return NVDPage{}, fail(ErrTooLarge, "The NVD answer is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	var a nvdAnswer
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&a); err != nil || a.TotalResults == nil {
		return NVDPage{}, fail(ErrBadSample, "The NVD answer is not the CVE API 2.0 format.")
	}
	out := NVDPage{Total: *a.TotalResults, Returned: len(a.Vulnerabilities), Affected: map[string][]AffectedRow{}, Published: map[string]string{}, CVSS: map[string]CVSS{}}
	tl := newTally()
	for i, v := range a.Vulnerabilities {
		row := i + 1
		id := strings.ToUpper(strings.TrimSpace(v.CVE.ID))
		if !cveRE.MatchString(id) {
			tl.reject(row, "id: %s is not a CVE ID", quoteVal(v.CVE.ID))
			continue
		}
		rows, bad := []AffectedRow{}, ""
	entries:
		for _, c := range v.CVE.Configurations {
			for _, n := range c.Nodes {
				if n.Negate {
					continue
				}
				for _, m := range n.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					r := AffectedRow{CPE: m.Criteria, StartIncl: m.StartIncl, StartExcl: m.StartExcl, EndIncl: m.EndIncl, EndExcl: m.EndExcl}
					if bad = badAffected(r); bad != "" || len(rows) >= nvdMaxRowsPerCVE {
						if bad == "" {
							bad = "more than " + strconv.Itoa(nvdMaxRowsPerCVE) + " entries"
						}
						break entries
					}
					rows = append(rows, r)
				}
			}
		}
		if bad != "" {
			tl.reject(row, "%s: %s", id, bad)
			continue
		}
		tl.Accepted++
		out.Affected[id] = rows
		if d, ok := publishedDay(v.CVE.Published); ok {
			out.Published[id] = d
		}
		if c := severityOf(v.CVE.Metrics); c.Score != nil {
			out.CVSS[id] = CVSS{Score: *c.Score, Version: c.Version, Source: c.Source, Vector: c.Vector}
		}
	}
	out.Stats = tl.stats()
	return out, nil
}

// publishedDay is the day of NVD's `published` ("2017-03-17T00:59:00.000" -> "2017-03-17"); ok is false for anything that does
// not start with a real date, so a hostile value never reaches the table.
func publishedDay(s string) (string, bool) {
	if len(s) < 10 {
		return "", false
	}
	if _, err := time.Parse(time.DateOnly, s[:10]); err != nil {
		return "", false
	}
	return s[:10], true
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

package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Microsoft's Security Update Guide: the list of every CVE Microsoft flags "Exploited: Yes" (the same flag as the Exploit Status of its
// CVRF and CSAF documents), asked as one OData query (`$filter=exploited eq 'Yes'`, about 200 CVEs and 1 MB in November 2026) instead
// of the monthly CVRF documents (about 19 MB each, rewritten almost every day). Of each CVE only its id, its release date and the
// dates of its revisions are read.

// msrcCVEURL is where a person reads Microsoft's page of a CVE.
const msrcCVEURL = "https://msrc.microsoft.com/update-guide/vulnerability/"

// Bounds of the Security Update Guide list: bytes of one page, pages followed (@odata.nextLink), CVEs of the whole list (198 in
// November 2026) and revisions read of one CVE. msrcFloor is the shrink guard (as the public-exploit indexes).
const (
	msrcMaxBytes     = 32 << 20
	msrcMaxPages     = 20
	msrcMaxCVEs      = 20_000
	msrcMaxRevisions = 500
	msrcFloor        = 100
)

// msrcExploitedRevRE: a revision that set or corrected the exploited flag dates the claim ("Corrected the Exploitability Index, Exploited
// flag and CVSS vector"); "Exploit Code Maturity" of a CVSS vector does not.
var msrcExploitedRevRE = regexp.MustCompile(`(?i)\bexploited\b|exploitation detected`)

type msrcVuln struct {
	CVE         string `json:"cveNumber"`
	ReleaseDate string `json:"releaseDate"`
	Exploited   string `json:"exploited"`
	Revisions   []struct {
		Date        string `json:"revisionDate"`
		Description string `json:"unformattedDescription"`
	} `json:"revisions"`
}

// msrcPage is one page of the list as parseMSRCExploited read it.
type msrcPage struct {
	Claims []vendorClaim
	Next   string // @odata.nextLink, "" on the last page
	Stats
}

// parseMSRCExploited reads one page of the Security Update Guide's vulnerability list. A CVE is a claim when its exploited field is
// "Yes" (the query asks only for those; others are skipped, not trusted). Its date is the first revision that set the flag, else its
// release. A row without a CVE id or a readable release date is rejected. The page must be one JSON object with a "value" array
// (fail-closed).
func parseMSRCExploited(r io.Reader) (msrcPage, error) {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return msrcPage{}, readFail(err, "Microsoft's list is not a JSON object.")
	}
	var (
		out       msrcPage
		sawValues bool
	)
	tl := newTally()
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return msrcPage{}, readFail(err, "Microsoft's list could not be read: %v.", err)
		}
		key, _ := tok.(string)
		switch key {
		case "@odata.nextLink":
			if err := dec.Decode(&out.Next); err != nil {
				return msrcPage{}, readFail(err, "Microsoft's list has a bad next page link.")
			}
		case "value":
			sawValues = true
			if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
				return msrcPage{}, readFail(err, "Microsoft's list has no list of CVEs.")
			}
			row := 0
			for dec.More() {
				if row++; row > msrcMaxCVEs {
					return msrcPage{}, fail(ErrBadSample, "Microsoft's list names more than %s CVEs.", grouped(msrcMaxCVEs))
				}
				var v msrcVuln
				if err := dec.Decode(&v); err != nil {
					var te *json.UnmarshalTypeError
					if !errors.As(err, &te) {
						return msrcPage{}, readFail(err, "Microsoft's list could not be read: %v.", err)
					}
					tl.reject(row, "CVE: a field has the wrong type")
					continue
				}
				if !strings.EqualFold(strings.TrimSpace(v.Exploited), "Yes") {
					continue
				}
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(v.CVE)), "ADV") {
					continue // a Microsoft security advisory (ADV200006) flagged as exploited: no CVE to hold it by
				}
				c, ok := msrcClaim(v)
				if !ok {
					tl.reject(row, "%s: no CVE id or release date", v.CVE)
					continue
				}
				tl.Accepted++
				out.Claims = append(out.Claims, c)
			}
			if _, err := dec.Token(); err != nil { // ]
				return msrcPage{}, readFail(err, "Microsoft's list is cut short.")
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return msrcPage{}, readFail(err, "Microsoft's list could not be read: %v.", err)
			}
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return msrcPage{}, readFail(err, "Microsoft's list is cut short.")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return msrcPage{}, readFail(err, "Microsoft's list has data after its end.")
	}
	if !sawValues {
		return msrcPage{}, fail(ErrBadSample, "Microsoft's list has no list of CVEs.")
	}
	out.Stats = tl.stats()
	return out, nil
}

// msrcClaim is the claim of one flagged CVE: dated by the first revision that set the exploited flag, else by its release.
func msrcClaim(v msrcVuln) (vendorClaim, bool) {
	cve := strings.ToUpper(strings.TrimSpace(v.CVE))
	release, err := time.Parse(time.RFC3339, v.ReleaseDate)
	if len(cve) > 20 || !cveRE.MatchString(cve) || err != nil {
		return vendorClaim{}, false
	}
	date := time.Time{}
	for i, r := range v.Revisions {
		if i == msrcMaxRevisions {
			break
		}
		d, err := time.Parse(time.RFC3339, r.Date)
		if err != nil || d.Before(release) || !msrcExploitedRevRE.MatchString(r.Description) {
			continue
		}
		if date.IsZero() || d.Before(date) {
			date = d
		}
	}
	if date.IsZero() {
		date = release
	}
	return vendorClaim{CVE: cve, Date: date.UTC()}, true
}

// buildMSRC reads Microsoft's list of exploited CVEs, page after page as the list links them (only pages of the same address), and
// parses all of it before anything is written.
func (s *Service) buildMSRC(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	base, err := url.Parse(src.URL)
	if err != nil {
		return p, fail(ErrBadConfig, "The feed's address is not valid.")
	}
	ctx, cancel := context.WithTimeout(ctx, vendorTimeout)
	defer cancel()
	var (
		read vendorRead
		size int
		seen = map[string]bool{}
	)
	read.Whole = true
	next := src.URL
	for page := 0; next != ""; page++ {
		if page == msrcMaxPages {
			return p, fail(ErrBadSample, "Microsoft's list has more than %d pages.", msrcMaxPages)
		}
		var pg msrcPage
		if _, err := s.Fetcher.Fetch(ctx, Request{URL: next, MaxBytes: msrcMaxBytes, Stream: func(r io.Reader) error {
			c := &countReader{r: r}
			var err error
			pg, err = parseMSRCExploited(c)
			size += c.n
			return err
		}}); err != nil {
			return p, err
		}
		read.Accepted += pg.Accepted
		read.Rejected += pg.Rejected
		read.Reasons = append(read.Reasons, pg.Reasons...)
		for _, c := range pg.Claims {
			if seen[c.CVE] {
				continue
			}
			seen[c.CVE] = true
			read.Docs = append(read.Docs, claimDoc{URL: msrcCVEURL + c.CVE, Detail: `{"exploited":"Yes"}`, Claims: []vendorClaim{c}})
			if len(read.Docs) > msrcMaxCVEs {
				return p, fail(ErrBadSample, "Microsoft's list names more than %s CVEs.", grouped(msrcMaxCVEs))
			}
		}
		next = ""
		if pg.Next != "" {
			u, err := base.Parse(pg.Next)
			if err != nil || u.Scheme != base.Scheme || u.Host != base.Host || u.Path != base.Path {
				return p, fail(ErrBadSample, "Microsoft's list links its next page at another address.")
			}
			next = u.String()
		}
	}
	if err := accepted(read.Stats); err != nil {
		return p, err
	}
	// A cut list must not take the flag from CVEs it no longer names, as for the public-exploit indexes.
	if n, held := len(read.Docs), src.Records; held != nil && *held >= publicExploitShrinkFloor && 2*n < *held && n < msrcFloor {
		return p, fail(ErrBadSample, "Microsoft's list names %s CVEs, fewer than half of the %s of the last good list; Vedette kept the claims it had. To take this list anyway, turn the feed off and on again.", grouped(n), grouped(*held))
	}
	p.out = outcome{OK: true, Bytes: size}
	p.out.fill(read.Stats, len(read.Docs))
	p.vendor, p.hasVendor = read, true
	return p, nil
}

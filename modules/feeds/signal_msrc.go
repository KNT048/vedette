package feeds

import (
	"context"
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

// Bounds of the Security Update Guide list: bytes of one page (the whole list is about 1 MB in November 2026), pages followed
// (@odata.nextLink), CVEs of the whole list (198), revisions of one CVE and the length of a revision's text read.
const (
	msrcMaxBytes     = 4 << 20
	msrcMaxPages     = 20
	msrcMaxCVEs      = 20_000
	msrcMaxRevisions = 500
	msrcMaxRevText   = 1 << 10
	msrcShrinkFrom   = 20 // the shrink guard judges a list only after a good one of at least this many CVEs
)

// msrcExploitedRevRE: a revision that set or corrected the exploited flag dates the claim ("Corrected the Exploitability Index, Exploited
// flag and CVSS vector"); "Exploit Code Maturity" of a CVSS vector does not.
var msrcExploitedRevRE = regexp.MustCompile(`(?i)\bexploited\b|exploitation detected`)

type msrcRevision struct {
	Date, Description string
}

type msrcVuln struct {
	CVE, ReleaseDate, Exploited string
	Revisions                   []msrcRevision
}

// msrcPage is one page of the list as parseMSRCExploited read it.
type msrcPage struct {
	Claims []vendorClaim
	Next   string // @odata.nextLink, "" on the last page
	Stats
}

// parseMSRCExploited reads one page of the Security Update Guide's vulnerability list as a stream (every bound holds while reading).
// A CVE is a claim when its exploited field is "Yes" (the query asks only for those; others are skipped, not trusted). Its date is
// the first revision that set the flag, else its release. A row without a CVE id or a readable release date is rejected. The page
// must be one JSON object with a "value" array (fail-closed).
func parseMSRCExploited(r io.Reader) (msrcPage, error) {
	j := newJSONStream(r, "Microsoft's list")
	var (
		out       msrcPage
		sawValues bool
	)
	tl := newTally()
	row := 0
	vuln := func() error {
		row++
		var v msrcVuln
		_, err := j.object(func(k string) (err error) {
			switch k {
			case "cveNumber":
				v.CVE, err = j.str(64)
			case "releaseDate":
				v.ReleaseDate, err = j.str(64)
			case "exploited":
				v.Exploited, err = j.str(16)
			case "revisions":
				err = j.array(msrcMaxRevisions, nil, "revisions of one CVE", func() error {
					var rv msrcRevision
					_, err := j.object(func(k string) (err error) {
						switch k {
						case "revisionDate":
							rv.Date, err = j.str(64)
						case "unformattedDescription":
							rv.Description, err = j.str(msrcMaxRevText)
						default:
							err = j.skip()
						}
						return err
					})
					v.Revisions = append(v.Revisions, rv)
					return err
				})
			default:
				err = j.skip()
			}
			return err
		})
		if err != nil {
			return err
		}
		switch {
		case !strings.EqualFold(strings.TrimSpace(v.Exploited), "Yes"):
		case strings.HasPrefix(strings.ToUpper(strings.TrimSpace(v.CVE)), "ADV"):
			// a Microsoft security advisory (ADV200006) flagged as exploited: no CVE to hold it by
		default:
			c, ok := msrcClaim(v)
			if !ok {
				tl.reject(row, "%s: no CVE id or release date", v.CVE)
				return nil
			}
			tl.Accepted++
			out.Claims = append(out.Claims, c)
		}
		return nil
	}
	ok, err := j.object(func(k string) (err error) {
		switch k {
		case "@odata.nextLink":
			out.Next, err = j.str(2048)
		case "value":
			sawValues, err = j.arrayOK(msrcMaxCVEs, nil, "CVEs", vuln)
		default:
			err = j.skip()
		}
		return err
	})
	if err != nil {
		return msrcPage{}, err
	}
	if !ok {
		return msrcPage{}, fail(ErrBadSample, "Microsoft's list is not a JSON object.")
	}
	if err := j.end(); err != nil {
		return msrcPage{}, err
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
	for _, r := range v.Revisions {
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
	return vendorClaim{CVE: cve, Date: date.UTC(), Flag: true}, true
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
	// A cut list must not take the flag from CVEs it no longer names: Microsoft's list only grows (a flag corrected away is rare), so
	// a list that lost more than a tenth of the last good one is refused (feeds_source.records: cleared by a new address or by turning
	// the feed off and on, the way to take such a list anyway).
	if n, held := len(read.Docs), src.Records; held != nil && *held >= msrcShrinkFrom && 10*n < 9**held {
		return p, fail(ErrBadSample, "Microsoft's list names %s CVEs, fewer than the %s of the last good list by more than a tenth; Vedette kept the claims it had. To take this list anyway, turn the feed off and on again.", grouped(n), grouped(*held))
	}
	p.out = outcome{OK: true, Bytes: size}
	p.out.fill(read.Stats, len(read.Docs))
	p.vendor, p.hasVendor = read, true
	return p, nil
}

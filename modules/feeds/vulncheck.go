package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// VulnCheck KEV (D-557): the free VulnCheck Community list of exploited vulnerabilities, read with the customer's own
// API key (bearer header, never in the address). It lists CVEs reported as exploited before CISA adds them. Only the
// entries CISA does not list (no cisa_date_added) and that VulnCheck added in the last vulnCheckWindow become exploited
// entries of source "vulncheck-kev"; CISA wins every CVE it lists. The data stays on the box.
const (
	vulnCheckFeedID  = "vulncheck-kev"
	vulnCheckWindow  = 180 * 24 * time.Hour
	vulnCheckPage    = 100
	vulnCheckMaxPage = 60 // 6,000 entries; the list has about 4,500
	vulnCheckAction  = "Reported as exploited in the wild by VulnCheck KEV (not on the CISA list yet)."
)

// vulnCheckPause is the wait between two pages; vulnCheckRetryWaits the waits before the next try of a page the source
// answered busy (429, 5xx) or not at all. Vars for the tests (Service.wait replaces the real waits).
var (
	vulnCheckPause      = 500 * time.Millisecond
	vulnCheckRetryWaits = []time.Duration{6 * time.Second, 30 * time.Second}
)

// VulnCheckPageURL is the address of page n of the list under base (the built-in address or a mirror's).
func VulnCheckPageURL(base string, page int) (string, error) {
	if err := CheckURL(base); err != nil {
		return "", err
	}
	if strings.ContainsAny(base, "?#") {
		return "", fail(ErrInvalidURL, "The VulnCheck address must not carry a query string.")
	}
	return strings.TrimSpace(base) + "?" + url.Values{"limit": {strconv.Itoa(vulnCheckPage)}, "page": {strconv.Itoa(page)}}.Encode(), nil
}

// VulnCheckPageResult is one parsed page of the list.
type VulnCheckPageResult struct {
	Vulns      []Vuln // entries CISA does not list and VulnCheck added inside the window
	TotalPages int
	FirstCVE   string // the first entry's CVE (a server that ignores "page" repeats it)
	Stats
}

type vcExploit struct {
	URL       string `json:"url"`
	DateAdded string `json:"date_added"`
}

type vcEntry struct {
	CVE               json.RawMessage `json:"cve"` // an array of CVE IDs; a bare string is accepted
	VendorProject     string          `json:"vendorProject"`
	Product           string          `json:"product"`
	VulnerabilityName string          `json:"vulnerabilityName"`
	ShortDescription  string          `json:"shortDescription"`
	RequiredAction    string          `json:"required_action"`
	Ransomware        string          `json:"knownRansomwareCampaignUse"`
	DateAdded         string          `json:"date_added"`
	CISADateAdded     string          `json:"cisa_date_added"`
	Reported          []vcExploit     `json:"vulncheck_reported_exploitation"`
}

func vcCVE(raw json.RawMessage) (string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		c := strings.ToUpper(jsTrim(one))
		return c, cveRE.MatchString(c)
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 {
		return "", false
	}
	c := strings.ToUpper(jsTrim(many[0])) // the first CVE names the entry; a CVE of its own gets its own entry
	return c, cveRE.MatchString(c)
}

// vcDay turns VulnCheck's timestamp ("2024-05-01T00:00:00.000Z") into its day, fail-closed.
func vcDay(s string) (string, bool) {
	s = jsTrim(s)
	if len(s) < 10 || !strictDateRE.MatchString(s[:10]) || (len(s) > 10 && s[10] != 'T') {
		return "", false
	}
	d, ok := normDate(s[:10], DateAuto)
	return d, ok
}

// ParseVulnCheckPage reads one page of the index answer ({"_meta":{...},"data":[...]}), fail-closed per entry (INV-3):
// a bad entry is rejected and counted, the rest are kept. A body that is not that envelope fails the page. now fixes
// the window of "recent".
func ParseVulnCheckPage(data []byte, now time.Time) (VulnCheckPageResult, error) {
	res := VulnCheckPageResult{Vulns: []Vuln{}}
	if len(data) > MaxBodyBytes {
		return res, fail(ErrTooLarge, "The VulnCheck answer is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	var env struct {
		Meta struct {
			TotalPages int `json:"total_pages"`
		} `json:"_meta"`
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(cleanText(data)), &env); err != nil || env.Data == nil {
		return res, fail(ErrBadSample, "The answer is not a VulnCheck KEV page.")
	}
	res.TotalPages = env.Meta.TotalPages
	tl := newTally()
	cutoff := now.UTC().AddDate(0, 0, -int(vulnCheckWindow/(24*time.Hour))).Format(time.DateOnly)
	today := now.UTC().Format(time.DateOnly)
	for i, raw := range env.Data {
		if i == vulnCheckPage*2 { // a page is at most vulnCheckPage entries: an answer that is not is not trusted further
			tl.Truncated = true
			break
		}
		var e vcEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			tl.reject(i+1, "entry has a field of the wrong type")
			continue
		}
		cve, ok := vcCVE(e.CVE)
		if !ok {
			tl.reject(i+1, "cve: not a CVE ID")
			continue
		}
		if i == 0 {
			res.FirstCVE = cve
		}
		v := Vuln{CVE: cve, Vendor: jsTrim(e.VendorProject), Product: jsTrim(e.Product), Links: []string{}}
		if v.Vendor == "" || v.Product == "" {
			tl.reject(i+1, "vendorProject/product: missing")
			continue
		}
		if len([]rune(v.Vendor)) > maxKeyText || len([]rune(v.Product)) > maxKeyText || hasControlStrict(v.Vendor) || hasControlStrict(v.Product) {
			tl.reject(i+1, "vendorProject/product: too long or contains control characters")
			continue
		}
		added, ok := vcDay(e.DateAdded)
		if !ok {
			tl.reject(i+1, "date_added: unrecognised date")
			continue
		}
		if added > today {
			added = today
		}
		v.DateAdded = added
		name, okName := freeText(e.VulnerabilityName, maxNameText)
		desc, okDesc := freeText(e.ShortDescription, maxDescText)
		act, okAct := freeText(e.RequiredAction, 500)
		if !okName || !okDesc || !okAct {
			tl.reject(i+1, "text: contains control characters")
			continue
		}
		if name == "" {
			name = cve
		}
		v.Name, v.Description = name, desc
		first := ""
		for _, r := range e.Reported {
			if len(v.Links) < maxLinks && validIndicatorURL(r.URL) && !hasControl(r.URL) && strings.HasPrefix(strings.ToLower(r.URL), "https://") && !containsStr(v.Links, r.URL) {
				v.Links = append(v.Links, r.URL)
			}
			if d, ok := vcDay(r.DateAdded); ok && (first == "" || d < first) {
				first = d
			}
		}
		v.RequiredAction = vulnCheckAction
		if first != "" {
			v.RequiredAction += " First reported exploited " + first + "."
		}
		if act != "" {
			v.RequiredAction += " " + act
		}
		v.Ransomware = e.Ransomware == "Known"
		tl.Accepted++
		if jsTrim(e.CISADateAdded) != "" || added < cutoff {
			continue // CISA lists it (CISA's entry wins), or it is old news
		}
		res.Vulns = append(res.Vulns, v)
	}
	res.Stats = tl.stats()
	return res, nil
}

// isKEVSource says whether the feed lists exploited vulnerabilities that make KEV events: the CISA list, and VulnCheck
// KEV for the CVEs CISA does not list yet.
func isKEVSource(id string) bool { return id == "cisa-kev" || id == vulnCheckFeedID }

// mergeReasons adds the reasons of one page to those of the pages before (same text: counts add up).
func mergeReasons(all, more []Reason) []Reason {
	for _, r := range more {
		if i := slices.IndexFunc(all, func(x Reason) bool { return x.Reason == r.Reason }); i >= 0 {
			all[i].Count += r.Count
		} else if len(all) < maxReasons {
			all = append(all, r)
		}
	}
	return all
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// buildVulnCheck reads every page of the list with the customer's key and returns the recent entries CISA does not
// list. Any failed page fails the pull (the data on the box is kept): a half-read list would delete entries it did not
// reach.
func (s *Service) buildVulnCheck(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	auth, err := s.authFor(ctx, src)
	if err != nil {
		return p, err
	}
	if auth.Type != AuthBearer || !auth.Secret.IsSet() {
		return p, fail(ErrInvalidAuth, "Add your VulnCheck API key to turn this feed on.")
	}
	now := s.now()
	var (
		vulns       []Vuln
		firstOfPrev string
		bytes       int
		tl          = newTally()
		seen        = map[string]bool{}
		reasons     []Reason
	)
	for page := 1; page <= vulnCheckMaxPage; page++ {
		if page > 1 {
			if err := s.sleep(ctx, vulnCheckPause); err != nil {
				return p, err
			}
		}
		u, err := VulnCheckPageURL(src.URL, page)
		if err != nil {
			return p, err
		}
		resp, err := s.vulnCheckGet(ctx, u, auth)
		if err != nil {
			return p, vulnCheckError(err)
		}
		bytes += len(resp.Body)
		res, err := ParseVulnCheckPage(resp.Body, now)
		if err != nil {
			return p, err
		}
		if page > 1 && res.FirstCVE != "" && res.FirstCVE == firstOfPrev { // "page" ignored: the same page again
			break
		}
		firstOfPrev = res.FirstCVE
		tl.Accepted += res.Accepted
		tl.Rejected += res.Rejected
		tl.Rejects = append(tl.Rejects, res.Rejects[:min(len(res.Rejects), MaxRejects-len(tl.Rejects))]...)
		reasons = mergeReasons(reasons, res.Reasons)
		for _, v := range res.Vulns {
			if !seen[v.CVE] {
				seen[v.CVE] = true
				vulns = append(vulns, v)
			}
		}
		if res.Accepted+res.Rejected == 0 || page >= res.TotalPages {
			break
		}
	}
	st := tl.stats()
	st.Reasons = reasons
	if err := accepted(st); err != nil {
		return p, err
	}
	p.out = outcome{OK: true, Bytes: bytes}
	p.vulns, p.hasVulns, p.replaceVulns = vulns, true, true
	p.out.fill(st, len(vulns))
	if n := len(vulns); n > 0 {
		p.out.Note = fmt.Sprintf("%s exploited CVEs VulnCheck added in the last 180 days are not on the CISA list yet. %s", grouped(n), p.out.Note)
		p.out.Note = strings.TrimSpace(p.out.Note)
	}
	return p, nil
}

// vulnCheckGet fetches one page, trying again after vulnCheckRetryWaits (or the source's Retry-After, at most 2 min)
// while it is busy or slow.
func (s *Service) vulnCheckGet(ctx context.Context, u string, auth Auth) (*Response, error) {
	for try := 0; ; try++ {
		resp, err := s.get(ctx, Request{URL: u, Auth: auth})
		if err == nil || ctx.Err() != nil || !nvdRetryable(err) || try >= len(vulnCheckRetryWaits) {
			return resp, err
		}
		wait := vulnCheckRetryWaits[try]
		var se *StatusError
		if errors.As(err, &se) && se.RetryAfter > wait {
			wait = min(se.RetryAfter, 2*time.Minute)
		}
		if err := s.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// vulnCheckError words a failed page for Settings -> Feeds: a refused key is the customer's to fix; the key itself and the
// address (which may carry nothing secret, but need not be shown) are never in the text.
func vulnCheckError(err error) error {
	var se *StatusError
	if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
		return &Error{Err: err, Detail: "VulnCheck did not accept the API key. Check the key in Settings, Feeds, VulnCheck KEV and save it again."}
	}
	return err
}

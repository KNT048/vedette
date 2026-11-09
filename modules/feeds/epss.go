package feeds

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EPSSBatchSize is how many CVE ids one api.first.org request may ask for.
const EPSSBatchSize = 100

// EPSSScore is one row of the FIRST EPSS API.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"` // YYYY-MM-DD the score is for, "" when the API gave none
}

// EPSSData is a parsed EPSS API answer.
type EPSSData struct {
	Scores []EPSSScore
	Stats
}

// EPSSDate is the YYYY-MM-DD (UTC) of the day daysAgo days before now: pass 7
// for the "7 days ago" score that gives the delta.
func EPSSDate(now time.Time, daysAgo int) string {
	return now.UTC().AddDate(0, 0, -daysAgo).Format("2006-01-02")
}

// EPSSBatchURLs builds the requests that fetch the scores of cves from the API
// at base (the built-in source address), at most EPSSBatchSize ids each:
// base?cve=A,B,...[&date=YYYY-MM-DD]. date may be empty (latest). Ids are
// validated, upper-cased and de-duplicated.
func EPSSBatchURLs(base string, cves []string, date string) ([]string, error) {
	if err := CheckURL(base); err != nil {
		return nil, err
	}
	if strings.ContainsAny(base, "?#") {
		return nil, fail(ErrInvalidURL, "The EPSS address must not carry a query string.")
	}
	if date != "" {
		if _, ok := normDate(date, DateAuto); !ok || !strictDateRE.MatchString(date) {
			return nil, fail(ErrBadConfig, "The EPSS date must be YYYY-MM-DD.")
		}
	}
	seen := map[string]bool{}
	var ids []string
	for _, c := range cves {
		id := strings.ToUpper(jsTrim(c))
		if !cveRE.MatchString(id) {
			return nil, fail(ErrBadConfig, "%s is not a CVE ID.", quoteVal(c))
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	var out []string
	for i := 0; i < len(ids); i += EPSSBatchSize {
		end := min(i+EPSSBatchSize, len(ids))
		q := url.Values{"cve": {strings.Join(ids[i:end], ",")}}
		if date != "" {
			q.Set("date", date)
		}
		out = append(out, strings.TrimSpace(base)+"?"+q.Encode())
	}
	return out, nil
}

// EPSSURLMaxLen is the longest request address the fetcher accepts for these batches.
const EPSSURLMaxLen = 2048

var epssNum = regexp.MustCompile(`^[0-9]*\.?[0-9]+([eE][+-]?[0-9]+)?$`)

// unitValue reads a probability the API sends as a number or a numeric string.
func unitValue(n *jnode) (float64, bool) {
	if n == nil {
		return 0, false
	}
	var f float64
	var err error
	switch n.k {
	case jNum:
		f, err = strconv.ParseFloat(n.s, 64)
	case jStr:
		if !epssNum.MatchString(n.s) {
			return 0, false
		}
		f, err = strconv.ParseFloat(n.s, 64)
	default:
		return 0, false
	}
	return f, err == nil && f >= 0 && f <= 1
}

func shown(n *jnode) string {
	if n == nil {
		return ""
	}
	return jsString(n)
}

// ParseEPSS reads an api.first.org EPSS answer: {"status":"OK","total":N,
// "data":[{"cve","epss","percentile","date"}]}, with epss and percentile as
// numbers or strings. Rows are validated (CVE id, 0..1, date) and bad ones
// rejected and counted. A damaged answer or an error status fails the parse so
// the caller keeps its previous scores. Truncated is set when the API says it
// has more rows than it returned.
func ParseEPSS(data []byte) (EPSSData, error) {
	if len(data) > MaxBodyBytes {
		return EPSSData{}, fail(ErrTooLarge, "The EPSS answer is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	root, err := decodeJSON(cleanText(data))
	if err != nil || root.k != jObj {
		return EPSSData{}, fail(ErrBadSample, "The EPSS answer is not valid JSON.")
	}
	if st, ok := root.get("status"); ok && (st.k != jStr || st.s != "OK") {
		return EPSSData{}, fail(ErrBadSample, "The EPSS source reported an error.")
	}
	list, _ := root.get("data")
	if list == nil || list.k != jArr {
		return EPSSData{}, fail(ErrBadSample, `The EPSS answer has no "data" list.`)
	}
	out := EPSSData{Scores: []EPSSScore{}}
	tl := newTally()
	for i, n := range list.children() {
		if i == MaxRows {
			tl.Truncated = true
			break
		}
		row := i + 1
		if n.k != jObj {
			tl.reject(row, "entry is not an object")
			continue
		}
		cveN, _ := n.get("cve")
		epssN, _ := n.get("epss")
		pctN, _ := n.get("percentile")
		dateN, hasDate := n.get("date")
		cve := ""
		if cveN != nil && cveN.k == jStr {
			cve = strings.ToUpper(jsTrim(cveN.s))
		}
		score, ok1 := unitValue(epssN)
		pct, ok2 := unitValue(pctN)
		date := ""
		okDate := true
		if hasDate && dateN.k != jNull {
			d := ""
			if dateN.k == jStr {
				d = jsTrim(dateN.s)
			}
			if _, ok := normDate(d, DateAuto); ok && strictDateRE.MatchString(d) {
				date = d
			} else {
				okDate = false
			}
		}
		switch {
		case !cveRE.MatchString(cve):
			tl.reject(row, "cve: %s is not a CVE ID", cve)
		case !ok1:
			tl.reject(row, "epss: %s is not a number from 0 to 1", shown(epssN))
		case !ok2:
			tl.reject(row, "percentile: %s is not a number from 0 to 1", shown(pctN))
		case !okDate:
			tl.reject(row, "date: %s is not a date", shown(dateN))
		default:
			tl.Accepted++
			out.Scores = append(out.Scores, EPSSScore{cve, score, pct, date})
		}
	}
	if t, ok := root.get("total"); ok && t.k == jNum {
		if total, err := strconv.ParseFloat(t.s, 64); err == nil && total > float64(len(list.children())) {
			tl.Truncated = true
		}
	}
	out.Stats = tl.stats()
	return out, nil
}

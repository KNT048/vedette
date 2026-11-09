package feeds

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Vuln is one exploited vulnerability, shaped like a feeds_vuln row (DATA_MODEL §4.1).
type Vuln struct {
	CVE            string   `json:"cve"`
	Vendor         string   `json:"vendor"`
	Product        string   `json:"product"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RequiredAction string   `json:"required_action"`
	Links          []string `json:"links"`
	DateAdded      string   `json:"date_added"` // YYYY-MM-DD
	DueDate        string   `json:"due_date"`   // YYYY-MM-DD, empty when KEV gives none
	Ransomware     bool     `json:"ransomware"`
}

// Key is the inventory matching key (ProductKey of vendor and product).
func (v Vuln) Key() string { return ProductKey(v.Vendor, v.Product) }

// KEVCatalog is a parsed CISA KEV JSON catalog.
type KEVCatalog struct {
	Version  string // catalogVersion, "" when absent or odd
	Released string // dateReleased as YYYY-MM-DD, "" when absent or odd
	Vulns    []Vuln
	Stats
}

type kevEntry struct {
	CVEID       string `json:"cveID"`
	Vendor      string `json:"vendorProject"`
	Product     string `json:"product"`
	Name        string `json:"vulnerabilityName"`
	DateAdded   string `json:"dateAdded"`
	Description string `json:"shortDescription"`
	Action      string `json:"requiredAction"`
	DueDate     string `json:"dueDate"`
	Ransomware  string `json:"knownRansomwareCampaignUse"`
	Notes       string `json:"notes"`
}

// Text caps for descriptive fields (clipped); vendor/product are the matching
// key, so an overlong one rejects the row instead.
const (
	maxKeyText  = 200
	maxNameText = 300
	maxDescText = 2000
	maxLinks    = 10
)

var (
	versionRE    = regexp.MustCompile(`^[0-9A-Za-z._-]{1,40}$`)
	strictDateRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

func clip(s string, runes int) string {
	if utf8.RuneCountInString(s) <= runes {
		return s
	}
	return string([]rune(s)[:runes])
}

// kevLinks splits the KEV "notes" field (URLs separated by ";") into valid http(s) links.
func kevLinks(notes string) []string {
	links := []string{}
	for _, part := range strings.FieldsFunc(notes, func(r rune) bool { return r == ';' || jsIsSpace(r) }) {
		if len(links) == maxLinks {
			break
		}
		if !validIndicatorURL(part) {
			continue
		}
		if u, err := url.Parse(part); err != nil || u.Host == "" {
			continue
		}
		dup := false
		for _, l := range links {
			dup = dup || l == part
		}
		if !dup {
			links = append(links, part)
		}
	}
	return links
}

func (e kevEntry) toVuln() (Vuln, string) {
	cve := strings.ToUpper(jsTrim(e.CVEID))
	if !cveRE.MatchString(cve) {
		return Vuln{}, `cveID: "` + jsSlice(cve, 30) + `" is not a CVE ID`
	}
	v := Vuln{CVE: cve, Links: kevLinks(e.Notes)}
	for _, f := range []struct {
		name, val string
	}{{"vendorProject", e.Vendor}, {"product", e.Product}, {"vulnerabilityName", e.Name}, {"shortDescription", e.Description}, {"requiredAction", e.Action}, {"notes", e.Notes}} {
		if hasControl(f.val) {
			return Vuln{}, f.name + ": contains control characters"
		}
	}
	v.Vendor, v.Product = jsTrim(e.Vendor), jsTrim(e.Product)
	if v.Vendor == "" || v.Product == "" {
		return Vuln{}, "vendorProject/product: missing"
	}
	if utf8.RuneCountInString(v.Vendor) > maxKeyText || utf8.RuneCountInString(v.Product) > maxKeyText {
		return Vuln{}, "vendorProject/product: too long"
	}
	v.Name = clip(jsTrim(e.Name), maxNameText)
	v.Description = clip(jsTrim(e.Description), maxDescText)
	v.RequiredAction = clip(jsTrim(e.Action), maxDescText)
	d, ok := normDate(e.DateAdded, DateAuto)
	if !ok || !strictDateRE.MatchString(jsTrim(e.DateAdded)) {
		return Vuln{}, `dateAdded: unrecognised date "` + jsSlice(e.DateAdded, 30) + `"`
	}
	v.DateAdded = d
	if due := jsTrim(e.DueDate); due != "" {
		dd, ok := normDate(due, DateAuto)
		if !ok || !strictDateRE.MatchString(due) {
			return Vuln{}, `dueDate: unrecognised date "` + jsSlice(due, 30) + `"`
		}
		v.DueDate = dd
	}
	v.Ransomware = e.Ransomware == "Known"
	return v, ""
}

// ParseKEV parses the CISA Known Exploited Vulnerabilities JSON catalog,
// fail-closed per entry (INV-3): a bad entry is rejected and counted, the rest
// are kept. Syntax errors, a missing "vulnerabilities" array or input over
// MaxBodyBytes fail the whole parse so the caller keeps the data it has.
// Duplicate CVE ids keep the first entry.
func ParseKEV(data []byte) (KEVCatalog, error) {
	if len(data) > MaxBodyBytes {
		return KEVCatalog{}, fail(ErrTooLarge, "The catalog is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	dec := json.NewDecoder(strings.NewReader(cleanText(data)))
	bad := func() (KEVCatalog, error) {
		return KEVCatalog{}, fail(ErrBadSample, "The data is not a valid KEV JSON catalog.")
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return bad()
	}
	cat := KEVCatalog{Vulns: []Vuln{}}
	tl := newTally()
	seen := map[string]bool{}
	found := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return bad()
		}
		key, _ := kt.(string)
		switch key {
		case "catalogVersion", "dateReleased":
			var s string
			if err := dec.Decode(&s); err != nil {
				var te *json.UnmarshalTypeError
				if !errors.As(err, &te) {
					return bad()
				}
				continue
			}
			if key == "catalogVersion" && versionRE.MatchString(s) {
				cat.Version = s
			}
			if key == "dateReleased" {
				if d, ok := normDate(s, DateAuto); ok && isoRE.MatchString(s) {
					cat.Released = d
				}
			}
		case "vulnerabilities":
			t, err := dec.Token()
			if err != nil {
				return bad()
			}
			if t != json.Delim('[') {
				return bad()
			}
			found = true
			row := 0
			for dec.More() {
				if row == MaxRows {
					tl.Truncated = true
					cat.Stats = tl.stats()
					return cat, nil
				}
				row++
				var e kevEntry
				if err := dec.Decode(&e); err != nil {
					var te *json.UnmarshalTypeError
					if !errors.As(err, &te) {
						return bad()
					}
					tl.reject(row, "entry has a field of the wrong type")
					continue
				}
				v, why := e.toVuln()
				if why == "" && seen[v.CVE] {
					why = "cveID: duplicate in the catalog"
				}
				if why != "" {
					tl.reject(row, why)
					continue
				}
				seen[v.CVE] = true
				tl.Accepted++
				cat.Vulns = append(cat.Vulns, v)
			}
			if _, err := dec.Token(); err != nil { // ]
				return bad()
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return bad()
			}
		}
	}
	if _, err := dec.Token(); err != nil { // }
		return bad()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return bad()
	}
	if !found {
		return KEVCatalog{}, fail(ErrBadSample, `The catalog has no "vulnerabilities" list.`)
	}
	cat.Stats = tl.stats()
	return cat, nil
}

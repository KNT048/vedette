package feeds

import (
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
	CVEID, Vendor, Product, Name, DateAdded, Description, Action, DueDate, Ransomware, Notes string
}

// kevFields maps KEV JSON keys (exact case, last duplicate wins like JSON.parse) to entry fields.
func kevEntryFrom(n *jnode) (kevEntry, bool) {
	var e kevEntry
	ok := true
	for key, dst := range map[string]*string{
		"cveID": &e.CVEID, "vendorProject": &e.Vendor, "product": &e.Product, "vulnerabilityName": &e.Name,
		"dateAdded": &e.DateAdded, "shortDescription": &e.Description, "requiredAction": &e.Action,
		"dueDate": &e.DueDate, "knownRansomwareCampaignUse": &e.Ransomware, "notes": &e.Notes,
	} {
		v, found := n.get(key)
		switch {
		case !found || v.k == jNull:
		case v.k == jStr:
			*dst = v.s
		default:
			ok = false
		}
	}
	return e, ok
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
		if !validIndicatorURL(part) || hasControl(part) {
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

// freeText strips invisible characters and clips; ok is false when a C0 control remains.
func freeText(s string, runes int) (string, bool) {
	s = clip(jsTrim(stripFormat(s)), runes)
	return s, !hasControl(s)
}

func (e kevEntry) toVuln() (Vuln, rej) {
	cve := strings.ToUpper(jsTrim(e.CVEID))
	if !cveRE.MatchString(cve) {
		return Vuln{}, rj("cveID: %s is not a CVE ID", cve)
	}
	v := Vuln{CVE: cve, Links: kevLinks(e.Notes)}
	v.Vendor, v.Product = jsTrim(e.Vendor), jsTrim(e.Product)
	if v.Vendor == "" || v.Product == "" {
		return Vuln{}, rj("vendorProject/product: missing")
	}
	if utf8.RuneCountInString(v.Vendor) > maxKeyText || utf8.RuneCountInString(v.Product) > maxKeyText {
		return Vuln{}, rj("vendorProject/product: too long")
	}
	if hasControlStrict(v.Vendor) || hasControlStrict(v.Product) {
		return Vuln{}, rj("vendorProject/product: contains control or invisible characters")
	}
	var ok bool
	for _, f := range []struct {
		dst  *string
		src  string
		max  int
		name string
	}{{&v.Name, e.Name, maxNameText, "vulnerabilityName"}, {&v.Description, e.Description, maxDescText, "shortDescription"}, {&v.RequiredAction, e.Action, maxDescText, "requiredAction"}} {
		if *f.dst, ok = freeText(f.src, f.max); !ok {
			return Vuln{}, rj(f.name + ": contains control characters")
		}
	}
	added := jsTrim(e.DateAdded)
	d, ok := normDate(added, DateAuto)
	if !ok || !strictDateRE.MatchString(added) {
		return Vuln{}, rj("dateAdded: unrecognised date %s", added)
	}
	v.DateAdded = d
	if due := jsTrim(e.DueDate); due != "" {
		dd, ok := normDate(due, DateAuto)
		if !ok || !strictDateRE.MatchString(due) {
			return Vuln{}, rj("dueDate: unrecognised date %s", due)
		}
		v.DueDate = dd
	}
	v.Ransomware = e.Ransomware == "Known"
	return v, rej{}
}

// ParseKEV parses the CISA Known Exploited Vulnerabilities JSON catalog,
// fail-closed per entry (INV-3): a bad entry is rejected and counted, the rest
// are kept. Syntax errors, a missing "vulnerabilities" array or input over
// MaxBodyBytes fail the whole parse so the caller keeps the data it has.
// Keys are matched exactly and the last duplicate key wins, as JSON.parse in
// the SPA does. Duplicate CVE ids keep the first entry.
func ParseKEV(data []byte) (KEVCatalog, error) {
	if len(data) > MaxBodyBytes {
		return KEVCatalog{}, fail(ErrTooLarge, "The catalog is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	root, err := decodeJSON(cleanText(data))
	if err != nil || root.k != jObj {
		return KEVCatalog{}, fail(ErrBadSample, "The data is not a valid KEV JSON catalog.")
	}
	list, _ := root.get("vulnerabilities")
	if list == nil || list.k != jArr {
		return KEVCatalog{}, fail(ErrBadSample, `The catalog has no "vulnerabilities" list.`)
	}
	cat := KEVCatalog{Vulns: []Vuln{}}
	if v, ok := root.get("catalogVersion"); ok && v.k == jStr && versionRE.MatchString(v.s) {
		cat.Version = v.s
	}
	if v, ok := root.get("dateReleased"); ok && v.k == jStr {
		if d, ok := normDate(v.s, DateAuto); ok && isoRE.MatchString(v.s) {
			cat.Released = d
		}
	}
	tl := newTally()
	seen := map[string]bool{}
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
		e, ok := kevEntryFrom(n)
		if !ok {
			tl.reject(row, "entry has a field of the wrong type")
			continue
		}
		v, why := e.toVuln()
		if why.none() && seen[v.CVE] {
			why = rj("cveID: duplicate in the catalog")
		}
		if !why.none() {
			tl.rejectR(row, why)
			continue
		}
		seen[v.CVE] = true
		tl.Accepted++
		cat.Vulns = append(cat.Vulns, v)
	}
	cat.Stats = tl.stats()
	return cat, nil
}

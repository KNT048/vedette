package feeds

import (
	"regexp"
	"slices"
	"strings"
	"time"
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
	// ReleasedAt is dateReleased to the second (zero when absent or odd): the tie-breaker of two copies with one catalogVersion
	ReleasedAt time.Time
	Vulns      []Vuln
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

// kevLinks splits the KEV "notes" field (URLs separated by ";") into valid https links. A plain http link is dropped:
// the finding page offers these as the vendor advisory to act on, and a link anyone on the path can rewrite is no
// advisory. Each part is cleaned first (cleanLink): the notes are prose, and "see (https://…) for", "https://a,
// https://b" or a link that ends a sentence otherwise keep a character that sends the reader to the wrong page.
func kevLinks(notes string) []string {
	links := []string{}
	for _, field := range strings.FieldsFunc(notes, func(r rune) bool { return r == ';' || jsIsSpace(r) }) {
		for _, part := range splitJoined(field) {
			if len(links) == maxLinks {
				return links
			}
			part = cleanLink(part)
			if !validIndicatorURL(part) || hasControl(part) || !strings.HasPrefix(strings.ToLower(part), "https://") {
				continue
			}
			if !slices.Contains(links, part) {
				links = append(links, part)
			}
		}
	}
	return links
}

// splitJoined splits links written one after the other with only a comma ("https://a/1,https://a/2") at each "," that
// is directly followed by "http://" or "https://". A comma elsewhere stays: URLs hold commas ("#:~:text=a,-b"), and an
// archived page's own URL follows a "/" ("https://web.archive.org/web/2015/https://…"), never a ",".
func splitJoined(s string) []string {
	var out []string
	for {
		lower, cut := strings.ToLower(s), -1
		for i := strings.IndexByte(lower, ','); i >= 0; {
			if rest := lower[i+1:]; strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
				cut = i
				break
			}
			next := strings.IndexByte(lower[i+1:], ',')
			if next < 0 {
				break
			}
			i += 1 + next
		}
		if cut < 0 {
			return append(out, s)
		}
		out, s = append(out, s[:cut]), s[cut+1:]
	}
}

// cleanLink drops what prose puts around a link and is not part of it: an opening "(", "<", "[" or quote before it;
// sentence punctuation (". , ; : ! ?"), a quote or ">" after it; a ")" or "]" after it only when the link has no
// matching opening one, written or percent-encoded (a vendor path such as ".../advisory-(cve-2020-14472)" keeps its own). "https:/host" (one
// slash, a typo in the list) becomes "https://host".
func cleanLink(s string) string {
	s = strings.TrimLeft(s, "(<[\"'")
	for s != "" {
		switch last := s[len(s)-1]; {
		case strings.IndexByte(".,;:!?\"'>", last) >= 0:
		case last == ')' && opened(s, "(", "%28") < strings.Count(s, ")"):
		case last == ']' && opened(s, "[", "%5b") < strings.Count(s, "]"):
		default:
			if len(s) > 7 && strings.EqualFold(s[:7], "https:/") && s[7] != '/' {
				s = s[:7] + "/" + s[7:]
			}
			return s
		}
		s = s[:len(s)-1]
	}
	return s
}

// opened counts the opening brackets of a link, written or percent-encoded ("/a%28b)" keeps its ")").
func opened(s, plain, encoded string) int {
	return strings.Count(s, plain) + strings.Count(strings.ToLower(s), encoded)
}

// cleanLinks is splitJoined and cleanLink over stored or parsed links, each once and at most maxLinks, dropping one
// that is no link once cleaned. The store applies it to every feed's links on write and on read, so a row stored
// before the rule reads clean too and a pull of an unchanged list does not see a difference to write.
func cleanLinks(links []string) []string {
	out := make([]string, 0, len(links))
	for _, joined := range links {
		for _, l := range splitJoined(joined) {
			if l = cleanLink(l); len(out) < maxLinks && validLink(l) && !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
	}
	return out
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
		if at, err := time.Parse(time.RFC3339Nano, v.s); err == nil {
			cat.ReleasedAt = at.UTC().Truncate(time.Millisecond) // as stored (store.FormatTS), so a held catalog compares equal to itself
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

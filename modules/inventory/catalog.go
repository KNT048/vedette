package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// Catalog is the list of products a person can pick when declaring a device (INV-12, D-30): curated
// products by commercial name plus every vendor/product pair of KEV. It is a port of web/.../catalog.ts;
// content/catalog/search-golden.json keeps the two giving the same answers.
type Catalog struct {
	entries  []*catEntry
	byID     map[string]*catEntry
	kevCount map[string]int
	kev      []KEVProduct
	byCPE    map[string][]string // "part:vendor:product" -> the KEV keys of the curated entry that names it (curatedRow.CPE)
}

type catEntry struct {
	id, display, category, hint, vendor, product, kind, versionHint string
	kev                                                             []string
	aliases                                                         []string
	kevCount                                                        int
	curated                                                         bool
	order                                                           int
	// folded search text
	hName, hVendor, hProduct, hCat, hAll, hVendorProduct string
	hAlias                                               []string
	// the same words split once, so a search does not split them again for every term of every entry
	nameWords, vendorWords, productWords []string
	aliasWords                           [][]string
}

// CatalogItem is one search hit (contract.ts CatalogItem).
type CatalogItem struct {
	ID          string `json:"id"`
	Display     string `json:"display"`
	Hint        string `json:"hint"`
	Category    string `json:"category"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Kind        string `json:"kind"`
	VersionHint string `json:"version_hint"`
	KevCVEs     int    `json:"kev_cves"`
}

// CatalogResult is GET /inventory/catalog.
type CatalogResult struct {
	Items []CatalogItem `json:"items"`
	Total int           `json:"total"`
}

type curatedRow struct {
	Display     string   `json:"display"`
	Category    string   `json:"category"`
	Kind        string   `json:"kind"`
	Vendor      string   `json:"vendor"`
	Product     string   `json:"product"`
	Aliases     string   `json:"aliases"`
	VersionHint string   `json:"version_hint"`
	KevMatch    []string `json:"kev_match"`
	// CPE names the product the way nmap's CPE output does, "part:vendor:product" (an OS CPE such as o:apple:iphone_os), so
	// software nmap identified gets this entry's KEV keys rather than a key no KEV row has (D-501).
	CPE []string `json:"cpe"`
}

const otherCategory = "Other"

func kevKey(vendor, product string) string {
	return strings.ToLower(vendor) + "|" + strings.ToLower(product)
}

func slug(s string) string { return strings.ReplaceAll(fold(s), " ", "-") }

// kindHints guess the type of a KEV product from its name; a wrong guess is fixed on the device page.
var kindHints = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`(?i)firewall|fortios|pan-os|asa|sonicos|firebox|utm`), "firewall"},
	{regexp.MustCompile(`(?i)router|routeros|vigor|archer|wan vpn`), "router"}, //nolint:misspell // product name
	{regexp.MustCompile(`(?i)switch`), "switch"},
	{regexp.MustCompile(`(?i)access point|\bwap\b|wireless|wifi`), "ap"},
	{regexp.MustCompile(`(?i)nas\b|storage|diskstation|qts`), "nas"},
	{regexp.MustCompile(`(?i)camera|ipc|dvr|surveillance`), "camera"},
	{regexp.MustCompile(`(?i)nvr`), "nvr"},
	{regexp.MustCompile(`(?i)printer|mfp|laserjet`), "printer"},
	{regexp.MustCompile(`(?i)wordpress|joomla|drupal|cms|plugin|wiki|webmail|\bphp\b|struts|laravel|magento`), "web"},
	{regexp.MustCompile(`(?i)windows|macos|ios|chrome|firefox|office|reader|acrobat|winrar|7-zip|desktop|client`), "pc"},
	{regexp.MustCompile(`(?i)phone|mobile|android|\biot\b`), "iot"},
}

// NewCatalog builds the catalog from the curated JSON and the KEV pairs.
func NewCatalog(curatedJSON []byte, kev []KEVProduct) (*Catalog, error) {
	var rows []curatedRow
	if err := json.Unmarshal(curatedJSON, &rows); err != nil {
		return nil, fmt.Errorf("inventory: curated catalog: %w", err)
	}
	c := &Catalog{byID: map[string]*catEntry{}, kevCount: map[string]int{}, kev: kev, byCPE: map[string][]string{}}
	for _, r := range kev {
		c.kevCount[kevKey(r.Vendor, r.Product)] = r.Count
	}
	for i, r := range rows {
		if !validKind(r.Kind) {
			return nil, fmt.Errorf("inventory: curated catalog: %q has kind %q", r.Display, r.Kind)
		}
		keys := c.keysFor(r.KevMatch, kevKey(r.Vendor, r.Product))
		for _, p := range r.CPE {
			if _, dup := c.byCPE[p]; dup || strings.Count(p, ":") != 2 {
				return nil, fmt.Errorf("inventory: curated catalog: %q has a duplicate or malformed cpe %q", r.Display, p)
			}
			c.byCPE[p] = keys
		}
		var aliases []string
		for a := range strings.SplitSeq(r.Aliases, ",") {
			if a = strings.TrimSpace(a); a != "" {
				aliases = append(aliases, a)
			}
		}
		c.add(&catEntry{id: slug(r.Display), display: r.Display, category: r.Category, hint: r.Vendor + " " + r.Product, vendor: r.Vendor, product: r.Product,
			kind: r.Kind, kev: keys, aliases: aliases, versionHint: r.VersionHint, kevCount: c.sum(keys), curated: true, order: i})
	}
	auto := map[string]*catEntry{}
	for i, r := range kev {
		key := kevKey(r.Vendor, r.Product)
		id := "kev:" + slug(r.Vendor) + ":" + slug(r.Product)
		if dup, ok := auto[id]; ok { // two KEV rows that differ only in odd spacing are one product
			dup.kev = append(dup.kev, key)
			dup.kevCount += r.Count
			continue
		}
		display := r.Vendor + " " + r.Product
		if strings.HasPrefix(strings.ToLower(r.Product), strings.ToLower(r.Vendor)) {
			display = r.Product
		}
		kind := "server"
		for _, h := range kindHints {
			if h.re.MatchString(r.Product + " " + r.Vendor) {
				kind = h.kind
				break
			}
		}
		e := &catEntry{id: id, display: display, category: otherCategory, hint: r.Vendor + ", " + r.Product, vendor: r.Vendor, product: r.Product, kind: kind,
			kev: []string{key}, versionHint: "The version shown in the product, its About page or its admin console.", kevCount: r.Count, order: 1000 + i}
		auto[id] = e
		c.add(e)
	}
	return c, nil
}

func (c *Catalog) add(e *catEntry) {
	e.hName, e.hVendor, e.hProduct, e.hCat = fold(e.display), fold(e.vendor), fold(e.product), fold(e.category)
	e.hVendorProduct = fold(e.vendor + " " + e.product)
	e.nameWords, e.vendorWords, e.productWords = strings.Fields(e.hName), strings.Fields(e.hVendor), strings.Fields(e.hProduct)
	for _, a := range e.aliases {
		f := fold(a)
		e.hAlias = append(e.hAlias, f)
		e.aliasWords = append(e.aliasWords, strings.Fields(f))
	}
	e.hAll = fold(e.display + " " + e.vendor + " " + e.product + " " + e.category + " " + strings.Join(e.aliases, " "))
	c.entries = append(c.entries, e)
	if _, ok := c.byID[e.id]; !ok {
		c.byID[e.id] = e
	}
}

// keysFor turns the "vendor|product" fragments of a curated entry into real KEV keys: a pair matches when its
// vendor contains the vendor fragment and its product contains the product fragment (empty = any).
func (c *Catalog) keysFor(matches []string, fallback string) []string {
	if len(matches) == 0 {
		return []string{fallback}
	}
	var keys []string
	seen := map[string]bool{}
	for _, m := range matches {
		v, p, _ := strings.Cut(strings.ToLower(m), "|")
		for _, r := range c.kev {
			if strings.Contains(strings.ToLower(r.Vendor), v) && (p == "" || strings.Contains(strings.ToLower(r.Product), p)) {
				if k := kevKey(r.Vendor, r.Product); !seen[k] {
					seen[k] = true
					keys = append(keys, k)
				}
			}
		}
	}
	if len(keys) == 0 {
		return []string{fallback}
	}
	return keys
}

// keysForCPE is the KEV keys of the curated entry that names the product of a CPE 2.2 URI ("cpe:/o:apple:iphone_os:17" ->
// the keys of iOS / iPadOS), nil when no entry names it (D-501). Only part, vendor and product are compared.
func (c *Catalog) keysForCPE(cpe string) []string {
	f := strings.SplitN(strings.ToLower(strings.TrimPrefix(cpe, "cpe:/")), ":", 4)
	if len(f) < 3 {
		return nil
	}
	return c.byCPE[f[0]+":"+f[1]+":"+f[2]]
}

func (c *Catalog) sum(keys []string) int {
	n := 0
	for _, k := range keys {
		n += c.kevCount[k]
	}
	return n
}

// score ranks one entry for the search terms: exact name > start of name > first word of name > alias or
// vendor > category. Zero means no match. Curated entries and entries with many exploited CVEs rank higher.
func (e *catEntry) score(terms []string) float64 {
	nameWords := e.nameWords
	total := 0.0
	matched := 0
	q := strings.Join(terms, " ")
	if e.hName == q {
		total += 200
	} else if strings.HasPrefix(e.hName, q) {
		total += 120
	}
	hasWord := func(words []string, t string) bool { return indexOf(words, t) }
	hasPrefixWord := func(words []string, t string) bool {
		for _, w := range words {
			if strings.HasPrefix(w, t) {
				return true
			}
		}
		return false
	}
	for _, t := range terms {
		s := 0.0
		switch {
		case hasWord(nameWords, t):
			s = 40
		case hasPrefixWord(nameWords, t):
			s = 32
		case e.aliasEquals(t):
			s = 30
		case e.aliasPrefix(t):
			s = 24
		case hasPrefixWord(e.vendorWords, t):
			s = 22
		case hasPrefixWord(e.productWords, t):
			s = 20
		case strings.Contains(e.hCat, t):
			s = 8
		case len(t) >= 3 && strings.Contains(e.hAll, t):
			s = 5
		}
		if s > 0 {
			matched++
		}
		total += s
	}
	unmatched := len(terms) - matched
	onlyNumbers := true
	for _, t := range terms {
		if !strings.Contains(e.hAll, t) && !strings.ContainsAny(t, "0123456789") {
			onlyNumbers = false
		}
	}
	if unmatched > 0 && (matched == 0 || !onlyNumbers) {
		return 0
	}
	if matched == 0 {
		return 0
	}
	if e.curated {
		total += 15 - float64(min(e.order, 150))/10
	}
	return total + float64(min(e.kevCount, 50))/10
}

func indexOf(words []string, t string) bool {
	for _, w := range words {
		if w == t {
			return true
		}
	}
	return false
}

func (e *catEntry) aliasEquals(t string) bool {
	for i, a := range e.hAlias {
		if a == t || indexOf(e.aliasWords[i], t) {
			return true
		}
	}
	return false
}

func (e *catEntry) aliasPrefix(t string) bool {
	for i, a := range e.hAlias {
		if strings.HasPrefix(a, t) {
			return true
		}
		for _, w := range e.aliasWords[i] {
			if strings.HasPrefix(w, t) {
				return true
			}
		}
	}
	return false
}

func (e *catEntry) item() CatalogItem {
	return CatalogItem{ID: e.id, Display: e.display, Hint: e.hint, Category: e.category, Vendor: e.vendor, Product: e.product, Kind: e.kind, VersionHint: e.versionHint, KevCVEs: e.kevCount}
}

// maxTerms caps the words of a search: more words never help and every word costs a pass over the whole catalog,
// so a pasted paragraph must not cost a pass per word (GET /inventory/catalog and the CSV import both reach it).
const maxTerms = 8

// searchTerms folds q into at most maxTerms words.
func searchTerms(q string) []string {
	terms := strings.Fields(fold(q))
	if len(terms) > maxTerms {
		terms = terms[:maxTerms]
	}
	return terms
}

func (c *Catalog) search(q string) ([]*catEntry, int) {
	terms := searchTerms(q)
	if len(terms) == 0 {
		var out []*catEntry
		for _, e := range c.entries {
			if e.curated && len(out) < MaxCatalogHits {
				out = append(out, e)
			}
		}
		return out, len(c.entries)
	}
	type hit struct {
		e *catEntry
		s float64
	}
	var hits []hit
	for _, e := range c.entries {
		if s := e.score(terms); s > 0 {
			hits = append(hits, hit{e, s})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].s != hits[j].s {
			return hits[i].s > hits[j].s
		}
		return hits[i].e.order < hits[j].e.order
	})
	out := make([]*catEntry, 0, min(MaxCatalogHits, len(hits)))
	for _, h := range hits[:min(MaxCatalogHits, len(hits))] {
		out = append(out, h.e)
	}
	return out, len(hits)
}

// Search returns at most MaxCatalogHits items and the number of matches (INV-12). An empty query lists the
// curated products in popularity order.
func (c *Catalog) Search(q string) CatalogResult {
	if utf8.RuneCountInString(q) > 80 {
		q = string([]rune(q)[:80])
	}
	list, total := c.search(q)
	res := CatalogResult{Items: make([]CatalogItem, 0, len(list)), Total: total}
	for _, e := range list {
		res.Items = append(res.Items, e.item())
	}
	return res
}

// find matches the text of a CSV cell exactly: an id, a display name, "vendor product" or an alias. There is no
// fuzzy fallback: a product the catalog does not know must stay unknown (the hand-entry box suggests, a person
// picks; a file cannot pick), or "Dns" would silently become D-Link. An alias shared by several products ("dns"
// is D-Link's NAS series and BIND) is not a match.
func (c *Catalog) find(text string) *catEntry {
	n := fold(text)
	if n == "" {
		return nil
	}
	id := strings.TrimSpace(text)
	var aliasHits, productHits, vendorHits []*catEntry
	for _, e := range c.entries {
		if e.id == id || e.hName == n || e.hVendorProduct == n {
			return e
		}
		if indexOf(e.hAlias, n) {
			aliasHits = append(aliasHits, e)
		}
		if e.hProduct == n {
			productHits = append(productHits, e)
		}
		if e.curated && e.hVendor == n {
			vendorHits = append(vendorHits, e)
		}
	}
	// Several products may share the text ("synology" is two Synology products, "dns" is D-Link and BIND, "php"
	// belongs to two vendors): the first (most popular) is taken only when they all have the same vendor, so the
	// make is never a guess. A bare vendor name is taken only when the vendor has one curated product.
	hits := aliasHits
	if len(hits) == 0 {
		hits = productHits
	}
	if len(hits) == 0 && len(vendorHits) == 1 {
		hits = vendorHits
	}
	for _, e := range hits {
		if e.hVendor != hits[0].hVendor {
			return nil
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return hits[0]
}

// custom is a product a person typed (vendor + product): matched to the exact KEV pair when there is one,
// else to every product of the vendor, else to the plain key.
func (c *Catalog) custom(vendor, product string) *catEntry {
	v, p := fold(vendor), fold(product)
	var exact, byVendor []string
	for _, r := range c.kev {
		if fold(r.Vendor) == v {
			byVendor = append(byVendor, kevKey(r.Vendor, r.Product))
			if fold(r.Product) == p {
				exact = append(exact, kevKey(r.Vendor, r.Product))
			}
		}
	}
	keys := exact
	if len(keys) == 0 {
		keys = byVendor
	}
	if len(keys) == 0 {
		keys = []string{kevKey(vendor, product)}
	}
	return &catEntry{display: strings.TrimSpace(vendor + " " + product), category: otherCategory, hint: vendor + ", " + product, vendor: vendor, product: product,
		kind: "unknown", kev: keys, kevCount: c.sum(keys), order: 9999}
}

// ---- the KEV data behind it ----

// EmbeddedKEV is the KEV stand-in until feeds (WP-20) implements KEV: the vendor/product pairs come from
// content/catalog/kev-products.json, and no CVE ids are known, so nothing is matched (deferred).
type EmbeddedKEV struct{}

// Products implements KEV.
func (EmbeddedKEV) Products(context.Context) (string, []KEVProduct, error) {
	var list []KEVProduct
	if err := json.Unmarshal(catalogdata.KEVProducts, &list); err != nil {
		return "", nil, fmt.Errorf("inventory: embedded KEV products: %w", err)
	}
	return "embedded", list, nil
}

// CVEs implements KEV: none known.
func (EmbeddedKEV) CVEs(context.Context, []string) ([]string, error) { return nil, nil }

type catalogCache struct {
	mu      sync.Mutex
	version string
	cat     *Catalog
}

// Catalog returns the catalog, rebuilt when the KEV list changes version.
func (s *Service) Catalog(ctx context.Context) (*Catalog, error) {
	src := s.kev
	if src == nil {
		src = EmbeddedKEV{}
	}
	version, list, err := src.Products(ctx)
	if err != nil {
		return nil, fmt.Errorf("inventory: KEV products: %w", err)
	}
	s.cat.mu.Lock()
	defer s.cat.mu.Unlock()
	if s.cat.cat != nil && s.cat.version == version {
		return s.cat.cat, nil
	}
	c, err := NewCatalog(catalogdata.Curated, list)
	if err != nil {
		return nil, err
	}
	s.cat.cat, s.cat.version = c, version
	return c, nil
}

// SearchCatalog is GET /inventory/catalog.
func (s *Service) SearchCatalog(ctx context.Context, q string) (CatalogResult, error) {
	c, err := s.Catalog(ctx)
	if err != nil {
		return CatalogResult{}, err
	}
	return c.Search(q), nil
}

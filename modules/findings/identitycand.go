package findings

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// Candidates for the AI's identification of a software line nothing else identifies (aiidentity.go). The box generates them itself,
// with high recall and no product list: the line's publisher and name are cleaned (legal-entity words, the line's own version, version
// numbers, architecture and language words and any text in parentheses dropped) and compared word by word with every product the box's
// own catalogue names (a CPE's vendor and product of a catalogue range, a CVE record's product key, an exploited-list entry): a product
// with no catalogue CVE could never match anything, so nothing outside the catalogue is offered and nothing is fetched for it. The
// candidates are ranked by how much of the product's name the line's name covers, how much of the line's name the product's covers,
// and whether the vendor is the publisher; up to identityCandidateMax go to the AI. An exact match of the cleaned names is only the
// first candidate: the box never links a line by itself.

// identityCandidateMax is the most candidates one line is offered.
const identityCandidateMax = 20

// CatalogueProduct is one product the box's catalogue names, with how many CVEs name it (Identifier.Products).
type CatalogueProduct struct {
	Vendor, Product string // a CPE's vendor and product as the catalogue stores them, or a CVE record's product key (Record)
	Record          bool   // a CVE record's product key without a CPE
	// Kev is the exploited-list entry's own "vendor|product" (productid.Key) when an exploited-list entry names the product, else "".
	Kev string
	// Title is the product's readable name: the exploited list's words when it names it, else "" (titleOf derives one).
	Title     string
	CVEs      int // the catalogue CVEs that name it
	Exploited int // how many of them are on an exploited list
}

// CatalogueName is one product name as the catalogue gives it (Identifier.Products): a range's vendor and product (a CPE's names,
// or, Record set, a CVE record's product key) or, Kev set, an exploited-list entry's own vendor and product, with its CVE counts.
type CatalogueName struct {
	Vendor, Product string
	Record, Kev     bool
	CVEs, Exploited int
}

// mergeCatalogue is the candidates' products from the catalogue's names, one per normalised vendor and product: a CPE product, else
// a CVE record's product key (a record key with a CPE product's normalised names is that product: both reach the line, newSWInfo);
// an exploited-list entry with a product's normalised names gives that product its list key and title, any other is a product of
// its own, reached by its list key only.
func mergeCatalogue(names []CatalogueName) []CatalogueProduct {
	out := make([]CatalogueProduct, 0, len(names))
	at := map[string]int{}
	add := func(n CatalogueName, record bool) {
		k := productid.NormKey(n.Vendor, n.Product)
		if i, ok := at[k]; ok {
			out[i].CVEs, out[i].Exploited = max(out[i].CVEs, n.CVEs), max(out[i].Exploited, n.Exploited)
			return
		}
		at[k] = len(out)
		out = append(out, CatalogueProduct{Vendor: n.Vendor, Product: n.Product, Record: record, CVEs: n.CVEs, Exploited: n.Exploited})
	}
	for _, n := range names {
		if !n.Kev && !n.Record {
			add(n, false)
		}
	}
	for _, n := range names {
		if !n.Kev && n.Record {
			add(n, true)
		}
	}
	for _, n := range names {
		if !n.Kev {
			continue
		}
		key, title := productid.Key(n.Vendor, n.Product), strings.Join(strings.Fields(n.Product), " ")
		if v := strings.Join(strings.Fields(n.Vendor), " "); !strings.HasPrefix(strings.ToLower(title), strings.ToLower(v)) {
			title = v + " " + title
		}
		title = clipRunes(title, 120)
		if i, ok := at[productid.NormKey(n.Vendor, n.Product)]; ok {
			out[i].Kev, out[i].Title = key, title
			continue
		}
		at[productid.NormKey(n.Vendor, n.Product)] = len(out)
		out = append(out, CatalogueProduct{Vendor: n.Vendor, Product: n.Product, Kev: key, Title: title, CVEs: n.CVEs, Exploited: n.Exploited})
	}
	return out
}

// key is the product's identity among candidates: its normalised vendor and product (mergeCatalogue keeps one per key).
func (p CatalogueProduct) key() string {
	return productid.NormKey(p.Vendor, p.Product)
}

// titleOf is the product's readable name: its exploited-list name, else its vendor and product with the CPE's escapes and underscores
// read as words, the vendor left out when the product starts with it.
func titleOf(p CatalogueProduct) string {
	if p.Title != "" {
		return p.Title
	}
	words := func(s string) string {
		s = strings.ReplaceAll(s, `\`, "")
		return strings.Join(strings.Fields(strings.ReplaceAll(s, "_", " ")), " ")
	}
	v, pr := words(p.Vendor), words(p.Product)
	if v == "" || strings.HasPrefix(productid.Norm(pr), productid.Norm(v)) {
		return clipRunes(pr, 120)
	}
	return clipRunes(v+" "+pr, 120)
}

// identityCandidate is one product offered to the AI for a line, with its id in the request ("c1" ... "c20").
type identityCandidate struct {
	ID      string
	Product CatalogueProduct
	Title   string
	score   float64
}

// The words a line's name or a product's name carries that never tell which product it is: articles, packaging and generic software
// words. A product chosen by the AI must share a word outside these with the line's name (sharesNameWord).
var identityStopwords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "for": true, "of": true, "to": true, "in": true, "on": true, "with": true, "by": true,
	"version": true, "edition": true, "update": true, "updates": true, "updater": true, "setup": true, "install": true, "installer": true,
	"package": true, "app": true, "apps": true, "application": true, "applications": true, "software": true, "tool": true, "tools": true,
	"program": true, "utility": true, "utilities": true, "plugin": true, "plug": true, "addin": true, "add": true, "extension": true,
	"component": true, "components": true, "common": true, "file": true, "files": true, "shared": true, "service": true,
	"services": true, "helper": true, "support": true, "client": true, "desktop": true, "free": true, "lite": true, "portable": true,
	"beta": true, "preview": true, "current": true, "user": true, "users": true, "windows": true, "win": true, "mac": true,
	"macos": true, "linux": true, "x": true, "bit": true, "runtime": true, "redistributable": true, "framework": true, "library": true,
	"driver": true, "drivers": true, "module": true, "manager": true, "launcher": true, "online": true, "pack": true, "kit": true,
	"sdk": true, "core": true, "host": true, "standard": true, "professional": true, "pro": true, "enterprise": true, "home": true,
	"community": true, "personal": true, "server": true, "system": true, "systems": true, "data": true, "new": true, "plus": true,
}

// legalWords are a publisher's legal-entity and company words.
var legalWords = map[string]bool{
	"inc": true, "incorporated": true, "corp": true, "corporation": true, "co": true, "company": true, "ltd": true, "limited": true,
	"llc": true, "llp": true, "gmbh": true, "mbh": true, "ag": true, "se": true, "sa": true, "sas": true, "sarl": true, "srl": true,
	"spa": true, "plc": true, "bv": true, "nv": true, "kk": true, "oy": true, "ab": true, "as": true, "aps": true, "pty": true,
	"pte": true, "sro": true, "ltda": true, "kg": true, "the": true, "team": true, "contributors": true, "project": true,
}

var (
	reParens   = regexp.MustCompile(`\([^()]*\)|\[[^\[\]]*\]`)
	reArch     = regexp.MustCompile(`(?i)\b(x86[_-]64|x64|x86|amd64|arm64|aarch64|ia64|win64|win32|64[ -]?bit|32[ -]?bit)\b`)
	reLanguage = regexp.MustCompile(`(?i)\b[a-z]{2}-[a-z]{2}\b|\b(english|deutsch|german|french|francais|espanol|spanish|italiano|japanese|chinese|korean|russian|vietnamese|multilingual|mui)\b`)
	reVersion  = regexp.MustCompile(`(?i)^v?[0-9]+([._][0-9a-z]+)+$|^v[0-9]*$|^r[0-9]+$|^build$|^[0-9]+(st|nd|rd|th)$`)
	reWordSep  = regexp.MustCompile(`[^\p{L}\p{N}+#]+`)
)

// nameWords are the words of a name as candidates compare them: lower case, the CPE's escapes removed, split on anything but letters,
// digits, "+" and "#" ("Notepad++", "C#").
func nameWords(s string) []string {
	var out []string
	for _, w := range reWordSep.Split(strings.ReplaceAll(strings.ToLower(s), `\`, ""), -1) {
		base := strings.Trim(w, "+#")
		if base == "" {
			continue
		}
		out = append(out, base)
		if w != base {
			out = append(out, w)
		}
	}
	return out
}

// cleanPublisher is a publisher's words without legal-entity words ("Zoom Video Communications, Inc." -> zoom video communications).
func cleanPublisher(publisher string) []string {
	ws := nameWords(reParens.ReplaceAllString(publisher, " "))
	out := slices.DeleteFunc(slices.Clone(ws), func(w string) bool { return legalWords[w] })
	if len(out) == 0 {
		return ws
	}
	return out
}

// cleanName is a line's name without what never names the product: text in parentheses ("(x64 en-US)", "(Current user)"), the line's
// own version and any version number, architecture and language words. A name made only of those keeps its words.
func cleanName(name, version string) []string {
	s := reParens.ReplaceAllString(name, " ")
	if v := strings.TrimSpace(version); v != "" {
		s = strings.ReplaceAll(strings.ToLower(s), strings.ToLower(v), " ")
	}
	s = reArch.ReplaceAllString(s, " ")
	s = reLanguage.ReplaceAllString(s, " ")
	var out []string
	for _, w := range strings.Fields(s) {
		if reVersion.MatchString(strings.Trim(w, ",;:")) {
			continue
		}
		out = append(out, nameWords(w)...)
	}
	if len(out) == 0 {
		return nameWords(name)
	}
	return out
}

// IdentityKey is the key of a line's identification: its cleaned publisher and name, one row for every device that has the same
// software. ok is false for a line with no name left to identify.
func IdentityKey(s Software) (publisher, name string, ok bool) {
	n := s.Product
	if strings.TrimSpace(n) == "" {
		n = s.Display
	}
	words := cleanName(n, s.Version)
	if len(words) == 0 {
		return "", "", false
	}
	return clipRunes(strings.Join(cleanPublisher(s.Vendor), " "), 200), clipRunes(strings.Join(words, " "), 200), true
}

// wordSet is a name's words with the joins of neighbours and of all, as names are written with and without spaces ("draw io" is
// "drawio", "Visual Studio Code" is "visualstudiocode").
func wordSet(words []string) map[string]bool {
	out := make(map[string]bool, 2*len(words)+1)
	for i, w := range words {
		out[w] = true
		if i > 0 {
			out[words[i-1]+w] = true
		}
	}
	if len(words) > 2 {
		out[strings.Join(words, "")] = true
	}
	return out
}

// productIndex is the catalogue's products indexed by the words of their names, built once per run.
type productIndex struct {
	products []CatalogueProduct
	words    [][]string       // per product: its product's words
	vendors  []string         // per product: its normalised vendor
	byWord   map[string][]int // a word (or the join of all) of a product's name -> products
	byVendor map[string][]int // a normalised vendor -> products
}

func newProductIndex(products []CatalogueProduct) *productIndex {
	ix := &productIndex{products: products, words: make([][]string, len(products)), vendors: make([]string, len(products)),
		byWord: map[string][]int{}, byVendor: map[string][]int{}}
	for i, p := range products {
		ws := nameWords(p.Product)
		ix.words[i] = ws
		ix.vendors[i] = productid.Norm(p.Vendor)
		seen := map[string]bool{}
		for _, w := range append(slices.Clone(ws), strings.Join(ws, "")) {
			if w != "" && !seen[w] {
				seen[w] = true
				ix.byWord[w] = append(ix.byWord[w], i)
			}
		}
		if ix.vendors[i] != "" {
			ix.byVendor[ix.vendors[i]] = append(ix.byVendor[ix.vendors[i]], i)
		}
	}
	return ix
}

// vendorIs says whether a catalogue vendor is the publisher: one normalised name starts with the other ("zoom" and Zoom Video
// Communications), at least three letters long.
func vendorIs(vendor string, publisher []string) bool {
	if len(publisher) == 0 || len(vendor) < 3 {
		return false
	}
	pub := strings.Join(publisher, "")
	return len(pub) >= 3 && (strings.HasPrefix(pub, vendor) || strings.HasPrefix(vendor, pub))
}

// identifying are the words of a name that may tell which product it is (not identityStopwords).
func identifying(ws map[string]bool) map[string]bool {
	out := make(map[string]bool, len(ws))
	for w := range ws {
		if len(w) > 1 && !identityStopwords[w] {
			out[w] = true
		}
	}
	return out
}

// sharesNameWord says whether a product's name shares a word that may tell the product (not a stopword) with a line's cleaned name:
// the box's check of the AI's choice.
func sharesNameWord(product string, name []string) bool {
	ws := identifying(wordSet(name))
	pw := nameWords(product)
	for _, w := range append(pw, strings.Join(pw, "")) {
		if ws[w] {
			return true
		}
	}
	return false
}

// identityCandidates is the candidates for a line of cleaned publisher and name, best first, at most identityCandidateMax, leaving out
// the products a person said it is not (rejected, by CatalogueProduct.key). Every candidate shares a word that may tell the product
// with the line's name, so any choice among them passes sharesNameWord.
func (ix *productIndex) identityCandidates(publisher, name []string, rejected map[string]bool) []identityCandidate {
	nw := wordSet(name)
	idw := identifying(nw)
	at := map[int]bool{}
	for w := range idw {
		for _, i := range ix.byWord[w] {
			at[i] = true
		}
	}
	for vn, l := range ix.byVendor { // the publisher's own products, when their name shares a word with the line's
		if !vendorIs(vn, publisher) {
			continue
		}
		for _, i := range l {
			if sharesAny(ix.words[i], idw) {
				at[i] = true
			}
		}
	}
	var out []identityCandidate
	for i := range at {
		p := ix.products[i]
		if rejected[p.key()] {
			continue
		}
		if sc, ok := ix.score(i, publisher, name, nw); ok {
			out = append(out, identityCandidate{Product: p, Title: titleOf(p), score: sc})
		}
	}
	slices.SortFunc(out, func(a, b identityCandidate) int {
		if a.score != b.score {
			return cmp.Compare(b.score, a.score)
		}
		if c := cmp.Compare(b.Product.Exploited, a.Product.Exploited); c != 0 {
			return c
		}
		if c := cmp.Compare(b.Product.CVEs, a.Product.CVEs); c != 0 {
			return c
		}
		return strings.Compare(a.Product.key(), b.Product.key())
	})
	if len(out) > identityCandidateMax {
		out = out[:identityCandidateMax]
	}
	for i := range out {
		out[i].ID = "c" + strconv.Itoa(i+1)
	}
	return out
}

// weight is how much a word tells the product: less the more catalogue products have it in their name.
func (ix *productIndex) weight(w string) float64 {
	return 1 / math.Log2(2+float64(len(ix.byWord[w])))
}

// score ranks product i for a line of cleaned publisher and name (nw: wordSet of name): twice the share of the product's name the
// line's name covers, twice the share of the line's name the product's name covers (both weighted by weight), one more when the vendor
// is the publisher, and a half more when the two cleaned names are the same. ok is false when the line's name covers none of it.
func (ix *productIndex) score(i int, publisher, name []string, nw map[string]bool) (float64, bool) {
	pw := ix.words[i]
	if len(pw) == 0 {
		return 0, false
	}
	join := strings.Join(pw, "")
	joined := len(pw) > 1 && nw[join] // "draw.io" as "drawio" in one word of the product's, or the reverse
	var have, all float64
	for _, w := range pw {
		all += ix.weight(w)
		if joined || nw[w] {
			have += ix.weight(w)
		}
	}
	if have == 0 {
		return 0, false
	}
	ps := wordSet(pw)
	vendor := vendorIs(ix.vendors[i], publisher)
	var hit, total float64
	exact := true
	for k, w := range name {
		total += ix.weight(w)
		in := ps[w] || joined && strings.Contains(join, w) || k > 0 && ps[name[k-1]+w] || k+1 < len(name) && ps[w+name[k+1]] ||
			vendor && vendorIs(ix.vendors[i], []string{w}) // the vendor's own name in the line's name
		if in {
			hit += ix.weight(w)
		} else {
			exact = false
		}
	}
	sc := 2*have/all + 2*hit/total
	if vendor {
		sc++
	}
	if exact && have == all {
		sc += 0.5 // the cleaned names are the same: the first candidate, never a link by itself
	}
	return sc, true
}

func sharesAny(words []string, set map[string]bool) bool {
	for _, w := range append(slices.Clone(words), strings.Join(words, "")) {
		if set[w] {
			return true
		}
	}
	return false
}

// topSet is the top identityTopN candidates as a stored answer keeps them (fnd_identity.candidates): a short hash of each product,
// in rank order, separated by spaces; askAgain compares it with the top of a later offer.
func topSet(cs []identityCandidate) string {
	var out []string
	for i, c := range cs {
		if i == identityTopN {
			break
		}
		h := sha256.Sum256([]byte(c.Product.key()))
		out = append(out, hex.EncodeToString(h[:4]))
	}
	return strings.Join(out, " ")
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

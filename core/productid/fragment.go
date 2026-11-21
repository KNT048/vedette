package productid

import (
	"regexp"
	"strings"
)

// A picker row (content/catalog/curated.json) names the exploited-list products it covers with fragments "vendor|product". A
// fragment matches whole words, never pieces of a word: "cisco|rv" does not reach "Identity Services Engine", and a list name that
// merely contains a product's name ("NetScaler SD-WAN Enterprise, CloudBridge Virtual WAN, and XenMobile Server" holds "NetScaler")
// is not that product's. The same rule is written in web/src/features/inventory/catalog.ts; content/catalog/search-golden.json
// proves they agree.
//
//   - The vendor part (empty = any vendor) is a run of whole words of the list's vendor.
//   - The product part (empty = every product of the vendor) is judged against the list's product name and against each part of it
//     when the name lists several products (split at a comma, "/", "&" or "and"): a list name lands on every product it names and on
//     no other. A part names the product when it is the fragment's words alone, or the fragment's words and then only qualifiers
//     ("software", "appliance", "devices" ...: words that do not name another product).
//   - A fragment ending in "*" names a family: the part starts with the fragment's words and may go on ("windows*" for every
//     Windows component, "rv*" for RV160, RV320 ... in the last word).
//   - Text in brackets is left out on both sides ("Adaptive Security Appliance (ASA)").

var (
	bracketRE = regexp.MustCompile(`\([^)]*\)`)
	partSplit = regexp.MustCompile(`\s*(?:,|/|&|\band\b)\s*`)
	wordRE    = regexp.MustCompile(`[a-z0-9]+`)
)

// qualifiers are words a list name may add to a product's name without naming another product.
var qualifiers = map[string]bool{
	"software": true, "appliance": true, "appliances": true, "device": true, "devices": true, "server": true, "servers": true,
	"series": true, "router": true, "routers": true, "firmware": true, "edition": true, "editions": true, "community": true,
	"enterprise": true, "data": true, "center": true, "web": true, "ui": true, "ce": true, "ee": true,
}

// words are the lower-case words of s, bracketed text left out.
func words(s string) []string {
	s = strings.ToLower(bracketRE.ReplaceAllString(spaced(s), " "))
	return wordRE.FindAllString(s, -1)
}

// FragmentMatch says whether a kev_match fragment ("vendor|product", see above) names the exploited-list product (vendor, product).
func FragmentMatch(fragment, vendor, product string) bool {
	fv, fp, _ := strings.Cut(fragment, "|")
	if v, _ := fragWords(fv); len(v) > 0 && !hasRun(words(vendor), v) {
		return false
	}
	p, star := fragWords(fp)
	if len(p) == 0 {
		return true
	}
	name := bracketRE.ReplaceAllString(strings.ToLower(spaced(product)), " ")
	if namesPart(wordRE.FindAllString(name, -1), p, star) {
		return true
	}
	for _, part := range partSplit.Split(name, -1) {
		if namesPart(wordRE.FindAllString(part, -1), p, star) {
			return true
		}
	}
	return false
}

// fragWords are the words of a fragment part and whether it ends in "*".
func fragWords(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	return words(strings.TrimSuffix(s, "*")), strings.HasSuffix(s, "*")
}

// hasRun says whether the words of want are a run of whole words of have.
func hasRun(have, want []string) bool {
	for i := 0; i+len(want) <= len(have); i++ {
		ok := true
		for j, w := range want {
			if have[i+j] != w {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// namesPart says whether one part of a list name (its words) is the fragment's words, a family of them (star), or them and only
// qualifiers.
func namesPart(part, frag []string, star bool) bool {
	n := len(frag)
	if len(part) < n {
		return false
	}
	for i, w := range frag[:n-1] {
		if part[i] != w {
			return false
		}
	}
	if star {
		return strings.HasPrefix(part[n-1], frag[n-1])
	}
	if part[n-1] != frag[n-1] {
		return false
	}
	for _, w := range part[n:] {
		if !qualifiers[w] {
			return false
		}
	}
	return true
}

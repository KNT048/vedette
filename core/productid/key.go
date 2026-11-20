// Package productid is the one product identity of Vedette. It owns:
//
//   - the key of a vendor and product (Key) and the normalised name comparison (Norm, NormVendor, NormProduct) that feeds,
//     inventory, findings and exposure use; no other package normalises product names;
//   - the product catalogue (content/catalog/products/*.json): per product, the names each source gives it (package names,
//     Windows program names and patterns, the CPE nmap prints), its NVD CPE products, its exploited-list keys, its version
//     scheme, its release-train rule and its class; a runtime family (OpenJDK: Oracle, Temurin, Zulu, Corretto, Microsoft,
//     Red Hat, Liberica, Semeru) is one product with the distribution kept as an attribute;
//   - Resolve: a source's raw name (and vendor, CPE) to a Product, with the version a program name states split off.
//
// Everything here is pure: no I/O beyond the embedded catalogue, no database.
package productid

import "strings"

// Key is the matching key of a vendor and product, as the exploited lists, the inventory and findings compare them:
// lower(trim(vendor)) + "|" + lower(trim(product)). "Oracle", "Java SE" is "oracle|java se".
func Key(vendor, product string) string {
	return strings.ToLower(strings.TrimSpace(vendor)) + "|" + strings.ToLower(strings.TrimSpace(product))
}

// Norm keeps only [a-z0-9] of the lower-cased text, so a name and the NVD spelling of it compare equal: "Photo Station" and
// "photo_station" are both "photostation", "Palo Alto Networks" is "paloaltonetworks".
func Norm(s string) string {
	if normalised(s) {
		return s // already [a-z0-9] only: no copy (the matcher normalises NVD names that mostly are)
	}
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func normalised(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// NormKey is the normalised identity of a vendor and product: Norm(vendor) + "|" + Norm(product) ("Palo Alto Networks",
// "PAN-OS" is "paloaltonetworks|panos").
func NormKey(vendor, product string) string { return Norm(vendor) + "|" + Norm(product) }

// companyWords are the words a vendor's legal name adds to the name a list writes without them ("Progress Software Corporation"
// is "Progress", "Juniper Networks" is "Juniper").
var companyWords = map[string]bool{
	"inc": true, "incorporated": true, "corp": true, "corporation": true, "co": true, "company": true, "ltd": true,
	"limited": true, "llc": true, "gmbh": true, "ag": true, "se": true, "sa": true, "plc": true, "software": true,
	"foundation": true, "technologies": true, "technology": true, "systems": true, "networks": true,
}

// NormVendor is a vendor without its trailing company words, normalised: "Progress Software Corporation" is "progress".
func NormVendor(s string) string {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') })
	for len(words) > 1 && companyWords[words[len(words)-1]] {
		words = words[:len(words)-1]
	}
	return strings.Join(words, "")
}

// NormProduct is a product normalised, without the vendor's name in front: "Apache HTTP Server" of "Apache Software Foundation"
// and "HTTP Server" of "Apache" are both "httpserver".
func NormProduct(product, vendor string) string {
	p := Norm(product)
	for _, v := range []string{NormVendor(vendor), Norm(vendor)} {
		if v != "" && len(p) > len(v) && strings.HasPrefix(p, v) {
			return p[len(v):]
		}
	}
	return p
}

// NormalizeKey is a "vendor|product" key in Key's form: "Microsoft | Windows" is "microsoft|windows".
func NormalizeKey(key string) string {
	v, p, _ := strings.Cut(key, "|")
	return Key(v, p)
}

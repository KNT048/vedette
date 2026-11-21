package findings

import (
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// cpeAliases maps the identity of an inventory product (its vendor and product, or another name the catalogue gives it) to the
// NVD CPE products that name the same thing: "Apple iOS" is "apple:iphone_os" and "apple:ipados" in NVD, "GNU Bash" is "gnu:bash",
// Temurin and Oracle's JDK are one Java, so without this the version of an iPhone, of bash or of a JDK is never compared with the
// ranges. The data is the product catalogue of core/productid (content/catalog/products). A prefix name matches every product
// starting with it ("f5:big-ip_*").
var cpeAliases = loadAliases(productid.Products())

func loadAliases(products []productid.Product) map[identity][]identity {
	out := map[identity][]identity{}
	for _, p := range products {
		var ids []identity
		for _, c := range p.CPEs {
			if id := (identity{vendor: productid.Norm(c.Vendor), product: productid.Norm(c.Product), prefix: c.Prefix}); id.ok() {
				ids = append(ids, id)
			}
		}
		own := identity{vendor: productid.Norm(p.Vendor), product: productid.Norm(p.Product)}
		if len(ids) == 0 { // a product NVD has no name for: its other names are its own name (a CVE record names it so, MatchName)
			if !own.ok() || len(p.Also) == 0 {
				continue
			}
			ids = []identity{own}
		}
		names := [][2]string{{p.Vendor, p.Product}}
		for _, a := range p.Also {
			v, pr, _ := strings.Cut(a, "|")
			names = append(names, [2]string{v, pr})
		}
		for _, n := range names {
			if key := (identity{vendor: productid.Norm(n[0]), product: productid.Norm(n[1])}); key.ok() {
				if _, taken := out[key]; !taken {
					out[key] = ids
				}
			}
		}
	}
	return out
}

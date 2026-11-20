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
		if len(ids) == 0 {
			continue
		}
		names := append([]string{p.Vendor + "|" + p.Product}, p.Also...)
		for _, n := range names {
			v, pr, _ := strings.Cut(n, "|")
			if key := (identity{vendor: productid.Norm(v), product: productid.Norm(pr)}); key.ok() {
				if _, taken := out[key]; !taken {
					out[key] = ids
				}
			}
		}
	}
	return out
}

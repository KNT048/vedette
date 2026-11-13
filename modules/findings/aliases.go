package findings

import (
	"encoding/json"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// cpeAliases maps the identity of an inventory product (vendor and product as the catalog and the osquery
// package map store them) to the NVD CPE products that name the same thing (D-500): "Apple iOS" is
// "apple:iphone_os" and "apple:ipados" in NVD, "GNU Bash" is "gnu:bash", so without this the version of an
// iPhone or of bash is never compared with the ranges. The data is content/catalog/nvd-cpe.json (D-58:
// knowledge about products is data). A trailing "*" in the product matches a prefix ("f5:big-ip_*").
var cpeAliases, cpeAliasErr = loadAliases(catalogdata.NVDCPE)

func loadAliases(data []byte) (map[identity][]identity, error) {
	var rows map[string]json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil {
		return map[identity][]identity{}, err // TestAliases_DataIsValid fails on it; the matcher only loses aliases
	}
	out := map[identity][]identity{}
	for k, raw := range rows {
		vendor, product, ok := strings.Cut(k, "|")
		if !ok {
			continue // "_about"
		}
		var cpes []string
		if err := json.Unmarshal(raw, &cpes); err != nil {
			return out, err
		}
		key := identity{vendor: norm(vendor), product: norm(product)}
		for _, a := range cpes {
			v, p, ok := strings.Cut(a, ":")
			if !ok {
				continue
			}
			id := identity{vendor: norm(v), product: norm(strings.TrimSuffix(p, "*")), prefix: strings.HasSuffix(p, "*")}
			if key.ok() && id.ok() {
				out[key] = append(out[key], id)
			}
		}
	}
	return out, nil
}

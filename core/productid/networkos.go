package productid

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// The operating systems network gear states about itself (content/catalog/network-os.json: Junos, FortiOS, Cisco IOS XE and IOS,
// RouterOS): each is a product of the catalogue, so the OS a device states is a software line like any other, with the product's
// exploited-list keys and its NVD name.

// netOS is one row of network-os.json.
type netOS struct {
	Display   string   `json:"display"`
	Vendor    string   `json:"vendor"`
	Product   string   `json:"product"`
	CPE       string   `json:"cpe"`
	Statement string   `json:"statement"`
	LLDPOUI   string   `json:"lldp_oui"`
	Scheme    string   `json:"scheme"`
	KevKeys   []string `json:"kev_keys"`
	re        *regexp.Regexp
	key       string
}

var netOSRows = mustNetOS(catalogdata.NetworkOS)

func mustNetOS(data []byte) []netOS {
	rows, err := loadNetOS(cat, data)
	if err != nil {
		panic("productid: network-os.json: " + err.Error()) // embedded data; TestStatedOS_Loads names the fault
	}
	return rows
}

// loadNetOS reads the rows and makes each one's product known to c by its key: a product the catalogue lists takes the row's
// exploited-list keys and NVD name; any other becomes a product of its own.
func loadNetOS(c *catalogue, data []byte) ([]netOS, error) {
	var f struct {
		OS []netOS `json:"os"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	for i := range f.OS {
		r := &f.OS[i]
		re, err := regexp.Compile(r.Statement)
		if err != nil || re.NumSubexp() < 1 {
			return nil, fmt.Errorf("%q: the statement must compile with the version as group 1", r.Display)
		}
		if !cpeRE.MatchString(r.CPE) || r.Display == "" || r.Vendor == "" || r.Product == "" || len(r.KevKeys) == 0 {
			return nil, fmt.Errorf("%q: display, vendor, product, cpe and kev_keys are required", r.Display)
		}
		r.re, r.key = re, Key(r.Vendor, r.Product)
		f3 := strings.SplitN(r.CPE, ":", 3)
		e, ok := c.byKey[r.key]
		if !ok {
			e = &entry{p: Product{ID: "network-os-" + strings.Trim(slugRE.ReplaceAllString(strings.ToLower(r.Display), "-"), "-"), Display: r.Display,
				Vendor: r.Vendor, Product: r.Product, Key: r.key, KEV: []string{r.key}}}
			c.byKey[r.key] = e
		}
		for _, k := range r.KevKeys {
			if k = NormalizeKey(k); !slices.Contains(e.p.KEV, k) {
				e.p.KEV = append(e.p.KEV, k)
			}
		}
		if n := (CPEName{Part: f3[0], Vendor: f3[1], Product: f3[2]}); !slices.Contains(e.p.CPEs, n) {
			e.p.CPEs = append(e.p.CPEs, n)
		}
	}
	return f.OS, nil
}

// StatedOS reads the operating system a network device states (its SNMP system description, or for some its LLDP description, as
// the inventory records it: "JUNOS 15.1R7.9", "FortiOS 7.0.1"): the product, the version the statement gives, and the IEEE vendor
// whose network card must carry an LLDP statement of it ("" when only an SNMP answer counts). ok is false when no row reads it.
// The first row whose statement matches decides.
func StatedOS(text string) (p Product, version, lldpVendor string, ok bool) {
	if len(text) > maxName {
		return Product{}, "", "", false
	}
	for _, r := range netOSRows {
		m := r.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		e := cat.byKey[r.key]
		p = e.p
		p.Display = r.Display
		return p, m[1], r.LLDPOUI, true
	}
	return Product{}, "", "", false
}

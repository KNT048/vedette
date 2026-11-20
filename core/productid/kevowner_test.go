package productid

import (
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// An item named by an exploited-list name (a person picks "Cisco Identity Services Engine" in the add-software list, a scan's CPE
// keys) lands on another product's line only when that product names it: its own key, a name its catalogue entry lists (products
// files, network OS rows) or one of its own names (ownName). A broad picker row that a fragment gave many names ("RV series
// routers", "D-Link routers") never takes an item that is not it. Count test: the exploited-list names that move to a product that
// does not name them (85 before the rule, 0 after).
func TestByKEV_MovesANameOnlyToAProductThatNamesIt(t *testing.T) {
	t.Parallel()
	listed := map[string]map[string]bool{} // product key -> the names its catalogue entry lists
	names, err := fs.Glob(catalogdata.Products, "products/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		b, err := fs.ReadFile(catalogdata.Products, n)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Products []struct {
				Vendor, Product string
				KEV             []string `json:"kev"`
			}
		}
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		for _, p := range f.Products {
			k := Key(p.Vendor, p.Product)
			listed[k] = map[string]bool{}
			for _, n := range p.KEV {
				listed[k][n] = true
			}
		}
	}
	for _, r := range netOSRows {
		if listed[r.key] == nil {
			listed[r.key] = map[string]bool{}
		}
		for _, n := range r.KevKeys {
			listed[r.key][NormalizeKey(n)] = true
		}
	}
	var kev []struct{ Vendor, Product string }
	if err := json.Unmarshal(catalogdata.KEVProducts, &kev); err != nil {
		t.Fatal(err)
	}
	var wrong []string
	for _, k := range kev {
		key := Key(k.Vendor, k.Product)
		q, ok := ByKEV(key)
		if !ok || q.Key == key {
			continue
		}
		if listed[q.Key][key] || ownName(q.Product, q.Vendor, k.Product) && listed[q.Key] != nil {
			continue
		}
		wrong = append(wrong, key+" -> "+q.Key)
	}
	slices.Sort(wrong)
	t.Logf("exploited-list names moved to a product that does not name them: %d", len(wrong))
	if len(wrong) > 0 {
		t.Errorf("%d names move to the wrong product:\n  %s", len(wrong), strings.Join(wrong, "\n  "))
	}
}

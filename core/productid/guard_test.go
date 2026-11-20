package productid

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// keyByHand is a vendor|product key or a name normalisation written outside this package.
var keyByHand = regexp.MustCompile(`(?m)ToLower\([^)]*[Vv]endor[^)]*\)\s*\+\s*"\|"|` + // strings.ToLower(vendor) + "|" + …
	`ToLower\([^)]*[Vv]endor\s*\+\s*"\|"|` + // strings.ToLower(vendor + "|" + product)
	`[Vv]endor\)?\s*\+\s*"\|"\s*\+\s*[\w.(]*[Pp]roduct|` + // vendor + "|" + product
	`[Vv]endor\)?\s*\+\s*"\|"\s*$|` + // a vendor prefix: lower(vendor) + "|"
	`^func (norm|normKey|cnaVendorKey|cnaProductKey|ProductKey|KevKey|NormalizeKevKey)\(`)

// Only this package builds a product key or normalises a product name; every other package calls Key, Norm, NormVendor or
// NormProduct.
func TestOnlyThisPackageKeysProducts(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{"../../modules", "../../cmd", "../../core"} {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.Contains(p, "core/productid") {
				return err
			}
			b, err := os.ReadFile(p) //nolint:gosec // G304: a source file of this repository found by the walk
			if err != nil {
				return err
			}
			if m := keyByHand.Find(b); m != nil {
				t.Errorf("%s builds a product key by hand (%q): use core/productid", p, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

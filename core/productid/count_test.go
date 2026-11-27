package productid

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"testing"
)

type inventoryRow struct {
	Source, Vendor, Product, Display, Version, CPE string
	PkgSource                                      string `json:"pkg_source"`
	Packaged                                       bool
}

// resolveRow is how a stored software row resolves: the row, then a package's source package (the agent maps a binary package
// by its source package's name when its own is not listed).
func resolveRow(r inventoryRow) (Product, bool) {
	p, ok := ResolveStored(r.Vendor, r.Product, r.Display, r.CPE)
	if !ok && r.Packaged && r.PkgSource != "" {
		p, ok = Resolve(Linux, r.PkgSource, "", "")
	}
	return p, ok
}

// maxUnresolved is the number of distinct software names of the test inventory that resolve to no product with an NVD name
// (vendor, product and shown name). It may only go down: a catalogue change that leaves more names unresolved fails here.
// Before this package (commit 304c96663, where a name was tied to an NVD product only by a stored CPE, an alias of
// content/catalog/nvd-cpe.json, a curated or network-OS entry with a CPE, or a pair of modules/agent-intake/pkgmap.json) the
// same fixture left 1,526 distinct names (2,393 rows); the pull request that added this test shows the script. 13 of them are the
// .NET host and host resolver entries ("Microsoft .NET Host FX Resolver - 6.0.16 (x64)"), on purpose: they are not the runtime, and
// their version is that of a runtime that may be gone.
const maxUnresolved = 1304

var jdkName = regexp.MustCompile(`(?i)\b(?:jdk|jre|openjdk|temurin|corretto|zulu|liberica|semeru|java\(tm\)|java \d+ update|java se)\b`)

// TestUnresolvedNames counts the software names of an anonymised test inventory that resolve to no product with an NVD name, and
// checks that every JDK resolves to the one OpenJDK family. Run with -v to list the names that do not resolve.
func TestUnresolvedNames(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/inventory-software.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Rows []inventoryRow }
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var unresolved []string
	rowsLeft, jdks := 0, 0
	for _, r := range f.Rows {
		p, ok := resolveRow(r)
		resolved := ok && p.HasCPE()
		if jdkName.MatchString(r.Display) || jdkName.MatchString(r.Product) {
			jdks++
			if p.ID != "openjdk" {
				t.Errorf("JDK %q (%s) resolves to %q, not the OpenJDK family", r.Display, r.Vendor, p.ID)
			}
		}
		if resolved {
			continue
		}
		rowsLeft++
		name := fmt.Sprintf("%s | %s | %s", r.Vendor, r.Product, r.Display)
		if !seen[name] {
			seen[name] = true
			unresolved = append(unresolved, name)
		}
	}
	slices.Sort(unresolved)
	if testing.Verbose() {
		for _, n := range unresolved {
			t.Log("unresolved:", n)
		}
	}
	t.Logf("%d of %d rows, %d distinct names, do not resolve to a product with an NVD name; %d JDK rows", rowsLeft, len(f.Rows), len(unresolved), jdks)
	if jdks < 2 {
		t.Errorf("the fixture has %d JDK rows; it should have Oracle Java 8 and Temurin 21", jdks)
	}
	if len(unresolved) > maxUnresolved {
		t.Errorf("%d names do not resolve, more than %d", len(unresolved), maxUnresolved)
	}
}

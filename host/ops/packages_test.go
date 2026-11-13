package ops

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// D-470, INV-9: the structure of dpkg-query's output fails closed; a single package whose own fields break dpkg's rules is
// left out and counted, so it cannot hide the rest of the box.
func TestParsePackages(t *testing.T) {
	t.Parallel()
	good := "bash\t5.2.21-2ubuntu4\tamd64\tbash\tinstalled\n"
	list, dropped, err := parsePackages([]byte(good +
		"Old_Vendor_Tool\t1.0\tamd64\tOld_Vendor_Tool\tinstalled\n" + // "_" and upper case: an old third-party name
		"longver\t1." + strings.Repeat("9", 200) + "\tamd64\tlongver\tinstalled\n" + // a version over 128 characters
		"crpkg\t1.0\r\tamd64\tcrpkg\tinstalled\n" + // a CR inside a field
		"man-db\t2.12.0-4build2\tamd64\tman-db\ttriggers-awaited\n" + // dpkg's real spelling: configured, on disk
		"Removed_Old\t1.0\tamd64\tx\tconfig-files\n")) // not on disk: skipped before any check, not counted
	if err != nil || dropped != 3 || len(list) != 2 || list[0].Name != "bash" || list[1].Name != "man-db" {
		t.Fatalf("list %+v, dropped %d, err %v; want bash and man-db, 3 dropped", list, dropped, err)
	}
	// A package half-way through dpkg (apt running, or an interrupted run): no list, a retryable error.
	for _, st := range []string{"half-installed", "unpacked", "half-configured"} {
		if list, _, err := parsePackages([]byte(good + "zsh\t5.9-6\tamd64\tzsh\t" + st + "\n")); !errors.Is(err, errPackagesChanging) {
			t.Errorf("%s: %d packages, err %v; want errPackagesChanging", st, len(list), err)
		}
	}
	// The structure is still checked first: a broken line with a changing package is a plain failure.
	if _, _, err := parsePackages([]byte("zsh\t5.9-6\tamd64\tzsh\tunpacked\nbash\t5.2\n")); err == nil || errors.Is(err, errPackagesChanging) {
		t.Errorf("a broken line next to an unpacked package gave %v", err)
	}
	for name, out := range map[string]string{
		"a tab inside a field": "bash\t5.2\tamd64\tbash\textra\tinstalled\n" + good,
		"a cut last line":      good + "zsh\t5.9-6\tamd",
		"an unknown status":    good + "zsh\t5.9-6\tamd64\tzsh\tgone\n",
		"a misspelt status":    good + "zsh\t5.9-6\tamd64\tzsh\ttriggers-awaiting\n", // not a dpkg status
		"only bad packages":    "Bad_Name\t1.0\tamd64\tx\tinstalled\n",
		"nothing":              "",
	} {
		if list, _, err := parsePackages([]byte(out)); err == nil {
			t.Errorf("%s: %d packages, want an error", name, len(list))
		}
	}
	var b strings.Builder
	for i := range 20001 {
		fmt.Fprintf(&b, "pkg%d\t1.0-1\tamd64\tpkg%d\tinstalled\n", i, i)
	}
	if _, _, err := parsePackages([]byte(b.String())); err == nil {
		t.Error("more than MaxPackages installed packages were accepted")
	}
}

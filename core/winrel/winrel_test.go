package winrel

import (
	"strings"
	"testing"
)

// One release per build and kind, one per NVD name, every line the first build of a client release of the table, and a
// server release never on a client line.
func TestReleasesTable(t *testing.T) {
	seen, names := map[[2]int]bool{}, map[string]bool{}
	for _, r := range releases {
		kind := 0
		if r.Server {
			kind = 1
		}
		if seen[[2]int{r.Build, kind}] || names[r.Product] {
			t.Errorf("%+v: twice", r)
		}
		seen[[2]int{r.Build, kind}], names[r.Product] = true, true
		if !strings.HasPrefix(r.Product, "windows_") || r.Product != strings.ToLower(r.Product) || r.Build < 10240 || r.Build > 99999 || r.GA.IsZero() {
			t.Errorf("%+v", r)
		}
		first, ok := ByBuild(r.Line, r.Server)
		if !ok || first.Line != r.Line || r.Server && r.Line != r.Build {
			t.Errorf("%s: line %d", r.Product, r.Line)
		}
		if got, ok := ByProduct(r.Product); !ok || got != r {
			t.Errorf("ByProduct(%s): %+v", r.Product, got)
		}
	}
	if r, ok := ByBuild(26200, false); !ok || r.Product != "windows_11_25h2" || r.Line != 26100 {
		t.Errorf("25H2: %+v", r)
	}
	if r, _ := ByBuild(26100, false); r.GARev != 1742 || r.LastFreeRev != 0 {
		t.Errorf("24H2 revisions: %+v", r)
	}
	if r, _ := ByBuild(19045, false); r.LastFreeRev <= r.GARev {
		t.Errorf("10 22H2 revisions: %+v", r)
	}
	if r, ok := ByBuild(26100, true); !ok || r.Product != "windows_server_2025" || r.Line != 26100 {
		t.Errorf("Server 2025: %+v", r)
	}
	if _, ok := ByBuild(20348, false); ok {
		t.Error("20348 is a server build only")
	}
}

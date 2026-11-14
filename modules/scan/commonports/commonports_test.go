package commonports

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The list is fixed and documented (D-229): no port twice, ascending (nmap's -p names them in this order, D-514), about a hundred,
// every number a TCP port.
func TestList(t *testing.T) {
	t.Parallel()
	n := Numbers()
	if len(n) < 80 || len(n) > 110 || !slices.IsSorted(n) || len(slices.Compact(slices.Clone(n))) != len(n) {
		t.Fatalf("%d ports, sorted %v, distinct %d", len(n), slices.IsSorted(n), len(slices.Compact(slices.Clone(n))))
	}
	for _, p := range List {
		if p.Number < 1 || p.Number > 65535 || p.Service == "" {
			t.Errorf("bad entry %+v", p)
		}
	}
}

// The sensor binary links this package through nmapargv: it imports nothing.
func TestIsALeaf(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		if len(af.Imports) != 0 {
			t.Errorf("%s imports something: commonports imports nothing", f)
		}
	}
}

// D-523: nmap's top 1000 is exactly 1000 distinct ports, ascending; LAN is that plus List, without the OT ports, ascending,
// each once, and bounded (the probe log keeps the whole -p list).
func TestLAN(t *testing.T) {
	t.Parallel()
	top := NmapTop1000
	if len(top) != 1000 || !slices.IsSorted(top) || len(slices.Compact(slices.Clone(top))) != 1000 || top[0] < 1 || top[999] > 65535 {
		t.Fatalf("NmapTop1000: %d ports, sorted %v", len(top), slices.IsSorted(top))
	}
	// Spot checks against nmap's published ranking: the ends of the list and ports any top-1000 run names.
	for _, n := range []int{1, 22, 80, 443, 445, 3389, 8080, 65389} {
		if _, ok := slices.BinarySearch(top, n); !ok {
			t.Errorf("%d is not in NmapTop1000", n)
		}
	}
	lan := LAN()
	if len(lan) < 1000 || len(lan) > 1100 || !slices.IsSorted(lan) || len(slices.Compact(slices.Clone(lan))) != len(lan) {
		t.Fatalf("LAN: %d ports, sorted %v", len(lan), slices.IsSorted(lan))
	}
	has := func(n int) bool { _, ok := slices.BinarySearch(lan, n); return ok }
	for _, n := range top {
		if !has(n) {
			t.Errorf("LAN lacks %d of nmap's top 1000", n)
		}
	}
	for _, p := range List {
		if slices.Contains(otPorts, p.Number) == has(p.Number) {
			t.Errorf("port %d (%s): in LAN %v, an OT port %v", p.Number, p.Service, has(p.Number), slices.Contains(otPorts, p.Number))
		}
	}
	for _, n := range otPorts {
		if !slices.ContainsFunc(List, func(p Port) bool { return p.Number == n }) {
			t.Errorf("OT port %d is not in List: drop it from otPorts", n)
		}
	}
}

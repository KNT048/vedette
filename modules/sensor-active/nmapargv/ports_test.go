package nmapargv

import (
	"slices"
	"testing"

	"github.com/knt048/vedette/modules/scan/commonports"
)

// D-592: the Extra run after a normal or versions scan reads the surface list and the reviewed admin ports; the N100's SSH on
// 22222 and the deep-scan-only 10443, 11080, 11443 are in it; nothing of nmap-services is copied (the normal shape keeps
// --top-ports 1000).
func TestExtraPorts(t *testing.T) {
	t.Parallel()
	ns := ExtraPortNumbers
	if !slices.IsSorted(ns) || len(slices.Compact(slices.Clone(ns))) != len(ns) || ns[0] < 1 || ns[len(ns)-1] > 65535 {
		t.Fatal("ExtraPortNumbers is not ascending, distinct ports")
	}
	for _, n := range append([]int{22222, 10022, 10443, 11080, 11443, 9443, 5985, 5986, 8443, 16992, 61616}, commonports.Numbers()...) {
		if _, ok := slices.BinarySearch(ns, n); !ok {
			t.Errorf("port %d is not scanned", n)
		}
	}
	seen := map[int]bool{}
	for _, p := range AdminPortList {
		if p.Number < 1 || p.Number > 65535 || len(p.Why) < 10 || seen[p.Number] {
			t.Errorf("admin port %+v: out of range, no reason, or listed twice", p)
		}
		seen[p.Number] = true
	}
	if len(ns) > 200 {
		t.Fatalf("%d extra ports: each one is one more SYN to every device of every scan", len(ns))
	}
	if f, err := Flags(Normal, 100); err != nil || !slices.Contains(f, "--top-ports") || slices.Contains(f, "-p") {
		t.Fatalf("normal flags %q %v", f, err)
	}
	if f, err := Flags(Extra, 100); err != nil || !slices.Contains(f, ExtraPorts) || slices.Contains(f, "-O") {
		t.Fatalf("extra flags %q %v", f, err)
	}
	if got := rangesOf([]int{1, 2, 3, 5, 7, 8}); got != "1-3,5,7-8" {
		t.Fatalf("rangesOf = %q", got)
	}
}

// D-592: the weekly scan of every port: -p-, no -O, the four reviewed scripts, at most AllPortsMaxRate, one retry, 90 minutes.
func TestAllPortsShape(t *testing.T) {
	t.Parallel()
	got, err := Build(AllPorts, 100, nil)
	if err == nil {
		t.Fatalf("no target accepted: %q", got)
	}
	if _, err := Flags(AllPorts, AllPortsMaxRate+1); err == nil {
		t.Fatal("a rate over AllPortsMaxRate was accepted")
	}
	f, err := Flags(AllPorts, 60)
	want := []string{"--privileged", "-sS", "-sV", "--script", Scripts, "-n", "--max-rate", "60", "--max-retries", "1", "-p-", "--host-timeout", "90m"}
	if err != nil || !slices.Equal(f, want) {
		t.Fatalf("flags = %q %v", f, err)
	}
	if k, ok := KindOf("all_ports"); !ok || k != AllPorts || k.IsGentle() || k.IsExternal() {
		t.Fatalf("KindOf(all_ports) = %v %v", k, ok)
	}
}

package nmapargv

import (
	"net/netip"
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

// D-592 (review r1 H2): the weekly scan is port discovery only: -p-, no -sV, no script, no -O, at most AllPortsMaxRate, one retry,
// 90 minutes. Its follow-up reads at most MaxPortVersions ascending ports with -sV and the four scripts, on one target.
func TestAllPortsShape(t *testing.T) {
	t.Parallel()
	if _, err := Flags(AllPorts, AllPortsMaxRate+1); err == nil {
		t.Fatal("a rate over AllPortsMaxRate was accepted")
	}
	f, err := Flags(AllPorts, 60)
	want := []string{"--privileged", "-sS", "-n", "--max-rate", "60", "--max-retries", "1", "-p-", "--host-timeout", "90m"}
	if err != nil || !slices.Equal(f, want) {
		t.Fatalf("flags = %q %v", f, err)
	}
	if k, ok := KindOf("all_ports"); !ok || k != AllPorts || k.IsGentle() || k.IsExternal() {
		t.Fatalf("KindOf(all_ports) = %v %v", k, ok)
	}
	ip := netip.MustParseAddr("192.168.10.20")
	argv, err := BuildFor(PortVersions, 50, []int{22222, 40000}, []netip.Addr{ip})
	if err != nil || Validate(argv) != nil || !slices.Contains(argv, "22222,40000") || !slices.Contains(argv, "-sV") || slices.Contains(argv, "-O") {
		t.Fatalf("port_versions argv %q %v", argv, err)
	}
	k, rate, ports, targets, err := ParseFor(argv)
	if err != nil || k != PortVersions || rate != 50 || !slices.Equal(ports, []int{22222, 40000}) || len(targets) != 1 {
		t.Fatalf("ParseFor = %v %d %v %v %v", k, rate, ports, targets, err)
	}
	many := make([]int, MaxPortVersions+1)
	for i := range many {
		many[i] = i + 1
	}
	for name, ps := range map[string][]int{"none": nil, "too many": many, "unsorted": {80, 22}, "zero": {0}, "two targets": {22}} {
		ts := []netip.Addr{ip}
		if name == "two targets" {
			ts = append(ts, netip.MustParseAddr("192.168.10.21"))
		}
		if _, err := BuildFor(PortVersions, 50, ps, ts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := BuildFor(Normal, 50, []int{22}, []netip.Addr{ip}); err == nil {
		t.Error("a port list on the normal shape was accepted")
	}
	if k, ok := KindOf("port_versions"); !ok || k != PortVersions {
		t.Fatalf("KindOf(port_versions) = %v %v", k, ok)
	}
}

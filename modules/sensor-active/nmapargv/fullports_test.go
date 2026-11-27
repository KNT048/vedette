package nmapargv

import (
	"slices"
	"testing"
)

// The deep scan's port scan is a port scan only: every TCP port, half-open, no -sV, no script, no -O, at the full shapes' rate,
// bounded by its own host timeout. It is a full shape: the deep-scan fences and the worker's full capability apply to it.
func TestFullPortsShapeIsAPortScanOnly(t *testing.T) {
	t.Parallel()
	want := []string{"--privileged", "-sS", "-Pn", "-n", "-p-", "--max-rate", "300", "--max-retries", "2", "--host-timeout", "36m",
		"--stats-every", "5s", "-oX", "-", "8.8.8.8"}
	got, err := Build(ExternalFullPorts, FullRate, oneIP)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("argv = %q %v\nwant   %q", got, err, want)
	}
	if k, ok := KindOf("external_full_ports"); !ok || k != ExternalFullPorts || !k.IsFull() || !k.IsExternal() || ExternalRateOf(k) != FullRate {
		t.Fatalf("KindOf = %v %v", k, ok)
	}
	if k, rate, ports, n, _, err := ParseNarrow(got); err != nil || k != ExternalFullPorts || rate != FullRate || ports != nil || !n.wide() {
		t.Fatalf("ParseNarrow = %v %d %v %+v %v", k, rate, ports, n, err)
	}
	gentle, err := BuildNarrow(ExternalFullPorts, GentleRate, nil, Wide(), oneIP)
	if err != nil || gentle[slices.Index(gentle, "--max-rate")+1] != "100" || Validate(gentle) != nil {
		t.Fatalf("the gentle port scan: %q %v", gentle, err)
	}
	skipped, err := BuildNarrow(ExternalFullPorts, FullRate, nil, Narrow{Groups: AllGroups, SkipPorts: []int{25, 445}}, oneIP)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(skipped, "--exclude-ports"); i < 0 || skipped[i+1] != "25,445" {
		t.Fatalf("the port scan does not skip the target's ports: %q", skipped)
	}
	if _, _, _, n, _, err := ParseNarrow(skipped); err != nil || !slices.Equal(n.SkipPorts, []int{25, 445}) {
		t.Fatalf("ParseNarrow of the skipping port scan: %+v %v", n, err)
	}
	for name, c := range map[string]struct {
		rate  int
		ports []int
		n     Narrow
	}{
		"another rate": {ExternalRate * 2, nil, Wide()},
		"a port list":  {FullRate, []int{22}, Wide()},
		"a group off":  {FullRate, nil, Narrow{Groups: GroupDoS}},
	} {
		if a, err := BuildNarrow(ExternalFullPorts, c.rate, c.ports, c.n, oneIP); err == nil {
			t.Errorf("BuildNarrow accepted %s: %q", name, a)
		}
	}
	if _, err := Build(ExternalFullPorts, FullRate, addrs(t, "192.168.1.1")); err == nil {
		t.Error("the port scan took a LAN target")
	}
	for name, argv := range map[string][]string{
		"with -sV":      append(slices.Clone(got[:2]), append([]string{"-sV"}, got[2:]...)...),
		"with a script": append(slices.Clone(got[:5]), append([]string{"--script", "banner"}, got[5:]...)...),
		"a longer wait": func() []string { a := slices.Clone(got); a[slices.Index(a, "--host-timeout")+1] = "60m"; return a }(),
	} {
		if err := Validate(argv); err == nil {
			t.Errorf("Validate accepted the port scan %s: %q", name, argv)
		}
	}
}

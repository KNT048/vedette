package nmapargv

import (
	"slices"
	"strings"
	"testing"
)

// A deep scan runs in two nmap lines: the port scan of every TCP port (ExternalFullPorts: no -sV, no script), then -sV and the
// scripts on the open ports it found (ExternalFull with a -p list). The second line never sweeps every port again.
func TestFullRunReadsOnlyTheOpenPortsTheSweepFound(t *testing.T) {
	t.Parallel()
	open := []int{22, 443, 8443}
	got, err := BuildNarrow(ExternalFull, FullRate, open, Wide(), oneIP)
	if err != nil {
		t.Fatalf("the full line on the sweep's 3 open ports: %v", err)
	}
	if slices.Contains(got, "-p-") {
		t.Fatalf("the full line on the open ports sweeps every port again: %q", got)
	}
	if i := slices.Index(got, "-p"); i < 0 || got[i+1] != "22,443,8443" {
		t.Fatalf("the full line does not name the open ports: %q", got)
	}
	if scriptOf(got) != FullScripts || !slices.Contains(got, "-sV") || !slices.Contains(got, "--version-all") {
		t.Fatalf("the full line lost its scripts or -sV: %q", got)
	}
	if i := slices.Index(got, "--host-timeout"); i < 0 || got[i+1] != "30m" {
		t.Fatalf("the full line on the open ports has host timeout %q, want 30m", got[i+1])
	}
	if err := Validate(got); err != nil {
		t.Fatalf("Validate refuses the full line on the open ports: %v", err)
	}
	k, rate, ports, n, _, err := ParseNarrow(got)
	if err != nil || k != ExternalFull || rate != FullRate || !slices.Equal(ports, open) || !n.wide() {
		t.Fatalf("ParseNarrow = %v %d %v %+v %v", k, rate, ports, n, err)
	}
	if k, _, ps, _, err := ParseFor(got); err != nil || k != ExternalFull || !slices.Equal(ps, open) {
		t.Fatalf("ParseFor = %v %v %v", k, ps, err)
	}
	if again, err := BuildFor(ExternalFull, FullRate, open, oneIP); err != nil || !slices.Equal(again, got) {
		t.Fatalf("BuildFor = %q %v", again, err)
	}

	// The gentle speed drops --version-all here too; the target's skipped ports stay named in --exclude-ports, so the scripts that
	// follow another service's answer stay out, and a skipped port is never in the list.
	gentle, err := BuildNarrow(ExternalFull, GentleRate, open, Wide(), oneIP)
	if err != nil || slices.Contains(gentle, "--version-all") || Validate(gentle) != nil {
		t.Fatalf("the gentle line on the open ports: %q %v", gentle, err)
	}
	skip := Narrow{Groups: GroupLogins | GroupChange, SkipPorts: []int{25}}
	narrowed, err := BuildNarrow(ExternalFull, FullRate, open, skip, oneIP)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(narrowed, "--exclude-ports"); i < 0 || narrowed[i+1] != "25" {
		t.Fatalf("the narrowed line does not skip 25: %q", narrowed)
	}
	for s := range followScripts {
		if strings.Contains(","+scriptOf(narrowed)+",", ","+s+",") {
			t.Errorf("the narrowed line keeps %s, which follows another service's answer", s)
		}
	}
	if k, _, ps, n, _, err := ParseNarrow(narrowed); err != nil || k != ExternalFull || !slices.Equal(ps, open) || !slices.Equal(n.SkipPorts, []int{25}) || n.Groups != skip.Groups {
		t.Fatalf("ParseNarrow of the narrowed line = %v %v %+v %v", k, ps, n, err)
	}

	forty := make([]int, 41)
	for i := range forty {
		forty[i] = 1000 + i
	}
	for name, c := range map[string]struct {
		ports []int
		n     Narrow
	}{
		"41 ports":        {forty, Wide()},
		"unsorted ports":  {[]int{443, 22}, Wide()},
		"a skipped port":  {[]int{22, 25}, Narrow{Groups: AllGroups, SkipPorts: []int{25}}},
		"port 0":          {[]int{0, 22}, Wide()},
		"a port too high": {[]int{22, 65536}, Wide()},
		"a repeated port": {[]int{22, 22}, Wide()},
		"unknown groups":  {[]int{22}, Narrow{Groups: AllGroups + 1}},
	} {
		if a, err := BuildNarrow(ExternalFull, FullRate, c.ports, c.n, oneIP); err == nil {
			t.Errorf("BuildNarrow accepted %s: %q", name, a)
		}
	}
	set := func(i int, v string) []string { a := slices.Clone(got); a[i] = v; return a }
	at := func(flag string) int { return slices.Index(got, flag) + 1 }
	for name, argv := range map[string][]string{
		"every port as a range":   set(at("-p"), "1-65535"),
		"the sweep's host bound":  set(at("--host-timeout"), "60m"),
		"the disruptive scripts":  set(at("--script"), DisruptiveScripts),
		"a range in the list":     set(at("-p"), "22,443-445"),
		"another rate":            set(at("--max-rate"), "1000"),
		"a LAN target":            set(len(got)-1, "192.168.10.1"),
		"the list and every port": append(append(slices.Clone(got[:at("-p")+1]), "-p-"), got[at("-p")+1:]...),
	} {
		if err := Validate(argv); err == nil {
			t.Errorf("Validate accepted %s: %q", name, argv)
		}
	}
}

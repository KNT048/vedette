package nmapargv

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"
)

// nse795 reads testdata/nse-7.95-categories.txt: what `nmap --script-help` printed in the scan image for the two category
// expressions the lists were made from (block 0: full, block 1: disruptive), name → categories.
func nse795(t *testing.T) [2]map[string][]string {
	t.Helper()
	f, err := os.Open("testdata/nse-7.95-categories.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [2]map[string][]string
	block := -1
	for sc := bufio.NewScanner(f); sc.Scan(); {
		line := sc.Text()
		if strings.HasPrefix(line, "==") {
			block++
			out[block] = map[string][]string{}
			continue
		}
		if block < 0 { // the "Nmap version" line
			continue
		}
		name, cats, ok := strings.Cut(line, ": ")
		if !ok || block > 1 {
			t.Fatalf("unexpected line %q", line)
		}
		out[block][name] = strings.Fields(cats)
	}
	return out
}

// TestScriptListsAreReviewed (FULL-4, review r1 M2/M3/L5/L6): the two lists are sorted, unique and disjoint; every name is one
// nmap 7.95 resolved for its expression; none is excluded; no excluded name ever enters; every brute script keeps no output.
func TestScriptListsAreReviewed(t *testing.T) {
	t.Parallel()
	nse := nse795(t)
	for name, l := range map[string][]string{"fullScripts": fullScripts, "disruptiveExtra": disruptiveExtra} {
		if !slices.IsSorted(l) || len(slices.Compact(slices.Clone(l))) != len(l) {
			t.Errorf("%s is not sorted and unique", name)
		}
	}
	for _, s := range fullScripts {
		if _, ok := nse[0][s]; !ok {
			t.Errorf("full %s is not in nmap 7.95's (default or safe or vuln) and not (dos or brute or external or broadcast)", s)
		}
		if slices.Contains(disruptiveExtra, s) {
			t.Errorf("%s is in both lists", s)
		}
		if _, ok := disruptiveMoved[s]; ok {
			t.Errorf("%s tries logins or can crash a service, but runs without the tick", s)
		}
	}
	for _, s := range disruptiveExtra {
		if _, ok := nse[1][s]; !ok {
			t.Errorf("disruptive %s is not in nmap 7.95's disruptive expression", s)
		}
	}
	all := slices.Concat(fullScripts, disruptiveExtra)
	for s := range excludedScripts {
		if slices.Contains(all, s) {
			t.Errorf("excluded %s runs", s)
		}
	}
	for s, cats := range nse[1] {
		if slices.Contains(cats, "brute") && slices.Contains(all, s) && StoresOutput(s) {
			t.Errorf("brute script %s keeps its output (it can hold the credentials it found)", s)
		}
	}
	for _, s := range []string{"fcrdns", "ftp-bounce", "ipv6-ra-flood", "dns-update", "http-fileupload-exploiter"} {
		if strings.Contains(","+DisruptiveScripts+",", ","+s+",") {
			t.Errorf("%s is in the disruptive line", s)
		}
	}
	if StoresOutput("supermicro-ipmi-conf") || !StoresOutput("http-title") {
		t.Error("StoresOutput is wrong")
	}
}

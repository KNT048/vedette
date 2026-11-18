package findings

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/nvd-network-os-kev.csv is every NVD affected row of the exploited CVEs that name one of the network OSes of
// network-os.json (Junos, FortiOS, IOS XE, IOS, RouterOS): one row per cpeMatch entry, columns cve, cpe, start_incl, start_excl,
// end_incl, end_excl.
func loadNetworkOSRows(t *testing.T) map[string][]Affected {
	t.Helper()
	b, err := os.ReadFile("testdata/nvd-network-os-kev.csv")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]Affected{}
	for _, r := range recs[1:] {
		out[r[0]] = append(out[r[0]], Affected{CPE: r[1], Range: VersionRange{StartIncl: r[2], StartExcl: r[3], EndIncl: r[4], EndExcl: r[5]}})
	}
	return out
}

// networkOSVulns are the exploited CVEs whose NVD rows name the product of statement (the CPE part "o:juniper:junos"), keyed
// to that product the way CISA keys them.
func networkOSVulns(rows map[string][]Affected, cpe, vendor, product string) []Vuln {
	var out []Vuln
	for _, cve := range slices.Sorted(maps.Keys(rows)) {
		if slices.ContainsFunc(rows[cve], func(af Affected) bool { return strings.HasPrefix(af.CPE, "cpe:2.3:"+cpe+":") }) {
			out = append(out, Vuln{CVE: cve, Vendor: vendor, Product: product, Affected: rows[cve], NVDAnswered: true})
		}
	}
	return out
}

// networkOSOutcome is what the matcher made of one CVE on a device that has a finding for each (have): affected (a finding
// of basis version), not_affected (proved outside), no_finding (ruled out without a proof), or the reason it could not be
// checked ("unchecked:not_comparable").
func networkOSOutcomes(a Asset, vulns []Vuln) map[string]string {
	have := map[string]bool{}
	for _, v := range vulns {
		have[v.CVE] = true
	}
	res := MatchAsset(a, vulns, have, t0)
	out := map[string]string{}
	for _, v := range vulns {
		out[v.CVE] = "no_finding"
	}
	for _, m := range res.NotAffected {
		out[m.CVE] = "not_affected"
	}
	for _, u := range res.Unchecked {
		out[u.CVE] = "unchecked:" + string(u.Reason)
	}
	for _, m := range res.Existing {
		if m.Basis == BasisVersion {
			out[m.CVE] = "affected"
		} else {
			out[m.CVE] = "product_finding"
		}
	}
	return out
}

// The class of "could not be checked: not_comparable" on network gear, measured over every exploited CVE NVD lists for the five
// network OSes, at versions such devices really state. It prints each outcome per version (go test -v), holds a ceiling of
// not_comparable per version (a change that makes more of them fails) and the exact number of findings (a change that loses one,
// a false negative on an exploited CVE, fails too).
//
// What stays not_comparable is what NVD's data does not decide:
//   - Junos 15.1R7.9, CVE-2015-5477: NVD lists "15.1:r", an R release of the device's own release with no number;
//   - Junos 20.4R3-S8 (CVE-2023-36846, -36847) and 22.4R2-S1 (CVE-2023-36844 to -36847): a build after the last one NVD lists
//     on the device's own branch (no finding, no proof: junosListed);
//   - Junos 12.3X48-D10, CVE-2023-36851: NVD lists only releases from 21.2 on, so an older one is not proved outside;
//   - classic Cisco IOS: no order Vedette compares, every one of its CVEs, by design.
func TestNetworkOS_TrainBoundsClass(t *testing.T) {
	t.Parallel()
	rows := loadNetworkOSRows(t)
	products := []struct {
		cpe, vendor, product, statement string
		versions                        []string
	}{
		{"o:juniper:junos", "Juniper", "Junos OS", "JUNOS %s",
			[]string{"12.1R11", "12.3X48-D10", "15.1R7.9", "18.4R3-S1", "20.4R3-S8", "21.2R3", "22.4R2-S1", "23.2R1"}},
		{"o:fortinet:fortios", "Fortinet", "FortiOS", "FortiOS %s", []string{"6.0.4", "6.4.9", "7.0.12", "7.2.13", "7.4.3"}},
		{"o:cisco:ios_xe", "Cisco", "IOS XE Software", "Cisco IOS XE %s", []string{"16.9.4", "17.3.1", "17.9.4a"}},
		{"o:mikrotik:routeros", "MikroTik", "RouterOS", "RouterOS %s", []string{"6.48", "7.12.1"}}, //nolint:misspell // RouterOS is the product name
		{"o:cisco:ios", "Cisco", "IOS", "Cisco IOS %s", []string{"15.2(4)M3"}},
	}
	// Per stated OS: the findings (basis version) it must get, and the most not_comparable outcomes it may have. Before train
	// bounds were decided the same versions had 63 not_comparable (Junos 13, IOS XE 13, IOS 37) and 33 no_nvd_versions.
	want := map[string]struct{ affected, notComparable int }{
		"JUNOS 12.1R11": {6, 0}, "JUNOS 12.3X48-D10": {7, 1}, "JUNOS 15.1R7.9": {6, 1}, "JUNOS 18.4R3-S1": {5, 0},
		"JUNOS 20.4R3-S8": {3, 2}, "JUNOS 21.2R3": {6, 0}, "JUNOS 22.4R2-S1": {2, 4}, "JUNOS 23.2R1": {4, 0},
		"FortiOS 6.0.4": {11, 0}, "FortiOS 6.4.9": {7, 0}, "FortiOS 7.0.12": {9, 0}, "FortiOS 7.2.13": {2, 0}, "FortiOS 7.4.3": {5, 0},
		"Cisco IOS XE 16.9.4": {4, 0}, "Cisco IOS XE 17.3.1": {5, 0}, "Cisco IOS XE 17.9.4a": {2, 0},
		"RouterOS 6.48": {3, 0}, "RouterOS 7.12.1": {3, 0},
		"Cisco IOS 15.2(4)M3": {0, 37}, // not orderable: every CVE that gives a version, by design
	}
	// Outcomes that name the cases this test was written for.
	named := map[[2]string]string{
		{"JUNOS 15.1R7.9", "CVE-2015-5477"}:        "unchecked:not_comparable", // "15.1:r": the device's own release, no number
		{"JUNOS 18.4R3-S1", "CVE-2015-5477"}:       "not_affected",             // after every release NVD lists ("12.1r" too)
		{"JUNOS 23.2R1", "CVE-2015-5477"}:          "not_affected",
		{"Cisco IOS XE 17.3.1", "CVE-2018-0167"}:   "not_affected", // "up to 15.2(6)e0a", "up to 15.6.3m1", "5.2.0.base"
		{"Cisco IOS XE 17.9.4a", "CVE-2023-20273"}: "not_affected", // the fix itself; NVD lists 17.9.4, not 17.9.4a
		{"Cisco IOS XE 17.3.1", "CVE-2023-20273"}:  "affected",
	}
	total := map[string]int{}
	for _, p := range products {
		vulns := networkOSVulns(rows, p.cpe, p.vendor, p.product)
		for _, ver := range p.versions {
			stated := fmt.Sprintf(p.statement, ver)
			got := networkOSOutcomes(snmpDevice("d", stated), vulns)
			count := map[string]int{}
			var nc []string
			for _, cve := range slices.Sorted(maps.Keys(got)) {
				count[got[cve]]++
				total[got[cve]]++
				if got[cve] == "unchecked:"+string(UncheckedNotComparable) {
					nc = append(nc, cve)
				}
			}
			var parts []string
			for _, k := range slices.Sorted(maps.Keys(count)) {
				parts = append(parts, fmt.Sprintf("%s=%d", k, count[k]))
			}
			t.Logf("%-22s %d CVEs: %s", stated, len(vulns), strings.Join(parts, " "))
			if len(nc) > 0 && len(nc) < 40 {
				t.Logf("%-22s not_comparable: %s", "", strings.Join(nc, " "))
			}
			w, ok := want[stated]
			if !ok || len(nc) > w.notComparable || count["affected"] != w.affected {
				t.Errorf("%s: %d not_comparable (ceiling %d), %d affected (want %d)", stated, len(nc), w.notComparable, count["affected"], w.affected)
			}
			for k, o := range named {
				if k[0] == stated && got[k[1]] != o {
					t.Errorf("%s, %s: %s, want %s", stated, k[1], got[k[1]], o)
				}
			}
		}
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(total)) {
		parts = append(parts, fmt.Sprintf("%s=%d", k, total[k]))
	}
	t.Logf("all versions: %s", strings.Join(parts, " "))
}

// A Junos row or bound in a form the scheme does not read is still of its release: on another release than the device's it is a
// No, on the device's own release it stays Unknown (it may name the device's train with no build to compare).
func TestJunos_UnreadableFormOfAnotherRelease(t *testing.T) {
	t.Parallel()
	all := "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*"
	for _, tc := range []struct {
		cpe  string
		r    VersionRange
		ver  string
		want Tri
	}{
		{"cpe:2.3:o:juniper:junos:12.1r:*:*:*:*:*:*:*", VersionRange{}, "15.1R7.9", No},
		{"cpe:2.3:o:juniper:junos:12.1r:*:*:*:*:*:*:*", VersionRange{}, "12.3X48-D10", No},
		{"cpe:2.3:o:juniper:junos:12.1r:*:*:*:*:*:*:*", VersionRange{}, "12.1R11", Unknown}, // its own release
		{"cpe:2.3:o:juniper:junos:15.1r7:*:*:*:*:*:*:*", VersionRange{}, "15.1R7.9", Unknown},
		{"cpe:2.3:o:juniper:junos:15.1:r:*:*:*:*:*:*", VersionRange{}, "15.1R7.9", Unknown},   // an R release of 15.1, no number
		{"cpe:2.3:o:juniper:junos:12.1.3:*:*:*:*:*:*:*", VersionRange{}, "15.1R7.9", Unknown}, // not a Junos release at all
		{all, VersionRange{EndExcl: "12.1r5.4.2"}, "15.1R7.9", No},
		{all, VersionRange{EndExcl: "15.1r5.4.2"}, "15.1R7.9", Unknown},
		{all, VersionRange{StartIncl: "12.1r5.4.2"}, "15.1R7.9", Yes},
		{all, VersionRange{StartIncl: "12.1"}, "15.1R7.9", Yes},
		{all, VersionRange{EndExcl: "12.1"}, "15.1R7.9", No},
	} {
		c, err := ParseCPE(tc.cpe)
		if err != nil {
			t.Fatal(err)
		}
		if got, _, ok := junosEval(c, tc.r, tc.ver); !ok || got != tc.want {
			t.Errorf("%s %v on %s: %v, want %v", tc.cpe, tc.r, tc.ver, got, tc.want)
		}
	}
	// A row of another release that does not read counts as listed: before it and after every other row is not proved outside.
	row := func(rel, upd string) Affected {
		return Affected{CPE: "cpe:2.3:o:juniper:junos:" + rel + ":" + upd + ":*:*:*:*:*:*"}
	}
	for _, tc := range []struct {
		ver   string
		aff   []Affected
		want  Tri
		proof proofKind
	}{
		{"15.1R7", []Affected{row("12.1r", "*"), row("13.2", "r1")}, No, proofRange},
		{"11.4R1", []Affected{row("12.1r", "*")}, No, proofNone},
		{"13.1R1", []Affected{row("12.1r", "*"), row("14.1", "r1")}, Unknown, proofNone},
	} {
		v := Vuln{CVE: "CVE-2099-0002", Vendor: "Juniper", Product: "Junos OS", Affected: tc.aff}
		in := newSWInfo(Software{Vendor: "Juniper", Product: "Junos OS", Version: tc.ver}, "")
		if got, _, _, proof := decide(in, v, keyIDs(v)); got != tc.want || proof != tc.proof {
			t.Errorf("%s: %v proof %d, want %v proof %d", tc.ver, got, proof, tc.want, tc.proof)
		}
	}
}

// A dotted network OS (FortiOS, IOS XE, RouterOS) decides a bound or an exact version the generic comparison cannot read by the
// numbers it starts with, and only to rule the version out. The same rows of a product that is not a network OS stay Unknown.
func TestNetworkOS_DottedTrainBounds(t *testing.T) {
	t.Parallel()
	xe := "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"
	exact := func(v string) string { return "cpe:2.3:o:cisco:ios_xe:" + v + ":*:*:*:*:*:*:*" }
	for _, tc := range []struct {
		cpe  string
		r    VersionRange
		ver  string
		want Tri
	}{
		{xe, VersionRange{EndIncl: `15.2\(6\)e0a`}, "17.3.1", No},
		{xe, VersionRange{EndIncl: "15.6.3m1"}, "16.9.4", No},
		{xe, VersionRange{EndIncl: "15.6.3m1"}, "15.6.3", Unknown},    // its own train
		{xe, VersionRange{EndIncl: `15.2\(6\)e0a`}, "3.6.2", Unknown}, // before the bound: never a Yes from a guess
		{xe, VersionRange{StartIncl: "16.12.1z1"}, "16.9.4", No},      // before the start
		{xe, VersionRange{StartIncl: "3.2sg", EndIncl: "3.9e"}, "17.3.1", No},
		{exact("5.2.0.base"), VersionRange{}, "17.3.1", No},
		{exact("16.12.1z1"), VersionRange{}, "16.12.4", No},
		{exact("16.12.1z1"), VersionRange{}, "16.12.1", Unknown}, // the same train
		{exact("17.9.4"), VersionRange{}, "17.9.4a", No},         // NVD writes the rebuild as a row of its own
		{exact("17.9.4a"), VersionRange{}, "17.9.4a", Yes},
		{exact(`15.2\(2\)e4`), VersionRange{}, "17.3.1", No},
		{exact(`15.2\(2\)e4`), VersionRange{}, "15.2.2", Unknown},
		{"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", VersionRange{EndExcl: "6.0.3build0200"}, "7.0.12", No},
		{"cpe:2.3:a:acme:router:*:*:*:*:*:*:*:*", VersionRange{EndIncl: `15.2\(6\)e0a`}, "17.3.1", Unknown}, // not a network OS
		{"cpe:2.3:a:acme:router:5.2.0.base:*:*:*:*:*:*:*", VersionRange{}, "17.3.1", Unknown},
	} {
		c, err := ParseCPE(tc.cpe)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := evalAffected(c, tc.r, tc.ver, CPE{}, false); got != tc.want {
			t.Errorf("%s %v on %s: %v, want %v", tc.cpe, tc.r, tc.ver, got, tc.want)
		}
	}
}

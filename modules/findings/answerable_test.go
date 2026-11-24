package findings

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// answerableCase is one CVE of the answerable-questions fixture, with the cause of the question it used to give (or "kept": a question
// a person's answer can still change, which must stay).
type answerableCase struct {
	cause string
	v     Vuln
}

// The causes of the fixture's questions.
const (
	causeBanner   = "network banner x CVE on no exploited list" // compared only against a version the device or a person gives
	causeLLDP     = "release the device states over LLDP"       // the device's own word, read as a banner
	causeOlder    = "older exact release with a qualifier"      // NVD lists only older releases than the row's
	causeOpenEnd  = "open-ended and bounded range"              // the version is inside a range with a fix
	causeKept     = "kept"                                      // a question a person's answer can change
	juniperCardID = "3c:8a:b0:9c:85:ff"                         // an IEEE OUI of Juniper Networks
)

// answerableFixture is a small network shaped like a real one after one LAN scan: a Juniper switch that states its Junos release over
// LLDP and serves OpenSSH, a Linux web server seen by a scan (OpenSSH banner) running an nginx a person entered, an ESXi host that states
// its build on its API, a Synology NAS, and an application server with Java 21. Invented hosts; the CVE configurations are shaped like
// NVD's (exact releases with updates, ranges) but numbered in a private range.
func answerableFixture(t testing.TB) ([]Asset, []answerableCase) {
	junosKey := productid.Key("Juniper", "Junos OS")
	junosRows := func(v Vuln, spans ...[3]string) Vuln { // Juniper's CVE record: the fixed release of each line
		v.Schemed = schemedRows(t, "juniper-junos", junosKey, spans...)
		return v
	}
	onNoList := func(cve string, aff ...Affected) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Published: uncNew, Affected: aff}
	}
	exact := func(cpes ...string) []Affected {
		var out []Affected
		for _, c := range cpes {
			out = append(out, Affected{CPE: c})
		}
		return out
	}
	const (
		ssh   = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
		junos = "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*"
		nginx = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	)
	workstation := Affected{CPE: "cpe:2.3:a:vmware:workstation:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "17.6"}}
	sudo := Affected{CPE: "cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "1.9.5"}}
	sshLine := func(id, ver string) Software {
		return Software{ID: id, Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: ver, Source: "nmap", CPE: ssh,
			KevKeys: []string{"openbsd|openssh"}}
	}
	assets := []Asset{
		{ID: "core-sw", Name: "core-sw.example.com", OS: "Juniper EX2200 switch (JUNOS 12)", StatedOS: "JUNOS 15.1R7.9", MAC: juniperCardID,
			Software: []Software{
				{ID: "core-sw-junos", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7.9", Source: "passive",
					CPE: junos, KevKeys: []string{"juniper|junos os"}},
				sshLine("core-sw-ssh", "6.9"),
			}},
		{ID: "web-01", Name: "web-01.example.com", OS: "Ubuntu 24.04.1 LTS", Software: []Software{
			sshLine("web-01-ssh", "9.6"),
			{ID: "web-01-nginx", Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.30.5", Source: "manual", CPE: nginx},
		}},
		{ID: "esx-01", Name: "esx-01.example.com", OS: "VMware ESXi 8.0.3 (build 24022510)", Software: []Software{
			{ID: "esx-01-esxi", Display: "VMware ESXi 8.0.3 (build 24022510)", Vendor: "VMware", Product: "ESXi", Version: "8.0.3", Source: "nmap",
				KevKeys: []string{"vmware|esxi"}},
		}},
		{ID: "nas-01", Name: "nas-01.example.com", OS: "Synology DSM 7.2.1", Software: []Software{
			{ID: "nas-01-dsm", Display: "Synology DiskStation Manager", Vendor: "Synology", Product: "DiskStation Manager", Version: "7.2.1-69057-5",
				Source: "manual", KevKeys: []string{"synology|diskstation manager"}},
		}},
		{ID: "app-01", Name: "app-01.example.com", OS: "Microsoft Windows Server 2022", AgentOS: "Microsoft Windows Server 2022", Software: []Software{
			{ID: "app-01-java", Display: "Java SE Development Kit 21", Vendor: "Oracle", Product: "Java SE", Version: "21.0.7", Source: "agent",
				KevKeys: []string{"oracle|java se"}},
		}},
	}
	cases := []answerableCase{
		// OpenSSH read from a banner, CVEs on no list: inside a range, outside it, and NVD with no versions
		{causeBanner, onNoList("CVE-2026-80001", Affected{CPE: ssh, Range: VersionRange{EndExcl: "7.0"}})},
		{causeBanner, onNoList("CVE-2026-80002", Affected{CPE: ssh, Range: VersionRange{StartIncl: "9.0", EndExcl: "9.8"}})},
		{causeBanner, onNoList("CVE-2026-80003", Affected{CPE: ssh, Range: VersionRange{EndExcl: "6.0"}})},
		{causeBanner, onNoList("CVE-2026-80004", Affected{CPE: ssh})},
		{causeBanner, onNoList("CVE-2026-80005", exact("cpe:2.3:a:openbsd:openssh:9.6:-:*:*:*:*:*:*")...)},
		// Junos as the switch states it over LLDP, CVEs on no list: Juniper's record names its line with a later fix, and a fix before
		// its release (NVD lists exact releases)
		{causeLLDP, junosRows(onNoList("CVE-2026-80011", exact("cpe:2.3:o:juniper:junos:15.1:r7:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:15.1:r6:*:*:*:*:*:*")...),
			[3]string{"15.1", "15.1R7-S9", ""}, [3]string{"17.3", "17.3R3-S12", ""})},
		{causeLLDP, junosRows(onNoList("CVE-2026-80012", exact("cpe:2.3:o:juniper:junos:15.1:r4:*:*:*:*:*:*")...), [3]string{"0", "15.1R5", ""})},
		{causeLLDP, junosRows(onNoList("CVE-2026-80013"), [3]string{"17.3", "17.3R3-S12", ""}, [3]string{"18.4", "18.4R3-S10", ""})},
		// exploited CVEs of another product whose NVD list also names the row's product, at older exact releases with updates, builds
		// or a "1.x" Java name
		{causeOlder, uncVuln("CVE-2026-80021", "VMware", "Workstation", uncNew, append(exact("cpe:2.3:o:vmware:esxi:6.5:update1:*:*:*:*:*:*",
			"cpe:2.3:o:vmware:esxi:6.7:update3:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:7.0:update_3c:*:*:*:*:*:*"), workstation)...)},
		{causeOlder, uncVuln("CVE-2026-80022", "VMware", "Workstation", uncNew, append(exact("cpe:2.3:o:vmware:esxi:4.0:1:*:*:*:*:*:*",
			"cpe:2.3:o:vmware:esxi:5.5:-:*:*:*:*:*:*"), workstation)...)},
		{causeOlder, uncVuln("CVE-2026-80023", "Sudo Project", "Sudo", uncNew, append(exact("cpe:2.3:a:synology:diskstation_manager:4.3-3810:*:*:*:*:*:*:*",
			"cpe:2.3:a:synology:diskstation_manager:6.2:*:*:*:*:*:*:*"), sudo)...)},
		{causeOlder, uncVuln("CVE-2026-80024", "Oracle", "JavaFX", uncNew, exact("cpe:2.3:a:oracle:jdk:1.8:update_111:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:jre:1.7:update_121:*:*:*:*:*:*", "cpe:2.3:a:oracle:jre:1.9.0:*:*:*:*:*:*:*")...)},
		// nginx 1.30.5 a person entered: inside 1.30.0 to 1.30.6 and inside "1.25.0 or later"
		{causeOpenEnd, onNoList("CVE-2026-80031", Affected{CPE: nginx, Range: VersionRange{StartIncl: "1.30.0", EndExcl: "1.30.6"}},
			Affected{CPE: nginx, Range: VersionRange{StartIncl: "1.25.0"}})},
		// questions an answer still changes: Junos 15.1R7.9 against the exact releases NVD lists (no record rows), ESXi 8.0.3 against 8.0 Update 3 (which build of 8.0.3?), an exploited CVE whose NVD list
		// names OpenSSH 9.6 exactly (a banner is compared for an exploited CVE), Java 21.0.7 listed as it is
		{causeKept, onNoList("CVE-2026-80044", exact("cpe:2.3:o:juniper:junos:15.1:r7-s1:*:*:*:*:*:*", "cpe:2.3:o:juniper:junos:15.1:r6:*:*:*:*:*:*")...)},
		{causeKept, uncVuln("CVE-2026-80041", "VMware", "Workstation", uncNew, append(exact("cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*",
			"cpe:2.3:o:vmware:esxi:7.0:update_3c:*:*:*:*:*:*"), workstation)...)},
		{causeKept, uncVuln("CVE-2026-80042", "OpenBSD", "OpenSMTPD", uncNew, append(exact("cpe:2.3:a:openbsd:openssh:9.6:-:*:*:*:*:*:*"),
			Affected{CPE: "cpe:2.3:a:openbsd:opensmtpd:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "7.6"}})...)},
		{causeKept, uncVuln("CVE-2026-80043", "Oracle", "JavaFX", uncNew, exact("cpe:2.3:a:oracle:jdk:21.0.7:*:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:jdk:1.8:update_111:*:*:*:*:*:*")...)},
	}
	return assets, cases
}

// answerableCounts matches the fixture and counts the open questions it gives by kind and cause, and the findings and proofs by cause.
func answerableCounts(t *testing.T) (questions, findings, proofs map[string]int) {
	t.Helper()
	assets, cases := answerableFixture(t)
	vulns := make([]Vuln, len(cases))
	cause := map[string]string{}
	for i, c := range cases {
		vulns[i], cause[c.v.CVE] = c.v, c.cause
	}
	questions, findings, proofs = map[string]int{}, map[string]int{}, map[string]int{}
	for _, a := range assets {
		have := map[string]bool{}
		for _, v := range vulns {
			have[v.CVE] = true // a finding of every CVE, so a proof shows
		}
		res := MatchAsset(a, vulns, have, uncNow)
		for _, q := range questionsOfMatch(res) {
			questions[string(q.Kind)+" / "+cause[q.CVE]]++
		}
		for _, m := range slices.Concat(res.New, res.Existing) {
			findings[cause[m.CVE]]++
		}
		for _, m := range res.NotAffected {
			proofs[cause[m.CVE]]++
		}
	}
	return questions, findings, proofs
}

func countLines(m map[string]int) string {
	var b strings.Builder
	total := 0
	for _, k := range slices.Sorted(maps.Keys(m)) {
		fmt.Fprintf(&b, "\n  %-75s %d", k, m[k])
		total += m[k]
	}
	fmt.Fprintf(&b, "\n  %-75s %d", "total", total)
	return b.String()
}

// The open questions of a fixture network, by kind and cause: a question stays only when a person's answer can change the verdict.
// A version read from a network banner is never compared with a CVE on no exploited list, so no answer about comparability changes
// it (no question); the release a device states over LLDP is its own word and is compared; an exact older release with an update or
// build qualifier is not a candidate; a version inside a bounded range is a finding with that range's fix. The "kept" questions stay.
func TestQuestions_OnlyAnswerableOnes_Count(t *testing.T) {
	t.Parallel()
	questions, findings, proofs := answerableCounts(t)
	t.Logf("open questions by kind / cause:%s", countLines(questions))
	t.Logf("findings by cause:%s", countLines(findings))
	t.Logf("proofs (not affected) by cause:%s", countLines(proofs))
	// Before: 22 questions (10 banner x CVE on no list, 4 older exact releases, 2 LLDP-stated releases, 1 open-ended range, 5 kept).
	wantQ := map[string]int{"no_range_data / " + causeKept: 5}
	if !maps.Equal(questions, wantQ) {
		t.Errorf("questions %v, want %v", questions, wantQ)
	}
	if want := map[string]int{causeLLDP: 1, causeOpenEnd: 1}; !maps.Equal(findings, want) {
		t.Errorf("findings %v, want %v", findings, want)
	}
	if want := map[string]int{causeLLDP: 1}; !maps.Equal(proofs, want) {
		t.Errorf("proofs %v, want %v", proofs, want)
	}
}

// A version read from the network (a banner, the passive sensor, a row of unknown origin) is never compared with a CVE on no exploited
// list: no finding and no question, inside the range or not. The same version from the device's agent or a person is compared (inside:
// a finding); an exploited CVE is compared with the banner too.
func TestQuestions_BannerAndACVEOnNoList(t *testing.T) {
	t.Parallel()
	onNoList := catalogueOnly("CVE-2026-80101", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "9.0", "9.8")
	listed := onNoList
	listed.CVE, listed.Vendor, listed.Product = "CVE-2026-80102", "OpenBSD", "OpenSSH"
	for _, tc := range []struct {
		source            string
		findings, unasked int // of the CVE on no list
		listedFinding     bool
	}{
		{"nmap", 0, 0, true}, {"scan", 0, 0, true}, {"passive", 0, 0, true}, {"", 0, 0, true},
		{"agent", 1, 0, true}, {"manual", 1, 0, true}, {"snmp", 1, 0, true},
	} {
		a := Asset{ID: "h", Name: "h.example.com", Software: []Software{sshRow("9.6", "", tc.source)}}
		res := MatchAsset(a, []Vuln{onNoList, listed}, nil, uncNow)
		n, q, l := 0, 0, false
		for _, m := range res.New {
			n += btoi(m.CVE == onNoList.CVE)
			l = l || m.CVE == listed.CVE
		}
		for _, u := range res.Unchecked {
			q += btoi(u.CVE == onNoList.CVE)
		}
		if n != tc.findings || q != tc.unasked || l != tc.listedFinding {
			t.Errorf("source %q: %d findings and %d questions of the CVE on no list, listed finding %v; want %d, %d, %v",
				tc.source, n, q, l, tc.findings, tc.unasked, tc.listedFinding)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// The release a switch states over LLDP, recorded by the passive sensor as a row of its own, is the device's word: compared with a CVE
// on no list (a finding inside the line Juniper names, with its fix) and stored as a version the device itself reports. Not when the
// statement does not count (another maker's card, an SNMP answer or an agent naming another OS) or names another release: then it is a
// banner again, compared with nothing on no list and asking nothing.
func TestLLDPStatedRelease_IsTheDevicesWord(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2026-80111", NVDAnswered: true, Origin: RangeCNA, Published: uncNew,
		Schemed: schemedRows(t, "juniper-junos", productid.Key("Juniper", "Junos OS"), [3]string{"15.1", "15.1R7-S9", ""})}
	row := Software{ID: "sw-junos", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7.9", Source: "passive",
		CPE: "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", KevKeys: []string{"juniper|junos os"}}
	for _, tc := range []struct {
		name, stated, snmp, agent, mac string
		own                            bool
	}{
		{"LLDP on a Juniper card", "JUNOS 15.1R7.9", "", "", juniperCardID, true},
		{"LLDP, written in another case", "junos 15.1r7.9", "", "", juniperCardID, true},
		{"SNMP states it", "", "JUNOS 15.1R7.9", "", "", true},
		{"LLDP on another maker's card", "JUNOS 15.1R7.9", "", "", "00:0c:29:12:34:56", false},
		{"LLDP names another release", "JUNOS 15.1R6.7", "", "", juniperCardID, false},
		{"SNMP names another OS", "JUNOS 15.1R7.9", "Linux 6.1.0", "", juniperCardID, false},
		{"an agent reports another OS", "JUNOS 15.1R7.9", "", "Alpine Linux v3.23", juniperCardID, false},
	} {
		a := Asset{ID: "sw", Name: "core-sw.example.com", StatedOS: tc.stated, SNMPOS: tc.snmp, AgentOS: tc.agent, MAC: tc.mac,
			Software: []Software{row}}
		res := MatchAsset(a, []Vuln{v}, nil, uncNow)
		if got := len(res.New) == 1; got != tc.own {
			t.Errorf("%s: finding %v, want %v (%+v)", tc.name, got, tc.own, res.New)
		}
		if len(res.Unchecked) != 0 {
			t.Errorf("%s: a question %+v", tc.name, res.Unchecked)
		}
		if a.Software[0].stated {
			t.Errorf("%s: the caller's row was marked", tc.name)
		}
		if !tc.own {
			continue
		}
		if f := FixOf(a, deviceSoftware(a)[0], v); f.Version != "15.1R7-S9" {
			t.Errorf("%s: fix %+v", tc.name, f)
		}
		if d := detectionOf(res.New[0], deviceLines(a)); d.Basis != DetectDeviceVersion {
			t.Errorf("%s: basis %s, want %s", tc.name, d.Basis, DetectDeviceVersion)
		}
	}
	// The same row read by a scan is the device's word too when it is the very release the device states; a banner otherwise.
	scan := row
	scan.Source = "nmap"
	a := Asset{ID: "sw", Name: "core-sw.example.com", StatedOS: "JUNOS 15.1R7.9", MAC: juniperCardID, Software: []Software{scan}}
	if res := MatchAsset(a, []Vuln{v}, nil, uncNow); len(res.New) != 1 {
		t.Errorf("a scan's row of the stated release: %+v", res)
	}
	// The network OS the device states without a row of its own is stored as the device's word as well.
	b := labEX4200()
	b.MAC = juniperCardID
	res := MatchAsset(b, []Vuln{v}, nil, uncNow)
	if len(res.New) != 1 {
		t.Fatalf("the stated OS row: %+v", res)
	}
	if d := detectionOf(res.New[0], deviceLines(b)); d.Basis != DetectDeviceVersion {
		t.Errorf("the stated OS row: basis %s, want %s", d.Basis, DetectDeviceVersion)
	}
}

// Among the ranges a version is inside, the one with an end explains the finding: nginx 1.30.5 is inside 1.30.0 to 1.30.6 and inside
// "1.25.0 or later", so a CVE on no list is a finding, as an exploited one is. The fix stays the one resolver's (FixOf): 1.30.6 is
// inside the open-ended range, so it names none. A version inside only the open-ended range is still affected by an exploited CVE.
func TestDecide_PrefersTheRangeWithAFix(t *testing.T) {
	t.Parallel()
	const nginx = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	aff := []Affected{
		{CPE: nginx, Range: VersionRange{StartIncl: "1.25.0"}},
		{CPE: nginx, Range: VersionRange{StartIncl: "1.30.0", EndExcl: "1.30.6"}},
		{CPE: nginx, Range: VersionRange{StartIncl: "1.31.0", EndExcl: "1.31.9"}},
	}
	row := func(ver string) Software {
		return Software{ID: "s-nginx", Display: "nginx", Vendor: "F5", Product: "nginx", Version: ver, Source: "manual", CPE: nginx,
			KevKeys: []string{"f5|nginx"}}
	}
	onNoList := Vuln{CVE: "CVE-2026-80121", NVDAnswered: true, Origin: RangeNVD, Published: uncNew, Affected: aff}
	listed := uncVuln("CVE-2026-80122", "F5", "nginx", uncNew, aff...)
	for _, tc := range []struct {
		ver, within string
		offList     bool // the CVE on no list is a finding
	}{
		{"1.30.5", "1.30.0 to 1.30.6", true},
		{"1.31.2", "1.31.0 to 1.31.9", true},
		{"1.30.7", "", false}, // inside "1.25.0 or later" only
		{"1.24.0", "-", false},
	} {
		a := Asset{ID: "web", Name: "web-01.example.com", Software: []Software{row(tc.ver)}}
		t1, within, _, _ := decide(newSWInfo(row(tc.ver), ""), listed, nil)
		switch {
		case tc.within == "-":
			if t1 != No {
				t.Errorf("%s: %v, want not affected", tc.ver, t1)
			}
		case t1 != Yes:
			t.Errorf("%s: %v, want affected", tc.ver, t1)
		case tc.within != "" && within.StartIncl+" to "+within.EndExcl != tc.within:
			t.Errorf("%s: within %+v, want %s", tc.ver, within, tc.within)
		case tc.within == "" && endBound(within):
			t.Errorf("%s: within %+v, want the open-ended range", tc.ver, within)
		}
		res := MatchAsset(a, []Vuln{onNoList, listed}, nil, uncNow)
		got := map[string]bool{}
		for _, m := range res.New {
			got[m.CVE] = true
		}
		if got[onNoList.CVE] != tc.offList {
			t.Errorf("%s: finding of the CVE on no list %v, want %v", tc.ver, got[onNoList.CVE], tc.offList)
		}
		if got[listed.CVE] != (tc.within != "-") {
			t.Errorf("%s: finding of the exploited CVE %v", tc.ver, got[listed.CVE])
		}
		if f := FixOf(a, row(tc.ver), onNoList); tc.offList && f.Kind == FixUpdate {
			t.Errorf("%s: fix %+v: the open-ended range still holds every later release", tc.ver, f)
		}
	}
}

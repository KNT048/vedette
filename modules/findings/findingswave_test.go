package findings

import (
	"net/http"
	"strings"
	"testing"
)

// W-1 (TUNE-5b walk): the build a Windows server's own agent reports, inside NVD's range, is a detection: the evidence says
// what the agent reports and which build fixes it, never "only suspected". The same build read by a scan keeps the old words.
func TestMatchAsset_AgentBuildIsADetection(t *testing.T) {
	srv := winPC(26100, true, "1742", "x64")
	srv.Name = "WIN-LAB"
	_, m := oneMatch(t, srv, cve62215, false)
	s := m.Evidence.Summary
	if !m.Evidence.Agent || m.Basis != BasisVersion ||
		!strings.HasPrefix(s, "The agent on WIN-LAB reports Windows Server 2025 build 26100.1742. Microsoft fixed CVE-2025-62215 in build 26100.7092") ||
		strings.Contains(s, "suspected") {
		t.Fatalf("agent row: %+v", m)
	}
	scanned := winPC(26100, true, "1742", "x64")
	scanned.Software[0].Source = "nmap"
	_, m = oneMatch(t, scanned, cve62215, false)
	if m.Evidence.Agent || !strings.Contains(m.Evidence.Summary, "only suspected") {
		t.Fatalf("scan row: %+v", m)
	}
}

// W-3: one missing monthly update is one item: every open finding of the Windows row gets the same group, the build that
// fixes them all, and the mark that it is Windows's cumulative update.
func TestRowFixes_OneWindowsUpdate(t *testing.T) {
	a := winPC(26100, true, "1742", "x64")
	got := RowFixes(a, []Vuln{cve62215, cve29824, cve33073})
	for _, cve := range []string{cve62215.CVE, cve29824.CVE, cve33073.CVE} {
		f := got[cve]
		if f == nil || f.Group != "a-pc/s-win" || f.Kind != "fixed" || !f.Windows || f.Fixed != "10.0.26100.7092" || f.Software != "Windows Server 2025" || f.Version != "10.0.26100.1742" {
			t.Fatalf("%s: %+v", cve, f)
		}
	}
	if got := RowFixes(winPC(26100, true, "7092", "x64"), []Vuln{cve62215}); got[cve62215.CVE] != nil {
		t.Fatalf("a patched server has nothing to install: %+v", got)
	}
}

// What the CVE page asks. An agent's Ubuntu reading and a Junos switch's own statement rule the
// Alpine-only CVE out; a scan-seen OpenSSH with no platform, a guessed OS and a CVE not on the list do not.
func TestPlatformRuledOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    Asset
		cve  string
		want bool
	}{
		{"agent row, agent says Ubuntu", Asset{ID: "a", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("9.6p1", "", "agent")}}, "CVE-2026-123158", true},
		{"agent row, only a guessed OS", Asset{ID: "a", OS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("9.6p1", "", "agent")}}, "CVE-2026-123158", false},
		{"Junos switch, scan-seen OpenSSH", Asset{ID: "sw", StatedOS: "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9", SNMPOS: "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9", Software: []Software{sshRow("7.5", "", "nmap")}}, "CVE-2026-123158", true},
		{"forged LLDP Junos on an Alpine box (review r1 #3)", Asset{ID: "sw", StatedOS: "JUNOS 15.1R7.9", Software: []Software{sshRow("10.2", "", "nmap")}}, "CVE-2026-123158", false},
		{"firewall that says nothing", Asset{ID: "fw", Software: []Software{sshRow("10.2", "protocol 2.0", "nmap")}}, "CVE-2026-123158", false},
		{"a CVE not on the list", Asset{ID: "a", AgentOS: "Ubuntu 24.04.3 LTS", Software: []Software{sshRow("9.6p1", "", "agent")}}, "CVE-2024-6387", false},
	} {
		if got := PlatformRuledOut(tc.a, tc.cve, "OpenBSD", "OpenSSH", alpineSSH(), t0); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// W-1 + W-3 through GET /findings: the Windows server's open findings carry one fix group and the agent's evidence.
func TestContract_ListCarriesTheFixGroup(t *testing.T) {
	e := newHTTPEnv(t)
	srv := winPC(26100, true, "1742", "x64")
	srv.ID, srv.Name = "a-1", "WIN-LAB"
	e.inv.mu.Lock()
	e.inv.match["a-1"] = srv
	e.inv.mu.Unlock()
	e.feeds.vulns = []Vuln{cve62215, cve29824}
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	code, body := e.call(http.MethodGet, "/findings", "viewer", "")
	items, _ := body["items"].([]any)
	if code != http.StatusOK || len(items) != 2 {
		t.Fatalf("%d %v", code, body)
	}
	for _, it := range items {
		f := it.(map[string]any)
		fix, _ := f["fix"].(map[string]any)
		ev, _ := f["evidence"].(map[string]any)
		if fix["group"] != "a-1/s-win" || fix["kind"] != "fixed" || fix["windows"] != true || fix["fixed"] != "10.0.26100.7092" || ev["agent"] != true {
			t.Fatalf("row %v", f)
		}
	}
}

// Review r1 #1: a CVE NVD has no range for keeps its own row: the upgrade that clears the others proves nothing about it.
func TestRowFixes_NoRangeKeepsItsRow(t *testing.T) {
	ranged := func(cve, end string) Vuln {
		return Vuln{CVE: cve, Vendor: "QNAP", Product: "Photo Station", Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: end}}}}
	}
	bare := Vuln{CVE: "CVE-2099-0003", Vendor: "QNAP", Product: "Photo Station"}
	got := RowFixes(nas("6.1.1"), []Vuln{ranged("CVE-2099-0001", "6.1.2"), ranged("CVE-2099-0002", "6.2.0"), bare})
	if got["CVE-2099-0001"] == nil || got["CVE-2099-0002"] == nil || got["CVE-2099-0001"].Fixed != "6.2.0" || got[bare.CVE] != nil {
		t.Fatalf("fixes %+v", got)
	}
}

// Review r1 #5, #6, #7: no "Detected by the agent" while the platform condition is open or when NVD names no end; an ESU-only or a
// feature-update fix says so instead of "that monthly update".
func TestMatchAsset_AgentWordsOnlyWhenTheyHold(t *testing.T) {
	r := MatchAsset(Asset{ID: "a", Name: "fw1", Software: []Software{sshRow("10.2", "", "agent")}}, []Vuln{sshhole()}, nil, t0)
	if len(r.New) != 0 || len(r.Asked) != 1 { // No finding while the platform condition is open
		t.Fatalf("platform open: %+v", r)
	}
	m := MatchAsset(Asset{ID: "a", Name: "alp1", AgentOS: "Alpine Linux v3.23", Software: []Software{sshRow("10.2_p1-r0", "", "agent")}}, []Vuln{sshhole()}, nil, t0).New
	if len(m) != 1 || !m[0].Evidence.Agent {
		t.Fatalf("agent says Alpine: %+v", m)
	}
	all := Vuln{CVE: "CVE-2099-0004", Vendor: "QNAP", Product: "Photo Station", Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "6.0"}}}}
	box := nas("6.1.1")
	box.Software[0].Source = "agent"
	if m = MatchAsset(box, []Vuln{all}, nil, t0).New; len(m) != 1 || m[0].Evidence.Agent {
		t.Fatalf("no end: %+v", m)
	}
	_, w := oneMatch(t, winPC(19045, false, "6456", "x64"), cve62215, false) // Windows 10 22H2 after its last free update
	if !w.Evidence.Agent || !strings.Contains(w.Evidence.Summary, "comes only with Extended Security Updates for Windows 10 22H2") || strings.Contains(w.Evidence.Summary, "monthly update") {
		t.Fatalf("esu: %q", w.Evidence.Summary)
	}
}

// Review r2 #1: a NAS with Photo Station and QTS. The QTS-only CVE (a vendor-keyed "Multiple Products" entry) is QTS's to fix: it is not
// swallowed into "Upgrade Photo Station … fixes N", though Photo Station's upgrade is outside every range of the list.
func TestRowFixes_AnotherRowsRangeStaysWithThatRow(t *testing.T) {
	ps := func(cve, end string) Vuln {
		return Vuln{CVE: cve, Vendor: "QNAP", Product: "Photo Station", Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: end}}}}
	}
	qts := Vuln{CVE: "CVE-2099-0009", Vendor: "QNAP", Product: "Multiple Products", Affected: []Affected{{CPE: "cpe:2.3:o:qnap:qts:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "5.1.0"}}}}
	a := nas("6.1.1")
	a.Software[0].KevKeys = append(a.Software[0].KevKeys, "qnap|multiple products")
	a.Software = append(a.Software, Software{ID: "s-qts", Display: "QTS", Vendor: "QNAP", Product: "QTS", Version: "5.0.0", CPE: "cpe:2.3:o:qnap:qts:5.0.0:*:*:*:*:*:*:*", KevKeys: []string{"qnap|qts", "qnap|multiple products"}})
	got := RowFixes(a, []Vuln{ps("CVE-2099-0001", "6.1.2"), ps("CVE-2099-0002", "6.2.0"), qts})
	if f := got["CVE-2099-0001"]; f == nil || f.Group != "a-1/s-1" || f.Fixed != "6.2.0" {
		t.Fatalf("Photo Station: %+v", f)
	}
	if f := got[qts.CVE]; f != nil && f.Group == "a-1/s-1" {
		t.Fatalf("the QTS CVE went into Photo Station's upgrade: %+v", f)
	}
	all := FixedInForAll(a, []Vuln{ps("CVE-2099-0001", "6.1.2"), ps("CVE-2099-0002", "6.2.0"), qts})
	if g := all[qts.CVE]; g == nil || g.Software != "s-qts" || !g.Ranged[qts.CVE] {
		t.Fatalf("the QTS CVE's group is QTS's (the report counts it there): %+v", g)
	}
}

// Review r2 nit: an ended release read through a later sibling's rows says no update for it carries the fix (winFix feature_update).
func TestMatchAsset_FeatureUpdateSentence(t *testing.T) {
	_, m := oneMatch(t, winPC(22621, false, "6060", "x64"), cve62215, false) // Windows 11 22H2, out of service, NVD lists 23H2
	if !m.Evidence.Agent || !strings.Contains(m.Evidence.Summary, "but no update for this release carries it: this device has the flaw until it moves to Windows 11 23H2 or later") {
		t.Fatalf("%q", m.Evidence.Summary)
	}
}

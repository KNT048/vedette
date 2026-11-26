package findings

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// desktop55 is a test box's DESKTOP-55UKKFV (2026-11-17): Windows 11 Pro 26H2 (build 26300, out 2026-09-29) on a box that has not
// learned it from Microsoft's list (core/winrel's table alone does not list it), as agent-intake's windowsRow writes it (no release CPE, the product names the build), with a Photo Station row whose version compares.
func desktop55() Asset {
	return Asset{ID: "a-desk", Name: "DESKTOP-55UKKFV", OS: "Microsoft Windows 11 Pro 10.0.26300.9974", Software: []Software{
		{ID: "s-win", Display: "Windows 11 Pro", Vendor: "microsoft", Product: "Windows (build 26300)", Version: "10.0.26300.9974", Source: "agent",
			KevKeys: []string{"microsoft|windows"}},
		{ID: "s-1", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "6.1.1", Source: "agent", KevKeys: []string{"qnap|photo station"}},
	}}
}

// A Windows build newer than the release table cannot be placed among the releases NVD lists: every Windows KEV entry is "could
// not be checked" (not_comparable), never a finding, and the sentence says why in plain words. A version match on another row stays.
func TestMatchAsset_UnknownWindowsBuildIsUnchecked(t *testing.T) {
	t.Parallel()
	inRange := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	vulns := []Vuln{cve0367, cve0210, cve62215, inRange}
	for i := range vulns {
		vulns[i].NVDAnswered = true
	}
	res := MatchAsset(desktop55(), vulns, nil, winNow)
	if len(res.New) != 1 || res.New[0].CVE != inRange.CVE || res.New[0].Basis != BasisVersion {
		t.Fatalf("findings: %+v", res.New)
	}
	var dropped []string
	for _, m := range res.NameOnly {
		dropped = append(dropped, m.CVE)
		if !strings.HasPrefix(m.Evidence.Summary, NameOnlyNote) ||
			!strings.Contains(m.Evidence.Summary, "Windows build 26300 is newer than every Windows release Vedette knows (an Insider build, or a release not yet in its list), so Vedette cannot compare 10.0.26300.9974 with the builds NVD lists for "+m.CVE) ||
			!strings.Contains(m.Evidence.Summary, `now listed under "Could not be checked"`) || jsLen(m.Evidence.Summary) > MaxNote {
			t.Errorf("%s: %q", m.CVE, m.Evidence.Summary)
		}
	}
	slices.Sort(dropped)
	if want := []string{"CVE-2002-0367", "CVE-2004-0210", "CVE-2025-62215"}; !slices.Equal(dropped, want) {
		t.Fatalf("dropped %v, want %v", dropped, want)
	}
	if len(res.Unchecked) != 3 {
		t.Fatalf("unchecked %+v", res.Unchecked)
	}
	for _, u := range res.Unchecked {
		if u.SoftwareID != "s-win" || u.Reason != UncheckedNotComparable || u.Version != "10.0.26300.9974" {
			t.Errorf("unchecked %+v", u)
		}
	}
	// the same device on a build the table knows (26100, 24H2) is read as before: CVE-2025-62215 is a version finding
	known := desktop55()
	known.Software[0].Product, known.Software[0].Version = "Windows 11 24H2", "10.0.26100.6899"
	known.Software[0].CPE = "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.6899:*:*:*:*:*:x64:*"
	if r := MatchAsset(known, []Vuln{cve62215}, nil, winNow); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Fatalf("24H2: %+v", r)
	}
}

// The name-only rule on CISA's key: whatever made the product-only match (no NVD data, a version NVD's ranges cannot order, NVD naming other
// products), there is no finding; the CVE goes to the could-not-check list with #920's reason. A scannable CVE stays a finding on any
// row, the agent's too (the scan's target, review r1 H1 of #939).
func TestMatchAsset_CISAKeyUnknownIsUnchecked(t *testing.T) {
	t.Parallel()
	noData := qnapVuln()
	noData.NVDAnswered = true
	unordered := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}})
	unordered.CVE = "CVE-2023-0002"
	other := qnapVuln(Affected{CPE: "cpe:2.3:a:qnap:qts:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "5.0"}})
	other.CVE = "CVE-2023-0003"
	res := MatchAsset(nas("6.1.1"), []Vuln{noData, unordered, other}, nil, t0)
	if len(res.New)+len(res.Existing) != 0 || len(res.NameOnly) != 3 {
		t.Fatalf("result %+v", res)
	}
	got := map[string]UncheckedReason{}
	for _, u := range res.Unchecked {
		got[u.CVE] = u.Reason
	}
	want := map[string]UncheckedReason{noData.CVE: UncheckedNoNVDData, unordered.CVE: UncheckedNotComparable, other.CVE: UncheckedNotNamed}
	if len(got) != len(want) {
		t.Fatalf("unchecked %v, want %v", got, want)
	}
	for c, r := range want {
		if got[c] != r {
			t.Errorf("%s: %s, want %s", c, got[c], r)
		}
	}
	scan := qnapScanned()
	if r := MatchAsset(nas("6.1.1"), []Vuln{scan}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisProduct || len(r.NameOnly) != 0 {
		t.Fatalf("scannable on a scanned row: %+v", r)
	}
	agent := nas("6.1.1")
	agent.Software[0].Source = "agent"
	if r := MatchAsset(agent, []Vuln{scan}, nil, t0); len(r.New) != 1 || len(r.NameOnly) != 0 { // review r1 H1 of #939: on any row
		t.Fatalf("scannable on the agent's row: %+v", r)
	}
	// "every version" (NVD) without a version and a version inside a range stay findings
	every := qnapVuln(Affected{CPE: qnapCPE})
	if r := MatchAsset(nas(""), []Vuln{every}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisProduct || len(r.NameOnly) != 0 {
		t.Fatalf("every version, no version: %+v", r)
	}
	if r := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Fatalf("version: %+v", r)
	}
}

// Review r1 of #939, M1 and M2: NVD's "every version" is version evidence for a row whose version Vedette cannot read too, and which
// row wins never decides whether the CVE is a finding (both orders).
func TestMatchAsset_EveryVersionAndRowOrder(t *testing.T) {
	t.Parallel()
	every := qnapVuln(Affected{CPE: qnapCPE})
	for _, ver := range []string{"", "15.2(4)M3", "R7000-V1.0.11.100_10.2.100"} {
		if r := MatchAsset(nas(ver), []Vuln{every}, nil, t0); len(r.New) != 1 || len(r.NameOnly) != 0 || !r.New[0].every {
			t.Errorf("every version, version %q: %+v", ver, r)
		}
	}
	agent := Software{ID: "s-a", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "R7000-V1.0.11.100_10.2.100", Source: "agent", KevKeys: []string{"qnap|photo station"}}
	bare := Software{ID: "s-b", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", KevKeys: []string{"qnap|photo station"}}
	unordered := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}})
	for name, rows := range map[string][]Software{"agent first": {agent, bare}, "bare first": {bare, agent}} {
		a := Asset{ID: "a", Name: "nas", Software: rows}
		if r := MatchAsset(a, []Vuln{every}, nil, t0); len(r.New) != 1 || len(r.NameOnly) != 0 {
			t.Errorf("%s, every version: %+v", name, r)
		}
		// neither row has version evidence: no finding whatever the order, and the agent's row is the one listed
		if r := MatchAsset(a, []Vuln{unordered}, nil, t0); len(r.New) != 0 || len(r.NameOnly) != 1 || r.NameOnly[0].SoftwareID != "s-a" {
			t.Errorf("%s, unordered range: %+v", name, r)
		}
	}
}

// Review r1 of #939, M3 and H2 (a): "add the version" only where a version would decide; otherwise, and before NVD has answered at
// all, the CVE is under "could not be checked" at once with the reason (no_nvd_data, no_nvd_versions).
func TestMatchAsset_AddTheVersionOnlyWhereItDecides(t *testing.T) {
	t.Parallel()
	pending := qnapVuln() // NVD has not answered yet (NVDAnswered false)
	dash := qnapVuln(Affected{CPE: "cpe:2.3:a:qnap:photo_station:-:*:*:*:*:*:*:*"})
	dash.CVE = "CVE-2023-0004"
	ranged := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	ranged.CVE = "CVE-2023-0005"
	for _, ver := range []string{"", "6.1.1"} {
		r := MatchAsset(nas(ver), []Vuln{pending, dash, ranged}, nil, t0)
		got := uncByCVE(r.Unchecked)
		if got["s-1 "+pending.CVE].Reason != UncheckedNoNVDData || got["s-1 "+dash.CVE].Reason != UncheckedNoNVDVersions {
			t.Errorf("version %q: unchecked %+v", ver, r.Unchecked)
		}
		if ver == "" && (len(r.NeedVersion) != 1 || !slices.Equal(r.NeedVersion[0].CVEs, []string{ranged.CVE})) {
			t.Errorf("no version: need %+v", r.NeedVersion)
		}
	}
}

// Review r2 H1 of #939 and its check (lead decision): a version inside the range of every edition NVD pins for one of the row's products
// is version evidence when NVD lists at least two editions (GitLab community and enterprise): a version finding naming them. A lone
// edition (Acrobat "continuous", Splunk "enterprise", Jira "data_center") or a platform pin (AnyConnect for Windows only, on a Mac) is
// not: "could not be checked", with a sentence naming the edition. NVD's real rows (a test box's copy, 2026-11-16). Firefox ESR against "-"
// stays as #906 decided (TestNA_ApplicationEditionAsMain).
func TestMatchAsset_PinnedEditionStillDecides(t *testing.T) {
	t.Parallel()
	rows := func(cve, vendor, product string, aff ...[3]string) Vuln {
		v := Vuln{CVE: cve, Vendor: vendor, Product: product, NVDAnswered: true}
		for _, a := range aff {
			v.Affected = append(v.Affected, Affected{CPE: a[0], Range: VersionRange{StartIncl: a[1], EndExcl: a[2]}})
		}
		return v
	}
	acrobat := rows("CVE-2026-34621", "Adobe", "Acrobat and Reader",
		[3]string{"cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous:*:*:*", "", "26.001.21411"},
		[3]string{"cpe:2.3:a:adobe:acrobat_reader_dc:*:*:*:*:continuous:*:*:*", "", "26.001.21411"},
		[3]string{"cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*", "24.0.0", "24.001.30362"},
		[3]string{"cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*", "24.0.0", "24.001.30360"})
	gitlab := rows("CVE-2021-39935", "GitLab", "Community and Enterprise Editions",
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "10.5.0", "14.3.6"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "10.5.0", "14.3.6"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "14.4.0", "14.4.4"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "14.4.0", "14.4.4"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "14.5.0", "14.5.2"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "14.5.0", "14.5.2"})
	anyconnect := rows("CVE-2020-3153", "Cisco", "AnyConnect Secure Mobility Client",
		[3]string{"cpe:2.3:a:cisco:anyconnect_secure_mobility_client:*:*:*:*:*:windows:*:*", "", "4.8.02042"})
	splunk := rows("CVE-2026-20253", "Splunk", "Splunk Enterprise",
		[3]string{"cpe:2.3:a:splunk:splunk:*:*:*:*:enterprise:*:*:*", "9.0.0", "9.0.10"})
	jira := rows("CVE-2099-0103", "Atlassian", "Jira Service Management",
		[3]string{"cpe:2.3:a:atlassian:jira_service_management:*:*:*:*:data_center:*:*:*", "5.0.0", "5.4.17"})
	row := func(display, vendor, product, ver, source string, v Vuln) Asset {
		return Asset{ID: "a", Name: "pc", Software: []Software{{ID: "s", Display: display, Vendor: vendor, Product: product, Version: ver, Source: source,
			KevKeys: []string{productid.Key(v.Vendor, v.Product)}}}}
	}
	mac := row("Cisco AnyConnect Secure Mobility Client", "Cisco", "AnyConnect Secure Mobility Client", "4.8.01090", "agent", anyconnect)
	// Platform pins never lift, even when NVD lists two of them (the narrow check of #939's final H1): WhatsApp for iPhone and macOS
	// only, on a Windows PC, is no finding.
	whatsapp := rows("CVE-2025-55177", "Meta Platforms", "WhatsApp",
		[3]string{"cpe:2.3:a:whatsapp:whatsapp:*:*:*:*:*:iphone_os:*:*", "2.22.25.2", "2.25.21.73"},
		[3]string{"cpe:2.3:a:whatsapp:whatsapp:*:*:*:*:*:macos:*:*", "2.22.25.2", "2.25.21.78"})
	win := row("WhatsApp", "WhatsApp", "WhatsApp", "2.24.10.70", "agent", whatsapp)
	win.OS, win.AgentOS = "Microsoft Windows 11 Pro", "Microsoft Windows 11 Pro"
	if r := MatchAsset(win, []Vuln{whatsapp}, nil, t0); len(r.New) != 0 {
		t.Errorf("WhatsApp on Windows: platform pins lifted: %+v", r.New)
	}
	mac.OS, mac.AgentOS = "macOS 14.6", "macOS 14.6"
	for _, tc := range []struct {
		name string
		a    Asset
		v    Vuln
		says string // a finding saying this; "lone:<sentence>" no finding, could not be checked (not_comparable) with it; "" none at all
	}{
		{"GitLab 14.3.0 (nmap)", row("GitLab", "GitLab", "GitLab", "14.3.0", "nmap", gitlab), gitlab, "for community or enterprise only"},
		{"GitLab 14.3.6 (fixed)", row("GitLab", "GitLab", "GitLab", "14.3.6", "nmap", gitlab), gitlab, ""},
		{"Acrobat Reader DC 24.002.20759 (agent)", row("Adobe Acrobat Reader DC", "Adobe", "Acrobat and Reader", "24.002.20759", "agent", acrobat), acrobat,
			"lone:NVD lists CVE-2026-34621 for the continuous edition of Adobe Acrobat Reader DC only"},
		{"AnyConnect 4.8.01090 on macOS (a Windows-only row: another build)", mac, anyconnect, ""},
		{"Splunk Enterprise 9.0.5", row("Splunk", "Splunk", "Splunk", "9.0.5", "agent", splunk), splunk, "lone:for the enterprise edition of Splunk only"},
		{"Jira Service Management 5.4.0", row("Jira Service Management", "Atlassian", "Jira Service Management", "5.4.0", "manual", jira), jira, "lone:for the data_center edition"},
	} {
		r := MatchAsset(tc.a, []Vuln{tc.v}, nil, t0)
		switch {
		case tc.says == "":
			if len(r.New)+len(r.NameOnly) != 0 {
				t.Errorf("%s: %+v", tc.name, r)
			}
		case strings.HasPrefix(tc.says, "lone:"):
			if len(r.New) != 0 || len(r.NameOnly) != 1 || !strings.Contains(r.NameOnly[0].Evidence.Summary, strings.TrimPrefix(tc.says, "lone:")) ||
				len(r.Unchecked) != 1 || r.Unchecked[0].Reason != UncheckedNotComparable && tc.v.CVE != anyconnect.CVE {
				t.Errorf("%s: %+v", tc.name, r)
			}
		default:
			if len(r.New) != 1 || r.New[0].Basis != BasisVersion || !strings.Contains(r.New[0].Evidence.Summary, tc.says) || r.New[0].Evidence.Agent {
				t.Errorf("%s: %+v", tc.name, r)
			}
		}
	}
	// one edition whose ranges leave the version out (the edition would decide): not evidence
	mixed := rows("CVE-2099-0101", "GitLab", "Community and Enterprise Editions",
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "10.5.0", "14.3.6"},
		[3]string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", "10.5.0", "14.2.0"})
	if r := MatchAsset(row("GitLab", "GitLab", "GitLab", "14.3.0", "nmap", mixed), []Vuln{mixed}, nil, t0); len(r.New) != 0 || len(r.NameOnly) != 1 {
		t.Errorf("mixed editions: %+v", r)
	}
}

// Review r2 H2 of #939: an out-of-service Windows release (Windows 11 21H2) that NVD's list brackets with releases of its kind before
// and after it has the flaw (no update brings it the fix): a finding with that sentence, kept by the age rule. Listed only for newer
// releases (a feature it may not have), it stays "could not be checked".
func TestMatchAsset_EndedWindowsBracketedIsAFinding(t *testing.T) {
	t.Parallel()
	pc := winPC(22000, false, "2538", "x64")
	clfs := nvdWindows("CVE-2025-29824", "2025-04-08", nvdRow{"windows_10_21h2", "*", "x64", "10.0.19044.5737"}, nvdRow{"windows_11_22h2", "*", "x64", "10.0.22621.5189"},
		nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.3775"}, nvdRow{"windows_server_2025", "*", "x64", "10.0.26100.3775"})
	clfs.Published = winDay("2025-04-08")
	w, m := oneMatch(t, pc, clfs, false, cve62215)
	wantMatch(t, "21H2 bracketed", w, m, "new", BasisProduct, SeverityMedium, "Microsoft no longer updates Windows 11 21H2", "Windows 10 21H2", "move to a serviced release")
	if !versionBacked(m) {
		t.Error("bracketed: no version evidence")
	}
	newer := nvdWindows("CVE-2099-0102", "2026-10-01", nvdRow{"windows_11_22h2", "*", "x64", "10.0.22621.5189"}, nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.3775"})
	if w, _ := oneMatch(t, pc, newer, false, cve62215); w != "nameonly" {
		t.Errorf("newer releases only: %s", w)
	}
	// a serviced release (23H2) is read by its own rows, as before
	if w, _ := oneMatch(t, winPC(22631, false, "5189", "x64"), clfs, false, cve62215); w != "none" {
		t.Errorf("23H2 at the fix: %s", w)
	}
	// the guards (check of r2 H2): never a release still serviced (Server 2022), one an LTSC edition (Windows 10 21H2, even on a Pro) or
	// paid ESU (Windows 10 22H2) still services, and only releases of the device's kind bracket it (Server 1909 between two clients)
	bracket := func(cve string, rows ...nvdRow) Vuln {
		v := nvdWindows(cve, "2025-04-08", rows...)
		v.Published = winDay("2025-04-08")
		return v
	}
	for _, tc := range []struct {
		name string
		a    Asset
		v    Vuln
	}{
		{"Server 2022 (serviced)", winPC(20348, true, "3453", "x64"), bracket("CVE-2099-0104", nvdRow{"windows_server_2019", "*", "*", "10.0.17763.7136"}, nvdRow{"windows_server_2025", "*", "*", "10.0.26100.3775"})},
		{"Windows 10 21H2 (LTSC 2021 serviced)", winPC(19044, false, "5000", "x64"), bracket("CVE-2099-0105", nvdRow{"windows_10_1809", "*", "*", "10.0.17763.7136"}, nvdRow{"windows_11_22h2", "*", "*", "10.0.22621.5189"})},
		{"Windows 10 22H2 (ESU)", winPC(19045, false, "6000", "x64"), bracket("CVE-2099-0106", nvdRow{"windows_10_1809", "*", "*", "10.0.17763.7136"}, nvdRow{"windows_11_22h2", "*", "*", "10.0.22621.5189"})},
		{"Server 1909 between clients", winPC(18363, true, "1000", "x64"), bracket("CVE-2099-0107", nvdRow{"windows_10_1809", "*", "*", "10.0.17763.7136"}, nvdRow{"windows_11_22h2", "*", "*", "10.0.22621.5189"})},
	} {
		if w, m := oneMatch(t, tc.a, tc.v, false, cve62215); w == "new" || strings.Contains(m.Evidence.Summary, "Microsoft no longer updates") {
			t.Errorf("%s: %s %q", tc.name, w, m.Evidence.Summary)
		}
	}
	srv := bracket("CVE-2099-0108", nvdRow{"windows_server_1803", "*", "*", "10.0.17134.2208"}, nvdRow{"windows_server_2022", "*", "*", "10.0.20348.3453"})
	if w, m := oneMatch(t, winPC(18363, true, "1000", "x64"), srv, false, cve62215); w != "new" || !strings.Contains(m.Evidence.Summary, "no longer updates Windows Server 1909") {
		t.Errorf("Server 1909 between servers: %s %q", w, m.Evidence.Summary)
	}
}

// Review r2 M1 of #939: before NVD has answered for a CVE, its could-not-check row says Vedette is waiting for NVD's data (nvd_pending),
// not that NVD has none; once NVD answered with nothing, it says that.
func TestUnchecked_WaitingForNVD(t *testing.T) {
	t.Parallel()
	pending := qnapVuln()
	answered := qnapVuln()
	answered.CVE, answered.NVDAnswered = "CVE-2023-0006", true
	r := MatchAsset(nas("6.1.1"), []Vuln{pending, answered}, nil, t0)
	got := uncByCVE(r.Unchecked)
	if u := got["s-1 "+pending.CVE]; u.Reason != UncheckedNoNVDData || !u.NVDPending {
		t.Errorf("pending: %+v", u)
	}
	if u := got["s-1 "+answered.CVE]; u.Reason != UncheckedNoNVDData || u.NVDPending {
		t.Errorf("answered: %+v", u)
	}
	for _, m := range r.NameOnly {
		want := map[string]string{pending.CVE: "Vedette is waiting for NVD's data for " + pending.CVE, answered.CVE: "NVD has not published which products " + answered.CVE}[m.CVE]
		if !strings.Contains(m.Evidence.Summary, want) {
			t.Errorf("%s: %q", m.CVE, m.Evidence.Summary)
		}
	}
	e := newEnv(t)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{pending}); err != nil {
		t.Fatal(err)
	}
	qs, err := e.svc.Questions(t.Context(), "a-1")
	if err != nil || len(qs) != 1 || qs[0].CVE != pending.CVE || !qs[0].Detail.NVDPending {
		t.Fatalf("stored: %+v %v", qs, err)
	}
}

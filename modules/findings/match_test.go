package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
)

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

func nas(version string) Asset {
	return Asset{ID: "a-1", Name: "nas01", Software: []Software{
		{ID: "s-1", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: version, KevKeys: []string{"qnap|photo station"}},
	}}
}

func qnapVuln(affected ...Affected) Vuln {
	return Vuln{CVE: "CVE-2022-27593", Vendor: "QNAP", Product: "Photo Station", Affected: affected}
}

func TestMatchAsset_ProductBasisTextsMatchMock(t *testing.T) {
	t.Parallel()
	res := MatchAsset(nas("6.1.2"), []Vuln{qnapVuln()}, nil, t0)
	if len(res.New) != 1 || len(res.Existing) != 0 {
		t.Fatalf("result = %+v", res)
	}
	m := res.New[0]
	if m.Basis != BasisProduct || m.Confidence != 0.5 || m.Severity != SeverityMedium || !m.Evidence.CheckedAt.Equal(t0) {
		t.Fatalf("match = %+v", m)
	}
	want := "nas01 runs Photo Station 6.1.2. Vedette has not checked whether this version is in the affected range; compare it with the vendor advisory or run a scan."
	if m.Evidence.Summary != want {
		t.Fatalf("summary = %q", m.Evidence.Summary)
	}
}

func TestMatchAsset_NoVersionIsOneItemNotAFinding(t *testing.T) {
	t.Parallel()
	res := MatchAsset(nas(""), []Vuln{qnapVuln(), {CVE: "CVE-2023-0001", Vendor: "QNAP", Product: "Photo Station"}}, nil, t0)
	if len(res.New)+len(res.Existing) != 0 || len(res.NeedVersion) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if n := res.NeedVersion[0]; n.SoftwareID != "s-1" || n.Software != "Photo Station" || !slices.Equal(n.CVEs, []string{"CVE-2022-27593", "CVE-2023-0001"}) {
		t.Fatalf("item = %+v", n)
	}
}

// D-505: a "Multiple Products" entry is keyed by the vendor, but only NVD can tie it to the software: no NVD data gives no
// finding (a vendor-wide guess), and an NVD entry that may name the software (product ANY) gives a product finding.
func TestMatchAsset_MultipleProductsMatchesVendor(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a", Name: "fw", Software: []Software{{ID: "s", Display: "FortiOS", Version: "7.0.1", KevKeys: []string{"fortinet|fortios"}}}}
	v := Vuln{CVE: "CVE-2023-0001", Vendor: "Fortinet", Product: "Multiple Products", EPSS: 0.1}
	if r := MatchAsset(a, []Vuln{v}, nil, t0); len(r.New) != 0 {
		t.Fatalf("no NVD data yet, but a finding: %+v", r)
	}
	v.Affected = []Affected{{CPE: "cpe:2.3:o:fortinet:*:*:*:*:*:*:*:*:*"}}
	m := MatchAsset(a, []Vuln{v}, nil, t0).New[0]
	if m.Basis != BasisProduct || m.Confidence != 0.3 {
		t.Fatalf("match = %+v", m)
	}
	want := "fw runs FortiOS 7.0.1. CISA lists this flaw for several Fortinet products; check the advisory to see whether yours is one of them."
	if m.Evidence.Summary != want {
		t.Fatalf("summary = %q", m.Evidence.Summary)
	}
	other := Vuln{CVE: "CVE-2023-0002", Vendor: "Cisco", Product: "Multiple Products"}
	if r := MatchAsset(a, []Vuln{other}, nil, t0); len(r.New) != 0 {
		t.Fatalf("other vendor matched: %+v", r)
	}
}

func TestMatchAsset_KeyNormalisation(t *testing.T) {
	t.Parallel()
	a := nas("1")
	a.Software[0].KevKeys = []string{" QNAP | Photo Station "}
	v := Vuln{CVE: "CVE-2022-27593", Vendor: " qnap", Product: "PHOTO STATION "}
	if r := MatchAsset(a, []Vuln{v}, nil, t0); len(r.New) != 1 {
		t.Fatalf("normalised key did not match: %+v", r)
	}
	if got := KevKey(" QNAP ", " Photo Station"); got != "qnap|photo station" {
		t.Fatalf("KevKey = %q", got)
	}
	if got := NormalizeKevKey("Microsoft | Windows"); got != "microsoft|windows" {
		t.Fatalf("NormalizeKevKey = %q", got)
	}
	// no key, no match (the matcher does not guess from display names)
	b := nas("1")
	b.Software[0].KevKeys = nil
	if r := MatchAsset(b, []Vuln{qnapVuln()}, nil, t0); len(r.New) != 0 {
		t.Fatalf("matched without a KEV key: %+v", r)
	}
}

func TestMatchAsset_Severity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ransom bool
		epss   float64
		want   Severity
	}{
		{false, 0, SeverityHigh}, {false, 0.49, SeverityHigh}, {false, 0.5, SeverityCritical}, {true, 0, SeverityCritical},
	}
	for _, tt := range tests {
		v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "2"}})
		v.Ransomware, v.EPSS = tt.ransom, tt.epss
		if got := MatchAsset(nas("1"), []Vuln{v}, nil, t0).New[0].Severity; got != tt.want {
			t.Errorf("ransom=%v epss=%v: severity %s, want %s", tt.ransom, tt.epss, got, tt.want)
		}
		// a version that could not be compared is never more than medium (D-500)
		v.Affected = nil
		if got := MatchAsset(nas("1"), []Vuln{v}, nil, t0).New[0].Severity; got != SeverityMedium {
			t.Errorf("ransom=%v epss=%v, no range: severity %s, want medium", tt.ransom, tt.epss, got)
		}
	}
}

const (
	qnapCPE  = `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*`
	rangeCPE = `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*`
)

func TestMatchAsset_VersionRanges(t *testing.T) {
	t.Parallel()
	r := VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}
	tests := []struct {
		name    string
		version string
		af      []Affected
		want    Basis // "" = no finding
		conf    float64
	}{
		{"inside range", "6.1.1", []Affected{{CPE: qnapCPE, Range: r}}, BasisVersion, 0.7},
		{"fixed version", "6.1.2", []Affected{{CPE: qnapCPE, Range: r}}, "", 0},
		{"below range", "5.9", []Affected{{CPE: qnapCPE, Range: r}}, "", 0},
		{"vendor string inside", "6.1.1 build 2020", []Affected{{CPE: qnapCPE, Range: r}}, BasisVersion, 0.7},
		{"version unknown", "", []Affected{{CPE: qnapCPE, Range: r}}, needVersion, 0},
		{"version not comparable", "latest", []Affected{{CPE: qnapCPE, Range: r}}, needVersion, 0},
		{"build of the start release", "6.0-1234", []Affected{{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.0-2000"}}}, BasisVersion, 0.7},
		{"same text as an exact unordered version", "15.2(4)M3", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:15.2\(4\)m3:*:*:*:*:*:*:*`}}, BasisVersion, 0.7},
		{"year against a small number is not compared", "16.0.1", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:2016:*:*:*:*:*:*:*`}}, BasisProduct, 0.5},
		{"no configs", "9.9", nil, BasisProduct, 0.5},
		{"all versions affected", "9.9", []Affected{{CPE: qnapCPE}}, BasisVersion, 0.7},
		{"second config hits", "7.1", []Affected{{CPE: qnapCPE, Range: r}, {CPE: qnapCPE, Range: VersionRange{StartIncl: "7.0", EndExcl: "7.2"}}}, BasisVersion, 0.7},
		{"exact version in cpe", "6.1.1", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1:*:*:*:*:*:*:*`}}, "", 0},
		{"exact version in cpe hit", "6.1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1.0:*:*:*:*:*:*:*`}}, BasisVersion, 0.7},
		{"config for another product is ignored", "1.0", []Affected{{CPE: `cpe:2.3:a:qnap:qts:*:*:*:*:*:*:*:*`, Range: VersionRange{StartIncl: "9"}}}, BasisProduct, 0.5},
		{"malformed config ignored", "1.0", []Affected{{CPE: "garbage", Range: r}}, BasisProduct, 0.5},
		{"NA version in cpe is not decidable", "1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:-:*:*:*:*:*:*:*`}}, BasisProduct, 0.5},
		{"unknown beats no", "6.5", []Affected{{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1"}}, {CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}}}, BasisProduct, 0.5},
		{"plain release is not the pinned beta (D-500)", "6.1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1.0:beta1:*:*:*:*:*:*`}}, "", 0},
		{"update-pinned config cannot say yes", "6.1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1.0:p1:*:*:*:*:*:*`}}, BasisProduct, 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(nas(tt.version), []Vuln{qnapVuln(tt.af...)}, nil, t0)
			if tt.want == "" || tt.want == needVersion {
				if len(res.New) != 0 || (len(res.NeedVersion) == 1) != (tt.want == needVersion) {
					t.Fatalf("expected no finding (%s), got %+v", tt.want, res)
				}
				return
			}
			if len(res.New) != 1 || res.New[0].Basis != tt.want || res.New[0].Confidence != tt.conf {
				t.Fatalf("got %+v, want basis %s conf %v", res.New, tt.want, tt.conf)
			}
		})
	}
}

func TestMatchAsset_VersionEvidenceText(t *testing.T) {
	t.Parallel()
	af := Affected{CPE: rangeCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}}
	m := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln(af)}, nil, t0).New[0]
	want := "nas01 runs Photo Station 6.1.1. Its version is inside the range affected by CVE-2022-27593 (6.0 or later, before 6.1.2); no scan has confirmed it yet, so this is only suspected."
	if m.Evidence.Summary != want {
		t.Fatalf("summary = %q", m.Evidence.Summary)
	}
}

func TestMatchAsset_SoftwareCPEIdentity(t *testing.T) {
	t.Parallel()
	// the software has a CPE and different names from NVD's: the CPE decides which config applies
	a := Asset{ID: "a", Name: "srv", Software: []Software{{
		ID: "s", Display: "Apache", Version: "2.4.50", KevKeys: []string{"apache|http server"},
		CPE: `cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*`,
	}}}
	v := Vuln{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server", Affected: []Affected{
		{CPE: `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`},
		{CPE: `cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*`},
	}}
	if res := MatchAsset(a, []Vuln{v}, nil, t0); len(res.New) != 1 || res.New[0].Basis != BasisVersion {
		t.Fatalf("got %+v", res)
	}
	a.Software[0].Version = ""
	a.Software[0].CPE = `cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*` // version taken from the CPE
	if res := MatchAsset(a, []Vuln{v}, nil, t0); len(res.New) != 0 {
		t.Fatalf("2.4.51 should be outside: %+v", res)
	}
}

func TestMatchAsset_ExistingIsExplicitAndNotRecreated(t *testing.T) {
	t.Parallel()
	vulns := []Vuln{qnapVuln(), {CVE: "CVE-2023-0001", Vendor: "QNAP", Product: "Photo Station"}}
	have := map[string]bool{"CVE-2022-27593": true}
	res := MatchAsset(nas("1"), vulns, have, t0)
	if len(res.New) != 1 || res.New[0].CVE != "CVE-2023-0001" || len(res.Existing) != 1 || res.Existing[0].CVE != "CVE-2022-27593" {
		t.Fatalf("result = %+v", res)
	}
}

func TestMatchAsset_OneMatchPerCVEStrongestWins(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a", Name: "pc", Software: []Software{
		{ID: "old", Display: "Photo Station", Version: "9.0", KevKeys: []string{"qnap|photo station"}},
		{ID: "new", Display: "Photo Station", Version: "6.1.1", KevKeys: []string{"qnap|photo station"}},
	}}
	af := Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}
	dup := []Vuln{qnapVuln(af), qnapVuln(af)}
	res := MatchAsset(a, dup, nil, t0)
	if len(res.New) != 1 || res.New[0].SoftwareID != "new" || res.New[0].Basis != BasisVersion {
		t.Fatalf("result = %+v", res)
	}
}

func TestMatchAsset_SkipsInvalidCVE(t *testing.T) {
	t.Parallel()
	v := qnapVuln()
	for _, bad := range []string{"", "CVE-22-1", "cve-2022-27593", "CVE-2022-123", "CVE-2022-12a4", "CVE-2022-27593 "} {
		v.CVE = bad
		if r := MatchAsset(nas("1"), []Vuln{v}, nil, t0); len(r.New) != 0 {
			t.Errorf("CVE %q was accepted", bad)
		}
	}
	if !ValidCVE("CVE-2022-27593") || !ValidCVE("CVE-1999-0001") || !ValidCVE("CVE-2024-1234567") {
		t.Error("valid CVE rejected")
	}
}

func TestMatchAsset_EvidenceTextIsCleaned(t *testing.T) {
	t.Parallel()
	a := nas("1.2")
	a.Name = "evil\x1b[31m" + strings.Repeat("x", 300)
	a.Software[0].Display = "Photo\x00 Station\n"
	m := MatchAsset(a, []Vuln{qnapVuln()}, nil, t0).New[0]
	for _, r := range m.Evidence.Summary {
		if unicode.IsControl(r) {
			t.Fatalf("control character in summary %q", m.Evidence.Summary)
		}
	}
	a.Software[0].Version = "n/a\x00\n" // no number: the add-the-version item (a version with a number is a product finding, H1)
	n := MatchAsset(a, []Vuln{qnapVuln()}, nil, t0).NeedVersion[0]
	for _, r := range n.Software + n.Version {
		if unicode.IsControl(r) {
			t.Fatalf("control character in item %+v", n)
		}
	}
	if len(m.Evidence.Summary) > 700 {
		t.Fatalf("summary not capped: %d bytes", len(m.Evidence.Summary))
	}
}

func FuzzMatchAsset(f *testing.F) {
	f.Add("QNAP", "Photo Station", "6.1.1", "qnap|photo station", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*`, "6.0", "6.1.2", "CVE-2022-27593")
	f.Add("x", "Multiple Products", "", "x|y", "", "", "", "CVE-2020-0001")
	f.Add("", "", "weird", "|", "cpe:2.3:a:::::::::::", "a", "b", "CVE-1-1")
	f.Add("QNAP", "Photo Station", "weird", "x", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*`, "6.0", "6.1.2", "CVE-2022-27593")
	f.Add("QNAP", "Photo Station", "0.0.0", "x", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*`, "6.0", "6.1.2", "CVE-2022-27593")
	f.Add("QNAP", "Photo Station", "9.9", "x", "garbage", "6.0", "6.1.2", "CVE-2022-27593")
	f.Add("QNAP", "Photo Station", "", "x", "", "6.0", "6.1.2", "CVE-2022-27593")
	f.Fuzz(func(t *testing.T, vendor, product, version, key, cpe, lo, hi, cve string) {
		a := Asset{ID: "a", Name: vendor, Software: []Software{{ID: "s", Display: product, Vendor: vendor, Product: product, Version: version, KevKeys: []string{key, KevKey(vendor, product)}, CPE: cpe}}}
		v := Vuln{CVE: cve, Vendor: vendor, Product: product, Affected: []Affected{
			{CPE: cpe, Range: VersionRange{StartIncl: lo, EndExcl: hi}},
			{CPE: qnapCPE},
		}}
		res := MatchAsset(a, []Vuln{v, v}, map[string]bool{cve: len(key)%2 == 0}, t0)
		all := append(append([]Match{}, res.New...), res.Existing...)
		if len(all) > 1 {
			t.Fatalf("more than one match for one CVE: %+v", all)
		}
		// Oracle (review): a KEV-key match is never dropped when the version is empty,
		// unreadable or a placeholder, or when an Affected entry cannot be read: it is a
		// finding or, without a usable version, the software's "add the version" item (D-500).
		eff := version
		sc, scErr := ParseCPE(cpe)
		if eff == "" && scErr == nil {
			eff, _ = sc.Version.Literal()
		}
		if ValidCVE(cve) && !strings.Contains(vendor+product, "|") && (!versionKnown(eff) || scErr != nil) && len(all)+len(res.NeedVersion) != 1 {
			t.Fatalf("undecidable input dropped a KEV match: version=%q cpe=%q -> %+v", version, cpe, res)
		}
		for _, m := range all {
			if !ValidCVE(m.CVE) || m.Confidence <= 0 || m.Confidence > 1 || rank(m.Basis) == 0 || m.Basis == BasisScan {
				t.Fatalf("bad match %+v", m)
			}
			if m.Severity != SeverityHigh && m.Severity != SeverityCritical && m.Severity != SeverityMedium {
				t.Fatalf("bad severity %+v", m)
			}
			if nf, _ := NewFinding(m, t0); nf.Validate() != nil {
				t.Fatalf("NewFinding produced an invalid finding: %v", nf.Validate())
			}
		}
	})
}

func sshHost(version, cpe string) Asset {
	return Asset{ID: "a", Name: "gw", Software: []Software{
		{ID: "s", Display: "OpenSSH", Vendor: "OpenSSH", Product: "OpenSSH", Version: version, KevKeys: []string{"openbsd|openssh"}, CPE: cpe},
	}}
}

func sshVuln(cfg ...string) Vuln {
	v := Vuln{CVE: "CVE-2024-6387", Vendor: "OpenBSD", Product: "OpenSSH"}
	for _, c := range cfg {
		v.Affected = append(v.Affected, Affected{CPE: c})
	}
	return v
}

func basisOf(t *testing.T, res MatchResult) Basis {
	t.Helper()
	all := append(append([]Match{}, res.New...), res.Existing...)
	if len(all) == 0 {
		if len(res.NeedVersion) > 0 {
			return needVersion
		}
		return ""
	}
	return all[0].Basis
}

// needVersion is what basisOf reports for no finding but an "add the version" item (D-500).
const needVersion Basis = "need-version"

// Regression: a configuration pinned to an update must not drop a software whose
// version string carries that update (review bug 2).
func TestMatchAsset_UpdatePinnedConfig(t *testing.T) {
	t.Parallel()
	const pinned = `cpe:2.3:a:openssh:openssh:8.9:p1:*:*:*:*:*:*`
	tests := []struct {
		name, version, swCPE string
		cfg                  string
		want                 Basis // "" = dropped
	}{
		{"8.9p1 against 8.9:p1", "8.9p1", "", pinned, BasisVersion},
		{"8.9p2 against 8.9:p1 is another release (review H1: h1 is not h2)", "8.9p2", "", pinned, ""},
		{"8.8p1 is outside", "8.8p1", "", pinned, ""},
		{"plain 8.9 does not say which update", "8.9", "", pinned, BasisProduct},
		{"update from the software CPE", "8.9", `cpe:2.3:a:openssh:openssh:8.9:p1:*:*:*:*:*:*`, pinned, BasisVersion},
		{"other update in the software CPE", "8.9", `cpe:2.3:a:openssh:openssh:8.9:p2:*:*:*:*:*:*`, pinned, ""},
		{"beta1 against 2.0:beta1", "2.0-beta1", "", `cpe:2.3:a:openssh:openssh:2.0:beta1:*:*:*:*:*:*`, BasisVersion},
		{"plain 2.0 against 2.0:beta1 is the release, not the beta (D-500)", "2.0", "", `cpe:2.3:a:openssh:openssh:2.0:beta1:*:*:*:*:*:*`, ""},
		{"beta2 against 2.0:beta1 is another release", "2.0-beta2", "", `cpe:2.3:a:openssh:openssh:2.0:beta1:*:*:*:*:*:*`, ""},
		{"beta against 2.0:beta1 is undecided (no number)", "2.0-beta", "", `cpe:2.3:a:openssh:openssh:2.0:beta1:*:*:*:*:*:*`, BasisProduct},
		{"rc against 2.0:beta1 differs", "2.0-rc1", "", `cpe:2.3:a:openssh:openssh:2.0:beta1:*:*:*:*:*:*`, ""},
		{"wildcard update (bug 7)", "2.0", `cpe:2.3:a:openssh:openssh:2.0:beta2:*:*:*:*:*:*`, `cpe:2.3:a:openssh:openssh:2.0:beta*:*:*:*:*:*:*`, BasisVersion},
		{"wildcard update other prefix", "2.0", `cpe:2.3:a:openssh:openssh:2.0:rc2:*:*:*:*:*:*`, `cpe:2.3:a:openssh:openssh:2.0:beta*:*:*:*:*:*:*`, ""},
		{"update ANY covers 8.9p1 (not dropped)", "8.9p1", "", `cpe:2.3:a:openssh:openssh:8.9:*:*:*:*:*:*:*`, BasisProduct},
		{"update ANY, really other version", "9.0p1", "", `cpe:2.3:a:openssh:openssh:8.9:*:*:*:*:*:*:*`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(sshHost(tt.version, tt.swCPE), []Vuln{sshVuln(tt.cfg)}, nil, t0)
			if got := basisOf(t, res); got != tt.want {
				t.Fatalf("basis = %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression: an Affected entry that cannot be read must cap the result at
// "unknown" so a sibling entry cannot drop the finding (review risk 4).
func TestMatchAsset_UnparseableSiblingNeverDrops(t *testing.T) {
	t.Parallel()
	outside := Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "1.0"}}
	for name, bad := range map[string]string{
		"garbage":          "garbage",
		"non-ascii":        "cpe:2.3:a:qnap:photo_statión:*:*:*:*:*:*:*:*",
		"too long":         "cpe:2.3:a:qnap:" + strings.Repeat("a", 2000) + ":*:*:*:*:*:*:*:*",
		"part NA":          `cpe:2.3:-:qnap:photo_station:*:*:*:*:*:*:*:*`,
		"vendor ANY":       `cpe:2.3:a:*:*:*:*:*:*:*:*:*:*`,
		"product wildcard": `cpe:2.3:a:qnap:photo_*:*:*:*:*:*:*:*:*`,
		"empty":            "",
	} {
		res := MatchAsset(nas("9.9"), []Vuln{qnapVuln(outside, Affected{CPE: bad})}, nil, t0)
		if got := basisOf(t, res); got != BasisProduct {
			t.Errorf("%s: basis = %q, want product", name, got)
		}
	}
	// without the bad sibling the same data is a definite No
	if res := MatchAsset(nas("9.9"), []Vuln{qnapVuln(outside)}, nil, t0); len(res.New) != 0 {
		t.Fatalf("control case matched: %+v", res)
	}
	// a readable Yes still wins over a bad sibling
	yes := Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "10"}}
	if got := basisOf(t, MatchAsset(nas("9.9"), []Vuln{qnapVuln(Affected{CPE: "garbage"}, yes)}, nil, t0)); got != BasisVersion {
		t.Fatalf("basis = %q", got)
	}
}

// Regression: all-zero versions are "unknown" placeholders (review risk 5).
func TestMatchAsset_PlaceholderVersionIsNotEvidence(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"0", "0.0.0", "0.0.0.0"} {
		for _, r := range []VersionRange{{StartIncl: "6.0", EndExcl: "6.1.2"}, {EndExcl: "6.1.2"}} {
			res := MatchAsset(nas(v), []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: r})}, nil, t0)
			if got := basisOf(t, res); got != needVersion {
				t.Errorf("version %q range %+v: basis = %q, want the add-the-version item", v, r, got)
			}
		}
	}
}

// Regression: a configuration that pins attributes the software does not carry
// must not give basis=version (review risk 6).
func TestMatchAsset_PinnedAttributesNeedSoftwareSupport(t *testing.T) {
	t.Parallel()
	r := VersionRange{EndExcl: "10"}
	tests := []struct {
		name, cfg, swCPE string
		want             Basis
	}{
		{"target_sw pinned, software silent", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:wordpress:*:*`, "", BasisProduct},
		{"edition pinned, software silent", `cpe:2.3:a:qnap:photo_station:*:*:pro:*:*:*:*:*`, "", BasisProduct},
		{"language pinned", `cpe:2.3:a:qnap:photo_station:*:*:*:fr:*:*:*:*`, "", BasisProduct},
		{"sw_edition pinned", `cpe:2.3:a:qnap:photo_station:*:*:*:*:enterprise:*:*:*`, "", BasisProduct},
		{"target_hw pinned", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:x64:*`, "", BasisProduct},
		{"other pinned", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:special`, "", BasisProduct},
		{"target_sw pinned and software agrees", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:wordpress:*:*`, `cpe:2.3:a:qnap:photo_station:1.0:*:*:*:*:wordpress:*:*`, BasisVersion},
		{"target_sw pinned and software disagrees", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:wordpress:*:*`, `cpe:2.3:a:qnap:photo_station:1.0:*:*:*:*:drupal:*:*`, ""},
		{"target_sw pinned and software ANY", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:wordpress:*:*`, `cpe:2.3:a:qnap:photo_station:1.0:*:*:*:*:*:*:*`, BasisProduct},
		{"nothing pinned", `cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*`, "", BasisVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := nas("1.0")
			a.Software[0].CPE = tt.swCPE
			res := MatchAsset(a, []Vuln{qnapVuln(Affected{CPE: tt.cfg, Range: r})}, nil, t0)
			if got := basisOf(t, res); got != tt.want {
				t.Fatalf("basis = %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression: an unknown version is not a version match even when every version
// is affected (review nit); review M4: it is a product finding, not "add the
// version", because the answer does not depend on the version.
func TestMatchAsset_AllVersionsWithUnknownVersionIsProduct(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"", "latest"} {
		res := MatchAsset(nas(v), []Vuln{qnapVuln(Affected{CPE: qnapCPE})}, nil, t0)
		if got := basisOf(t, res); got != BasisProduct || len(res.NeedVersion) != 0 {
			t.Errorf("version %q: basis = %q (need %d), want a product finding", v, got, len(res.NeedVersion))
		}
	}
	if got := basisOf(t, MatchAsset(nas("2.1"), []Vuln{qnapVuln(Affected{CPE: qnapCPE})}, nil, t0)); got != BasisVersion {
		t.Errorf("known version, all affected: %q", got)
	}
}

// Regression: tails at the boundary go through the matcher too.
func TestMatchAsset_BuildTailAtBoundaryIsNotDropped(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a", Name: "adc", Software: []Software{{ID: "s", Display: "NetScaler", Vendor: "Citrix", Product: "NetScaler", Version: "13.1-48.47", KevKeys: []string{"citrix|netscaler"}}}}
	v := Vuln{CVE: "CVE-2023-4966", Vendor: "Citrix", Product: "NetScaler", Affected: []Affected{
		{CPE: `cpe:2.3:a:citrix:netscaler:*:*:*:*:*:*:*:*`, Range: VersionRange{StartIncl: "13.1", EndExcl: "13.1-49.15"}},
	}}
	if got := basisOf(t, MatchAsset(a, []Vuln{v}, nil, t0)); got == "" {
		t.Fatal("13.1-48.47 is before the fixed 13.1-49.15 and must not be dropped")
	}
	a.Software[0].Version = "13.1-49.15"
	if got := basisOf(t, MatchAsset(a, []Vuln{v}, nil, t0)); got != "" {
		t.Fatalf("the fixed build matched: %q", got)
	}
}

// TestMatchAsset_KevKeyAloneProvesNothing: review N1 of #663. A software found only by its KEV key (its own name is
// something else) with a version outside the range keeps a product finding and is never closed: the version may be of
// another thing than the product the range is about.
func TestMatchAsset_KevKeyAloneProvesNothing(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a-1", Name: "nas01", Software: []Software{
		{ID: "s-1", Display: "QNAP NAS", Vendor: "QNAP", Product: "QTS", Version: "6.2.0", KevKeys: []string{"qnap|photo station"}},
	}}
	v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	for _, have := range []map[string]bool{nil, {v.CVE: true}} {
		res := MatchAsset(a, []Vuln{v}, have, t0)
		got := append(slices.Clone(res.New), res.Existing...)
		if len(got) != 1 || got[0].Basis != BasisProduct || got[0].Severity != SeverityMedium || len(res.NotAffected) != 0 {
			t.Fatalf("have %v: result = %+v", have, res)
		}
	}
	a.Software[0].Product = "Photo Station" // its own name: now the range proves it
	if res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, t0); len(res.NotAffected) != 1 {
		t.Fatalf("own name: result = %+v", res)
	}
}

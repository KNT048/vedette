package findings

import (
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
	if m.Basis != BasisProduct || m.Confidence != 0.5 || m.Severity != SeverityHigh || !m.Evidence.CheckedAt.Equal(t0) {
		t.Fatalf("match = %+v", m)
	}
	want := "nas01 runs Photo Station 6.1.2. Vedette has not checked whether this version is in the affected range; compare it with the vendor advisory or run a scan."
	if m.Evidence.Summary != want {
		t.Fatalf("summary = %q", m.Evidence.Summary)
	}
}

func TestMatchAsset_NoVersionOmitsVersionInText(t *testing.T) {
	t.Parallel()
	m := MatchAsset(nas(""), []Vuln{qnapVuln()}, nil, t0).New[0]
	if !strings.HasPrefix(m.Evidence.Summary, "nas01 runs Photo Station. Vedette has not") {
		t.Fatalf("summary = %q", m.Evidence.Summary)
	}
}

func TestMatchAsset_MultipleProductsMatchesVendor(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "a", Name: "fw", Software: []Software{{ID: "s", Display: "FortiOS", Version: "7.0.1", KevKeys: []string{"fortinet|fortios"}}}}
	v := Vuln{CVE: "CVE-2023-0001", Vendor: "Fortinet", Product: "Multiple Products", EPSS: 0.1}
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
		v := qnapVuln()
		v.Ransomware, v.EPSS = tt.ransom, tt.epss
		if got := MatchAsset(nas("1"), []Vuln{v}, nil, t0).New[0].Severity; got != tt.want {
			t.Errorf("ransom=%v epss=%v: severity %s, want %s", tt.ransom, tt.epss, got, tt.want)
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
		{"version unknown", "", []Affected{{CPE: qnapCPE, Range: r}}, BasisProduct, 0.5},
		{"version not comparable", "latest", []Affected{{CPE: qnapCPE, Range: r}}, BasisProduct, 0.5},
		{"no configs", "9.9", nil, BasisProduct, 0.5},
		{"all versions affected", "9.9", []Affected{{CPE: qnapCPE}}, BasisVersion, 0.7},
		{"second config hits", "7.1", []Affected{{CPE: qnapCPE, Range: r}, {CPE: qnapCPE, Range: VersionRange{StartIncl: "7.0", EndExcl: "7.2"}}}, BasisVersion, 0.7},
		{"exact version in cpe", "6.1.1", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1:*:*:*:*:*:*:*`}}, "", 0},
		{"exact version in cpe hit", "6.1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1.0:*:*:*:*:*:*:*`}}, BasisVersion, 0.7},
		{"config for another product is ignored", "1.0", []Affected{{CPE: `cpe:2.3:a:qnap:qts:*:*:*:*:*:*:*:*`, Range: VersionRange{StartIncl: "9"}}}, BasisProduct, 0.5},
		{"malformed config ignored", "1.0", []Affected{{CPE: "garbage", Range: r}}, BasisProduct, 0.5},
		{"NA version in cpe is not decidable", "1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:-:*:*:*:*:*:*:*`}}, BasisProduct, 0.5},
		{"unknown beats no", "6.5", []Affected{{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1"}}, {CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}}}, BasisProduct, 0.5},
		{"update-pinned config cannot say yes", "6.1.0", []Affected{{CPE: `cpe:2.3:a:qnap:photo_station:6.1.0:beta1:*:*:*:*:*:*`}}, BasisProduct, 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(nas(tt.version), []Vuln{qnapVuln(tt.af...)}, nil, t0)
			if tt.want == "" {
				if len(res.New) != 0 {
					t.Fatalf("expected no finding, got %+v", res.New)
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
	a := nas("1\x00.\n2")
	a.Name = "evil\x1b[31m" + strings.Repeat("x", 300)
	m := MatchAsset(a, []Vuln{qnapVuln()}, nil, t0).New[0]
	for _, r := range m.Evidence.Summary {
		if unicode.IsControl(r) {
			t.Fatalf("control character in summary %q", m.Evidence.Summary)
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
	f.Fuzz(func(t *testing.T, vendor, product, version, key, cpe, lo, hi, cve string) {
		a := Asset{ID: "a", Name: vendor, Software: []Software{{ID: "s", Display: product, Vendor: vendor, Product: product, Version: version, KevKeys: []string{key}, CPE: cpe}}}
		v := Vuln{CVE: cve, Vendor: vendor, Product: product, Affected: []Affected{
			{CPE: cpe, Range: VersionRange{StartIncl: lo, EndExcl: hi}},
			{CPE: qnapCPE},
		}}
		res := MatchAsset(a, []Vuln{v, v}, map[string]bool{cve: len(key)%2 == 0}, t0)
		all := append(append([]Match{}, res.New...), res.Existing...)
		if len(all) > 1 {
			t.Fatalf("more than one match for one CVE: %+v", all)
		}
		for _, m := range all {
			if !ValidCVE(m.CVE) || m.Confidence <= 0 || m.Confidence > 1 || rank(m.Basis) == 0 || m.Basis == BasisScan {
				t.Fatalf("bad match %+v", m)
			}
			if m.Severity != SeverityHigh && m.Severity != SeverityCritical {
				t.Fatalf("bad severity %+v", m)
			}
			if nf, _ := NewFinding(m, t0); nf.Validate() != nil {
				t.Fatalf("NewFinding produced an invalid finding: %v", nf.Validate())
			}
		}
	})
}

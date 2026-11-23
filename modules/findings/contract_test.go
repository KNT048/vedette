package findings

import (
	"testing"

	"github.com/knt048/vedette/core/productid"
)

func TestContract_INV1_UniquePair(t *testing.T) {
	t.Parallel()
	// two software rows and a repeated KEV entry still give one result per CVE
	a := nas("6.1.1")
	a.Software = append(a.Software, Software{ID: "s-2", Display: "Photo Station", Version: "6.0", KevKeys: []string{"qnap|photo station"}})
	res := MatchAsset(a, []Vuln{qnapScanned(), qnapScanned()}, nil, t0)
	if len(res.New)+len(res.Existing) != 1 {
		t.Fatalf("want one result for one (asset, cve): %+v", res)
	}
}

func TestContract_INV3_ErrorsMapToAPICodes(t *testing.T) {
	t.Parallel()
	want := map[*APIError][2]any{
		ErrNotFound:     {404, "not_found"},
		ErrBadAction:    {400, "bad_action"},
		ErrNoteTooLong:  {400, "note_too_long"},
		ErrNoteRequired: {400, "note_required"},
		ErrAlreadyOpen:  {409, "already_open"},
	}
	for e, w := range want {
		if e.HTTP != w[0] || e.Code != w[1] || e.Message == "" {
			t.Errorf("%v: %d %s", e, e.HTTP, e.Code)
		}
	}
}

func TestContract_INV4_KeyAndRanges(t *testing.T) {
	t.Parallel()
	af := Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}}
	// key is vendorproject|product, lower case, trimmed
	if productid.Key(" QNAP", "Photo Station ") != "qnap|photo station" {
		t.Error("KevKey")
	}
	// multiple products are keyed by vendor, but only an NVD entry naming the software gives a finding
	multi := Vuln{CVE: "CVE-2023-0001", Vendor: "QNAP", Product: "Multiple products"}
	if r := MatchAsset(nas("1"), []Vuln{multi}, nil, t0); len(r.New) != 0 {
		t.Errorf("multiple products without NVD data: %+v", r)
	}
	multi.Affected = []Affected{{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}}
	if r := MatchAsset(nas("6.1.1"), []Vuln{multi}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Errorf("multiple products naming the software: %+v", r)
	}
	// inside the range: version; outside every range: nothing
	if r := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln(af)}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Errorf("inside: %+v", r)
	}
	if r := MatchAsset(nas("6.1.2"), []Vuln{qnapVuln(af)}, nil, t0); len(r.New)+len(r.Existing) != 0 {
		t.Errorf("outside: %+v", r)
	}
	// a usable version that cannot be compared: no finding, by the product name only (before, product, medium)
	if r := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "next"}})}, nil, t0); len(r.New) != 0 || len(r.NameOnly) != 1 || r.NameOnly[0].Basis != BasisProduct || r.NameOnly[0].Severity != SeverityMedium {
		t.Errorf("not comparable: %+v", r)
	}
	// no usable version: no finding, one "add the version" item
	if r := MatchAsset(nas("nightly"), []Vuln{qnapVuln(af)}, nil, t0); len(r.New) != 0 || len(r.NeedVersion) != 1 {
		t.Errorf("no usable version: %+v", r)
	}
}

func TestContract_INV5_Severity(t *testing.T) {
	t.Parallel()
	in := Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "2"}}
	hi, rw, ep, unchecked := qnapVuln(in), qnapVuln(in), qnapVuln(in), qnapScanned()
	rw.Ransomware, ep.EPSS, unchecked.Ransomware = true, 0.5, true
	for v, want := range map[*Vuln]Severity{&hi: SeverityHigh, &rw: SeverityCritical, &ep: SeverityCritical, &unchecked: SeverityMedium} {
		if got := MatchAsset(nas("1"), []Vuln{*v}, nil, t0).New[0].Severity; got != want {
			t.Errorf("ransomware=%v epss=%v: %s want %s", v.Ransomware, v.EPSS, got, want)
		}
	}
}

func TestContract_PRE1_CVEFormat(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"CVE-2022-27593": true, "CVE-2022-0001": true, "CVE-2022-123": false, "CVE-22-1234": false, "": false, "CVE-2022-27593\n": false,
	} {
		if ValidCVE(s) != want {
			t.Errorf("ValidCVE(%q) != %v", s, want)
		}
	}
}

func TestContract_FORBID4_NoGuessWhenNotComparable(t *testing.T) {
	t.Parallel()
	if _, ok := CompareVersions("latest", "1.0"); ok {
		t.Fatal("incomparable versions compared")
	}
	if got := (VersionRange{StartIncl: "6.0"}).Contains("latest"); got != Unknown {
		t.Fatalf("Contains = %v, want unknown", got)
	}
	af := Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}
	r := MatchAsset(nas("latest"), []Vuln{qnapVuln(af)}, nil, t0) // no claim either way: the add-the-version item
	if len(r.New) != 0 || len(r.NeedVersion) != 1 || r.NeedVersion[0].CVEs[0] != "CVE-2022-27593" {
		t.Fatalf("result = %+v", r)
	}
}

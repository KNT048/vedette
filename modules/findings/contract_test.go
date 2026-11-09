package findings

import (
	"errors"
	"strings"
	"testing"
	"time"
)
// Contract tests for modules/findings/CONTRACT.md. The pure-library ones are here; the ones that need
// the database, the service, the endpoints and the events are in service_test.go and handlers_test.go.
// and audit need the service layer (WP-21).

func TestContract_INV1_UniquePair(t *testing.T) {
	t.Parallel()
	// two software rows and a repeated KEV entry still give one result per CVE
	a := nas("6.1.1")
	a.Software = append(a.Software, Software{ID: "s-2", Display: "Photo Station", Version: "6.0", KevKeys: []string{"qnap|photo station"}})
	res := MatchAsset(a, []Vuln{qnapVuln(), qnapVuln()}, nil, t0)
	if len(res.New)+len(res.Existing) != 1 {
		t.Fatalf("want one result for one (asset, cve): %+v", res)
	}
}

func TestContract_INV2_StatusBasisConfidence(t *testing.T) {
	t.Parallel()
	for _, s := range []Status{StatusConfirmed, StatusSuspected, StatusMitigated, StatusPatched, StatusFalsePositive, StatusNotRelevant} {
		if !s.valid() {
			t.Errorf("status %s not valid", s)
		}
	}
	// every finding the library creates or transitions to passes Validate
	m := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln()}, nil, t0).New[0]
	f, _ := NewFinding(m, t0)
	steps := []func(Finding) (Finding, error){
		func(f Finding) (Finding, error) {
			o, err := f.ConfirmFromScan(scanEvidence(), t0)
			return o.Finding, err
		},
		func(f Finding) (Finding, error) {
			g, _, err := f.Apply(ActionFalsePositive, "lab box", "u", t0)
			return g, err
		},
		func(f Finding) (Finding, error) { g, _, err := f.Apply(ActionReopen, "", "u", t0); return g, err },
	}
	for i, step := range steps {
		var err error
		if f, err = step(f); err != nil || f.Validate() != nil {
			t.Fatalf("step %d: err=%v validate=%v finding=%+v", i, err, f.Validate(), f)
		}
	}
	if (Finding{Status: StatusConfirmed, Basis: BasisVersion, Confidence: 0.7}).Validate() == nil {
		t.Error("confirmed without scan basis and evidence accepted")
	}
	if (Finding{Status: StatusSuspected, Basis: BasisProduct, Confidence: 1.5}).Validate() == nil {
		t.Error("confidence above 1 accepted")
	}
}

func TestContract_INV2_BasisNeverDowngrades(t *testing.T) {
	t.Parallel()
	f := suspected()
	f = f.ApplyMatch(Match{Basis: BasisVersion, Confidence: ConfVersion})
	f = f.ApplyMatch(Match{Basis: BasisProduct, Confidence: ConfProduct})
	if f.Basis != BasisVersion {
		t.Fatalf("basis = %s", f.Basis)
	}
	out, _ := f.ConfirmFromScan(scanEvidence(), t0)
	if g := out.Finding.ApplyMatch(Match{Basis: BasisVersion, Confidence: ConfVersion}); g.Basis != BasisScan {
		t.Fatalf("scan basis downgraded to %s", g.Basis)
	}
}

func TestContract_INV3_StatusActions(t *testing.T) {
	t.Parallel()
	f := suspected()
	cases := []struct {
		action Action
		note   string
		err    *APIError
	}{
		{ActionPatched, "", nil}, {ActionMitigated, "", nil}, {ActionFalsePositive, "why", nil}, {ActionNotRelevant, "why", nil},
		{ActionFalsePositive, "no", ErrNoteRequired}, {ActionNotRelevant, "", ErrNoteRequired},
		{ActionPatched, strings.Repeat("x", 501), ErrNoteTooLong}, {"bogus", "", ErrBadAction}, {ActionReopen, "", ErrAlreadyOpen},
	}
	for _, c := range cases {
		_, h, err := f.Apply(c.action, c.note, "u", t0)
		if c.err == nil && (err != nil || h.Action != string(c.action)) {
			t.Errorf("%s: err=%v history=%+v", c.action, err, h)
		}
		if c.err != nil && !errors.Is(err, c.err) {
			t.Errorf("%s: err=%v want %v", c.action, err, c.err)
		}
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
	if KevKey(" QNAP", "Photo Station ") != "qnap|photo station" {
		t.Error("KevKey")
	}
	// multiple products match by vendor
	multi := Vuln{CVE: "CVE-2023-0001", Vendor: "QNAP", Product: "Multiple products"}
	if r := MatchAsset(nas("1"), []Vuln{multi}, nil, t0); len(r.New) != 1 || r.New[0].Confidence != ConfVendorOnly {
		t.Errorf("multiple products: %+v", r)
	}
	// inside the range: version; outside every range: nothing
	if r := MatchAsset(nas("6.1.1"), []Vuln{qnapVuln(af)}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisVersion {
		t.Errorf("inside: %+v", r)
	}
	if r := MatchAsset(nas("6.1.2"), []Vuln{qnapVuln(af)}, nil, t0); len(r.New)+len(r.Existing) != 0 {
		t.Errorf("outside: %+v", r)
	}
	// not comparable: falls back to product
	if r := MatchAsset(nas("nightly"), []Vuln{qnapVuln(af)}, nil, t0); len(r.New) != 1 || r.New[0].Basis != BasisProduct {
		t.Errorf("not comparable: %+v", r)
	}
}

func TestContract_INV5_Severity(t *testing.T) {
	t.Parallel()
	hi, rw, ep := qnapVuln(), qnapVuln(), qnapVuln()
	rw.Ransomware, ep.EPSS = true, 0.5
	for v, want := range map[*Vuln]Severity{&hi: SeverityHigh, &rw: SeverityCritical, &ep: SeverityCritical} {
		if got := MatchAsset(nas("1"), []Vuln{*v}, nil, t0).New[0].Severity; got != want {
			t.Errorf("ransomware=%v epss=%v: %s want %s", v.Ransomware, v.EPSS, got, want)
		}
	}
}

func TestContract_INV6_Idempotent(t *testing.T) {
	t.Parallel()
	vulns := []Vuln{qnapVuln(), {CVE: "CVE-2023-0001", Vendor: "QNAP", Product: "Photo Station"}}
	a := nas("1")
	have := map[string]bool{}
	first := MatchAsset(a, vulns, have, t0)
	for _, m := range first.New {
		have[m.CVE] = true
	}
	second := MatchAsset(a, vulns, have, t0.Add(time.Hour))
	if len(first.New) != 2 || len(second.New) != 0 || len(second.Existing) != 2 {
		t.Fatalf("first %+v second %+v", first, second)
	}
	// a closed finding is "had", so it is not recreated or reopened by a match
	f, _ := NewFinding(first.New[0], t0)
	closed, _, _ := f.Apply(ActionPatched, "", "u", t0)
	if got := closed.ApplyMatch(second.Existing[0]); got != closed {
		t.Fatalf("closed finding touched: %+v", got)
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

func TestContract_PRE2_EvidenceNeedsTemplate(t *testing.T) {
	t.Parallel()
	ev := scanEvidence()
	ev.Template = ""
	if _, err := suspected().ConfirmFromScan(ev, t0); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v", err)
	}
}

func TestContract_POST2_ScanNeverReopensClosedByPerson(t *testing.T) {
	t.Parallel()
	for _, a := range []Action{ActionFalsePositive, ActionNotRelevant} {
		closed, _, err := suspected().Apply(a, "because", "u", t0)
		if err != nil {
			t.Fatal(err)
		}
		out, err := closed.ConfirmFromScan(scanEvidence(), t0)
		if err != nil || out.Finding.Status != closed.Status || !out.Notify || len(out.History) != 1 {
			t.Fatalf("%s: %+v err=%v", a, out, err)
		}
	}
	open, err := suspected().ConfirmFromScan(scanEvidence(), t0)
	if err != nil || open.Finding.Status != StatusConfirmed || open.Finding.Basis != BasisScan || !open.Notify {
		t.Fatalf("open: %+v err=%v", open, err)
	}
	patched, _, _ := suspected().Apply(ActionPatched, "", "u", t0)
	out, _ := patched.ConfirmFromScan(scanEvidence(), t0)
	if out.Finding.Status != StatusConfirmed || out.History[0].Action != "reopened" || !out.Notify {
		t.Fatalf("patched: %+v", out)
	}
}

func TestContract_FORBID2_NothingAutoCloses(t *testing.T) {
	t.Parallel()
	if h := ScanClear(t0); h.Action != "rescan_clear" || h.User != SystemUser {
		t.Fatalf("history = %+v", h)
	}
	// no library path moves an open finding to a closed status without a person's action
	for _, from := range []Finding{suspected(), func() Finding { o, _ := suspected().ConfirmFromScan(scanEvidence(), t0); return o.Finding }()} {
		out, _ := from.ConfirmFromScan(scanEvidence(), t0)
		if !out.Finding.Status.Open() {
			t.Fatalf("scan closed a finding: %+v", out.Finding)
		}
		if !from.ApplyMatch(Match{Basis: BasisVersion, Confidence: ConfVersion}).Status.Open() {
			t.Fatal("match closed a finding")
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
	r := MatchAsset(nas("latest"), []Vuln{qnapVuln(af)}, nil, t0)
	if len(r.New) != 1 || r.New[0].Basis != BasisProduct {
		t.Fatalf("result = %+v", r)
	}
}

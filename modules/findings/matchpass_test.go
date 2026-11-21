package findings

import (
	"testing"
)

// catalogueOnly is a CVE on no exploited list: only the catalogue holds it, with NVD's ranges.
func catalogueOnly(cve, cpe, start, end string) Vuln {
	return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: cpe, Range: VersionRange{StartIncl: start, EndExcl: end}}}}
}

func fortigate(version string) Asset {
	return Asset{ID: "a-1", Name: "fw01", Software: []Software{{ID: "sw-fos", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS",
		Version: version, CPE: "cpe:2.3:o:fortinet:fortios:" + version + ":*:*:*:*:*:*:*", Source: "snmp", KevKeys: []string{"fortinet|fortios"}}}}
}

// A CVE on no exploited list that the device's version is inside a bounded range of is a finding like any other (a range with no end
// says something only for an entry CISA's key reaches), with the fix the one resolver reads
// and the origin of the ranges it compared; the pass that follows writes nothing.
func TestMatchPass_EveryCatalogueCVEIsAFindingWithItsFix(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.inv.match = map[string]Asset{"a-1": fortigate("7.2.5")}
	rec := catalogueOnly("CVE-2026-100001", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")
	cna := Vuln{CVE: "CVE-2026-100002", NVDAnswered: true, Origin: RangeCNA, RangesFrom: RangesCVEOrg,
		Affected: []Affected{{CPE: "cpe:2.3:*:fortinet:fortios:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.2.0", EndExcl: "7.2.11"}}}}
	open := catalogueOnly("CVE-2026-100003", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.0.0", "")
	open.Vendor, open.Product = "Fortinet", "FortiOS" // an exploited-list entry: CISA's key reaches the row by its name
	out := catalogueOnly("CVE-2026-100004", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.4.0", "7.4.3")
	e.feeds.vulns = []Vuln{rec, cna, open, out}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Finding{}
	for _, f := range fs {
		got[f.CVE] = f
	}
	want := map[string]struct {
		origin string
		fix    Fix
	}{
		"CVE-2026-100001": {RangeNVD, Fix{Kind: FixUpdate, Version: "7.2.9"}},
		"CVE-2026-100002": {RangeCNA, Fix{Kind: FixUpdate, Version: "7.2.11"}},
		"CVE-2026-100003": {RangeNVD, Fix{Kind: FixNoneYet}},
	}
	if len(got) != len(want) {
		t.Fatalf("findings %v, want %v", keysOf(got), want)
	}
	for cve, w := range want {
		f := got[cve]
		if !f.Detected || f.RangeOrigin != w.origin || f.Fix != w.fix || f.FixKey != FixKey("fortinet|fortios", w.fix) {
			t.Errorf("%s: detected %v origin %q fix %+v key %q, want origin %q fix %+v", cve, f.Detected, f.RangeOrigin, f.Fix, f.FixKey, w.origin, w.fix)
		}
	}
	rows := e.count(`SELECT count(*) FROM fnd_finding_event`)
	stamp := e.count(`SELECT count(*) FROM fnd_finding WHERE updated_at = (SELECT max(updated_at) FROM fnd_finding)`)
	e.advance(ReconcileEvery)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event`); n != rows {
		t.Errorf("a pass that changes nothing appended %d events", n-rows)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE updated_at = (SELECT max(updated_at) FROM fnd_finding)`); n != stamp || e.count(`SELECT count(*) FROM fnd_finding WHERE updated_at > '`+t0.Format(tsLayout)+`'`) != 0 {
		t.Error("a pass that changes nothing rewrote rows")
	}
	e.advance(lastSeenStep)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE last_seen > '` + t0.Format(tsLayout) + `'`); n != len(want) {
		t.Errorf("after a day, last seen moved on %d findings, want %d", n, len(want))
	}
}

// The software line goes from the device: the pass still compares the CVEs of its findings (they are pinned), so the finding goes
// away as patched, even when no device runs the product any more.
func TestMatchPass_APinnedCVEIsJudgedWhenTheProductIsGone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.inv.match = map[string]Asset{"a-1": fortigate("7.2.5")}
	e.feeds.vulns = []Vuln{catalogueOnly("CVE-2026-100001", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	pinned, err := e.svc.pinnedCVEs(t.Context(), "")
	if err != nil || len(pinned) != 1 {
		t.Fatalf("pinned %v %v", pinned, err)
	}
	a := fortigate("7.2.5")
	a.Software = nil
	e.inv.match = map[string]Asset{"a-1": a}
	e.advance(ReconcileEvery)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %v %v", fs, err)
	}
	if f := fs[0]; f.Open() || f.Via != ViaSoftwareRemoved || f.Detected {
		t.Errorf("finding %+v, want handled via software_removed", f)
	}
}

// The scope asks the catalogue only for what the devices run, the device's own entries come from the vendors of its lines, and every
// exploited-list entry is read for every device (CISA's key reaches a row by its name).
func TestMatchPass_ScopeAndIndex(t *testing.T) {
	t.Parallel()
	a := fortigate("7.2.5")
	sc := NewMatchScope([]Asset{a}, nil)
	if !sc.Keep("fortinet", "fortios") || sc.Keep("apache", "http_server") {
		t.Errorf("scope keeps the wrong products")
	}
	kev := Vuln{CVE: "CVE-2024-0001", Vendor: "Apache", Product: "HTTP Server"}
	other := catalogueOnly("CVE-2026-100009", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.60")
	own := catalogueOnly("CVE-2026-100001", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")
	got := newMatchSet([]Vuln{kev, other, own}).forDevice(a)
	if len(got) != 2 || got[0].CVE != kev.CVE || got[1].CVE != own.CVE {
		t.Errorf("forDevice %v", vulnCVEs(got))
	}
}

func keysOf(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func vulnCVEs(vs []Vuln) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.CVE
	}
	return out
}

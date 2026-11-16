package findings

import (
	"slices"
	"strings"
	"testing"
)

// M2-4 (walk n74): the EX4200 on JUNOS 15.1R7.9 is inside CVE-2023-36845's "before 20.4", but NVD lists 20.4:r1 … one by one
// as affected: 20.4 is not the fix, and the page says so instead of "Fixed version not known yet".
func TestFixedIn_M24_RangeEndThatIsItselfAffectedIsNotTheFix(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == "CVE-2023-36845" })
	f := FixedInFor(walk1EX4200(), vulns[i])
	if f == nil || f.Kind != "end_listed" || f.Fixed != "20.4" || f.Version != "15.1R7.9" {
		t.Fatalf("got %+v, want end_listed 20.4 for 15.1R7.9", f)
	}
	// A range whose end is outside every entry still names the fix.
	v := Vuln{CVE: "CVE-2099-0001", Vendor: "Acme", Product: "Gate", Affected: []Affected{{CPE: "cpe:2.3:a:acme:gate:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.0"}}}}
	a := Asset{ID: "a", Name: "gw", Software: []Software{{ID: "s", Display: "Acme Gate", Vendor: "Acme", Product: "Gate", Version: "1.5", KevKeys: []string{"acme|gate"}}}}
	if f := FixedInFor(a, v); f == nil || f.Kind != "fixed" || f.Fixed != "2.0" {
		t.Fatalf("a plain range end: got %+v", f)
	}
}

// M2-6: a scan row's display already ends with its version ("OpenSSH 10.2"): the evidence names the version once.
func TestMatch_M26_ScanDisplayWithVersionIsNotDoubled(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2099-0002", Vendor: "OpenBSD", Product: "OpenSSH", Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}}}}
	a := Asset{ID: "a", Name: "192.168.18.1", Software: []Software{{ID: "s", Display: "OpenSSH 10.2", Vendor: "openbsd", Product: "openssh", Version: "10.2", KevKeys: []string{"openbsd|openssh"}, Source: "nmap"}}}
	r := MatchAsset(a, []Vuln{v}, nil, t0)
	if len(r.New) != 1 {
		t.Fatalf("got %+v", r)
	}
	if s := r.New[0].Evidence.Summary; !strings.HasPrefix(s, "192.168.18.1 runs OpenSSH 10.2. Its version") {
		t.Errorf("summary %q", s)
	}
	for _, c := range []struct{ display, version, want string }{
		{"OpenSSH 10.2", "10.2", "OpenSSH 10.2"},
		{"Juniper Junos OS", "15.1R7.9", "Juniper Junos OS 15.1R7.9"},
		{"Python 3", "3.12.1", "Python 3 3.12.1"},
		{"10.2", "10.2", "10.2 10.2"},
	} {
		if got := withVersion(c.display, c.version); got != c.want {
			t.Errorf("withVersion(%q, %q) = %q, want %q", c.display, c.version, got, c.want)
		}
	}
}

// M2-3: the version the box has, and who gave it, for every source; nil without a version or a known source.
func TestKnownVersion_M23_EverySource(t *testing.T) {
	t.Parallel()
	ex := walk1EX4200()
	osRow := deviceSoftware(ex)[0]
	if k := knownVersion(ex, osRow); k == nil || *k != (KnownVersion{Software: "Juniper Junos OS", Version: "15.1R7.9", Source: VersionByStated}) {
		t.Errorf("LLDP-stated Junos: %+v", k)
	}
	ex.SNMPOS = ex.StatedOS
	if k := knownVersion(ex, osRow); k == nil || k.Source != VersionBySNMP {
		t.Errorf("SNMP-read Junos: %+v", k)
	}
	a := Asset{ID: "a"}
	for src, want := range map[string]string{"agent": VersionByAgent, "snmp": VersionBySNMP, "manual": VersionByManual, "scan": VersionByScan, "nmap": VersionByScan, "passive": VersionByStated, "": ""} {
		k := knownVersion(a, Software{ID: "s", Display: "OpenSSH 10.2", Version: "10.2", Source: src})
		if want == "" {
			if k != nil {
				t.Errorf("source %q: %+v, want nil", src, k)
			}
			continue
		}
		if k == nil || k.Source != want || k.Software != "OpenSSH" || k.Version != "10.2" {
			t.Errorf("source %q: %+v", src, k)
		}
	}
	if k := knownVersion(a, Software{ID: "s", Display: "X", Source: "manual"}); k != nil {
		t.Errorf("no version: %+v", k)
	}
}

// M2-3: the finding page carries the version the box has for the matched software and who gave it: the EX4200's Junos from its
// SNMP answer, and fixed_in says 20.4 is not the fix (M2-4).
func TestFindingDetail_M23_KnownVersion(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	ex := walk1EX4200()
	ex.ID, ex.SNMPOS = "a-1", ex.StatedOS
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == "CVE-2023-36845" })
	e.inv.mu.Lock()
	e.inv.match["a-1"] = ex
	e.inv.mu.Unlock()
	e.feeds.vulns = []Vuln{vulns[i]}
	e.feeds.kev[vulns[i].CVE] = KevInfo{Name: vulns[i].Name, Vendor: "Juniper", Product: "Junos OS", RequiredAction: "Apply updates."}
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 1 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	_, b := e.call("GET", "/findings/"+res.Created[0], "viewer", "")
	k, _ := b["known_version"].(map[string]any)
	if k["software"] != "Juniper Junos OS" || k["version"] != "15.1R7.9" || k["source"] != "snmp" {
		t.Fatalf("known_version: %v", b["known_version"])
	}
	if f, _ := b["fixed_in"].(map[string]any); f["kind"] != "end_listed" || f["fixed"] != "20.4" {
		t.Fatalf("fixed_in: %v", b["fixed_in"])
	}
}

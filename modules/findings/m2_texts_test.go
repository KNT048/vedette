package findings

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The EX4200 on JUNOS 15.1R7.9 is inside CVE-2023-36845's "before 20.4", but NVD lists 20.4:r1 … one by one
// as affected: 20.4 is not the fix, and the page says so instead of "Fixed version not known yet".
func TestFixedIn_M24_RangeEndThatIsItselfAffectedIsNotTheFix(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == "CVE-2023-36845" })
	f := FixedInFor(labEX4200(), vulns[i])
	if f == nil || f.Kind != "end_listed" || f.Fixed != "20.4" || f.Version != "15.1R7.9" {
		t.Fatalf("got %+v, want end_listed 20.4 for 15.1R7.9", f)
	}
	// Inside two ranges whose ends are both listed: the highest end, the range the evidence quotes (review r1 L2).
	two := Vuln{CVE: "CVE-2099-0003", Vendor: "Acme", Product: "Gate", Affected: []Affected{
		{CPE: "cpe:2.3:a:acme:gate:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "8.0"}},
		{CPE: "cpe:2.3:a:acme:gate:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "9.1"}},
		{CPE: "cpe:2.3:a:acme:gate:8.0:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:a:acme:gate:9.1:*:*:*:*:*:*:*"},
	}}
	gate := Asset{ID: "a", Name: "gw", Software: []Software{{ID: "s", Display: "Acme Gate", Vendor: "Acme", Product: "Gate", Version: "7.5", KevKeys: []string{"acme|gate"}}}}
	if f := FixedInFor(gate, two); f == nil || f.Kind != "end_listed" || f.Fixed != "9.1" {
		t.Fatalf("two listed ends: got %+v, want end_listed 9.1", f)
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
	a := Asset{ID: "a", Name: "192.168.142.1", Software: []Software{{ID: "s", Display: "OpenSSH 10.2", Vendor: "openbsd", Product: "openssh", Version: "10.2", KevKeys: []string{"openbsd|openssh"}, Source: "nmap"}}}
	r := MatchAsset(a, []Vuln{v}, nil, t0)
	if len(r.New) != 1 {
		t.Fatalf("got %+v", r)
	}
	if s := r.New[0].Evidence.Summary; !strings.HasPrefix(s, "192.168.142.1 runs OpenSSH 10.2. Its version") {
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
	ex := labEX4200()
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
		name := "OpenSSH"
		if src == "manual" {
			name = "OpenSSH 10.2" // the inventory display, as the "I updated <software>" button shows it (review r1 L4)
		}
		if k == nil || k.Source != want || k.Software != name || k.Version != "10.2" {
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
	ex := labEX4200()
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

// detailKnown seeds device a with one exploited entry v, creates its finding and returns the GET /findings/{id} body.
func detailKnown(t *testing.T, a Asset, v Vuln) map[string]any {
	t.Helper()
	e := newHTTPEnv(t)
	e.inv.mu.Lock()
	e.inv.match[a.ID] = a
	e.inv.mu.Unlock()
	e.feeds.vulns = []Vuln{v}
	e.feeds.kev[v.CVE] = KevInfo{Name: v.Name, Vendor: v.Vendor, Product: v.Product, RequiredAction: "Apply updates."}
	res, err := e.svc.OnMatchChanged(t.Context(), a.ID)
	if err != nil || len(res.Created) != 1 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	_, b := e.call("GET", "/findings/"+res.Created[0], "viewer", "")
	return b
}

// Review r1 L8 + M3 of #896: the walked 192.168.142.1 (OpenSSH 10.2 read by a scan) and WINLAB01 (the agent's Windows release row)
// through GET /findings/{id}; and with two rows keyed to the same product (an nmap row first by name, then the agent's), known_version
// is the row the finding was matched on, the one the evidence names, not the first keyed one.
func TestFindingDetail_M23_KnownVersionIsTheMatchedRow(t *testing.T) {
	t.Parallel()
	ssh := Vuln{CVE: "CVE-2099-12315", Vendor: "OpenBSD", Product: "OpenSSH", Name: "OpenBSD OpenSSH", Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}}}}
	gw := Asset{ID: "a-1", Name: "192.168.142.1", Software: []Software{{ID: "s-1", Display: "OpenSSH 10.2", Vendor: "openbsd", Product: "openssh", Version: "10.2", KevKeys: []string{"openbsd|openssh"}, Source: "nmap"}}}
	b := detailKnown(t, gw, ssh)
	if k, _ := b["known_version"].(map[string]any); k["software"] != "OpenSSH" || k["version"] != "10.2" || k["source"] != "scan" {
		t.Errorf("192.168.142.1: %v", b["known_version"])
	}
	if ev, _ := b["evidence"].(map[string]any); !strings.HasPrefix(ev["summary"].(string), "192.168.142.1 runs OpenSSH 10.2. ") {
		t.Errorf("192.168.142.1 evidence: %v", ev["summary"])
	}

	two := Asset{ID: "a-1", Name: "web-01", Software: []Software{
		{ID: "s-a", Display: "OpenSSH 9.6p1 Ubuntu 3ubuntu13.5", Vendor: "openbsd", Product: "openssh", Version: "", KevKeys: []string{"openbsd|openssh"}, Source: "nmap"},
		{ID: "s-b", Display: "OpenSSH", Vendor: "openbsd", Product: "openssh", Version: "9.6", KevKeys: []string{"openbsd|openssh"}, Source: "agent"},
	}}
	b = detailKnown(t, two, ssh)
	if k, _ := b["known_version"].(map[string]any); k["version"] != "9.6" || k["source"] != "agent" {
		t.Errorf("two keyed rows: %v", b["known_version"])
	}

	vulns := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == "CVE-2024-43572" })
	win := winlab01()
	win.ID = "a-1"
	b = detailKnown(t, win, vulns[i])
	if k, _ := b["known_version"].(map[string]any); k["source"] != "agent" || !strings.HasPrefix(k["version"].(string), "10.0.26100.1742") {
		t.Errorf("WINLAB01: %v", b["known_version"])
	}
}

// known_version.seen_at is when the matched row's source last gave the version (a scan, an agent's list, a person), so the page can
// say it beside last_seen, which is only when Vedette last matched the pair; null when the row carries no time.
func TestFindingDetail_KnownVersionSaysWhenTheVersionWasReported(t *testing.T) {
	t.Parallel()
	ssh := Vuln{CVE: "CVE-2099-12315", Vendor: "OpenBSD", Product: "OpenSSH", Name: "OpenBSD OpenSSH", Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6"}}}}
	at := time.Date(2026, 11, 15, 9, 30, 0, 0, time.FixedZone("UTC+7", 7*3600))
	gw := Asset{ID: "a-1", Name: "edge firewall", Software: []Software{{ID: "s-1", Display: "OpenSSH", Vendor: "openbsd", Product: "openssh", Version: "10.2", KevKeys: []string{"openbsd|openssh"}, Source: "manual", SeenAt: at}}}
	b := detailKnown(t, gw, ssh)
	k, _ := b["known_version"].(map[string]any)
	if k["source"] != "manual" || k["seen_at"] != "2026-11-15T02:30:00Z" {
		t.Errorf("manual row: %v", b["known_version"])
	}
	if f, _ := b["last_seen"].(string); f == "" || f == k["seen_at"] {
		t.Errorf("last_seen is the match time, not the row's: %v", b["last_seen"])
	}

	gw.Software[0].SeenAt = time.Time{}
	b = detailKnown(t, gw, ssh)
	k, _ = b["known_version"].(map[string]any)
	if v, ok := k["seen_at"]; !ok || v != nil {
		t.Errorf("no time on the row: seen_at must be null, got %v (present %v)", v, ok)
	}
}

// The network OS row a device states itself has the time of that statement: its SNMP answer's for source snmp, its LLDP
// statement's for source stated.
func TestFindingDetail_StatedOSVersionHasTheTimeOfTheStatement(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == "CVE-2023-36845" })
	lldpAt, snmpAt := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC), time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, snmp, source, want string }{
		{"snmp", "JUNOS 15.1R7.9", "snmp", "2026-11-16T09:00:00Z"},
		{"lldp", "", "stated", "2026-11-15T08:00:00Z"},
	} {
		ex := labEX4200()
		ex.ID, ex.SNMPOS, ex.StatedOSAt = "a-1", tc.snmp, lldpAt
		if tc.snmp != "" {
			ex.SNMPOSAt = snmpAt
		}
		b := detailKnown(t, ex, vulns[i])
		if k, _ := b["known_version"].(map[string]any); k["source"] != tc.source || k["seen_at"] != tc.want {
			t.Errorf("%s: %v", tc.name, b["known_version"])
		}
	}
}

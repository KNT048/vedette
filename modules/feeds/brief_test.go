package feeds

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// The brief fixture: the CVE Program record and NVD's answer of CVE-2025-22225 (VMware ESXi arbitrary write, on the CISA list since
// 2025-03-04), as published on 2026-11-21 (testdata/brief). Public data: the record under the CVE Program terms of use, NVD's answer in
// the public domain.
const briefCVE = "CVE-2025-22225"

// briefStore fills a catalogue the way the box does: the CISA list's entry, then the record and NVD's answer in the order given.
func briefStore(t *testing.T, nvdFirst bool) *env {
	t.Helper()
	e := newEnv(t)
	v := vuln(briefCVE, "VMware", "ESXi", "2025-03-04")
	v.Name, v.Ransomware = "VMware ESXi Arbitrary Write Vulnerability", false
	applyV(t, e.db, e.clock(), "cisa-kev", []Vuln{v}, false)
	nvdData, err := os.ReadFile("testdata/brief/" + briefCVE + ".nvd.json")
	if err != nil {
		t.Fatal(err)
	}
	page, err := ParseNVD(nvdData)
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("NVD answer: %d records, %v", len(page.Records), err)
	}
	recData, err := os.ReadFile("testdata/brief/" + briefCVE + ".record.json")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := ParseCVERecord(recData, briefCVE)
	if err != nil {
		t.Fatal(err)
	}
	nvd := func() {
		write(t, e.db, func(tx *sql.Tx) error { return storeRecords(t.Context(), tx, page.Records, e.clock()) })
	}
	record := func() {
		write(t, e.db, func(tx *sql.Tx) error {
			k, err := recordKeepOf(t.Context(), tx, e.clock(), nil)
			if err != nil {
				return err
			}
			_, err = writeRecords(t.Context(), tx, []CVERecord{rec}, k, e.clock())
			return err
		})
	}
	if nvdFirst {
		nvd()
		record()
	} else {
		record()
		nvd()
	}
	return e
}

// TestBrief_CVE2025_22225 is the brief of an exploited ESXi CVE built from its two public records: the weaknesses of NVD and of
// CISA's ADP with their MITRE names, the Broadcom advisory as a vendor advisory, NVD's 55 affected entries (NVD analysed it, so
// they count), NVD's picked score read into words, the CISA entry and its signal. The same whichever record the box read first.
func TestBrief_CVE2025_22225(t *testing.T) {
	t.Parallel()
	for _, nvdFirst := range []bool{true, false} {
		e := briefStore(t, nvdFirst)
		b, ok, err := e.svc.st.Brief(t.Context(), briefCVE)
		if err != nil || !ok {
			t.Fatalf("nvd first %v: %v %v", nvdFirst, ok, err)
		}
		if want := []Weakness{{"CWE-787", "Out-of-bounds Write"}, {"CWE-123", "Write-what-where Condition"}}; !slices.Equal(b.CWE, want) {
			t.Errorf("nvd first %v: CWE %v, want %v", nvdFirst, b.CWE, want)
		}
		const advisory = "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390"
		i := slices.IndexFunc(b.References, func(r Reference) bool { return r.URL == advisory })
		if i != 0 || !slices.Contains(b.References[i].Tags, "vendor-advisory") || b.References[i].Group != "vendor-advisory" {
			t.Errorf("nvd first %v: the Broadcom advisory is not the first vendor advisory: %+v", nvdFirst, b.References)
		}
		if g := b.References[len(b.References)-1]; g.Group != "government-resource" {
			t.Errorf("nvd first %v: the CISA page is not a government resource: %+v", nvdFirst, g)
		}
		counting := slices.DeleteFunc(slices.Clone(b.Ranges), func(r BriefRange) bool { return !r.Counts })
		if len(counting) != 55 || b.RangesFrom != OriginNVD || b.RangesComplete {
			t.Errorf("nvd first %v: %d ranges count, from %q complete %v", nvdFirst, len(counting), b.RangesFrom, b.RangesComplete)
		}
		// NVD names exact releases and no fix; VMware's record states the fixed build of each train in its own notation
		// ("ESXi80U3d-24585383"): kept as stated beside NVD's rows, never counted, read by the ESXi version scheme.
		if slices.ContainsFunc(counting, func(r BriefRange) bool { return r.Fixed != "" || r.Origin != OriginNVD || r.Train != "" }) {
			t.Errorf("nvd first %v: a counting row is not NVD's or carries a fixed version", nvdFirst)
		}
		wantFixes := []BriefFix{{"vmware", "esxi", OriginCNA, "8.0 U3", "8.0 U3d (build 24585383)"}, {"vmware", "esxi", OriginCNA, "8.0 U2", "8.0 U2d (build 24585300)"},
			{"vmware", "esxi", OriginCNA, "7.0 U3", "7.0 U3s (build 24585291)"}}
		if !slices.Equal(b.Fixes, wantFixes) {
			t.Errorf("nvd first %v: fixes %+v", nvdFirst, b.Fixes)
		}
		var esxi []BriefRange
		for _, r := range b.Ranges {
			if r.Origin == OriginCNA && r.Product == "esxi" {
				esxi = append(esxi, r)
			}
		}
		if len(esxi) != 3 || esxi[0].Counts || esxi[0].VersionType != "vendor:custom" || esxi[0].StartIncl != "8.0" || esxi[0].Fixed != "ESXi80U3d-24585383" ||
			esxi[0].Train != "8.0 U3" || esxi[0].Versions != "from 8.0 before 8.0 U3d (build 24585383)" || esxi[2].Versions != "from 7.0 before 7.0 U3s (build 24585291)" {
			t.Errorf("nvd first %v: VMware's rows %+v", nvdFirst, esxi)
		}
		// the other products of the record, written as text ("5.x, 4.5.x"), are kept as written and read by no scheme
		if i := slices.IndexFunc(b.Ranges, func(r BriefRange) bool { return r.Product == "cloudfoundation" && r.Origin == OriginCNA }); i < 0 ||
			b.Ranges[i].Versions != "5.x, 4.5.x" || b.Ranges[i].Counts || b.Ranges[i].Train != "" {
			t.Errorf("nvd first %v: Cloud Foundation %+v", nvdFirst, b.Ranges)
		}
		if got := []string{counting[0].Versions, counting[2].Versions, counting[43].Versions}; !slices.Equal(got, []string{"7.0", "7.0 update_1", "every version"}) {
			t.Errorf("nvd first %v: versions %q", nvdFirst, got)
		}
		if !slices.Equal(b.Products, []string{"vmware cloud foundation", "vmware esxi", "vmware telco cloud infrastructure", "vmware telco cloud platform"}) {
			t.Errorf("nvd first %v: products %q", nvdFirst, b.Products)
		}
		if b.CVSS == nil || b.CVSS.Source != MetricNVD || b.CVSS.Score != 8.2 || b.CVSS.Severity != "HIGH" || b.CVSS.Reading == nil ||
			b.CVSS.Reading.Summary != "Attacker needs local access, low complexity, high privileges needed, no user action; high impact on confidentiality, integrity and availability; can reach beyond the vulnerable component." {
			t.Errorf("nvd first %v: CVSS %+v", nvdFirst, b.CVSS)
		}
		if len(b.Lists) != 1 || b.Lists[0].List != ListCISA || b.Lists[0].SourceName != "CISA KEV" || b.Display != b.Lists[0].Display {
			t.Errorf("nvd first %v: lists %+v display %q", nvdFirst, b.Lists, b.Display)
		}
		if len(b.Signals) != 1 || b.Signals[0].Kind != SignalExploited || b.Signals[0].Source != "cisa-kev" || b.Signals[0].SourceName != "CISA KEV" {
			t.Errorf("nvd first %v: signals %+v", nvdFirst, b.Signals)
		}
		if b.SSVC != (SSVC{Exploitation: "active", Automatable: "no", Impact: "total"}) || b.NVDStatus != "Analyzed" || b.Published == nil ||
			b.Published.Format(time.DateOnly) != "2025-03-04" || b.Description == "" || b.Solution != "" || b.Workaround != "" {
			t.Errorf("nvd first %v: %+v", nvdFirst, b)
		}
	}
}

// The brief reads every signal row as stored, whatever its kind and source: a kind or a source that comes later appears without a
// change, named by its feed when the box has one, else by its id.
func TestBrief_SignalsAreReadGenerically(t *testing.T) {
	t.Parallel()
	e := briefStore(t, true)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url, detail) VALUES
(?, 'public_exploit', 'metasploit', '2025-03-10T00:00:00.000Z', '2026-11-05T00:00:00.000Z', '2026-11-05T00:00:00.000Z', 1, 'https://www.rapid7.com/db/modules/x', '{"modules":1}'),
(?, 'ids_rule', 'a-later-source', '2025-04-01T00:00:00.000Z', '2026-11-05T00:00:00.000Z', '2026-11-05T00:00:00.000Z', 0, 'javascript:x', '{"sids":6,"nested":{"a":1}}')`, briefCVE, briefCVE)
		return err
	})
	c, b := e.get("/feeds/cve/" + briefCVE)
	if c != http.StatusOK {
		t.Fatalf("%d %v", c, b)
	}
	sigs, _ := at(b, "signals").([]any)
	if len(sigs) != 3 || at(sigs[1], "source_name") != "Metasploit modules" || at(sigs[1], "detail", "modules") != 1.0 {
		t.Fatalf("signals %v", sigs)
	}
	if at(sigs[2], "kind") != "ids_rule" || at(sigs[2], "source_name") != "a-later-source" || at(sigs[2], "url") != nil || at(sigs[2], "qualifies") != false ||
		at(sigs[2], "detail", "sids") != 6.0 || at(sigs[2], "detail", "nested") != nil {
		t.Errorf("a new kind and source: %v", sigs[2])
	}
}

// GET /feeds/cve/{id} answers the brief of any CVE the catalogue holds (NVD's 55 rows, then VMware's 3 fixed builds and its 3 text
// rows; the fixed release of each train), 404 not_in_data for one it does not, and the generated
// server refuses an id that is not a CVE id before the handler runs.
func TestBriefRoute(t *testing.T) {
	t.Parallel()
	e := briefStore(t, false)
	e.inv.matches["vmware|esxi"] = []MatchedAsset{{ID: "a1", IP: "192.0.2.10", Display: "ESXi host", How: HaveYes}}
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := applyEPSS(t.Context(), tx, map[string]float64{briefCVE: 0.42}, map[string]float64{briefCVE: 0.40})
		return err
	})
	c, b := e.get("/feeds/cve/" + briefCVE)
	if c != http.StatusOK || at(b, "cwe", 0, "name") != "Out-of-bounds Write" || at(b, "references", 0, "group") != "vendor-advisory" ||
		len(at(b, "ranges").([]any)) != 61 || at(b, "ranges", 55, "train") != "8.0 U3" || at(b, "ranges", 55, "counts") != false ||
		at(b, "fixes", 2, "release") != "7.0 U3s (build 24585291)" || at(b, "fixes", 2, "train") != "7.0 U3" ||
		at(b, "ranges_from") != "nvd" || at(b, "cvss", "severity") != "high" ||
		at(b, "cvss", "reading", "attack_vector") != "local" || at(b, "cvss", "reading", "user_interaction") != "none" ||
		at(b, "cvss", "reading", "attack_requirements") != nil || at(b, "matched", 0, "id") != "a1" || at(b, "epss", "score") != 0.42 ||
		at(b, "epss", "week_ago") != 0.40 || at(b, "epss", "day") != epssDayForTests || at(b, "workaround") != nil || at(b, "title") != nil ||
		at(b, "ssvc", "exploitation") != "active" || at(b, "nvd_url") != "https://nvd.nist.gov/vuln/detail/"+briefCVE {
		t.Errorf("%d %v", c, b)
	}
	// a CVE the catalogue holds that is on no list: the brief, and no devices by product
	write(t, e.db, func(tx *sql.Tx) error { return ensureCVE(t.Context(), tx, "CVE-2026-0042", "2026-11-01T00:00:00.000Z") })
	if c, b := e.get("/feeds/cve/CVE-2026-0042"); c != http.StatusOK || at(b, "matched") != nil || len(at(b, "lists").([]any)) != 0 || at(b, "cvss") != nil || at(b, "epss") != nil {
		t.Errorf("not listed: %d %v", c, b)
	}
	if c, b := e.get("/feeds/cve/CVE-2026-9999"); c != http.StatusNotFound || code(b) != "not_in_data" {
		t.Errorf("unknown CVE: %d %v", c, b)
	}
	for _, id := range []string{"CVE-26-1", "CVE-2026-12", "XYZ-2026-1234", "CVE-2026-1234%20"} {
		if c, b := e.get("/feeds/cve/" + id); c != http.StatusBadRequest {
			t.Errorf("%s: %d %v", id, c, b)
		}
	}
}

// Before NVD tags a CVE's references the CVE record's stand, with the CNA's tags; once NVD has, NVD's replace them and a later
// record never puts the untagged ones back. NVD's weaknesses replace the record's once NVD lists any.
func TestBrief_ReferencePrecedence(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	cve := "CVE-2026-0700"
	applyV(t, e.db, e.clock(), "cisa-kev", []Vuln{vuln(cve, "Acme", "Box", "2026-11-01")}, false)
	rec := CVERecord{CVE: cve, State: RecordPublished, CWE: []string{"CWE-79"}, Refs: []RecordRef{
		{URL: "https://acme.example.com/advisory", Tags: []string{"vendor-advisory"}, Source: OriginCNA},
		{URL: "https://acme.example.com/blog", Tags: []string{}, Source: OriginCNA},
	}}
	writeRec := func() {
		write(t, e.db, func(tx *sql.Tx) error {
			k, err := recordKeepOf(t.Context(), tx, e.clock(), nil)
			if err != nil {
				return err
			}
			_, err = writeRecords(t.Context(), tx, []CVERecord{rec}, k, e.clock())
			return err
		})
	}
	writeNVD := func(r NVDRecord) {
		write(t, e.db, func(tx *sql.Tx) error { return storeRecords(t.Context(), tx, []NVDRecord{r}, e.clock()) })
	}
	refs := func() []Reference {
		b, _, err := e.svc.st.Brief(t.Context(), cve)
		if err != nil {
			t.Fatal(err)
		}
		return b.References
	}
	writeRec()
	writeNVD(NVDRecord{CVE: cve, Status: "Awaiting Analysis", Refs: []RecordRef{{URL: "https://acme.example.com/advisory", Tags: []string{}, Source: RefsNVD}}})
	if r := refs(); len(r) != 2 || r[0].Source != OriginCNA || r[0].Group != "vendor-advisory" || r[1].Group != RefOther {
		t.Fatalf("NVD has tagged nothing yet: %+v", r)
	}
	writeNVD(NVDRecord{CVE: cve, Status: "Analyzed", CWE: []string{"CWE-89"}, Refs: []RecordRef{
		{URL: "https://acme.example.com/advisory", Tags: []string{"patch", "vendor-advisory"}, Source: RefsNVD},
		{URL: "https://acme.example.com/blog", Tags: []string{"third-party-advisory"}, Source: RefsNVD},
	}})
	writeRec()
	r := refs()
	if len(r) != 2 || r[0].Source != RefsNVD || !slices.Equal(r[0].Tags, []string{"patch", "vendor-advisory"}) || r[0].Group != "vendor-advisory" ||
		r[1].Group != "third-party-advisory" {
		t.Errorf("NVD's tagged references must stand: %+v", r)
	}
	if b, _, _ := e.svc.st.Brief(t.Context(), cve); !slices.Equal(b.CWE, []Weakness{{"CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"}}) {
		t.Errorf("NVD's weaknesses must stand: %+v", b.CWE)
	}
}

// The weaknesses are NVD's once NVD lists any, else the CVE record's newest, whichever pull came first, with one known limit: a CVE
// record's change after NVD answered with no weakness is not applied (nothing records who wrote cwe). The limit case asserts today's
// answer, so a fix of it flips this test.
func TestBrief_WeaknessesDoNotDependOnWriteOrder(t *testing.T) {
	t.Parallel()
	cwe := func(steps ...any) []Weakness {
		e := newEnv(t)
		cve := "CVE-2026-0701"
		applyV(t, e.db, e.clock(), "cisa-kev", []Vuln{vuln(cve, "Acme", "Box", "2026-11-01")}, false)
		for _, st := range steps {
			write(t, e.db, func(tx *sql.Tx) error {
				switch x := st.(type) {
				case CVERecord:
					x.CVE, x.State = cve, RecordPublished
					k, err := recordKeepOf(t.Context(), tx, e.clock(), nil)
					if err != nil {
						return err
					}
					_, err = writeRecords(t.Context(), tx, []CVERecord{x}, k, e.clock())
					return err
				case NVDRecord:
					x.CVE, x.Status = cve, "Analyzed"
					return storeRecords(t.Context(), tx, []NVDRecord{x}, e.clock())
				}
				return nil
			})
		}
		b, _, err := e.svc.st.Brief(t.Context(), cve)
		if err != nil {
			t.Fatal(err)
		}
		return b.CWE
	}
	rec := func(ids ...string) CVERecord { return CVERecord{CWE: ids} }
	nvd := func(ids ...string) NVDRecord { return NVDRecord{CWE: ids} }
	for _, c := range []struct {
		name  string
		steps []any
		want  string
	}{
		{"record, record again, NVD with none", []any{rec("CWE-787"), rec("CWE-79"), nvd()}, "CWE-79"},
		{"record, NVD with one", []any{rec("CWE-79"), nvd("CWE-89")}, "CWE-89"},
		{"NVD with one, record", []any{nvd("CWE-89"), rec("CWE-79")}, "CWE-89"},
		// known limit: the record's update to CWE-79 is not applied (a fix makes this CWE-79, as in the first case)
		{"record, NVD with none, record again", []any{rec("CWE-787"), nvd(), rec("CWE-79")}, "CWE-787"},
	} {
		if got := cwe(c.steps...); len(got) != 1 || got[0].ID != c.want {
			t.Errorf("%s: %+v, want %s", c.name, got, c.want)
		}
	}
}

func TestNVDTagWords(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"Vendor Advisory": "vendor-advisory", "US Government Resource": "government-resource", "Third Party Advisory": "third-party-advisory",
		"Press/Media Coverage": "media-coverage", "Tool Signature": "signature", "Patch": "patch", "Issue Tracking": "issue-tracking", "VDB Entry": "vdb-entry"} {
		if got := nvdTag(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestReadVector(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		vector string
		want   *VectorReading
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L", &VectorReading{AttackVector: "network", AttackComplexity: "low", PrivilegesRequired: "none",
			UserInteraction: "required", Scope: "unchanged", Confidentiality: "high", Integrity: "none", Availability: "low",
			Summary: "Remote attack over the network, low complexity, no privileges needed, a user must take an action; impact: confidentiality high, integrity none, availability low."}},
		{"CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/E:A", &VectorReading{AttackVector: "adjacent", AttackComplexity: "high",
			AttackRequirements: "present", PrivilegesRequired: "low", UserInteraction: "passive", Confidentiality: "high", Integrity: "high", Availability: "high",
			Subsequent: &Impact{"low", "none", "none"},
			Summary:    "Attacker needs access to the same local network segment, high complexity, only under conditions the attacker does not control, low privileges needed, a user must be involved; high impact on confidentiality, integrity and availability; can also affect other systems (impact: confidentiality low, integrity none, availability none)."}},
		{"AV:N/AC:M/Au:N/C:N/I:N/A:N", &VectorReading{AttackVector: "network", AttackComplexity: "medium", PrivilegesRequired: "none", Confidentiality: "none",
			Integrity: "none", Availability: "none", Summary: "Remote attack over the network, medium complexity, no privileges needed; no impact on confidentiality, integrity or availability."}},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", nil},            // a base metric missing
		{"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil},   // given twice
		{"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil},        // a value the version does not define
		{"CVSS:5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil},        // an unknown version
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/broken", nil}, // not metric:value
	} {
		if got := ReadVector(c.vector); !sameReading(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.vector, got, c.want)
		}
	}
}

// sameReading compares two readings, their Subsequent impacts by value.
func sameReading(a, b *VectorReading) bool {
	if a == nil || b == nil {
		return a == b
	}
	if (a.Subsequent == nil) != (b.Subsequent == nil) || a.Subsequent != nil && *a.Subsequent != *b.Subsequent {
		return false
	}
	x, y := *a, *b
	x.Subsequent, y.Subsequent = nil, nil
	return x == y
}

// TestCWENames: the embedded CWE names are MITRE's list, keyed by CWE id, with a name for every id.
func TestCWENames(t *testing.T) {
	t.Parallel()
	var f struct {
		About   string            `json:"_about"`
		Version string            `json:"version"`
		Names   map[string]string `json:"names"`
	}
	if err := json.Unmarshal(catalogdata.CWENames, &f); err != nil {
		t.Fatal(err)
	}
	id := regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)
	for k, v := range f.Names {
		if !id.MatchString(k) || v == "" {
			t.Errorf("%q: %q", k, v)
		}
	}
	if len(f.Names) < 900 || f.Names["CWE-787"] != "Out-of-bounds Write" || f.Version == "" || !regexp.MustCompile(`MITRE`).MatchString(f.About) {
		t.Errorf("%d names, version %q", len(f.Names), f.Version)
	}
	if got := weaknesses([]string{"CWE-787", "CWE-9999999"}); got[1] != (Weakness{ID: "CWE-9999999"}) {
		t.Errorf("an id the list does not hold: %+v", got)
	}
}

// CVE-2026-88779 (the public record sample): NetScaler states "13.1-64.28" and its FIPS/NDcPP fix "13.1-37.282" without the word, so
// both end in train 13.1 of ADC: the brief names no train or fixed release for them, and keeps the 14.1 line's (and Gateway's 13.1, stated once).
func TestBrief_TwoEndsInOneTrainNameNoFix(t *testing.T) {
	t.Parallel()
	_, recs := loadRecordSample(t)
	rec, ok := recs["CVE-2026-88779"]
	if !ok {
		t.Fatal("CVE-2026-88779 is not in the sample")
	}
	rows, _, _ := briefRanges(rec.Ranges)
	var trains, plain []string
	for _, r := range rows {
		if r.Product != "adc" {
			continue
		}
		if r.Train != "" {
			trains = append(trains, r.Train+" "+r.FixedRelease)
		} else {
			plain = append(plain, r.Versions)
		}
	}
	if !slices.ContainsFunc(trains, func(s string) bool { return strings.HasPrefix(s, "14.1 ") }) || slices.ContainsFunc(trains, func(s string) bool { return strings.HasPrefix(s, "13.1 ") }) ||
		!slices.Contains(plain, "before 13.1-37.282") {
		t.Fatalf("trains %q, rows without one %q", trains, plain)
	}
	for _, f := range briefFixes(rows) {
		if f.Product == "adc" && f.Train == "13.1" {
			t.Fatalf("fix named for the ambiguous train: %+v", f)
		}
	}
}

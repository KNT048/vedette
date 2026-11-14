package feeds

import (
	"database/sql"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

func TestCVEOrgRecordURL(t *testing.T) {
	t.Parallel()
	const base = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
	for cve, want := range map[string]string{
		"CVE-2024-3400":  base + "/2024/3xxx/CVE-2024-3400.json",
		"CVE-2023-12345": base + "/2023/12xxx/CVE-2023-12345.json",
		"CVE-2021-0001":  base + "/2021/0xxx/CVE-2021-0001.json",
	} {
		if got, err := CVEOrgRecordURL(base+"/", cve); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", cve, got, err, want)
		}
	}
	for _, bad := range []string{"CVE-2024-3400/../../x", "cve-2024-3400", "CVE-2024-34", ""} {
		if _, err := CVEOrgRecordURL(base, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := CVEOrgRecordURL(base+"?x=1", "CVE-2024-3400"); err == nil {
		t.Error("a base with a query string was accepted")
	}
}

// record wraps CNA affected entries in a CVE JSON 5 record of CVE-2026-1000.
func record(affected string) []byte {
	return []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{"affected":[` + affected + `]}}}`)
}

const anyCPE = "cpe:2.3:*:acme:gateway:*:*:*:*:*:*:*:*"

// D-556: the conversion of CNA affected versions to NVD-shaped rows, and everything it refuses to guess.
func TestParseCVERecord_Conversion(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, affected string
		outcome        string
		rows           []AffectedRow
	}{
		{"lessThan from a start", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0","lessThan":"7.0.4","status":"affected","versionType":"semver"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: anyCPE, StartIncl: "7.0", EndExcl: "7.0.4"}}},
		{"lessThanOrEqual from 0 is no start", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"0","lessThanOrEqual":"6.2.9","status":"affected"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: anyCPE, EndIncl: "6.2.9"}}},
		{"n/a start below an end", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"n/a","lessThan":"3.1","status":"affected"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: anyCPE, EndExcl: "3.1"}}},
		{"lessThanOrEqual * is no end", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"5.0","lessThanOrEqual":"*","status":"affected"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: anyCPE, StartIncl: "5.0"}}},
		{"exact versions, quoted in the CPE", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"15.2(4)M3","status":"affected"},{"version":"9.9","status":"unaffected"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: `cpe:2.3:*:acme:gateway:15.2\(4\)M3:*:*:*:*:*:*:*`}}},
		{"default affected, nothing unaffected: every version", `{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`,
			CVEOrgRanges, []AffectedRow{{CPE: anyCPE}}},
		{"company words and the vendor in the product name", `{"vendor":"Acme Software Corporation","product":"Acme Gateway","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: anyCPE, StartIncl: "1.0", EndExcl: "1.5"}}},
		{"another product of the vendor is skipped", `{"vendor":"Acme","product":"Portal","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"2.0","status":"affected"}]}`,
			CVEOrgRanges, []AffectedRow{{CPE: "cpe:2.3:*:acme:gateway:2.0:*:*:*:*:*:*:*"}}},
		{"vendor mismatch", `{"vendor":"Acmex","product":"Gateway","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]}`, CVEOrgNoMatch, nil},
		{"package without vendor", `{"packageName":"gateway","collectionURL":"https://pypi.org","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]}`, CVEOrgNoMatch, nil},
		{"status unknown only", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unknown","versions":[{"version":"n/a","status":"unknown"}]}`, CVEOrgNoVersions, nil},
		{"git commits", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1da177e4c3f4","lessThan":"6b2c1e3fa9d1","status":"affected","versionType":"git"}]}`, CVEOrgUnusable, nil},
		{"a change inside the range (a hotfix)", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"10.2.0","lessThan":"10.2.9","status":"affected","changes":[{"at":"10.2.5-h6","status":"unaffected"}]}]}`, CVEOrgUnusable, nil},
		{"default affected with unaffected versions", `{"vendor":"Acme","product":"Gateway","defaultStatus":"affected","versions":[{"version":"0","lessThan":"5.10","status":"unaffected"}]}`, CVEOrgUnusable, nil},
		{"wildcard bound", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"5.15","lessThanOrEqual":"5.15.*","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"x series", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.x","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"text version", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"All versions","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"comparison in the version", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"< 2.4","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"reversed range (review M1)", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.0.5","lessThan":"3.0","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"empty range", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.0","lessThan":"3.0","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"an unaffected backport inside the range (review M2)", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"2.0","status":"affected"},{"version":"1.5.3","status":"unaffected"}]}`, CVEOrgUnusable, nil},
		{"an unaffected hotfix of the range's line", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"10.2.0","lessThan":"10.2.9-h1","status":"affected"},{"version":"10.2.5-h6","status":"unaffected"}]}`, CVEOrgUnusable, nil},
		{"a change to affected", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"2.0","status":"affected","changes":[{"at":"2.0","status":"affected"}]}]}`, CVEOrgUnusable, nil},
		{"only some platforms (review L3)", `{"vendor":"Acme","product":"Gateway","platforms":["SRX Series"],"versions":[{"version":"1.0","lessThan":"2.0","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"both bounds", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"2.0","lessThanOrEqual":"2.0","status":"affected"}]}`, CVEOrgUnusable, nil},
		{"one bad product of CISA's spoils the CVE", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"2.x","status":"affected"}]}`, CVEOrgUnusable, nil},
	} {
		got, err := ParseCVERecord(record(c.affected), "CVE-2026-1000", "Acme", "Gateway")
		if err != nil || got.Outcome != c.outcome || !slices.Equal(got.Rows, c.rows) {
			t.Errorf("%s: %+v %v, want %s %+v", c.name, got, err, c.outcome, c.rows)
		}
	}
	if got, _ := ParseCVERecord(record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`), "CVE-2026-1000", "Acme", "Multiple Products"); got.Outcome != CVEOrgNoMatch {
		t.Errorf("a Multiple Products entry got %+v", got)
	}
	// H1: Junos versions need findings' own comparator (D-510): a Juniper record is skipped, never read generically
	junos := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","versions":[{"version":"21.4","lessThan":"21.4R3-S5","status":"affected","versionType":"semver"}]}]}}}`
	if got, _ := ParseCVERecord([]byte(junos), "CVE-2026-1000", "Juniper", "Junos OS"); got.Outcome != CVEOrgUnusable || got.Rows != nil {
		t.Errorf("Junos: %+v", got)
	}
	// H2: only a product that says what an unlisted version is gives a complete list
	for ds, want := range map[string]bool{`"defaultStatus":"unaffected",`: true, `"defaultStatus":"unknown",`: false, ``: false} {
		got, _ := ParseCVERecord(record(`{"vendor":"Acme","product":"Gateway",`+ds+`"versions":[{"version":"3.0","lessThan":"3.0.5","status":"affected"}]}`), "CVE-2026-1000", "Acme", "Gateway")
		if got.Outcome != CVEOrgRanges || got.Complete != want {
			t.Errorf("defaultStatus %q: complete %v, want %v", ds, got.Complete, want)
		}
	}
	if got, _ := ParseCVERecord(record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"3.0","lessThan":"3.0.5","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"2.0","status":"affected"}]}`), "CVE-2026-1000", "Acme", "Gateway"); got.Complete {
		t.Error("one partial entry of CISA's product must make the list partial")
	}
}

func TestParseCVERecord_Fixtures(t *testing.T) {
	t.Parallel()
	got, err := ParseCVERecord([]byte(testFile(t, "cveorg/CVE-2024-3400.json")), "CVE-2024-3400", "Palo Alto Networks", "PAN-OS")
	const pan = "cpe:2.3:*:paloaltonetworks:panos:*:*:*:*:*:*:*:*"
	want := []AffectedRow{{CPE: pan, StartIncl: "10.2.0", EndExcl: "10.2.9-h1"}, {CPE: pan, StartIncl: "11.0.0", EndExcl: "11.0.4-h1"}, {CPE: pan, StartIncl: "11.1.0", EndExcl: "11.1.2-h3"}}
	if err != nil || got.Outcome != CVEOrgRanges || !slices.Equal(got.Rows, want) {
		t.Fatalf("PAN-OS: %+v %v", got, err)
	}
	if got, err := ParseCVERecord([]byte(testFile(t, "cveorg/CVE-2024-3400.json")), "CVE-2024-3400", "Palo Alto Networks", "Prisma Access"); err != nil || got.Outcome != CVEOrgNoVersions {
		t.Fatalf("Prisma Access (unaffected only): %+v %v", got, err)
	}
	if got, err := ParseCVERecord([]byte(testFile(t, "cveorg/CVE-2026-0001-unknown.json")), "CVE-2026-0001", "Acme", "Gateway"); err != nil || got.Outcome != CVEOrgNoVersions || got.Rows != nil {
		t.Fatalf("unknown: %+v %v", got, err)
	}
	if got, err := ParseCVERecord([]byte(testFile(t, "cveorg/CVE-2026-0002-hostile.json")), "CVE-2026-0002", "Acme", "Gateway"); err != nil || got.Outcome != CVEOrgUnusable || got.Rows != nil {
		t.Fatalf("hostile: %+v %v", got, err)
	}
}

// Untrusted input fails closed: not CVE JSON 5, another CVE's record, an unknown state, too large.
func TestParseCVERecord_Hostile(t *testing.T) {
	t.Parallel()
	for name, data := range map[string][]byte{
		"not JSON":        []byte(`<html>rate limited</html>`),
		"another CVE":     record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`),
		"CVE 4 format":    []byte(`{"data_type":"CVE","data_version":"4.0","CVE_data_meta":{"ID":"CVE-2026-0003"}}`),
		"unknown state":   []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"RESERVED"}}`),
		"wrong types":     []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"Acme","product":"Gateway","versions":[{"version":1.0}]}]}}}`),
		"too large":       append([]byte(`{"dataType":"CVE_RECORD",`), make([]byte, CVEOrgMaxBytes)...),
		"truncated":       []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003"`),
		"nested too deep": []byte(strings.Repeat("[", 20000)),
		"trailing bytes":  append([]byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED"}}`), []byte(`{"x":1}`)...),
	} {
		if got, err := ParseCVERecord(data, "CVE-2026-0003", "Acme", "Gateway"); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}
	got, err := ParseCVERecord([]byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"REJECTED"}}`), "CVE-2026-0003", "Acme", "Gateway")
	if err != nil || got.Outcome != CVEOrgRejected || got.Rows != nil {
		t.Errorf("rejected: %+v %v", got, err)
	}
	many := strings.TrimSuffix(strings.Repeat(`{"version":"1.0","status":"affected"},`, cveOrgMaxVersions+1), ",")
	if got, _ := ParseCVERecord(record(`{"vendor":"Acme","product":"Gateway","versions":[`+many+`]}`), "CVE-2026-1000", "Acme", "Gateway"); got.Outcome != CVEOrgUnusable {
		t.Errorf("too many versions: %+v", got.Outcome)
	}
}

func FuzzParseCVERecord(f *testing.F) {
	f.Add(record(`{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0","lessThan":"7.0.4","status":"affected"}]}`))
	f.Add(record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseCVERecord(data, "CVE-2026-1000", "Acme", "Gateway")
		if err != nil {
			return
		}
		if (got.Outcome == CVEOrgRanges) != (len(got.Rows) > 0) {
			t.Fatalf("outcome %s with %d rows", got.Outcome, len(got.Rows))
		}
		for _, r := range got.Rows { // every row fits the table's CHECKs and the NVD parser's limits
			if bad := badAffected(r); bad != "" || !strings.HasPrefix(r.CPE, "cpe:2.3:*:acme:gateway:") {
				t.Fatalf("row %+v: %s", r, bad)
			}
		}
	})
}

// cveOrgEnv is a box whose CISA list holds three CVEs without NVD ranges and one with them, and whose cve-org feed
// reads from the origin.
func cveOrgEnv(t *testing.T) (*env, *origin, *[]RangesUpdatedEvent) {
	t.Helper()
	e, o := pullEnv(t)
	e.only("cve-org")
	e.mirror("cve-org", o.url("/cves"))
	applyV(t, e.db, epoch0, "cisa-kev", []Vuln{
		vuln("CVE-2024-3400", "Palo Alto Networks", "PAN-OS", "2024-04-12"),
		vuln("CVE-2026-0001", "Acme", "Gateway", "2026-11-01"),
		vuln("CVE-2026-0004", "Initech", "Portal", "2026-11-02"),
		vuln("CVE-2026-0005", "Acme", "Router", "2026-11-03"),
	}, false)
	write(t, e.db, func(tx *sql.Tx) error {
		_, _, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-0005": {{CPE: "cpe:2.3:o:acme:router:*:*:*:*:*:*:*:*", EndExcl: "4.0"}}}, false, epoch0)
		return err
	})
	o.serve("/cves/2024/3xxx/CVE-2024-3400.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(testFile(t, "cveorg/CVE-2024-3400.json")))
	})
	o.serve("/cves/2026/0xxx/CVE-2026-0001.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(testFile(t, "cveorg/CVE-2026-0001-unknown.json")))
	})
	o.serve("/cves/2026/0xxx/CVE-2026-0004.json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	var got []RangesUpdatedEvent
	e.svc.Events = publishFunc(func(ev events.Event) {
		if r, ok := ev.Data.(RangesUpdatedEvent); ok {
			got = append(got, r)
		}
	})
	return e, o, &got
}

// D-556, INV-20: only the CISA CVEs NVD gave no ranges are asked for, one record each; the vendor's ranges are stored as
// CVE.org's, findings learns their source, and NVD's ranges win as soon as NVD has some.
func TestContract_CVEOrgRanges(t *testing.T) {
	t.Parallel()
	e, o, got := cveOrgEnv(t)
	if err := e.svc.Fetch(t.Context(), "cve-org"); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/cves/2026/0xxx/CVE-2026-0005.json"); n != 0 { // NVD has ranges for it (an undeclared path also fails the test)
		t.Fatalf("asked CVE.org for a CVE NVD has ranges for: %d", n)
	}
	for _, h := range o.all() {
		if h.query != "" || h.header.Get("Authorization") != "" || h.header.Get("Cookie") != "" {
			t.Fatalf("a request carried more than the CVE ID: %+v", h)
		}
	}
	f := e.feed("cve-org")
	if f.Status != "ok" || f.Records == nil || *f.Records != 1 || f.Error == nil ||
		*f.Error != "Read 3 CVE.org records of exploited CVEs NVD has no versions for: 1 with affected versions from their CNA, 1 without versions Vedette can compare, 1 not on CVE.org yet." {
		t.Fatalf("feed = %+v %v", f, *f.Error)
	}
	if len(*got) != 1 || !slices.Equal((*got)[0].CVEs, []string{"CVE-2024-3400"}) || !(*got)[0].First {
		t.Fatalf("events = %+v", *got)
	}
	aff, err := e.svc.st.KevAffected(t.Context())
	if err != nil || len(aff["CVE-2024-3400"]) != 3 || aff["CVE-2024-3400"][0].EndExcl != "10.2.9-h1" || len(aff["CVE-2026-0005"]) != 1 {
		t.Fatalf("KevAffected = %+v %v", aff, err)
	}
	if _, ok := aff["CVE-2026-0001"]; ok {
		t.Fatal("a record without versions stored an empty answer")
	}
	src, err := e.svc.st.RangesFromCVEOrg(t.Context())
	if err != nil || src["CVE-2024-3400"] != "cve.org" || len(src) != 1 { // PAN-OS says defaultStatus unaffected: a complete list
		t.Fatalf("RangesFromCVEOrg = %v %v", src, err)
	}

	// within cveOrgRecheck nothing is asked again
	before := len(o.all())
	if err := e.svc.Fetch(t.Context(), "cve-org"); err != nil || len(o.all()) != before {
		t.Fatalf("asked again too soon: %d requests, %v", len(o.all())-before, err)
	}

	// NVD answers without a vulnerable entry: CVE.org's ranges stay; with ranges: NVD's replace them
	write(t, e.db, func(tx *sql.Tx) error {
		_, _, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2024-3400": {}}, false, epoch0)
		return err
	})
	if src, _ := e.svc.st.RangesFromCVEOrg(t.Context()); src["CVE-2024-3400"] != "cve.org" {
		t.Fatal("an empty NVD answer dropped the CVE.org ranges")
	}
	nvd := []AffectedRow{{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", StartIncl: "10.2.0", EndExcl: "10.2.9"}}
	var changed []string
	write(t, e.db, func(tx *sql.Tx) (err error) {
		changed, _, err = applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2024-3400": nvd, "CVE-2026-0005": {{CPE: "cpe:2.3:o:acme:router:*:*:*:*:*:*:*:*", EndExcl: "4.0"}}}, true, epoch0)
		return err
	})
	aff, _ = e.svc.st.KevAffected(t.Context())
	if src, _ := e.svc.st.RangesFromCVEOrg(t.Context()); len(src) != 0 || !slices.Equal(aff["CVE-2024-3400"], nvd) || !slices.Contains(changed, "CVE-2024-3400") {
		t.Fatalf("NVD did not win: %v %+v %v", src, aff["CVE-2024-3400"], changed)
	}

	// the next day CVE.org is asked only for what NVD still has no ranges for, and leaves NVD's alone
	e.setNow(e.clock().Add(cveOrgRecheck + time.Hour))
	if err := e.svc.Fetch(t.Context(), "cve-org"); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/cves/2024/3xxx/CVE-2024-3400.json"); n != 1 {
		t.Fatalf("CVE.org asked %d times for a CVE NVD has ranges for", n)
	}
	if f := e.feed("cve-org"); *f.Records != 0 {
		t.Fatalf("records = %d", *f.Records)
	}
}

// A busy source is tried again; one that stays busy before any record fails the pull (back-off), and later records
// are read at the next pull.
func TestCVEOrgPull_Busy(t *testing.T) {
	t.Parallel()
	e, o, _ := cveOrgEnv(t)
	busy := 0
	o.serve("/cves/2026/0xxx/CVE-2026-0004.json", func(w http.ResponseWriter, _ *http.Request) {
		busy++
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if err := e.svc.Fetch(t.Context(), "cve-org"); err != nil { // never read first, newest first: 0004 is asked first
		t.Fatal(err)
	}
	if busy != 3 || !slices.Equal(e.waited(), []time.Duration{6 * time.Second, 30 * time.Second}) {
		t.Fatalf("%d tries, waits %v", busy, e.waited())
	}
	f := e.feed("cve-org")
	if f.Status != "error" || f.Error == nil || !strings.HasPrefix(*f.Error, "CVE.org (GitHub) was busy") {
		t.Fatalf("feed = %+v", f)
	}
	if o.count("/cves/2024/3xxx/CVE-2024-3400.json") != 0 {
		t.Fatal("went on after the source stayed busy")
	}
}

// Review M4, L1: a file the source refuses (403) is stamped and the pull goes on with the others; an answer that is not
// a CVE record (a proxy page) keeps the ranges stored before.
func TestCVEOrgPull_OneBadFileDoesNotStopIt(t *testing.T) {
	t.Parallel()
	e, o, _ := cveOrgEnv(t)
	o.serve("/cves/2026/0xxx/CVE-2026-0004.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	if err := e.svc.Fetch(t.Context(), "cve-org"); err != nil {
		t.Fatal(err)
	}
	f := e.feed("cve-org")
	if f.Status != "ok" || *f.Records != 1 || f.Error == nil || !strings.Contains(*f.Error, "1 unreadable") {
		t.Fatalf("feed = %+v %v", f, *f.Error)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cveorg_checked`); n != 3 {
		t.Fatalf("%d CVEs stamped, want 3 (the refused one too, so the next pull does not start with it)", n)
	}
	o.serve("/cves/2024/3xxx/CVE-2024-3400.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>sign in</html>")) })
	e.setNow(e.clock().Add(cveOrgRecheck + time.Hour))
	if err := e.svc.Fetch(t.Context(), "cve-org"); err != nil {
		t.Fatal(err)
	}
	if src, _ := e.svc.st.RangesFromCVEOrg(t.Context()); src["CVE-2024-3400"] != "cve.org" {
		t.Fatalf("an unreadable answer dropped the stored ranges: %v", src)
	}
}

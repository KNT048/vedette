package feeds

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

func TestCVERecordURL(t *testing.T) {
	t.Parallel()
	const base = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
	for cve, want := range map[string]string{
		"CVE-2024-3400":   base + "/2024/3xxx/CVE-2024-3400.json",
		"CVE-2023-12345":  base + "/2023/12xxx/CVE-2023-12345.json",
		"CVE-2021-0001":   base + "/2021/0xxx/CVE-2021-0001.json",
		"CVE-2026-133612": base + "/2026/133xxx/CVE-2026-133612.json",
	} {
		if got, err := CVERecordURL(base+"/", cve); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", cve, got, err, want)
		}
	}
	for _, bad := range []string{"CVE-2024-3400/../../x", "cve-2024-3400", "CVE-2024-34", ""} {
		if _, err := CVERecordURL(base, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := CVERecordURL(base+"?x=1", "CVE-2024-3400"); err == nil {
		t.Error("a base with a query string was accepted")
	}
	src, err := recordSourceOf(recordsRepo)
	if err != nil || src.records != "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves" || !slices.Equal(src.redirect, recordHosts) ||
		src.archiveURL(time.Date(2026, 11, 20, 13, 0, 0, 0, time.UTC), true) != recordsRepo+"/releases/download/cve_2026-11-20_2300Z/2026-11-20_all_CVEs_at_midnight.zip.zip" ||
		src.archiveURL(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), false) != recordsRepo+"/releases/download/cve_2026-11-19_at_end_of_day/2026-11-19_delta_CVEs_at_end_of_day.zip" {
		t.Fatalf("GitHub: %+v %v", src, err)
	}
	if m, err := recordSourceOf("https://mirror.example.com/cvelist/"); err != nil || m.records != "https://mirror.example.com/cvelist/cves" || m.redirect != nil {
		t.Fatalf("mirror: %+v %v", m, err)
	}
}

// recordJSON is a CVE JSON 5 record of cve published on day with the CNA's affected entries (JSON array items).
func recordJSON(cve, day, affected string) []byte {
	return []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + cve + `","state":"PUBLISHED","assignerShortName":"acme","datePublished":"` +
		day + `T10:00:00.000Z","dateUpdated":"` + day + `T12:00:00.000Z"},"containers":{"cna":{"affected":[` + affected + `]}}}`)
}

// record is a CVE JSON 5 record of CVE-2026-1000 with the CNA's affected entries.
func record(affected string) []byte { return recordJSON("CVE-2026-1000", "2026-11-01", affected) }

// span is a range row of the record conversion as the tests write it.
type span struct{ si, se, ei, ee, fixed, def string }

func spansOf(rs []Range) []span {
	out := []span{}
	for _, r := range rs {
		out = append(out, span{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.DefaultStatus})
	}
	return out
}

// genericRows are the rows the generic comparison reads (Range.Generic).
func genericRows(rs []Range) []Range {
	return slices.DeleteFunc(slices.Clone(rs), func(r Range) bool { return !r.Generic() })
}

// vspan is a row kept in the vendor's notation, with its version_type.
type vspan struct {
	span
	typ string
}

// vendorSpans are the rows kept in the vendor's notation.
func vendorSpans(rs []Range) []vspan {
	out := []vspan{}
	for _, r := range rs {
		if r.Generic() {
			continue
		}
		out = append(out, vspan{span{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.DefaultStatus}, r.VersionType})
	}
	return out
}

// The conversion of affected versions to ranges, and everything it refuses to guess (the rows the generic comparison reads; what the
// refused products keep in their vendor's notation: TestParseCVERecord_VendorRows).
func TestParseCVERecord_Ranges(t *testing.T) {
	t.Parallel()
	const u, a, k = DefaultUnaffected, DefaultAffected, DefaultUnknown
	for _, c := range []struct {
		name, affected string
		want           []span // nil: no rows (skipped or nothing to compare)
		skipped        int
	}{
		{"lessThan from a start", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0","lessThan":"7.0.4","status":"affected","versionType":"semver"}]}`,
			[]span{{si: "7.0", ee: "7.0.4", def: k}}, 0},
		{"lessThan with its fix", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"10.2.0","lessThan":"10.2.9-h1","status":"affected","changes":[{"at":"10.2.9-h1","status":"unaffected"}]}]}`,
			[]span{{si: "10.2.0", ee: "10.2.9-h1", fixed: "10.2.9-h1", def: u}}, 0},
		{"lessThanOrEqual from 0 is no start", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"0","lessThanOrEqual":"6.2.9","status":"affected"}]}`,
			[]span{{ei: "6.2.9", def: k}}, 0},
		{"n/a start below an end", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"n/a","lessThan":"3.1","status":"affected"}]}`,
			[]span{{ee: "3.1", def: k}}, 0},
		{"an end of * is no end", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"5.0","lessThanOrEqual":"*","status":"affected"},{"version":"0","lessThan":"*","status":"affected"}]}`,
			[]span{{si: "5.0", def: k}, {def: k}}, 0},
		{"an exact version", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"15.2(4)M3","status":"affected"},{"version":"9.9","status":"unaffected"}]}`,
			[]span{{si: "15.2(4)M3", ei: "15.2(4)M3", def: k}}, 0},
		{"n/a passed over, all versions is every version", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"n/a","status":"affected"},{"version":"All versions","status":"affected"}]}`,
			[]span{{def: k}}, 0},
		{"default affected, nothing unaffected: every version", `{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`, []span{{def: a}}, 0},
		{"modules and processor platforms do not limit the product", `{"vendor":"Acme","product":"Gateway","modules":["Login"],"platforms":["x64-based Systems","ARM64-based Systems"],"versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]}`,
			[]span{{si: "1.0", ee: "1.5", def: k}}, 0},
		{"status unknown only", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unknown","versions":[{"version":"n/a","status":"unknown"}]}`, nil, 0},
		{"package without vendor or product", `{"packageName":"gateway","collectionURL":"https://pypi.org","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]}`, nil, 0},
		{"git commits", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1da177e4c3f4","lessThan":"6b2c1e3fa9d1","status":"affected","versionType":"git"}]}`, nil, 1},
		{"a change inside the range (a hotfix)", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"10.2.0","lessThan":"10.2.9","status":"affected","changes":[{"at":"10.2.5-h6","status":"unaffected"}]}]}`, nil, 1},
		{"default affected with unaffected versions", `{"vendor":"Acme","product":"Gateway","defaultStatus":"affected","versions":[{"version":"0","lessThan":"5.10","status":"unaffected"}]}`, nil, 1},
		{"wildcard bound", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"5.15","lessThanOrEqual":"5.15.*","status":"affected"}]}`, nil, 1},
		{"x series", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.x","status":"affected"}]}`, nil, 1},
		{"a comparison in words", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"before 2.4","status":"affected"}]}`, nil, 1},
		{"reversed range", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.0.5","lessThan":"3.0","status":"affected"}]}`, nil, 1},
		{"same numbers, reversed suffix", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.0.5-h2","lessThan":"3.0.5-h1","status":"affected"}]}`, nil, 1},
		{"empty range", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.0","lessThan":"3.0","status":"affected"}]}`, nil, 1},
		{"an unaffected backport inside the range", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"2.0","status":"affected"},{"version":"1.5.3","status":"unaffected"}]}`, nil, 1},
		{"a change to affected", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"2.0","status":"affected","changes":[{"at":"2.0","status":"affected"}]}]}`, nil, 1},
		{"only some operating systems: rows per system", `{"vendor":"Acme","product":"Gateway","platforms":["Windows"],"versions":[{"version":"1.0","lessThan":"2.0","status":"affected"}]}`,
			[]span{{si: "1.0", ee: "2.0", def: k}}, 0},
		{"only some models", `{"vendor":"Acme","product":"Gateway","platforms":["GW-400 Series"],"versions":[{"version":"1.0","lessThan":"2.0","status":"affected"}]}`, nil, 1},
		{"a system and a model", `{"vendor":"Acme","product":"Gateway","platforms":["Windows","GW-400 Series"],"versions":[{"version":"1.0","lessThan":"2.0","status":"affected"}]}`, nil, 1},
		{"both bounds", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"2.0","lessThanOrEqual":"2.0","status":"affected"}]}`, nil, 1},
		{"one bad entry spoils its product", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"2.x","status":"affected"}]}`, nil, 1},
		{"letter releases: only their versions are left out, the list is partial", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"3.5.0","lessThan":"3.5.10","status":"affected","versionType":"semver"},{"version":"1.1.1","lessThan":"1.1.1zk","status":"affected","versionType":"custom"},{"version":"1.0.2","lessThan":"1.0.2zt","status":"affected","versionType":"custom"},{"version":"1.0.2zt","status":"unaffected"}]}`,
			[]span{{si: "3.5.0", ee: "3.5.10", def: k}}, 0},
		{"a letter release alone is an exact version", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"1.1.1zk","status":"affected"}]}`,
			[]span{{si: "1.1.1zk", ei: "1.1.1zk", def: u}}, 0},
		{"a letter branch alone gives no row", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"1.1.1","lessThan":"1.1.1zk","status":"affected"}]}`, nil, 0},
		{"a lone unaffected version above every affected row: the fix of the line they end on", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"0","lessThanOrEqual":"6.49.18","status":"affected"},{"version":"7.0.0","lessThanOrEqual":"7.11.2","status":"affected"},{"version":"7.24.0","status":"unaffected"}]}`,
			[]span{{ei: "6.49.18", def: k}, {si: "7.0.0", ei: "7.11.2", fixed: "7.24.0", def: k}}, 0},
		{"a lone unaffected pre-release above every affected row", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"0","lessThanOrEqual":"7.24.2","status":"affected"},{"version":"7.25beta4","status":"unaffected","versionType":"custom"}]}`,
			[]span{{ei: "7.24.2", fixed: "7.25beta4", def: k}}, 0},
		{"a lone unaffected version on another line than the rows end on", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0.0","lessThanOrEqual":"7.11.2","status":"affected"},{"version":"8.1.0","status":"unaffected"}]}`,
			[]span{{si: "7.0.0", ei: "7.11.2", def: k}}, 0},
		{"an unaffected version beside two", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0.0","lessThanOrEqual":"7.11.2","status":"affected"},{"version":"7.24.0","status":"unaffected"},{"version":"7.25.0","status":"unaffected"}]}`,
			[]span{{si: "7.0.0", ei: "7.11.2", def: k}}, 0},
		{"an unaffected range above the rows is no lone version", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0.0","lessThanOrEqual":"7.11.2","status":"affected"},{"version":"7.24.0","lessThan":"7.30.0","status":"unaffected"}]}`,
			[]span{{si: "7.0.0", ei: "7.11.2", def: k}}, 0},
		{"a lone unaffected version below an affected row's end", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0.0","lessThanOrEqual":"7.11.2","status":"affected"},{"version":"7.30.0","lessThan":"7.30.4","status":"affected"},{"version":"7.24.0","status":"unaffected"}]}`,
			[]span{{si: "7.0.0", ei: "7.11.2", def: k}, {si: "7.30.0", ee: "7.30.4", def: k}}, 0},
		{"a lone unaffected version below a left-out letter release", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0.0","lessThanOrEqual":"1.4.2","status":"affected"},{"version":"1.5.1","lessThan":"1.5.1zk","status":"affected","versionType":"custom"},{"version":"1.5.0","status":"unaffected"}]}`,
			[]span{{si: "1.0.0", ei: "1.4.2", def: k}}, 0},
		{"a partial entry makes its product's list partial", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"3.0","lessThan":"3.0.5","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"2.0","status":"unaffected"}]}`,
			[]span{{si: "3.0", ee: "3.0.5", def: k}}, 0},
	} {
		got, err := ParseCVERecord(record(c.affected), "CVE-2026-1000")
		if err != nil || !slices.Equal(spansOf(genericRows(got.Ranges)), append([]span{}, c.want...)) || got.Skipped != c.skipped {
			t.Errorf("%s: %+v skipped %d %v, want %+v skipped %d", c.name, spansOf(genericRows(got.Ranges)), got.Skipped, err, c.want, c.skipped)
		}
		for _, r := range got.Ranges {
			if r.CVE != "CVE-2026-1000" || r.Origin != OriginCNA || r.Vendor != "acme" || r.Product != "gateway" || r.Part != "" || r.CPE != "" {
				t.Errorf("%s: identity %+v", c.name, r)
			}
		}
	}
	// another product is its own key; "n/a" as the vendor is the assigner's product (VMware's records); company words go
	got, _ := ParseCVERecord(record(`{"vendor":"Acme Software Corporation","product":"Acme Portal","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]},`+
		`{"vendor":"n/a","product":"Acme Box","versions":[{"version":"2.0","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.x","status":"affected"}]}`), "CVE-2026-1000")
	if g := genericRows(got.Ranges); len(g) != 2 || g[0].Product != "portal" || g[1].Vendor != "acme" || g[1].Product != "box" || got.Skipped != 1 {
		t.Fatalf("products: %+v skipped %d", got.Ranges, got.Skipped)
	}
	if k := RecordProductKey("Palo Alto Networks", "PAN-OS"); k != (ProductKey{"paloalto", "panos"}) {
		t.Fatalf("key %+v", k)
	}
}

// A product the generic rules refuse keeps its versions as the vendor states them, in rows the generic comparison never reads
// (version_type "vendor:…"): bounds as written, the fixed release where the record says the versions from there are unaffected,
// a hotfix range split at its changes, an "affected except" list as one range per fixed release. Git commits, entries limited to
// some models and text the column cannot hold safely are left out.
func TestParseCVERecord_VendorRows(t *testing.T) {
	t.Parallel()
	const u, a, k = DefaultUnaffected, DefaultAffected, DefaultUnknown
	for _, c := range []struct {
		name, affected string
		want           []vspan
	}{
		{"VMware's builds per train", `{"vendor":"n/a","product":"VMware ESXi","defaultStatus":"unaffected","versions":[{"version":"8.0","lessThan":"ESXi80U3d-24585383","status":"affected","versionType":"custom"},{"version":"7.0","lessThan":"ESXi70U3s-24585291","status":"affected","versionType":"custom"}]}`,
			[]vspan{{span{si: "8.0", ee: "ESXi80U3d-24585383", fixed: "ESXi80U3d-24585383", def: u}, "vendor:custom"}, {span{si: "7.0", ee: "ESXi70U3s-24585291", fixed: "ESXi70U3s-24585291", def: u}, "vendor:custom"}}},
		{"text as written", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"5.x, 4.5.x","status":"affected"}]}`,
			[]vspan{{span{si: "5.x, 4.5.x", ei: "5.x, 4.5.x", def: u}, "vendor:text"}}},
		{"a wildcard end", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"5.15","lessThanOrEqual":"5.15.*","status":"affected","versionType":"semver"}]}`,
			[]vspan{{span{si: "5.15", ei: "5.15.*", def: k}, "vendor:semver"}}},
		{"hotfixes split the range", `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"12.1.0","lessThan":"12.1.10-h2","status":"affected","changes":[{"at":"12.1.4-h12","status":"unaffected"},{"at":"12.1.5","status":"affected"},{"at":"12.1.6-h3","status":"unaffected"},{"at":"12.1.7","status":"affected"}]}]}`,
			[]vspan{{span{si: "12.1.0", ee: "12.1.4-h12", fixed: "12.1.4-h12", def: u}, "vendor:text"}, {span{si: "12.1.5", ee: "12.1.6-h3", fixed: "12.1.6-h3", def: u}, "vendor:text"},
				{span{si: "12.1.7", ee: "12.1.10-h2", fixed: "12.1.10-h2", def: u}, "vendor:text"}}},
		{"affected except the fixed releases", `{"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[{"version":"6.0","status":"affected"},{"version":"0","lessThan":"6.0","status":"unaffected","versionType":"semver"},{"version":"6.1.149","lessThanOrEqual":"6.1.*","status":"unaffected","versionType":"semver"},{"version":"6.6.30","lessThanOrEqual":"6.6.*","status":"unaffected","versionType":"semver"},{"version":"6.17","lessThanOrEqual":"*","status":"unaffected","versionType":"original_commit_for_fix"}]},{"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[{"version":"84c61fe1a75b","lessThan":"2902c3ebcca5","status":"affected","versionType":"git"}]}`,
			[]vspan{{span{si: "6.0", ee: "6.1.149", fixed: "6.1.149", def: a}, "vendor:semver"}, {span{si: "6.0", ee: "6.6.30", fixed: "6.6.30", def: a}, "vendor:semver"},
				{span{si: "6.0", ee: "6.17", fixed: "6.17", def: a}, "vendor:semver"}}},
		{"one bad entry: the product's rows kept as stated", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"1.5","status":"affected"}]},{"vendor":"Acme","product":"Gateway","versions":[{"version":"2.x","status":"affected"}]}`,
			[]vspan{{span{si: "1.0", ee: "1.5", def: k}, "vendor:text"}, {span{si: "2.x", ei: "2.x", def: k}, "vendor:text"}}},
		{"git commits only", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1da177e4c3f4","lessThan":"6b2c1e3fa9d1","status":"affected","versionType":"git"}]}`, []vspan{}},
		{"only some models", `{"vendor":"Acme","product":"Gateway","platforms":["GW-400 Series"],"versions":[{"version":"1.0","lessThan":"2.0","status":"affected"}]}`, []vspan{}},
		{"quotes and semicolons", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0') DROP TABLE x;--","status":"affected"},{"version":"3.x","status":"affected"}]}`,
			[]vspan{{span{si: "3.x", ei: "3.x", def: k}, "vendor:text"}}},
	} {
		got, err := ParseCVERecord(record(c.affected), "CVE-2026-1000")
		if err != nil || !slices.Equal(vendorSpans(got.Ranges), c.want) || len(genericRows(got.Ranges)) != 0 {
			t.Errorf("%s: %+v (%d generic) %v, want %+v", c.name, vendorSpans(got.Ranges), len(genericRows(got.Ranges)), err, c.want)
		}
	}
}

// The rows kept as the vendor states them are bounded: a range of 60 000 hotfix changes, or a record whose products together pass the
// record's bound, keeps no row of the product over the bound, counted; the work stops at the bound.
func TestParseCVERecord_StatedRowsBounded(t *testing.T) {
	t.Parallel()
	var changes strings.Builder
	for i := range 60000 {
		if i > 0 {
			changes.WriteString(",")
		}
		st := "unaffected"
		if i%2 == 1 {
			st = "affected"
		}
		fmt.Fprintf(&changes, `{"at":"1.%d","status":"%s"}`, i+1, st)
	}
	start := time.Now()
	got, err := ParseCVERecord(record(`{"vendor":"Acme","product":"Gateway","versions":[{"version":"1.0","lessThan":"9.9","status":"affected","changes":[`+changes.String()+`]}]}`), "CVE-2026-1000")
	if err != nil || len(got.Ranges) != 0 || got.Skipped != 1 || got.StatedDropped != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("hotfix flood: %d rows, skipped %d, dropped %d, %v", len(got.Ranges), got.Skipped, got.StatedDropped, err)
	}
	var products []string
	for p := range 5 { // 450 exact text versions each: four fit the record's 2000, the fifth does not
		var vs []string
		for i := range 450 {
			vs = append(vs, fmt.Sprintf(`{"version":"%d.x build %d","status":"affected"}`, p, i))
		}
		products = append(products, fmt.Sprintf(`{"vendor":"Acme","product":"P%d","versions":[%s]}`, p, strings.Join(vs, ",")))
	}
	got, err = ParseCVERecord(record(strings.Join(products, ",")), "CVE-2026-1000")
	if err != nil || len(got.Ranges) != 1800 || got.Skipped != 5 || got.StatedDropped != 1 {
		t.Fatalf("record bound: %d rows, skipped %d, dropped %d, %v", len(got.Ranges), got.Skipped, got.StatedDropped, err)
	}
}

// The fields of a whole record: the PAN-OS record with CISA's ADP (CPE names, SSVC, CWE) and the Java4Shell record.
func TestParseCVERecord_Fields(t *testing.T) {
	t.Parallel()
	pan, err := ParseCVERecord(fixture(t, "cveorg/CVE-2024-3400.json"), "CVE-2024-3400")
	if err != nil {
		t.Fatal(err)
	}
	want := []span{{si: "10.2.0", ee: "10.2.9-h1", fixed: "10.2.9-h1", def: DefaultUnaffected}, {si: "11.0.0", ee: "11.0.4-h1", fixed: "11.0.4-h1", def: DefaultUnaffected},
		{si: "11.1.0", ee: "11.1.2-h3", fixed: "11.1.2-h3", def: DefaultUnaffected}}
	if pan.State != RecordPublished || pan.Published != time.Date(2024, 4, 12, 7, 20, 0, 707_000_000, time.UTC) || !slices.Equal(spansOf(pan.Ranges), want) ||
		pan.Ranges[0].VersionType != "custom" || pan.Ranges[0].Vendor != "paloalto" {
		t.Fatalf("PAN-OS: %+v %+v", pan, spansOf(pan.Ranges))
	}
	java, err := ParseCVERecord(fixture(t, "cverecord/CVE-2026-114938.json"), "CVE-2026-114938")
	if err != nil {
		t.Fatal(err)
	}
	var javaSE []string
	for _, r := range java.Ranges {
		if r.Vendor == "oracle" && r.Product == "javase" {
			javaSE = append(javaSE, r.StartIncl)
		}
	}
	if !slices.Equal(javaSE, []string{"8u511b33-perf", "17.0.21.0.3", "21.0.13.0.3", "25.0.5.0.3", "27.0.1.0.3"}) || java.Assigner != "oracle" ||
		java.SSVC != (SSVC{Exploitation: "none", Automatable: "no", Impact: "total"}) || !slices.Equal(java.CWE, []string{"CWE-122"}) ||
		len(java.Refs) != 14 || java.Refs[0].Source != OriginCNA || !slices.Equal(java.Refs[0].Tags, []string{"vendor-advisory"}) || java.Refs[1].Source != OriginADP ||
		!strings.HasPrefix(java.Description, "Vulnerability in the Oracle Java SE") {
		t.Fatalf("Java4Shell: %v %+v %v %d %+v", javaSE, java.SSVC, java.CWE, len(java.Refs), java.Refs[:2])
	}
	// a supplier ADP's affected list is origin adp; "0" up to "*" is every version
	if !slices.ContainsFunc(java.Ranges, func(r Range) bool {
		return r.Origin == OriginADP && r.Vendor == "siemens" && r.Product == "siveillancecontrol" && r.StartIncl == "" && r.EndExcl == ""
	}) {
		t.Fatalf("supplier ADP: %+v", java.Ranges)
	}
	// CISA's ADP names CPEs: its rows are that CPE's product
	adp, err := ParseCVERecord(recordADP(`{"vendor":"paloaltonetworks","product":"pan-os","cpes":["cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:*"],"defaultStatus":"unknown","versions":[{"version":"10.2.0","lessThan":"10.2.9-h1","status":"affected","versionType":"custom"}]}`), "CVE-2026-1000")
	if err != nil || len(adp.Ranges) != 1 || !reflect.DeepEqual(adp.Ranges[0], Range{CVE: "CVE-2026-1000", Origin: OriginADP, Part: "o", Vendor: "paloaltonetworks", Product: "pan-os",
		CPE: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", StartIncl: "10.2.0", EndExcl: "10.2.9-h1", VersionType: "custom", DefaultStatus: DefaultUnknown}) || adp.SSVC != (SSVC{Exploitation: "poc", Impact: "partial"}) {
		t.Fatalf("ADP: %+v %+v %v", adp.Ranges, adp.SSVC, err)
	}
}

func recordADP(affected string) []byte {
	return []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{},"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"affected":[` + affected + `],"metrics":[{"other":{"type":"ssvc","content":{"options":[{"Exploitation":"poc"},{"Automatable":3},{"Technical Impact":"partial"}]}}}]}]}}`)
}

// Untrusted input fails closed: not CVE JSON 5, another CVE's record, an unknown state, too large; the rest is capped.
func TestParseCVERecord_Hostile(t *testing.T) {
	t.Parallel()
	for name, data := range map[string][]byte{
		"not JSON":        []byte(`<html>rate limited</html>`),
		"another CVE":     record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`),
		"CVE 4 format":    []byte(`{"data_type":"CVE","data_version":"4.0","CVE_data_meta":{"ID":"CVE-2026-0003"}}`),
		"unknown state":   []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"RESERVED"}}`),
		"wrong types":     []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED"},"containers":{"cna":{"affected":[{"vendor":"Acme","product":"Gateway","versions":[{"version":1.0}]}]}}}`),
		"too large":       append([]byte(`{"dataType":"CVE_RECORD",`), make([]byte, RecordMaxBytes)...),
		"truncated":       []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003"`),
		"nested too deep": []byte(strings.Repeat("[", 20000)),
		"trailing bytes":  append([]byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED"}}`), []byte(`{"x":1}`)...),
		"many ADPs":       []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED"},"containers":{"adp":[` + strings.TrimSuffix(strings.Repeat(`{},`, recordMaxContainers+1), ",") + `]}}`),
	} {
		if got, err := ParseCVERecord(data, "CVE-2026-0003"); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}
	got, err := ParseCVERecord([]byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-0003","state":"REJECTED"}}`), "CVE-2026-0003")
	if err != nil || got.State != RecordRejected || got.Ranges != nil {
		t.Errorf("rejected: %+v %v", got, err)
	}
	h, err := ParseCVERecord(fixture(t, "cveorg/CVE-2026-0002-hostile.json"), "CVE-2026-0002")
	if err != nil || len(h.Ranges) != 1 || h.Ranges[0].Vendor != "evil" || h.Skipped != 1 { // the gateway's NUL and SQL are refused, kept in no form
		t.Fatalf("hostile: %+v %v", h, err)
	}
	many := strings.TrimSuffix(strings.Repeat(`{"version":"1.0","status":"affected"},`, recordMaxVersions+1), ",")
	if got, _ := ParseCVERecord(record(`{"vendor":"Acme","product":"Gateway","versions":[`+many+`]}`), "CVE-2026-1000"); len(got.Ranges) != 0 || got.Skipped != 1 {
		t.Errorf("too many versions: %+v", got)
	}
	long := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED"},"containers":{"cna":{"title":"` + strings.Repeat("é", 400) +
		`","descriptions":[{"lang":"en","value":"a\u0000b` + strings.Repeat("x", 5000) + `"}],"references":[{"url":"javascript:alert(1)"},{"url":"https://example.com/a","tags":["Patch","x y","vendor-advisory"]}],` +
		`"problemTypes":[{"descriptions":[{"cweId":"CWE-79"},{"cweId":"79; DROP"}]}]}}}`
	g, err := ParseCVERecord([]byte(long), "CVE-2026-1000")
	if err != nil || len(g.Title) > recordMaxTitle || len(g.Description) > recordMaxText || strings.ContainsRune(g.Description, 0) || !strings.HasPrefix(g.Description, "ab") ||
		len(g.Refs) != 1 || !slices.Equal(g.Refs[0].Tags, []string{"patch", "vendor-advisory"}) || !slices.Equal(g.CWE, []string{"CWE-79"}) {
		t.Fatalf("caps: %d %d %+v %v %v", len(g.Title), len(g.Description), g.Refs, g.CWE, err)
	}
}

func FuzzParseCVERecord(f *testing.F) {
	f.Add(record(`{"vendor":"Acme","product":"Gateway","versions":[{"version":"7.0","lessThan":"7.0.4","status":"affected"}]}`))
	f.Add(record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`))
	f.Add(recordADP(`{"vendor":"x","product":"y","cpes":["cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"],"versions":[{"version":"1","lessThanOrEqual":"*","status":"affected"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseCVERecord(data, "CVE-2026-1000")
		if err != nil {
			return
		}
		if len(got.Title) > recordMaxTitle || len(got.Description) > recordMaxText || len(got.Solution) > recordMaxText || len(got.Refs) > recordMaxRefs || len(got.CWE) > recordMaxCWE {
			t.Fatalf("caps: %+v", got)
		}
		for _, r := range got.Ranges { // every row fits the table's CHECKs
			for _, v := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed} {
				if len(v) > nvdMaxVersion || !printableASCII(v) {
					t.Fatalf("row %+v", r)
				}
			}
			if r.Origin != OriginCNA && r.Origin != OriginADP || r.Vendor == "" || r.Product == "" || len(r.Vendor) > recordMaxName || r.CPE != "" && badAffected(AffectedRow{CPE: r.CPE}) != "" {
				t.Fatalf("row %+v", r)
			}
		}
		for _, ref := range got.Refs {
			if len(ref.URL) > recordMaxURL || !strings.HasPrefix(ref.URL, "http") || len(ref.Tags) > recordMaxTags {
				t.Fatalf("ref %+v", ref)
			}
		}
	})
}

// ---- archives ----

// zipOf is a zip of the given files, deflated.
func zipOf(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// streamZip is a zip whose entries carry their sizes before the data (as the CVE Program's inner archive): written with CreateRaw.
func streamZip(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	names := slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	})
	for _, name := range names {
		var c bytes.Buffer
		fw, _ := flateWriter(&c)
		_, _ = fw.Write(files[name])
		_ = fw.Close()
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, CRC32: crc(files[name]), CompressedSize64: uint64(c.Len()), UncompressedSize64: uint64(len(files[name]))} //nolint:gosec // test sizes
		f, err := w.CreateRaw(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(c.Bytes())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// dailyArchive is the CVE Program's daily file: a zip holding cves.zip.
func dailyArchive(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	return zipOf(t, map[string][]byte{"cves.zip": streamZip(t, files)})
}

func TestArchives(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"cves/2026/1xxx/CVE-2026-1000.json": record(`{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`),
		"cves/2024/3xxx/CVE-2024-3400.json": fixture(t, "cveorg/CVE-2024-3400.json"),
		"cves/deltaLog.json":                []byte(`[]`),
	}
	data := dailyArchive(t, files)
	var got []string
	err := walkDailyArchive(bytes.NewReader(data), int64(len(data)), func(e archiveEntry, body func() ([]byte, error)) error {
		b, err := body()
		if err != nil {
			return err
		}
		if !bytes.Equal(b, files[e.Name]) {
			t.Errorf("%s: body differs", e.Name)
		}
		got = append(got, e.CVE)
		return nil
	})
	if err != nil || !slices.Equal(got, []string{"CVE-2024-3400", "CVE-2026-1000"}) {
		t.Fatalf("daily: %v %v", got, err)
	}
	// an entry fn does not read is skipped without inflating; a damaged one fails the walk
	inner := streamZip(t, files)
	if err := walkZipStream(bytes.NewReader(inner), func(archiveEntry, func() ([]byte, error)) error { return nil }); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(inner)
	bad[14] ^= 0xff // the first entry's CRC
	if err := walkZipStream(bytes.NewReader(bad), func(_ archiveEntry, body func() ([]byte, error)) error { _, err := body(); return err }); !errors.Is(err, errArchive) {
		t.Fatalf("damaged: %v", err)
	}
	if err := walkZipStream(bytes.NewReader(inner[:len(inner)/2]), func(archiveEntry, func() ([]byte, error)) error { return nil }); !errors.Is(err, errArchive) {
		t.Fatalf("cut: %v", err)
	}
	// a zip with sizes after the data (zip.Writer's own way) is refused, not guessed
	if err := walkZipStream(bytes.NewReader(zipOf(t, files)), func(archiveEntry, func() ([]byte, error)) error { return nil }); !errors.Is(err, errArchive) {
		t.Fatalf("data descriptor: %v", err)
	}
	// the hourly archive: a plain zip; the one after midnight is an empty zip
	got = nil
	if err := walkDeltaArchive(zipOf(t, map[string][]byte{"deltaCves/CVE-2026-1000.json": files["cves/2026/1xxx/CVE-2026-1000.json"]}), func(e archiveEntry, _ func() ([]byte, error)) error {
		got = append(got, e.CVE)
		return nil
	}); err != nil || !slices.Equal(got, []string{"CVE-2026-1000"}) {
		t.Fatalf("delta: %v %v", got, err)
	}
	empty := zipOf(t, map[string][]byte{})
	if err := walkDeltaArchive(empty, func(archiveEntry, func() ([]byte, error)) error { t.Fatal("an entry"); return nil }); err != nil || len(empty) != 22 {
		t.Fatalf("empty: %v %d", err, len(empty))
	}
	if err := walkDeltaArchive([]byte("<html>"), func(archiveEntry, func() ([]byte, error)) error { return nil }); !errors.Is(err, errArchive) {
		t.Fatalf("not a zip: %v", err)
	}
}

func FuzzWalkZipStream(f *testing.F) {
	f.Add(streamZip(f, map[string][]byte{"cves/2026/1xxx/CVE-2026-1000.json": record(`{"vendor":"Acme","product":"Gateway"}`)}))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = walkZipStream(bytes.NewReader(data), func(e archiveEntry, body func() ([]byte, error)) error {
			b, err := body()
			if err == nil && len(b) > RecordMaxBytes {
				t.Fatalf("%s: %d bytes", e.Name, len(b))
			}
			return nil
		})
	})
}

// ---- the catalogue ----

// Java4Shell: NVD has received the CVE but not analysed it; its record gives Oracle's versions, read as ranges of the record's product.
// NVD's rows win as soon as NVD analyses the CVE; the record's stay beside them.
func TestRecordRanges_BeforeAndAfterNVD(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	const cve = "CVE-2026-114938"
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	java, err := ParseCVERecord(fixture(t, "cverecord/CVE-2026-114938.json"), cve)
	if err != nil {
		t.Fatal(err)
	}
	write(t, db, func(tx *sql.Tx) error {
		if err := storeRecords(t.Context(), tx, []NVDRecord{{CVE: cve, Published: now.AddDate(0, 0, -2), LastModified: now, Status: "Received", Description: "NVD's text."}}, now); err != nil {
			return err
		}
		k, err := recordKeepOf(t.Context(), tx, now, nil)
		if err != nil {
			return err
		}
		w, err := writeRecords(t.Context(), tx, []CVERecord{java}, k, now)
		if err == nil && w.Stored != 1 {
			err = fmt.Errorf("stored %d", w.Stored)
		}
		return err
	})
	javaSE := RecordProductKey("Oracle Corporation", "Oracle Java SE")
	got, err := s.Ranges(t.Context(), []ProductKey{javaSE})
	if err != nil || len(got) != 5 || got[2].StartIncl != "21.0.13.0.3" || got[2].EndIncl != "21.0.13.0.3" || got[2].Origin != OriginCNA {
		t.Fatalf("before NVD: %+v %v", got, err)
	}
	cat, err := s.Catalogue(t.Context(), []string{cve})
	if err != nil || cat[cve].RangesFrom != OriginADP && cat[cve].RangesFrom != OriginCNA || cat[cve].Description != "NVD's text." || cat[cve].RecordAt == nil {
		t.Fatalf("catalogue: %+v %v", cat[cve], err)
	}
	var title, cwe string
	var ssvc sql.NullString
	if err := db.Reader().QueryRowContext(t.Context(), `SELECT title, cwe, ssvc_impact FROM feeds_cve WHERE cve = ?`, cve).Scan(&title, &cwe, &ssvc); err != nil || cwe != `["CWE-122"]` || ssvc.String != "total" {
		t.Fatalf("columns: %q %q %v %v", title, cwe, ssvc, err)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_ref WHERE cve = ?`, cve); n != 14 {
		t.Fatalf("references of a CVE no list, signal or finding names: %d, want the record's 14", n)
	}
	write(t, db, func(tx *sql.Tx) error {
		return storeRecords(t.Context(), tx, []NVDRecord{{CVE: cve, Published: now.AddDate(0, 0, -2), LastModified: now.Add(time.Hour), Status: "Analyzed",
			Affected: []AffectedRow{{CPE: "cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", StartIncl: "21.0.0", EndExcl: "21.0.14"}}}}, now)
	})
	// NVD's rows lead; the record's (a partial list) are read beside them and only ever say "affected"
	if got, _ := s.Ranges(t.Context(), []ProductKey{javaSE}); len(got) != 5 || slices.ContainsFunc(got, func(r Range) bool { return !r.AffectedOnly }) {
		t.Fatalf("the record's rows beside NVD's: %+v", got)
	}
	if got, _ := s.Ranges(t.Context(), []ProductKey{{"oracle", "jdk"}}); len(got) != 1 || got[0].Origin != OriginNVD {
		t.Fatalf("NVD's rows: %+v", got)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_range WHERE cve = ? AND origin <> 'nvd'`, cve); n == 0 {
		t.Fatal("the record's rows went")
	}
}

// The exploited-list view findings reads keeps its rows: the CNA's rows of the listed product, the CPE named by the list, an exact
// version in the CPE, complete or partial; Juniper's and "Multiple Products" entries have none. References are kept for listed CVEs.
func TestRecordRanges_ExploitedListView(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2024-3400", "Palo Alto Networks", "PAN-OS", "2024-04-12"), vuln("CVE-2026-1000", "Acme", "Gateway", "2026-11-01"),
		vuln("CVE-2026-1001", "Juniper", "Junos OS", "2026-11-01"), vuln("CVE-2026-1002", "Acme", "Multiple Products", "2026-11-01")}, false)
	pan, err := ParseCVERecord(fixture(t, "cveorg/CVE-2024-3400.json"), "CVE-2024-3400")
	if err != nil {
		t.Fatal(err)
	}
	parse := func(cve, affected string) CVERecord {
		b := bytes.Replace(recordJSON(cve, "2026-11-01", affected), []byte(`"cna":{`), []byte(`"cna":{"references":[{"url":"https://example.com/advisory","tags":["vendor-advisory"]}],`), 1)
		r, err := ParseCVERecord(b, cve)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	recs := []CVERecord{pan, parse("CVE-2026-1000", `{"vendor":"Acme","product":"Gateway","versions":[{"version":"15.2(4)M3","status":"affected"}]},{"vendor":"Acme","product":"Other","defaultStatus":"affected"}`),
		parse("CVE-2026-1001", `{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","versions":[{"version":"21.4","lessThan":"21.4R3-S5","status":"affected"}]}`),
		parse("CVE-2026-1002", `{"vendor":"Acme","product":"Gateway","defaultStatus":"affected"}`)}
	write(t, db, func(tx *sql.Tx) error {
		k, err := recordKeepOf(t.Context(), tx, epoch0, nil)
		if err != nil {
			return err
		}
		w, err := writeRecords(t.Context(), tx, recs, k, epoch0)
		if err == nil && (!w.KEVFirst || len(w.KEVChanged) != 4) { // Junos's rows: none generic, but the Junos scheme reads them (news)
			err = fmt.Errorf("write %+v", w)
		}
		return err
	})
	aff, err := s.KevAffected(t.Context())
	const pcpe = "cpe:2.3:*:paloaltonetworks:panos:*:*:*:*:*:*:*:*"
	if err != nil || !slices.Equal(aff["CVE-2024-3400"], []AffectedRow{{CPE: pcpe, StartIncl: "10.2.0", EndExcl: "10.2.9-h1", VendorList: true},
		{CPE: pcpe, StartIncl: "11.0.0", EndExcl: "11.0.4-h1", VendorList: true}, {CPE: pcpe, StartIncl: "11.1.0", EndExcl: "11.1.2-h3", VendorList: true}}) || !slices.Equal(aff["CVE-2026-1000"], []AffectedRow{{CPE: `cpe:2.3:*:acme:gateway:15.2\(4\)M3:*:*:*:*:*:*:*`}}) ||
		aff["CVE-2026-1001"] != nil || aff["CVE-2026-1002"] != nil {
		t.Fatalf("KevAffected = %+v %v", aff, err)
	}
	src, err := s.RangesFromCVEOrg(t.Context())
	if err != nil || len(src) != 2 || src["CVE-2024-3400"] != rangesCVEOrg || src["CVE-2026-1000"] != rangesCVEOrgPartial {
		t.Fatalf("RangesFromCVEOrg = %v %v", src, err)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_ref WHERE cve = 'CVE-2026-1000' AND tags = '["vendor-advisory"]' AND source = 'cna'`); n != 1 {
		t.Fatal("no references kept for a listed CVE")
	}
	// the same record read again changes nothing: no news for findings
	write(t, db, func(tx *sql.Tx) error {
		k, _ := recordKeepOf(t.Context(), tx, epoch0, nil)
		w, err := writeRecords(t.Context(), tx, recs, k, epoch0)
		if err == nil && len(w.KEVChanged) != 0 {
			err = fmt.Errorf("changed again: %v", w.KEVChanged)
		}
		return err
	})
}

// ---- the pull ----

// recordEnv is a box whose CISA list holds three CVEs without NVD ranges and one with them, and whose CVE records feed reads from the
// origin; the whole list is loaded already (the cursor says so) unless whole.
func recordEnv(t *testing.T, whole bool) (*env, *origin, *[]RangesUpdatedEvent) {
	t.Helper()
	e, o := pullEnv(t)
	e.svc.DataDir = t.TempDir()
	e.only(cveOrgFeedID)
	e.mirror(cveOrgFeedID, o.url("/repo"))
	applyV(t, e.db, epoch0, "cisa-kev", []Vuln{
		vuln("CVE-2024-3400", "Palo Alto Networks", "PAN-OS", "2024-04-12"),
		vuln("CVE-2026-0001", "Acme", "Gateway", "2026-11-01"),
		vuln("CVE-2026-0004", "Initech", "Portal", "2026-11-02"),
		vuln("CVE-2026-0005", "Acme", "Router", "2026-11-03"),
	}, false)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-0005": {{CPE: "cpe:2.3:o:acme:router:*:*:*:*:*:*:*:*", EndExcl: "4.0"}}}, false, epoch0)
		return err
	})
	if !whole {
		recordsCurrent(t, e, o)
	}
	o.serve("/repo/cves/2024/3xxx/CVE-2024-3400.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture(t, "cveorg/CVE-2024-3400.json"))
	})
	o.serve("/repo/cves/2026/0xxx/CVE-2026-0001.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture(t, "cveorg/CVE-2026-0001-unknown.json"))
	})
	o.serve("/repo/cves/2026/0xxx/CVE-2026-0004.json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	o.serve("/repo/cves/2026/0xxx/CVE-2026-0005.json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	var got []RangesUpdatedEvent
	e.svc.Events = publishFunc(func(ev events.Event) {
		if r, ok := ev.Data.(RangesUpdatedEvent); ok {
			got = append(got, r)
		}
	})
	return e, o, &got
}

// recordsCurrent says the whole list and its changes are read up to now: a pull reads only by ID.
func recordsCurrent(t *testing.T, e *env, o *origin) {
	t.Helper()
	write(t, e.db, func(tx *sql.Tx) error {
		now := e.clock()
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: recordCursorURL(o.url("/repo")), Mode: modeDone, From: now, To: now, Until: now})
	})
}

// By ID: only CVEs a public list names, one record each, nothing but the ID in the request; the vendor's ranges reach findings, and a
// record is not asked again before recordRecheck.
func TestContract_CVERecordsByID(t *testing.T) {
	t.Parallel()
	e, o, got := recordEnv(t, false)
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	for _, h := range o.all() {
		if h.query != "" || h.header.Get("Authorization") != "" || h.header.Get("Cookie") != "" {
			t.Fatalf("a request carried more than the CVE ID: %+v", h)
		}
	}
	f := e.feed(cveOrgFeedID)
	if f.Status != "ok" || f.Records == nil || *f.Records != 4 || deref(f.Error) != "2 by their ID, 2 not published yet." && !strings.Contains(deref(f.Error), "2 not published yet") {
		t.Fatalf("feed = %+v %q", f, deref(f.Error))
	}
	if len(*got) != 1 || !slices.Equal((*got)[0].CVEs, []string{"CVE-2024-3400"}) || !(*got)[0].First {
		t.Fatalf("events = %+v", *got)
	}
	if src, err := e.svc.st.RangesFromCVEOrg(t.Context()); err != nil || src["CVE-2024-3400"] != rangesCVEOrg || len(src) != 1 {
		t.Fatalf("RangesFromCVEOrg = %v %v", src, err)
	}
	before := len(o.all())
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil || len(o.all()) != before {
		t.Fatalf("asked again too soon: %d %v", len(o.all())-before, err)
	}
	e.setNow(e.clock().Add(recordRecheck + time.Hour)) // the ones without NVD ranges are asked again; 0005 has NVD's
	recordsCurrent(t, e, o)
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o.count("/repo/cves/2026/0xxx/CVE-2026-0005.json") != 1 || o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json") != 2 {
		t.Fatalf("asked: %d %d", o.count("/repo/cves/2026/0xxx/CVE-2026-0005.json"), o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json"))
	}
}

// A busy source is tried again; one that stays busy before any record fails the pull (back-off). A refused file is stamped and the
// pull goes on; an answer that is not a record keeps what was stored.
func TestCVERecordsByID_BusyAndBadFiles(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, false)
	busy := 0
	o.serve("/repo/cves/2026/0xxx/CVE-2026-0005.json", func(w http.ResponseWriter, _ *http.Request) {
		busy++
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil { // never read first, newest ID first: 0005 is asked first
		t.Fatal(err)
	}
	if f := e.feed(cveOrgFeedID); busy != 3 || f.Status != "error" || !strings.HasPrefix(deref(f.Error), "The CVE Program's files (GitHub) were busy") {
		t.Fatalf("%d tries, feed %+v %q", busy, f, deref(f.Error))
	}

	e2, o2, _ := recordEnv(t, false)
	o2.serve("/repo/cves/2026/0xxx/CVE-2026-0004.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	if err := e2.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e2.db, `SELECT count(*) FROM feeds_cve WHERE record_at IS NOT NULL`); n != 4 {
		t.Fatalf("%d CVEs stamped, want 4", n)
	}
	o2.serve("/repo/cves/2024/3xxx/CVE-2024-3400.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>sign in</html>")) })
	e2.setNow(e2.clock().Add(recordRecheck + time.Hour))
	recordsCurrent(t, e2, o2)
	if err := e2.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if src, _ := e2.svc.st.RangesFromCVEOrg(t.Context()); src["CVE-2024-3400"] != rangesCVEOrg {
		t.Fatalf("an unreadable answer dropped the stored ranges: %v", src)
	}
}

// The whole list: the daily archive downloads (a cut download goes on from its last byte), only the records the catalogue keeps are
// stored (a CVE it holds, one published inside the window), the file is deleted, and the next pull reads the change log: the day that is
// over from its archive of changes, what it does not hold by ID, today's when few.
func TestCVERecords_WholeListThenChanges(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, true)
	e.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	files := map[string][]byte{
		"cves/2024/3xxx/CVE-2024-3400.json":   fixture(t, "cveorg/CVE-2024-3400.json"),
		"cves/2026/7xxx/CVE-2026-7000.json":   recordJSON("CVE-2026-7000", "2026-10-01", `{"vendor":"Acme","product":"Box","versions":[{"version":"1.0","lessThan":"1.2","status":"affected"}]}`),
		"cves/2019/7xxx/CVE-2019-7000.json":   recordJSON("CVE-2019-7000", "2019-10-01", `{"vendor":"Acme","product":"Old","defaultStatus":"affected"}`),
		"cves/2026/0xxx/CVE-2026-0001.json":   fixture(t, "cveorg/CVE-2026-0001-unknown.json"),
		"cves/2026/88xxx/CVE-2026-88000.json": recordJSON("CVE-2026-88000", "2026-11-19", `{"vendor":"Acme","product":"New","defaultStatus":"affected"}`),
	}
	archive := dailyArchive(t, files)
	const path = "/repo/releases/download/cve_2026-11-20_2300Z/2026-11-20_all_CVEs_at_midnight.zip.zip"
	tries := 0
	o.serve(path, func(w http.ResponseWriter, r *http.Request) {
		tries++
		if tries == 1 { // the first answer stops half way
			w.Header().Set("Content-Length", fmt.Sprint(len(archive)))
			_, _ = w.Write(archive[:len(archive)/2])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(archive))
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	cur, err := e.svc.st.nvdCursor(t.Context(), selectorRecord)
	if err != nil || cur == nil || cur.Mode != modeFill || cur.NextIndex != len(archive)/2 || cur.Total != len(archive) { // the size is known from the first answer
		t.Fatalf("after a cut download: %+v %v", cur, err)
	}
	if owed, _ := e.svc.st.recordsOwed(t.Context(), o.url("/repo")); !owed {
		t.Fatal("an unfinished download is not owed")
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	hits := o.all()
	if last := hits[len(hits)-1]; last.path != path || last.header.Get("Range") != fmt.Sprintf("bytes=%d-", len(archive)/2) {
		t.Fatalf("not resumed: %+v", last)
	}
	for cve, want := range map[string]int{"CVE-2024-3400": 1, "CVE-2026-7000": 1, "CVE-2019-7000": 0, "CVE-2026-88000": 1} {
		if n := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve = ? AND record_at IS NOT NULL`, cve); n != want {
			t.Errorf("%s stored %d, want %d", cve, n, want)
		}
	}
	cur, _ = e.svc.st.nvdCursor(t.Context(), selectorRecord)
	if cur.Mode != modeDone || !cur.Until.Equal(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("cursor %+v", cur)
	}
	if left, _ := filepathGlob(e.svc.recordWorkDir()); len(left) != 0 {
		t.Fatalf("work files left: %v", left)
	}

	// the changes: 7000 changed yesterday (in the day's archive), 88000 changed in yesterday's last hour (not in it: by ID), 3400 today
	logJSON := `[{"fetchTime":"2026-11-19T09:00:00.000Z","new":[],"updated":[]},{"fetchTime":"2026-11-20T09:00:00.000Z","new":[],"updated":[{"cveId":"CVE-2026-7000","dateUpdated":"2026-11-20T08:59:00.000Z"},{"cveId":"CVE-2019-7000","dateUpdated":"2026-11-20T08:59:00.000Z"}]},` +
		`{"fetchTime":"2026-11-20T23:40:00.000Z","new":[],"updated":[{"cveId":"CVE-2026-88000","dateUpdated":"2026-11-20T23:39:00.000Z"}]},` +
		`{"fetchTime":"2026-11-21T11:00:00.000Z","new":[],"updated":[{"cveId":"CVE-2024-3400","dateUpdated":"2026-11-21T10:59:00.000Z"}]}]`
	o.serve("/repo/cves/deltaLog.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(logJSON)) })
	changed := recordJSON("CVE-2026-7000", "2026-10-01", `{"vendor":"Acme","product":"Box","versions":[{"version":"1.0","lessThan":"1.3","status":"affected"}]}`)
	changed = bytes.Replace(changed, []byte(`"dateUpdated":"2026-10-01T12:00:00.000Z"`), []byte(`"dateUpdated":"2026-11-20T08:59:00.000Z"`), 1)
	o.serve("/repo/releases/download/cve_2026-11-20_at_end_of_day/2026-11-20_delta_CVEs_at_end_of_day.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOf(t, map[string][]byte{"deltaCves/CVE-2026-7000.json": changed}))
	})
	o.serve("/repo/cves/2026/88xxx/CVE-2026-88000.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(files["cves/2026/88xxx/CVE-2026-88000.json"])
	})
	before := o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json")
	e.setNow(time.Date(2026, 11, 21, 11, 30, 0, 0, time.UTC)) // 3400 was read by ID at 10:00, before its change logged at 11:00
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	var end string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT end_excl FROM feeds_cve_range WHERE cve = 'CVE-2026-7000'`).Scan(&end); err != nil || end != "1.3" {
		t.Fatalf("the day's archive was not read: %q %v", end, err)
	}
	if o.count("/repo/cves/2026/88xxx/CVE-2026-88000.json") != 1 || o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json") != before+1 {
		t.Fatal("leftovers not asked for by ID")
	}
	cur, _ = e.svc.st.nvdCursor(t.Context(), selectorRecord)
	if !cur.Until.Equal(time.Date(2026, 11, 21, 11, 0, 0, 0, time.UTC)) || !cur.To.Equal(e.clock()) {
		t.Fatalf("cursor after the changes: %+v", cur)
	}
	// within recordDeltaEvery the change log is not read again
	n := o.count("/repo/cves/deltaLog.json")
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil || o.count("/repo/cves/deltaLog.json") != n {
		t.Fatalf("change log read again: %v", err)
	}
}

// After a load of an exploited list, the records follow by ID only: the list's alerts never wait for a download.
func TestCVERecords_AfterAListLoadOnlyByID(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, true)
	ctx := t.Context()
	p, err := e.svc.buildCVERecords(contextWithUrgent(ctx), e.feed(cveOrgFeedID), pullPlan{})
	if err != nil || !p.out.OK {
		t.Fatalf("%+v %v", p.out, err)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "/releases/") || strings.HasSuffix(h.path, "deltaLog.json") {
			t.Fatalf("a bulk request after a list load: %s", h.path)
		}
	}
}

// The fetcher's parts of a download: the rest of a file (206), a source that ignores Range (200, the bytes before skipped), a redirect
// only to a declared host.
func TestFetch_RangeAndRedirectHosts(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	body := []byte("0123456789abcdef")
	o.serve("/part", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "x", time.Time{}, bytes.NewReader(body))
	})
	o.serve("/whole", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	for _, p := range []string{"/part", "/whole"} {
		resp, err := e.svc.Fetcher.Fetch(t.Context(), Request{URL: o.url(p), From: 10})
		if err != nil || string(resp.Body) != "abcdef" || resp.Total != 16 || resp.Partial != (p == "/part") {
			t.Fatalf("%s: %+v %v", p, resp, err)
		}
	}
	if _, err := e.svc.Fetcher.Fetch(t.Context(), Request{URL: o.url("/part"), From: 10, WantTotal: 17}); !errors.Is(err, ErrFileChanged) {
		t.Fatalf("a file of another size was joined: %v", err)
	}
	for h, ok := range map[string]bool{"bytes 10-15/16": true, "bytes 9-15/16": false, "bytes 10-14/16": false, "items 10-15/16": false, "bytes 10-15/x": false} {
		if n, got := rangeTotal(h, 10); got != ok || ok && n != 16 {
			t.Errorf("%q: %d %v", h, n, got)
		}
	}
	req := func(u string) *http.Request {
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		return r
	}
	via := []*http.Request{req("https://github.com/x/y/releases/download/a/b.zip")}
	if err := checkRedirectTo(req("https://release-assets.githubusercontent.com/a?sig=1"), via, recordHosts); err != nil {
		t.Fatalf("declared host: %v", err)
	}
	for _, bad := range []string{"https://evil.example.com/a", "http://release-assets.githubusercontent.com/a", "https://release-assets.githubusercontent.com:8443/a"} {
		if err := checkRedirectTo(req(bad), via, recordHosts); err == nil {
			t.Errorf("%s followed", bad)
		}
	}
	if err := checkRedirect(req("https://release-assets.githubusercontent.com/a"), via); err == nil {
		t.Error("a feed without declared hosts followed another host")
	}
}

func flateWriter(w io.Writer) (*flate.Writer, error) {
	return flate.NewWriter(w, flate.DefaultCompression)
}

func crc(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

func filepathGlob(dir string) ([]string, error) { return filepath.Glob(filepath.Join(dir, "*")) }

func contextWithUrgent(ctx context.Context) context.Context {
	return context.WithValue(ctx, urgentOnlyKey{}, true)
}

// Privacy: a CVE only a custom list names, or a qualifying signal of a source the box builds itself, is never asked for by ID; the same
// predicate (publicListedSQL) chooses NVD's by-ID asks.
func TestCVERecordsByID_OnlyPublicSources(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, false)
	write(t, e.db, func(tx *sql.Tx) error {
		if err := ensureCVE(t.Context(), tx, "CVE-2026-0900", "2026-11-05T00:00:00.000Z"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_source (id, builtin, name, kind, format, url, parser, created_at)
VALUES ('cf-own', 0, 'Own list', 'vulnerabilities', 'json', 'https://feeds.example.com/x.json', '{}', '2026-11-05T00:00:00.000Z')`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, updated_at)
VALUES ('CVE-2026-0900', 'custom:cf-own', 'cf-own', 'Acme', 'Gateway', 'x', '2026-11-05', '2026-11-05T00:00:00.000Z')`); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies)
VALUES ('CVE-2026-0901', 'exploited', 'ids-local', '2026-11-05T00:00:00.000Z', '2026-11-05T00:00:00.000Z', '2026-11-05T00:00:00.000Z', 1)`)
		return err
	})
	due, err := e.svc.st.recordDue(t.Context(), e.clock(), 100)
	if err != nil || slices.Contains(due, "CVE-2026-0900") || slices.Contains(due, "CVE-2026-0901") || len(due) != 4 {
		t.Fatalf("due = %v %v", due, err)
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil { // an ask for either would also hit an undeclared path
		t.Fatal(err)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "CVE-2026-090") {
			t.Fatalf("asked by ID: %s", h.path)
		}
	}
	missing, err := e.svc.st.missingRecords(t.Context(), Window{Cutoff: e.clock().AddDate(0, 0, -windowDays)}, false, 100)
	if err != nil || slices.Contains(missing, "CVE-2026-0900") || slices.Contains(missing, "CVE-2026-0901") {
		t.Fatalf("NVD's by-ID set: %v %v", missing, err)
	}
}

// readWithTheWholeList stamps the records of the CVEs like (a LIKE pattern) as read with the whole list of 2026-11-20.
func readWithTheWholeList(t *testing.T, tx *sql.Tx, like string) error {
	t.Helper()
	_, err := tx.ExecContext(t.Context(), `UPDATE feeds_cve SET record_at = '2026-11-20T00:00:00.000Z' WHERE cve LIKE ?`, like)
	return err
}

// changesEnv is a box whose whole list is read up to 2026-11-20 00:00, with a CVE of the window and an old CVE only a finding pins.
func changesEnv(t *testing.T) (*env, *origin) {
	t.Helper()
	e, o, _ := recordEnv(t, true)
	e.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	e.svc.Pins = func(context.Context) ([]string, error) { return []string{"CVE-2019-7001", "CVE-2019-7002"}, nil }
	write(t, e.db, func(tx *sql.Tx) error {
		if err := storeRecords(t.Context(), tx, []NVDRecord{{CVE: "CVE-2026-7000", Published: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), LastModified: epoch0, Status: "Received"}}, e.clock()); err != nil {
			return err
		}
		if err := readWithTheWholeList(t, tx, "CVE-2026-7000"); err != nil { // the whole list read up to 2026-11-20 held it
			return err
		}
		for _, cve := range []string{"CVE-2019-7001", "CVE-2019-7002"} { // old CVEs only a finding keeps
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, nvd_status, updated_at) VALUES (?, '2019-10-01T00:00:00.000Z', 'Analyzed', '2026-11-01T00:00:00.000Z')`, cve); err != nil {
				return err
			}
		}
		midnight := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: recordCursorURL(o.url("/repo")), Mode: modeDone, From: midnight, Until: midnight})
	})
	return e, o
}

// Privacy: a change the day's archive does not hold is asked for by ID only for a CVE every box keeps (the window, a public list); a CVE
// only a finding pins is never asked: a past day's change waits for the next whole list, today's for tomorrow's archive.
func TestCVERecords_ChangesNeverAskForAPinOnlyCVE(t *testing.T) {
	t.Parallel()
	e, o := changesEnv(t)
	logJSON := `[{"fetchTime":"2026-11-19T09:00:00.000Z","new":[],"updated":[]},` +
		`{"fetchTime":"2026-11-20T23:40:00.000Z","new":[],"updated":[{"cveId":"CVE-2026-7000","dateUpdated":"2026-11-20T23:39:00.000Z"},{"cveId":"CVE-2019-7001","dateUpdated":"2026-11-20T23:39:00.000Z"}]},` +
		`{"fetchTime":"2026-11-21T08:00:00.000Z","new":[],"updated":[{"cveId":"CVE-2019-7002","dateUpdated":"2026-11-21T07:59:00.000Z"}]}]`
	o.serve("/repo/cves/deltaLog.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(logJSON)) })
	o.serve("/repo/releases/download/cve_2026-11-20_at_end_of_day/2026-11-20_delta_CVEs_at_end_of_day.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOf(t, map[string][]byte{}))
	})
	o.serve("/repo/cves/2026/7xxx/CVE-2026-7000.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(recordJSON("CVE-2026-7000", "2026-10-01", `{"vendor":"Acme","product":"Box","defaultStatus":"affected"}`))
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "CVE-2019-700") {
			t.Fatalf("a CVE only a finding pins was asked for by ID: %s", h.path)
		}
	}
	if o.count("/repo/cves/2026/7xxx/CVE-2026-7000.json") != 1 {
		t.Fatal("the window CVE's leftover was not asked for")
	}
	cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord)
	if !cur.Until.Equal(time.Date(2026, 11, 20, 23, 40, 0, 0, time.UTC)) { // past yesterday's, before today's pin-only change
		t.Fatalf("cursor %+v", cur)
	}
	if f := e.feed(cveOrgFeedID); !strings.Contains(deref(f.Error), "1 changed records of CVEs no public list names wait for the next read of the whole list (at most once a week)") {
		t.Fatalf("note %q", deref(f.Error))
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve = 'CVE-2019-7001' AND record_at = ?`, recordWaiting); n != 1 {
		var at sql.NullString
		_ = e.db.Reader().QueryRowContext(t.Context(), `SELECT record_at FROM feeds_cve WHERE cve = 'CVE-2019-7001'`).Scan(&at)
		t.Fatalf("the pin-only record is not marked waiting: %v", at)
	}
	// a waiting record brings the whole list within a week of the last one, never a request by ID
	e.setNow(time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC))
	o.serve("/repo/releases/download/cve_2026-11-26_2300Z/2026-11-26_all_CVEs_at_midnight.zip.zip", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(dailyArchive(t, map[string][]byte{
			"cves/2019/7xxx/CVE-2019-7001.json": recordJSON("CVE-2019-7001", "2019-10-01", `{"vendor":"Acme","product":"Old","defaultStatus":"affected"}`)})))
	})
	recordsCurrent(t, e, o) // the changes are read up to now; the last whole list is a week old
	write(t, e.db, func(tx *sql.Tx) error {
		c, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord)
		c.From = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
		return saveNVDCursor(t.Context(), tx, selectorRecord, *c)
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE record_at = ?`, recordWaiting); n != 0 {
		t.Fatalf("%d records still waiting after the whole list", n)
	}
}

// Whole days of changes gone (the release files live about four days): the whole list loads again instead of thousands of single asks;
// a box further behind than the release files reach loads it at once.
func TestCVERecords_ChangesGoneLoadTheWholeList(t *testing.T) {
	t.Parallel()
	e, o := changesEnv(t)
	e.setNow(time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)) // 2026-11-20 is no longer yesterday: its archive is gone, not late
	var updated []string
	write(t, e.db, func(tx *sql.Tx) error {
		var recs []NVDRecord
		for i := range recordLeftPerPull + 1 {
			cve := fmt.Sprintf("CVE-2026-8%04d", i)
			recs = append(recs, NVDRecord{CVE: cve, Published: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), LastModified: epoch0, Status: "Received"})
			updated = append(updated, fmt.Sprintf(`{"cveId":%q,"dateUpdated":"2026-11-20T10:00:00.000Z"}`, cve))
		}
		if err := storeRecords(t.Context(), tx, recs, e.clock()); err != nil {
			return err
		}
		return readWithTheWholeList(t, tx, "CVE-2026-8%")
	})
	logJSON := `[{"fetchTime":"2026-11-19T09:00:00.000Z","new":[],"updated":[]},{"fetchTime":"2026-11-20T10:00:00.000Z","new":[],"updated":[` + strings.Join(updated, ",") + `]}]`
	o.serve("/repo/cves/deltaLog.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(logJSON)) })
	o.serve("/repo/releases/download/cve_2026-11-20_at_end_of_day/2026-11-20_delta_CVEs_at_end_of_day.zip", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord); cur.Mode != modeFill {
		t.Fatalf("cursor %+v", cur)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "CVE-2026-8") {
			t.Fatalf("asked by ID: %s", h.path)
		}
	}
	// four days behind: the whole list at once, without reading the change log
	e2, o2 := changesEnv(t)
	e2.setNow(time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	o2.serve("/repo/releases/download/cve_2026-11-23_2300Z/2026-11-23_all_CVEs_at_midnight.zip.zip", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(dailyArchive(t, map[string][]byte{})))
	})
	if err := e2.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o2.count("/repo/cves/deltaLog.json") != 0 || o2.count("/repo/releases/download/cve_2026-11-23_2300Z/2026-11-23_all_CVEs_at_midnight.zip.zip") != 1 {
		t.Fatalf("hits %+v", o2.all())
	}
}

// The disk: too little free space fails the pull with what to check (never "the source did not answer") and downloads nothing; a feed
// turned off leaves no work file.
func TestCVERecords_DiskSpaceAndTurnedOff(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, true)
	e.svc.free = func(string) (int64, bool) { return 100 << 20, true }
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.feed(cveOrgFeedID)
	if f.Status != "error" || !strings.HasPrefix(deref(f.Error), "Not enough free disk space to download the CVE Program's whole list: 100 MB free, about 1,312 MB needed.") {
		t.Fatalf("feed %+v %q", f, deref(f.Error))
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "/releases/") {
			t.Fatalf("downloaded with no room: %s", h.path)
		}
	}
	dir := e.svc.recordWorkDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "2026-11-04_all.zip"), []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, b := e.put(cveOrgFeedID, `{"enabled":false}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("work folder left: %v", err)
	}
}

// More leftovers in one logged hour than one pull asks: each pull asks the next ones (a record read after its change counts, from any
// pull), none twice, and the cursor passes the hour once all are read.
func TestCVERecords_ManyLeftoversInOneHour(t *testing.T) {
	t.Parallel()
	e, o := changesEnv(t)
	var updated []string
	write(t, e.db, func(tx *sql.Tx) error {
		var recs []NVDRecord
		for i := range 450 {
			cve := fmt.Sprintf("CVE-2026-8%04d", i)
			recs = append(recs, NVDRecord{CVE: cve, Published: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), LastModified: epoch0, Status: "Received"})
			updated = append(updated, fmt.Sprintf(`{"cveId":%q,"dateUpdated":"2026-11-20T23:39:00.000Z"}`, cve))
		}
		if err := storeRecords(t.Context(), tx, recs, e.clock()); err != nil {
			return err
		}
		return readWithTheWholeList(t, tx, "CVE-2026-8%")
	})
	logJSON := `[{"fetchTime":"2026-11-19T09:00:00.000Z","new":[],"updated":[]},{"fetchTime":"2026-11-20T23:40:00.000Z","new":[],"updated":[` + strings.Join(updated, ",") + `]}]`
	o.serve("/repo/cves/deltaLog.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(logJSON)) })
	o.serve("/repo/releases/download/cve_2026-11-20_at_end_of_day/2026-11-20_delta_CVEs_at_end_of_day.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOf(t, map[string][]byte{}))
	})
	for i := range 450 {
		cve := fmt.Sprintf("CVE-2026-8%04d", i)
		o.serve(fmt.Sprintf("/repo/cves/2026/%dxxx/%s.json", (80000+i)/1000, cve), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(recordJSON(cve, "2026-10-01", `{"vendor":"Acme","product":"Box","defaultStatus":"affected"}`))
		})
	}
	asked := func() (n, most int) {
		for i := range 450 {
			c := o.count(fmt.Sprintf("/repo/cves/2026/%dxxx/CVE-2026-8%04d.json", (80000+i)/1000, i))
			if c > 0 {
				n++
			}
			most = max(most, c)
		}
		return n, most
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if n, most := asked(); n != recordLeftPerPull || most != 1 {
		t.Fatalf("first pull asked %d (most %d times)", n, most)
	}
	if cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord); !cur.Until.Equal(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("the cursor passed a partly read hour: %+v", cur)
	}
	e.setNow(e.clock().Add(recordDeltaEvery))
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if n, most := asked(); n != 450 || most != 1 {
		t.Fatalf("after the second pull asked %d (most %d times)", n, most)
	}
	if cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord); !cur.Until.Equal(time.Date(2026, 11, 20, 23, 40, 0, 0, time.UTC)) {
		t.Fatalf("cursor %+v", cur)
	}
}

// Yesterday's end-of-day archive is published about 00:40: before it, yesterday's changes wait like today's (no reload, and many are
// not asked for one by one).
func TestCVERecords_YesterdaysArchiveNotYetPublished(t *testing.T) {
	t.Parallel()
	e, o := changesEnv(t)
	e.setNow(time.Date(2026, 11, 21, 0, 20, 0, 0, time.UTC))
	var updated []string
	write(t, e.db, func(tx *sql.Tx) error {
		var recs []NVDRecord
		for i := range recordLeftPerPull + 1 {
			cve := fmt.Sprintf("CVE-2026-8%04d", i)
			recs = append(recs, NVDRecord{CVE: cve, Published: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), LastModified: epoch0, Status: "Received"})
			updated = append(updated, fmt.Sprintf(`{"cveId":%q,"dateUpdated":"2026-11-20T10:00:00.000Z"}`, cve))
		}
		if err := storeRecords(t.Context(), tx, recs, e.clock()); err != nil {
			return err
		}
		return readWithTheWholeList(t, tx, "CVE-2026-8%")
	})
	logJSON := `[{"fetchTime":"2026-11-19T09:00:00.000Z","new":[],"updated":[]},{"fetchTime":"2026-11-20T10:00:00.000Z","new":[],"updated":[` + strings.Join(updated, ",") + `]}]`
	o.serve("/repo/cves/deltaLog.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(logJSON)) })
	o.serve("/repo/releases/download/cve_2026-11-20_at_end_of_day/2026-11-20_delta_CVEs_at_end_of_day.zip", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord)
	if cur.Mode != modeDone || !cur.Until.Equal(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("cursor %+v", cur)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "CVE-2026-8") || strings.Contains(h.path, "_all_CVEs") {
			t.Fatalf("asked %s", h.path)
		}
	}
}

// A read of the whole list never rolls back a record read after the archive's midnight; a partial download that met a disk error is
// removed.
// A box whose records an older range reader read (its cursor carries no reader stamp) reads the whole list again, once: every record
// is replaced, a newer one too, so VMware's ESXi rows that reader dropped appear without waiting for VMware to edit its record; the
// cursor goes back to the archive's midnight so the changes since are read again.
func TestCVERecords_ReaderChangeReadsTheWholeListOnce(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, true)
	e.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	esxi := fixture(t, "brief/"+briefCVE+".record.json")
	write(t, e.db, func(tx *sql.Tx) error {
		r, err := ParseCVERecord(esxi, briefCVE)
		if err != nil {
			return err
		}
		k, err := recordKeepOf(t.Context(), tx, e.clock(), []string{briefCVE})
		if err != nil {
			return err
		}
		if _, err := writeRecords(t.Context(), tx, []CVERecord{r}, k, time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)); err != nil { // read after midnight
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_cve_range WHERE cve = ? AND version_type LIKE 'vendor:%'`, briefCVE); err != nil {
			return err // as the older reader stored it
		}
		now := e.clock()
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: o.url("/repo"), Mode: modeDone, From: now, To: now, Until: now})
	})
	const path = "/repo/releases/download/cve_2026-11-20_2300Z/2026-11-20_all_CVEs_at_midnight.zip.zip"
	o.serve(path, func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(dailyArchive(t, map[string][]byte{"cves/2025/22xxx/" + briefCVE + ".json": esxi})))
	})
	if owed, _ := e.svc.st.recordsOwed(t.Context(), o.url("/repo")); !owed {
		t.Fatal("a cursor of an older reader is not owed a pull")
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve_range WHERE cve = ? AND version_type = 'vendor:custom' AND product = 'esxi'`, briefCVE); n != 3 || o.count(path) != 1 {
		t.Fatalf("VMware's rows after the reread: %d, archive asked %d times", n, o.count(path))
	}
	cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecord)
	if cur.URL != recordCursorURL(o.url("/repo")) || cur.Mode != modeDone || !cur.Until.Equal(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("cursor %+v", cur)
	}
	if owed, _ := e.svc.st.recordsOwed(t.Context(), o.url("/repo")); owed {
		t.Fatal("still owed after the reread")
	}
}

func TestCVERecords_RereadKeepsNewerAndDiskErrorRemovesPart(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, true)
	e.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	newer := recordJSON("CVE-2026-7000", "2026-10-01", `{"vendor":"Acme","product":"Box","versions":[{"version":"1.0","lessThan":"1.3","status":"affected"}]}`)
	older := recordJSON("CVE-2026-7000", "2026-10-01", `{"vendor":"Acme","product":"Box","versions":[{"version":"1.0","lessThan":"1.2","status":"affected"}]}`)
	write(t, e.db, func(tx *sql.Tx) error {
		r, err := ParseCVERecord(newer, "CVE-2026-7000")
		if err != nil {
			return err
		}
		k, err := recordKeepOf(t.Context(), tx, e.clock(), nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, []CVERecord{r}, k, time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)) // read the day after the midnight below
		return err
	})
	o.serve("/repo/releases/download/cve_2026-11-20_2300Z/2026-11-20_all_CVEs_at_midnight.zip.zip", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(dailyArchive(t, map[string][]byte{"cves/2026/7xxx/CVE-2026-7000.json": older})))
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	var end string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT end_excl FROM feeds_cve_range WHERE cve = 'CVE-2026-7000'`).Scan(&end); err != nil || end != "1.3" {
		t.Fatalf("rolled back: %q %v", end, err)
	}

	e2, o2, _ := recordEnv(t, true)
	e2.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	dir := e2.svc.recordWorkDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(dir, "2026-11-20_all.zip")
	if err := os.WriteFile(part, []byte("partial"), 0o400); err != nil { // the box cannot write it any more
		t.Fatal(err)
	}
	write(t, e2.db, func(tx *sql.Tx) error {
		day := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: recordCursorURL(o2.url("/repo")), Mode: modeFill, From: day, To: day, Until: day, NextIndex: 7, Total: 1000})
	})
	if err := e2.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e2.feed(cveOrgFeedID); f.Status != "error" || !strings.Contains(deref(f.Error), "disk") {
		t.Fatalf("feed %+v %q", f, deref(f.Error))
	}
	if _, err := os.Stat(part); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the partial file stayed: %v", err)
	}
	if cur, _ := e2.svc.st.nvdCursor(t.Context(), selectorRecord); cur.NextIndex != 0 || cur.Total != 0 {
		t.Fatalf("cursor %+v", cur)
	}
}

package feeds

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/versionscheme"
)

// The affected lists of VMware's CVE records that state ESXi's versions in words (cvelistV5, as published), and forms VMware's
// advisories use in the same place.
const (
	affected31705 = `[{"vendor":"n/a","product":"VMware ESXi, VMware Workstation Pro / Player, VMware Fusion Pro / Fusion (Fusion), VMware Cloud Foundation","versions":[{"version":"VMware ESXi (8.0 prior to ESXi80a-20842819, 7.0 prior to ESXi70U3si-20841705, VMware Workstation Pro / Player (16.x prior to 16.2.5), VMware Fusion Pro / Fusion (12.x prior to 12.2.5), VMware Cloud Foundation (4.x, 3.x)","status":"affected"}]}]`
	affected21974 = `[{"product":"VMware ESXi","vendor":"n/a","versions":[{"status":"affected","version":"7.0 before ESXi70U1c-17325551"},{"status":"affected","version":"6.7 before ESXi670-202102401-SG"},{"status":"affected","version":"6.5 before ESXi650-202102101-SG"}]},{"product":"VMware Cloud Foundation","vendor":"n/a","versions":[{"status":"affected","version":"4.x before 4.2 and 3.x"}]}]`
	affected3992  = `[{"vendor":"n/a","product":"VMware ESXi","versions":[{"version":"VMware ESXi (7.0 before ESXi_7.0.1-0.0.16850804, 6.7 before ESXi670-202010401-SG, 6.5 before ESXi650-202010401-SG)","status":"affected"}]}]`
	affected5544  = `[{"vendor":"n/a","product":"ESXi and Horizon DaaS","versions":[{"version":"ESXi 6.7 prior to patch release ESXi670-201912001, ESXi 6.5 prior to patch release ESXi650-201912001, ESXi 6.0 prior to patch release ESXi600-201912001 and Horizon DaaS 8.x prior to BZ-2467224-Disable_SLPD_service_permanently_801_Hotfix.","status":"affected"}]}]`
	affected4905  = `[{"product":"ESXi","vendor":"VMware","versions":[{"status":"affected","version":"6.5 without patch ESXi650-201703410-SG"},{"status":"affected","version":"6.0 U3 without patch ESXi600-201703401-SG"},{"status":"affected","version":"5.5 without patch ESXi550-201703401-SG"}]},{"product":"Workstation Pro / Player","vendor":"VMware","versions":[{"status":"affected","version":"12.x prior to 12.5.5"}]}]`
)

func affectedList(t *testing.T, js string) []cnaAffected {
	t.Helper()
	var out []cnaAffected
	if err := json.Unmarshal([]byte(js), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// spanWords is the rows as "start < end", in order.
func spanWords(rows []Range) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.StartIncl+" < "+r.EndExcl)
	}
	return out
}

// Every form of VMware's words is read strictly: a clause of ESXi becomes the row from its line to its fixed build; another product's
// clause, a patch bulletin with no build, a fix of another line or a form not known give no row for that line; words that do not say
// whose versions they are give none at all.
func TestESXiTextRows_Forms(t *testing.T) {
	t.Parallel()
	one := func(versions ...string) string {
		var vs []string
		for _, v := range versions {
			vs = append(vs, fmt.Sprintf(`{"version":%q,"status":"affected"}`, v))
		}
		return `[{"vendor":"VMware","product":"ESXi","versions":[` + strings.Join(vs, ",") + `]}]`
	}
	for _, c := range []struct {
		name, affected, assigner string
		want                     []string
		used                     int
	}{
		{"CVE-2022-31705: one string for four products", affected31705, "vmware", []string{"8.0 < ESXi80a-20842819", "7.0 < ESXi70U3si-20841705"}, 0},
		{"CVE-2021-21974: one string per line, bulletins for 6.7 and 6.5", affected21974, "vmware", []string{"7.0 < ESXi70U1c-17325551"}, 1},
		{"CVE-2020-3992: the older build form", affected3992, "vmware", []string{"7.0 < ESXi70U1-16850804"}, 0},
		{"CVE-2019-5544: bulletins only", affected5544, "vmware", nil, 0},
		{"CVE-2017-4905: bulletins only", affected4905, "vmware", nil, 0},
		{"an update named in words", one("ESXi 8.0 before 8.0 Update 1"), "vmware", []string{"8.0 < ESXi80U1-21495797"}, 1},
		{"an update with its patch letter", one("8.0 U3 prior to ESXi 8.0 Update 3e"), "vmware", []string{"8.0 < ESXi80U3e-24674464"}, 1},
		{"a GA patch named in words", one("8.0 prior to 8.0a"), "vmware", []string{"8.0 < ESXi80a-20842819"}, 1},
		{"the same line also stated in a form not read", one("8.0 prior to ESXi80a-20842819", "8.0 fix pending"), "vmware", nil, 0},
		{"a fix of another line", one("8.0 prior to ESXi70U3si-20841705"), "vmware", nil, 0},
		{"a fix of another update than the clause names", one("8.0 U2 prior to ESXi80U3d-24585383"), "vmware", nil, 0},
		{"no line", one("all versions prior to ESXi80a-20842819"), "vmware", nil, 0},
		{"words that are no clause beside a clause", one("8.0 prior to ESXi80a-20842819", "Update 1 fix pending"), "vmware", nil, 0},
		{"words that are no clause inside ESXi's list", `[{"vendor":"n/a","product":"VMware ESXi, VMware Workstation","versions":[{"version":"VMware ESXi (8.0 prior to ESXi80a-20842819, Update 1 fix pending), VMware Workstation (16.x prior to 16.2.5)","status":"affected"}]}]`, "vmware", nil, 0},
		{"a line given as a major release only", one("ESXi 8.x prior to ESXi80a-20842819"), "vmware", nil, 0},
		{"a build in a form not known", one("8.0 prior to build 20842819"), "vmware", nil, 0},
		{"another vendor", `[{"vendor":"Acme","product":"ESXi plug-in","versions":[{"version":"8.0 prior to ESXi80a-20842819","status":"affected"}]}]`, "acme", nil, 0},
		{"a version before any product is named", `[{"vendor":"n/a","product":"ESXi and Horizon DaaS","versions":[{"version":"8.0 prior to ESXi80a-20842819","status":"affected"}]}]`, "vmware", nil, 0},
		{"a structured version is not words", `[{"vendor":"VMware","product":"ESXi","versions":[{"version":"8.0","lessThan":"ESXi80U3d-24585383","status":"affected","versionType":"custom"}]}]`, "vmware", nil, 0},
	} {
		rows, used := esxiTextRows(affectedList(t, c.affected), c.assigner)
		if got := spanWords(rows); !slices.Equal(got, c.want) || len(used) != c.used {
			t.Errorf("%s: rows %q, %d strings used; want %q, %d", c.name, got, len(used), c.want, c.used)
		}
		for _, r := range rows {
			if r.Vendor != "vmware" || r.Product != "esxi" || r.VersionType != RecordTextType || r.Fixed != r.EndExcl || r.DefaultStatus != DefaultUnknown {
				t.Errorf("%s: row %+v", c.name, r)
			}
		}
	}
}

// vmwareRecordJSON is a minimal published CVE record of VMware with this affected list.
func vmwareRecordJSON(cve, affected string) []byte {
	return []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + cve + `","state":"PUBLISHED","assignerShortName":"vmware",` +
		`"datePublished":"2022-12-13T00:00:00.000Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw."}],"affected":` + affected + `}}}`)
}

// The reader stores the rows read from the words beside what it kept before: a version string the rows say all of is not kept as words
// too, and one they do not (the 6.7 and 6.5 bulletins) still is, for the CVE page.
func TestRecordRanges_ESXiWords(t *testing.T) {
	t.Parallel()
	rec, err := ParseCVERecord(vmwareRecordJSON("CVE-2021-21974", affected21974), "CVE-2021-21974")
	if err != nil {
		t.Fatal(err)
	}
	var read, words []string
	for _, r := range rec.Ranges {
		if r.Vendor != "vmware" || r.Product != "esxi" {
			continue
		}
		if r.VersionType == RecordTextType {
			read = append(read, r.StartIncl+" < "+r.EndExcl)
			if r.Origin != OriginCNA || r.CVE != "CVE-2021-21974" {
				t.Errorf("row %+v", r)
			}
			continue
		}
		words = append(words, r.StartIncl)
	}
	if !slices.Equal(read, []string{"7.0 < ESXi70U1c-17325551"}) {
		t.Errorf("read rows %q", read)
	}
	if !slices.Equal(words, []string{"6.7 before ESXi670-202102401-SG", "6.5 before ESXi650-202102101-SG"}) {
		t.Errorf("rows kept as words %q, want the two bulletins only", words)
	}
}

// esxiSnapshotNVD is NVD's list of ESXi releases for CVE-2022-31705 (exact releases, 8.0 GA the only 8.0 one).
var esxiSnapshotNVD = []string{"7.0:-", "7.0:beta", "7.0:update_1", "7.0:update_1a", "7.0:update_1b", "7.0:update_1c", "7.0:update_1d",
	"7.0:update_1e", "7.0:update_2", "7.0:update_2a", "7.0:update_2c", "7.0:update_2d", "7.0:update_2e", "7.0:update_3c", "7.0:update_3d",
	"7.0:update_3e", "7.0:update_3f", "7.0:update_3g", "8.0:-"}

// seedESXi writes a CVE with NVD's exact ESXi releases (version:update) and NVD ranges, and VMware's record with this affected list.
func seedESXi(t *testing.T, cve, affected string, exact []string, ranges ...AffectedRow) *Store {
	t.Helper()
	s, db := newStore(t)
	nvd := NVDRecord{CVE: cve, Published: epoch0.AddDate(0, -1, 0), LastModified: epoch0, Status: "Analyzed", Description: "A flaw."}
	for _, e := range exact {
		v, u, _ := strings.Cut(e, ":")
		nvd.Affected = append(nvd.Affected, AffectedRow{CPE: "cpe:2.3:o:vmware:esxi:" + v + ":" + u + ":*:*:*:*:*:*"})
	}
	nvd.Affected = append(nvd.Affected, ranges...)
	rec, err := ParseCVERecord(vmwareRecordJSON(cve, affected), cve)
	if err != nil {
		t.Fatal(err)
	}
	write(t, db, func(tx *sql.Tx) error {
		if err := storeRecords(t.Context(), tx, []NVDRecord{nvd}, epoch0); err != nil {
			return err
		}
		k, err := recordKeepOf(t.Context(), tx, epoch0, nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, []CVERecord{rec}, k, epoch0)
		return err
	})
	return s
}

// esxiWord is what VMware's rows of cve say about an ESXi host (version and build as it reports them), read as the findings match pass
// reads them (vendorWord's rules: the rows must name the host's line, and "not affected" needs a row ending in the host's own update).
func esxiWord(t *testing.T, s *Store, cve, version, build string) string {
	t.Helper()
	rows, err := s.SchemeRangesOf(t.Context(), []string{cve})
	if err != nil {
		t.Fatal(err)
	}
	installed, ok := versionscheme.VMwareESXi.Installed(version, build)
	if !ok {
		t.Fatal(version, build)
	}
	var spans []versionscheme.Span
	for _, r := range rows {
		if _, sp, _, ok := RangeScheme(r); ok && r.CVE == cve {
			spans = append(spans, sp)
		}
	}
	named, ownTrain := false, false
	for _, sp := range spans {
		line := func(v *versionscheme.Version) bool { return v != nil && slices.Equal(v.Line, installed.Line) }
		named = named || line(sp.Start) || line(sp.End)
		ownTrain = ownTrain || sp.End != nil && !sp.End.LineStart && sp.End.Train == installed.Train
	}
	v := versionscheme.Judge(installed, spans)
	switch {
	case !named || v.State == versionscheme.NotComparable, v.State == versionscheme.NotAffected && !ownTrain:
		return ""
	case v.State == versionscheme.NotAffected:
		return "not affected"
	case v.Fix == nil:
		return "affected"
	}
	return "affected, fixed in " + v.Fix.Label
}

// CVE-2022-31705, which VMware fixed in 8.0a: an 8.0 Update 3 host (build 24022510) is not affected (Update 3 began after 8.0a),
// 8.0 GA is (fixed in 8.0a), and the 7.0 line is judged by its own fix. NVD's list (exact releases, 8.0 GA only) agrees with every one.
func TestSchemeRangesOf_ESXiWordsDecideTheHost(t *testing.T) {
	t.Parallel()
	s := seedESXi(t, "CVE-2022-31705", affected31705, esxiSnapshotNVD)
	for _, c := range []struct{ version, build, want string }{
		{"8.0.3", "24022510", "not affected"},                // 8.0 Update 3
		{"8.0.3", "24674464", "not affected"},                // 8.0 Update 3e
		{"8.0.2", "22380479", "not affected"},                // 8.0 Update 2
		{"8.0.1", "21495797", "not affected"},                // 8.0 Update 1
		{"8.0.0", "20513097", "affected, fixed in 8.0a"},     // 8.0 GA
		{"8.0.0", "21203435", "not affected"},                // 8.0b, after the fix in its own train
		{"7.0.3", "20328353", "affected, fixed in 7.0 U3si"}, // 7.0 Update 3g
		{"7.0.3", "21053776", "not affected"},                // 7.0 Update 3j
		{"7.0.2", "17630552", "affected, fixed in 7.0 U3si"}, // 7.0 Update 2: an older update than the fix's
	} {
		if got := esxiWord(t, s, "CVE-2022-31705", c.version, c.build); got != c.want {
			t.Errorf("%s build %s: %q, want %q", c.version, c.build, got, c.want)
		}
	}
}

// The affected side wins: when NVD lists a release of a line that the words say is not affected (8.0 Update 3 for a flaw the words
// fix in 8.0a), or a range that reaches the line, or an update the build table does not place, the line's words are dropped and NVD's
// rows decide (the host keeps its question or gets a finding). Another line keeps its words.
func TestSchemeRangesOf_ESXiWordsYieldToNVD(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		exact  []string
		ranges []AffectedRow
		want80 string
		want70 string
	}{
		{"NVD lists 8.0 Update 3", append(slices.Clone(esxiSnapshotNVD), "8.0:update_3"), nil, "", "affected, fixed in 7.0 U3si"},
		{"NVD lists every 8.0 release", append(slices.Clone(esxiSnapshotNVD[:18]), "8.0:*"), nil, "", "affected, fixed in 7.0 U3si"},
		{"NVD lists an 8.0 update it does not name the build of", append(slices.Clone(esxiSnapshotNVD), "8.0:update_9"), nil, "", "affected, fixed in 7.0 U3si"},
		{"an NVD range reaches 8.0", esxiSnapshotNVD, []AffectedRow{{CPE: "cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*", StartIncl: "7.0", EndExcl: "8.0.3"}}, "", ""},
		{"an NVD range ends before 8.0", esxiSnapshotNVD, []AffectedRow{{CPE: "cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*", StartIncl: "6.5", EndExcl: "7.0"}}, "not affected", "affected, fixed in 7.0 U3si"},
		{"NVD lists 7.0 Update 3i, past the 7.0 fix", append(slices.Clone(esxiSnapshotNVD), "7.0:update_3i"), nil, "not affected", ""},
	} {
		s := seedESXi(t, "CVE-2022-31705", affected31705, c.exact, c.ranges...)
		if got := esxiWord(t, s, "CVE-2022-31705", "8.0.3", "24022510"); got != c.want80 {
			t.Errorf("%s: 8.0 Update 3 %q, want %q", c.name, got, c.want80)
		}
		if got := esxiWord(t, s, "CVE-2022-31705", "7.0.3", "20328353"); got != c.want70 {
			t.Errorf("%s: 7.0 Update 3g %q, want %q", c.name, got, c.want70)
		}
	}
}

// An update that began before the stated fix gets no row: 8.0 Update 3 (build 24022510) began before 8.0 Update 2d (build 24585300),
// so a fix on Update 2 says nothing about it (CVE-2025-22224's case, which VMware fixed in Update 3d too). A line no words name (8.0
// for a record of 7.0 only) gets none either, and nothing is read for a record without words: NVD's exact 8.0 GA entry alone never
// makes 8.0 Update 3 "not affected".
func TestESXiLaterTrains_OnlyUpdatesBegunAfterTheFix(t *testing.T) {
	t.Parallel()
	words := `[{"vendor":"VMware","product":"ESXi","versions":[{"version":"8.0 prior to ESXi80U2d-24585300","status":"affected"}]}]`
	s := seedESXi(t, "CVE-2026-90001", words, []string{"8.0:-"})
	if got := esxiWord(t, s, "CVE-2026-90001", "8.0.3", "24022510"); got != "" {
		t.Errorf("8.0 Update 3 under a fix on Update 2 only: %q, want no word", got)
	}
	if got := esxiWord(t, s, "CVE-2026-90001", "8.0.2", "23825572"); got != "affected, fixed in 8.0 U2d" {
		t.Errorf("8.0 Update 2c: %q", got)
	}
	s = seedESXi(t, "CVE-2021-21974", affected21974, []string{"7.0.0:-", "7.0.0:b", "7.0.0:update_1", "7.0.0:update_1a", "7.0.0:update_1b"})
	for _, c := range []struct{ version, build, want string }{
		{"8.0.3", "24022510", ""}, // no word names 8.0: NVD's rows decide
		{"6.7.0", "17700523", ""}, // a bulletin with no build: NVD's rows decide
		{"7.0.1", "17168206", "affected, fixed in 7.0 U1c"},
		{"7.0.2", "17630552", "not affected"}, // 7.0 Update 2 began after Update 1c
		{"7.0.3", "18644231", "not affected"},
	} {
		if got := esxiWord(t, s, "CVE-2021-21974", c.version, c.build); got != c.want {
			t.Errorf("CVE-2021-21974 %s build %s: %q, want %q", c.version, c.build, got, c.want)
		}
	}
	s, db := newStore(t)
	write(t, db, func(tx *sql.Tx) error {
		return storeRecords(t.Context(), tx, []NVDRecord{{CVE: "CVE-2026-90002", Published: epoch0.AddDate(0, -1, 0), LastModified: epoch0, Status: "Analyzed",
			Affected: []AffectedRow{{CPE: "cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*"}}}}, epoch0)
	})
	if got := esxiWord(t, s, "CVE-2026-90002", "8.0.3", "24022510"); got != "" {
		t.Errorf("NVD's 8.0 GA entry alone: %q, want no word", got)
	}
}

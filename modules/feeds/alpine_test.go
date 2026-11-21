package feeds

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apkver"
)

// testdata/alpine holds four records of OSV.dev's Alpine all.zip as served on 2026-11-17, unmodified (Alpine Linux security
// database, CC BY-SA 4.0, converted by OSV.dev; THIRD_PARTY_NOTICES.md): CVE-2026-123158 (OpenSSH, the CVE of the platform list, every branch OSV
// lists), CVE-2026-31431 (docker, two fixed releases per branch), CVE-2021-3156 (sudo, old branches with a release apk cannot read)
// and CVE-2006-20001 (apache2, not on the CISA list).

// alpineZip packs files (name → text) into a zip archive, in the given order.
func alpineZip(t testing.TB, files ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// alpineRecords is the zip of the four real records, with a folder and a file that is no record.
func alpineRecords(t testing.TB) []byte {
	t.Helper()
	files := [][2]string{{"advisories/", ""}, {"README.txt", "not read"}}
	for _, id := range []string{"CVE-2006-20001", "CVE-2021-3156", "CVE-2026-31431", "CVE-2026-123158"} {
		files = append(files, [2]string{"ALPINE-" + id + ".json", testFile(t, "alpine/ALPINE-"+id+".json")})
	}
	return alpineZip(t, files...)
}

var alpineKEV = DistroWant{KEV: map[string]bool{"CVE-2026-123158": true, "CVE-2026-31431": true, "CVE-2021-3156": true}, Tier: map[string]bool{"CVE-2006-20001": true}}

// Every Alpine branch the record lists is kept with its first fixed release (secdb, read 2026-11-17: v3.16 9.0_p1-r6 … v3.24
// 10.3_p1-r2; OSV.dev lists no edge), the higher of two fixed releases, and a release apk cannot read drops only its branch.
func TestParseAlpineOSV(t *testing.T) {
	t.Parallel()
	res, err := ParseAlpineOSV(bytes.NewReader(alpineRecords(t)), alpineKEV)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]string{} // CVE → branch → release
	for _, r := range res.Rows {
		if r.Distro != DistroAlpine || r.Status != DistroFixed {
			t.Errorf("row %+v", r)
		}
		if got[r.CVE] == nil {
			got[r.CVE] = map[string]string{}
		}
		got[r.CVE][r.Release] = r.Package + " " + r.Fixed
	}
	want := map[string]map[string]string{
		"CVE-2026-123158": {"3.16": "openssh 9.0_p1-r6", "3.17": "openssh 9.1_p1-r7", "3.18": "openssh 9.3_p2-r4", "3.19": "openssh 9.6_p1-r3",
			"3.20": "openssh 9.7_p1-r6", "3.21": "openssh 9.9_p2-r1", "3.22": "openssh 10.0_p1-r11", "3.23": "openssh 10.2_p1-r1", "3.24": "openssh 10.3_p1-r2"},
		"CVE-2026-31431": {"3.23": "docker 29.4.3-r0", "3.24": "docker 29.4.3-r0"},
		"CVE-2021-3156": {"3.11": "sudo 1.8.31-r1", "3.19": "sudo 1.9.5_p2-r0", "3.20": "sudo 1.9.5_p2-r0", "3.21": "sudo 1.9.5_p2-r0",
			"3.22": "sudo 1.9.5_p2-r0", "3.23": "sudo 1.9.5_p2-r0", "3.24": "sudo 1.9.5_p2-r0"},
	}
	for cve, w := range want {
		if !mapsEqual(got[cve], w) {
			t.Errorf("%s: %v, want %v", cve, got[cve], w)
		}
	}
	// the tier CVE is read but keeps no row: no Alpine device runs apache2
	if len(got) != 3 || res.Accepted != 4 || res.Rejected != 8 || len(res.Reasons) != 1 || !strings.Contains(res.Reasons[0].Example, `1.9.5p2-r0`) {
		t.Errorf("%d CVEs, accepted %d, rejected %d, reasons %+v", len(got), res.Accepted, res.Rejected, res.Reasons)
	}
}

// A tier CVE (nvd-recent's 12 months, on no exploited list) keeps its rows for the source packages the Alpine devices run, like the
// Ubuntu and Debian feeds do, so "Updates to plan" judges an apk package by Alpine's own fixed releases.
func TestParseAlpineOSV_TierRowsOfTheDevicesPackages(t *testing.T) {
	t.Parallel()
	want := alpineKEV
	want.Packages = map[string]bool{"apache2": true}
	res, err := ParseAlpineOSV(bytes.NewReader(alpineRecords(t)), want)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range res.Rows {
		if r.CVE == "CVE-2006-20001" {
			if r.Package != "apache2" || r.Status != DistroFixed || r.Fixed == "" {
				t.Errorf("row %+v", r)
			}
			n++
		}
	}
	if n != 4 { // v3.14 to v3.17
		t.Fatalf("%d rows of the tier CVE", n)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The zip is read fail-closed. A cut or foreign archive, one where no name is an Alpine record (L10: a format
// change) or one whose end record lists too many files (L2) fails the pull; a record of another CVE, two files of one CVE (L1: the CVE
// is rejected, neither file kept), a bad package name, a record that names no Alpine branch (L10) or a file over 1 MiB is rejected
// alone; a withdrawn record keeps nothing (L5); secdb's "0" is "not affected"; a release longer than 100 characters drops its row.
func TestParseAlpineOSVFailsClosed(t *testing.T) {
	t.Parallel()
	whole := alpineRecords(t)
	for name, body := range map[string][]byte{
		"cut short": whole[:len(whole)-40], "not a zip": []byte("<html>"), "xz": xzTar(t, [2]string{"a", "b"}),
		"no Alpine record": alpineZip(t, [2]string{"osv/ALPINE-CVE-2026-123158.json", "{}"}, [2]string{"UBUNTU-CVE-2026-123158.json", "{}"}),
	} {
		if _, err := ParseAlpineOSV(bytes.NewReader(body), alpineKEV); !errors.Is(err, ErrBadSample) {
			t.Errorf("%s: %v, want ErrBadSample", name, err)
		}
	}
	rec := func(id, pkg, eco, fixed string) string {
		return `{"id":"ALPINE-` + id + `","affected":[{"package":{"name":"` + pkg + `","ecosystem":"` + eco + `"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]},` +
			`{"package":{"name":"` + pkg + `","ecosystem":"Alpine:edge"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1-r0"}]}]}]}`
	}
	res, err := ParseAlpineOSV(bytes.NewReader(alpineZip(t,
		[2]string{"ALPINE-CVE-2026-123158.json", rec("CVE-2026-31431", "openssh", "Alpine:v3.23", "10.2_p1-r1")}, // the record of another CVE
		[2]string{"ALPINE-CVE-2026-31431.json", rec("CVE-2026-31431", "Docker Engine", "Alpine:v3.23", "29.4.3-r0")},
		[2]string{"ALPINE-CVE-2021-3156.json", rec("CVE-2021-3156", "sudo", "Alpine:v3.23", "1.9.5_p2-r0")},
		[2]string{"ALPINE-CVE-2021-3156.json", rec("CVE-2021-3156", "sudo", "Alpine:v3.23", "1.9.5_p2-r0")}, // a second file of the same CVE
	)), alpineKEV)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 0 || res.Accepted != 0 || res.Rejected != 3 {
		t.Errorf("rows %+v, accepted %d, rejected %d %+v", res.Rows, res.Accepted, res.Rejected, res.Reasons)
	}
	res, err = ParseAlpineOSV(bytes.NewReader(alpineZip(t,
		[2]string{"ALPINE-CVE-2021-3156.json", rec("CVE-2021-3156", "sudo", "Alpine:v3.23", "0")},
		[2]string{"ALPINE-CVE-2026-31431.json", rec("CVE-2026-31431", "docker", "Alpine:3.23", "29.4.3-r0")}, // a renamed ecosystem
		[2]string{"ALPINE-CVE-2026-123158.json", `{"id":"ALPINE-CVE-2026-123158","withdrawn":"2026-11-10T00:00:00Z","affected":[{"package":{"name":"openssh","ecosystem":"Alpine:v3.23"},"ranges":[{"events":[{"fixed":"10.2_p1-r1"}]}]}]}`},
	)), alpineKEV)
	if err != nil || len(res.Rows) != 1 || res.Rows[0] != (DistroFix{Distro: DistroAlpine, Release: "3.23", Package: "sudo", CVE: "CVE-2021-3156", Status: DistroNotAffected}) ||
		res.Accepted != 2 || res.Rejected != 1 || !strings.Contains(res.Reasons[0].Example, "Alpine:3.23") {
		t.Errorf("not affected, renamed ecosystem, withdrawn: %+v %v", res, err)
	}
	long := alpineZip(t, [2]string{"ALPINE-CVE-2026-123158.json", rec("CVE-2026-123158", "openssh", "Alpine:v3.23", strings.Repeat("1.", 60)+"1-r1")})
	if res, err := ParseAlpineOSV(bytes.NewReader(long), alpineKEV); err != nil || res.Rejected != 1 || len(res.Rows) != 0 || res.Accepted != 1 {
		t.Errorf("a release over 100 characters: %+v %v", res, err)
	}
	big := alpineZip(t, [2]string{"ALPINE-CVE-2026-123158.json", strings.Repeat(" ", alpineMaxEntry+1) + "{}"})
	if res, err := ParseAlpineOSV(bytes.NewReader(big), alpineKEV); err != nil || res.Rejected != 1 || len(res.Rows) != 0 {
		t.Errorf("a file over 1 MiB: %+v %v", res, err)
	}
	// L2: the end record's count is read before the directory is parsed
	var many [][2]string
	for i := range alpineMaxFiles + 1 {
		many = append(many, [2]string{fmt.Sprintf("f%d", i), ""})
	}
	if _, err := ParseAlpineOSV(bytes.NewReader(alpineZip(t, many...)), alpineKEV); !errors.Is(err, ErrBadSample) || !strings.Contains(err.Error(), "files") {
		t.Errorf("%d files: %v", alpineMaxFiles+1, err)
	}
}

// alpine-osv is fetched only while a device states Alpine Linux, even before its first fill, so
// a box without one never contacts OSV.dev; then it keeps the CISA list's CVEs, sends its validators back (304 keeps the rows) and
// findings reads its rows with the others.
func TestAlpinePullOnlyWhileADeviceStatesAlpine(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(alpineOSVFeedID)
	e.mirror(alpineOSVFeedID, o.url("/Alpine/all.zip"))
	o.body("/Alpine/all.zip", `"z1"`, string(alpineRecords(t)))
	e.loadKEV()
	applyV(t, e.db, e.clock(), "cisa-kev", []Vuln{vuln("CVE-2026-123158", "OpenBSD", "OpenSSH", "2026-11-06")}, false)
	inv := &distroInv{got: map[string]map[string]bool{DistroUbuntu: {"openssh": true}}}
	e.svc.Inventory = inv
	const note = "Not updated: no Alpine Linux device now. Vedette fetches it on the next check after a device's agent or SNMP answer, or a person, says it runs Alpine Linux."
	for range 2 { // never filled, no Alpine device: nothing is fetched or recorded, and the next tick asks again
		if err := e.runPull(t.Context()); err != nil {
			t.Fatal(err)
		}
		e.setNow(e.clock().Add(10 * time.Minute))
	}
	f := e.svc.live(t.Context(), e.feed(alpineOSVFeedID))
	if o.count("/Alpine/all.zip") != 0 || inv.asked != 2 || f.Status != "never" || f.Error == nil || *f.Error != note {
		t.Fatalf("no Alpine device: %d requests, asked %d, feed %+v", o.count("/Alpine/all.zip"), inv.asked, f)
	}
	// an inventory that cannot be read, or none, never opens the gate (PRIVACY flow 1: "never")
	inv.err = errors.New("database is locked")
	if err := e.svc.Fetch(t.Context(), alpineOSVFeedID); err != nil || o.count("/Alpine/all.zip") != 0 {
		t.Fatalf("inventory read error: %v, %d requests", err, o.count("/Alpine/all.zip"))
	}
	inv.err = nil
	e.svc.Inventory = e.inv // no DistroLister
	if err := e.svc.Fetch(t.Context(), alpineOSVFeedID); err != nil || o.count("/Alpine/all.zip") != 0 {
		t.Fatalf("no lister: %v, %d requests", err, o.count("/Alpine/all.zip"))
	}
	e.svc.Inventory = inv
	loading := func() bool {
		t.Helper()
		l, err := e.svc.st.DistroLoading(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return l[DistroAlpine]
	}
	// on and never filled is loading (findings keeps the question); a failed pull with no rows still is
	if !loading() {
		t.Fatal("alpine-osv on and never filled is not loading")
	}
	inv.got = map[string]map[string]bool{DistroAlpine: {}} // a device's SNMP answer says Alpine Linux
	o.serve("/Alpine/all.zip", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "busy", http.StatusServiceUnavailable) })
	if err := e.svc.Fetch(t.Context(), alpineOSVFeedID); err != nil || o.count("/Alpine/all.zip") != 1 || e.feed(alpineOSVFeedID).Status != "error" || !loading() {
		t.Fatalf("a failed first pull: %v, %d requests, feed %+v, loading %v", err, o.count("/Alpine/all.zip"), e.feed(alpineOSVFeedID), loading())
	}
	o.body("/Alpine/all.zip", `"z1"`, string(alpineRecords(t)))
	if err := e.svc.Fetch(t.Context(), alpineOSVFeedID); err != nil {
		t.Fatal(err)
	}
	if loading() {
		t.Fatal("a filled alpine-osv is still loading")
	}
	fixes, err := e.svc.st.DistroFixes(t.Context())
	if f := e.svc.live(t.Context(), e.feed(alpineOSVFeedID)); err != nil || o.count("/Alpine/all.zip") != 2 || f.Status != "ok" || f.Error == nil || *f.Error != "Counts one record per package, release and CVE: 1 exploited CVE." || f.Records == nil || *f.Records != 9 {
		t.Fatalf("an Alpine device: %d requests, feed %+v %q, %v", o.count("/Alpine/all.zip"), f, deref(f.Error), err)
	}
	var branches []string
	for _, r := range fixes["CVE-2026-123158"] {
		branches = append(branches, r.Release+" "+r.Fixed)
	}
	if len(fixes) != 1 || !slices.Contains(branches, "3.23 10.2_p1-r1") || !slices.Contains(branches, "3.20 9.7_p1-r6") || len(branches) != 9 {
		t.Fatalf("findings reads %v", fixes) // only the CISA list's CVEs: CVE-2026-31431 and CVE-2021-3156 are not on this box's list
	}
	e.setNow(e.clock().Add(25 * time.Hour)) // due again, unchanged: 304, rows kept
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if o.count("/Alpine/all.zip") != 3 || rowsOf(t, e.db, "feeds_distro_fix") != 9 || e.feed(alpineOSVFeedID).Status != "ok" {
		t.Fatalf("after 304: %d requests, %d rows", o.count("/Alpine/all.zip"), rowsOf(t, e.db, "feeds_distro_fix"))
	}
	// turned off: not loading (findings falls back to NVD), its rows kept but not used
	if c, b := e.put(alpineOSVFeedID, `{"enabled":false}`); c != 200 || loading() {
		t.Fatalf("turned off: %d %v, loading %v", c, b, loading())
	}
}

// FuzzParseAlpineEntry fuzzes one record of the archive (the zip layer is the library's): a bad record never fails the archive, and
// every row is one feeds_distro_fix accepts with a release apk reads.
func FuzzParseAlpineEntry(f *testing.F) {
	f.Add([]byte(testFile(f, "alpine/ALPINE-CVE-2026-123158.json")))
	f.Add([]byte(`{"id":"ALPINE-CVE-2026-123158","affected":[{"package":{"name":"a","ecosystem":"Alpine:v3.23"},"ranges":[{"events":[{"fixed":"0"}]}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseAlpineOSV(bytes.NewReader(alpineZip(t, [2]string{"ALPINE-CVE-2026-123158.json", string(data)})), alpineKEV)
		if err != nil {
			t.Fatalf("a bad record failed the whole archive: %v", err)
		}
		for _, r := range res.Rows {
			if r.CVE != "CVE-2026-123158" || r.Distro != DistroAlpine || !apkPackageRE.MatchString(r.Package) || r.Release == "" || len(r.Release) > 8 ||
				strings.Trim(r.Release, "0123456789.") != "" || (r.Status == DistroFixed) != apkver.Valid(r.Fixed) || (r.Status != DistroFixed && (r.Status != DistroNotAffected || r.Fixed != "")) {
				t.Fatalf("row %+v", r)
			}
		}
	})
}

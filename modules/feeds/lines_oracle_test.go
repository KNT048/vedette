package feeds

import (
	"database/sql"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const javaKey = "oracle|java se"

// oracleSels is the csaf entries of line-sources.json's Oracle source, by catalogue key.
func oracleSels(t *testing.T) map[string]CSAFSelector {
	t.Helper()
	cat, err := lineCat()
	if err != nil {
		t.Fatal(err)
	}
	def := cat.sources[oracleLineFeedID]
	out := map[string]CSAFSelector{}
	for i, k := range cat.keys[oracleLineFeedID] {
		out[k] = def.CSAF[def.Products[i]]
	}
	return out
}

func oracleDocOf(t *testing.T, body string) oracleDoc {
	t.Helper()
	raw, err := parseCSAFLines(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return oracleFacts(raw, oracleSels(t))
}

// rowsByLine is a statement's rows as "line=status[:last affected][!]" ("!" for explicit), sorted.
func rowsByLine(st lineStatement) []string {
	var out []string
	for _, r := range st.Rows {
		s := r.Line + "=" + r.Status
		if r.LastAffected != "" {
			s += ":" + r.LastAffected
		}
		if r.Explicit {
			s += "!"
		}
		out = append(out, s)
	}
	return out
}

// Count test of the Oracle CSAF line source over four of its public documents cut to facts (testdata/lines/oracle-*.json: the
// product tree's Java SE branch and the product statuses of the CVEs named, CPU April 2022, CPU April 2026, CPU July 2026 and CSPU
// August 2026, as published on www.oracle.com on 27 Nov 2026). Oracle lists the newest affected release of each line ("8u491" read as
// 1.8.0_491 through the catalogue's version_map); a line the document assessed and does not list is not affected by the convention
// (explicit false); a line whose every release is listed not affected is explicitly not affected; a line the document did not assess
// (Java 7 in 2026) has no row; a CVE of another product only gets no statement.
func TestOracleLines_Count(t *testing.T) {
	t.Parallel()
	var docs []oracleDoc
	for _, f := range []string{"oracle-cpujul2026.json", "oracle-cpuapr2026.json", "oracle-cspuaug2026.json", "oracle-cpuapr2022.json"} {
		docs = append(docs, oracleDocOf(t, testFile(t, "lines/"+f)))
	}
	sts := combineOracle(docs, true)
	by := map[string]lineStatement{}
	for _, s := range sts {
		if s.Product != javaKey {
			t.Errorf("%s: product %q", s.CVE, s.Product)
		}
		by[s.CVE] = s
	}
	want := map[string][]string{
		"CVE-2026-46968": {"11=affected:11.0.31!", "17=affected:17.0.19!", "21=affected:21.0.11!", "25=affected:25.0.3!", "26=affected:26.0.1!", "8=affected:1.8.0_491!"},
		"CVE-2026-46917": {"11=affected:11.0.31!", "17=affected:17.0.19!", "21=affected:21.0.11!", "25=affected:25.0.3!", "26=affected:26.0.1!", "8=unaffected"},
		"CVE-2026-47013": {"11=unaffected", "17=unaffected", "21=unaffected", "25=unaffected", "26=unaffected", "8=affected:1.8.0_491!"},
		"CVE-2026-47057": {"11=affected:11.0.31!", "17=unaffected", "21=unaffected", "25=unaffected", "26=unaffected", "8=affected:1.8.0_491!"},
		"CVE-2026-60526": {"11=unaffected", "17=unaffected", "21=unaffected", "25=unaffected", "26=unaffected", "8=affected:1.8.0_491!"},
		"CVE-2026-33636": {"11=unaffected!", "17=unaffected!", "21=unaffected!", "25=unaffected!", "26=unaffected!", "8=unaffected!"},
		"CVE-2026-22008": {"11=unaffected", "17=unaffected", "21=unaffected", "25=affected:25.0.1!", "26=unaffected", "8=unaffected"},
		// 25.0.2 listed not affected, 25.0.1 not listed: line 25 only by the convention; 8u481 and 8u481-b50 both listed: explicit
		"CVE-2025-64505": {"11=unaffected!", "17=unaffected!", "21=unaffected!", "25=unaffected", "26=unaffected!", "8=unaffected!"},
		"CVE-2026-62574": {"11=affected:11.0.32!", "17=affected:17.0.20!", "21=affected:21.0.12!", "25=affected:25.0.4!", "26=affected:26.0.2!", "8=affected:1.8.0_501!"},
		// April 2022 writes "Oracle Java SE Version Oracle Java SE:7u331" and lists GraalVM under the Java SE branch (another product)
		"CVE-2022-21426": {"11=affected:11.0.14!", "17=affected:17.0.2!", "18=affected:18!", "7=affected:1.7.0_331!", "8=affected:1.8.0_321!"},
		"CVE-2022-21449": {"11=unaffected", "17=affected:17.0.2!", "18=affected:18!", "7=unaffected", "8=unaffected"},
	}
	if len(sts) != len(want) {
		t.Errorf("%d statements, want %d", len(sts), len(want))
	}
	for cve, rows := range want {
		if got := rowsByLine(by[cve]); !slices.Equal(got, rows) {
			t.Errorf("%s rows %v, want %v", cve, got, rows)
		}
	}
	if s := by["CVE-2026-46968"]; s.StatedAt != "2026-07-21" || s.Ref != "https://www.oracle.com/security-alerts/cpujul2026.html" {
		t.Errorf("stated %q ref %q", s.StatedAt, s.Ref)
	}
	if _, ok := by["CVE-2014-3643"]; ok {
		t.Error("a CVE of another Oracle product got a Java statement")
	}
}

// oracleDocText is a CSAF document of one Java SE branch (products: id -> name, or id -> "cpe:..." for a CPE) and vulnerabilities
// (cve -> category -> ids).
func oracleDocText(id, day string, products map[string]string, vulns map[string]map[string][]string) string {
	var ps []string
	for _, pid := range slices.Sorted(func(yield func(string) bool) {
		for k := range products {
			if !yield(k) {
				return
			}
		}
	}) {
		name := products[pid]
		if strings.HasPrefix(name, "cpe:") {
			ps = append(ps, fmt.Sprintf(`{"category":"product_version","name":"x","product":{"name":"x","product_id":%q,"product_identification_helper":{"cpe":%q}}}`, pid, name))
			continue
		}
		ps = append(ps, fmt.Sprintf(`{"category":"product_version","name":%q,"product":{"name":%q,"product_id":%q}}`, name, name, pid))
	}
	var vs []string
	for cve, st := range vulns {
		var cats []string
		for c, ids := range st {
			cats = append(cats, fmt.Sprintf(`%q:["%s"]`, c, strings.Join(ids, `","`)))
		}
		vs = append(vs, fmt.Sprintf(`{"cve":%q,"product_status":{%s}}`, cve, strings.Join(cats, ",")))
	}
	return fmt.Sprintf(`{"document":{"tracking":{"id":%q,"initial_release_date":"%sT13:00:00-07:00"},"references":[{"url":"https://www.oracle.com/security-alerts/%s.html"}]},
"vulnerabilities":[%s],
"product_tree":{"branches":[{"category":"vendor","name":"Oracle","branches":[{"category":"product_name","branches":[%s],"name":"Oracle Java SE"}]}]}}`,
		id, day, strings.ToLower(id), strings.Join(vs, ","), strings.Join(ps, ","))
}

// Hostile or odd documents never become wrong rows: a CVE that names a release Vedette cannot read, or names one in a status it does
// not read, or lists a release not affected below one listed affected, is dropped whole; a product with another product's CPE under the
// branch is not Java; several documents on one CVE are combined (the newest affected release of a line wins), and dropped when they
// disagree on a line; a feed with a document that could not be read gives no convention row.
func TestOracleLines_FailsClosed(t *testing.T) {
	t.Parallel()
	products := map[string]string{
		"j8": "Oracle Java SE Version 8u491", "j21": "cpe:2.3:a:oracle:java_se:21.0.11:*:*:*:*:*:*:*",
		"bad": "Oracle Java SE Version eight", "jmc": "cpe:2.3:a:oracle:jdk_mission_control:9.1.1:*:*:*:*:*:*:*",
		"graal": "Oracle Java SE Version Oracle GraalVM Enterprise Edition:21.3.18",
	}
	jul := oracleDocText("CPUJul2026csaf", "2026-07-21", products, map[string]map[string][]string{
		"CVE-2026-1001": {"known_affected": {"j8", "bad"}},                          // an unreadable release of Java
		"CVE-2026-1002": {"known_affected": {"j8"}, "under_investigation": {"j21"}}, // a status not read
		"CVE-2026-1003": {"known_affected": {"jmc", "graal"}},                       // other products only: no statement
		"CVE-2026-1004": {"known_affected": {"j8"}},
		"CVE-2026-1005": {"known_affected": {"j8"}},
		"CVE-2026-1006": {"known_affected": {"j21"}},
	})
	aug := oracleDocText("CSPUAug2026csaf", "2026-08-18", map[string]string{"j8": "Oracle Java SE Version 8u501", "j8old": "Oracle Java SE Version 8u481", "j21": "Oracle Java SE Version 21.0.12",
		"j8b": "cpe:2.3:a:oracle:java_se:8u511b33:*:*:*:*:*:*:*",                       // a patch build as November 2026 writes it
		"j8p": "cpe:2.3:a:oracle:java_se:8u511b33:*:*:*:enterprise_performance:*:*:*"}, // the Performance Pack: another edition
		map[string]map[string][]string{
			"CVE-2026-1004": {"known_affected": {"j8"}},                                  // a newer affected release on line 8
			"CVE-2026-1005": {"known_not_affected": {"j8old"}},                           // 8u481 not affected, July lists 8u491 affected: disagree
			"CVE-2026-1007": {"known_affected": {"j8"}, "known_not_affected": {"j8old"}}, // one document, not affected below affected
			"CVE-2026-1008": {"known_affected": {"j8b"}},
			"CVE-2026-1009": {"known_affected": {"j8p", "j21"}}, // the Performance Pack and 21 only: plain Java 8 not listed
		})
	docs := []oracleDoc{oracleDocOf(t, jul), oracleDocOf(t, aug)}
	by := map[string]lineStatement{}
	for _, s := range combineOracle(docs, true) {
		by[s.CVE] = s
	}
	for _, cve := range []string{"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1005", "CVE-2026-1007"} {
		if s, ok := by[cve]; ok {
			t.Errorf("%s stored: %v", cve, rowsByLine(s))
		}
	}
	if got := rowsByLine(by["CVE-2026-1004"]); !slices.Equal(got, []string{"21=unaffected", "8=affected:1.8.0_501!"}) || by["CVE-2026-1004"].StatedAt != "2026-08-18" {
		t.Errorf("CVE-2026-1004 %v %q", got, by["CVE-2026-1004"].StatedAt)
	}
	if got := rowsByLine(by["CVE-2026-1008"]); !slices.Equal(got, []string{"21=unaffected", "8=affected:1.8.0_511!"}) {
		t.Errorf("CVE-2026-1008 %v", got)
	}
	if got := rowsByLine(by["CVE-2026-1009"]); !slices.Equal(got, []string{"21=affected:21.0.12!", "8=unaffected"}) {
		t.Errorf("CVE-2026-1009 %v", got)
	}
	// a document of the feed not read: explicit rows stay, no line is not affected by the convention
	by = map[string]lineStatement{}
	for _, s := range combineOracle(docs, false) {
		by[s.CVE] = s
	}
	if got := rowsByLine(by["CVE-2026-1004"]); !slices.Equal(got, []string{"8=affected:1.8.0_501!"}) {
		t.Errorf("incomplete feed: CVE-2026-1004 %v", got)
	}
	if got := rowsByLine(by["CVE-2026-1006"]); !slices.Equal(got, []string{"21=affected:21.0.11!"}) {
		t.Errorf("incomplete feed: CVE-2026-1006 %v", got)
	}
	// a document that is not CSAF, or has no first release, is not read
	for _, bad := range []string{`[]`, `{"document":{"tracking":{"id":"x"}}}`, `{"document":{"tracking":{"id":"x","initial_release_date":"2026-07-21T13:00:00-07:00"}}} {}`} {
		if _, err := parseCSAFLines(strings.NewReader(bad)); err == nil {
			t.Errorf("%s read", bad)
		}
	}
}

const oracleRSS = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Oracle Security Alerts</title>
<item><title>CSPU August 2026</title><link>https://www.oracle.com/a/tech/docs/security-alerts/cspuaug2026csaf.json </link><guid isPermaLink="false">CSPUAug2026</guid></item>
<item><title>CPU July 2026</title>
  <link>https://www.oracle.com/a/tech/docs/security-alerts/cpujul2026csaf.json
  </link><guid isPermaLink="false">CPUJul2026</guid></item>
<item><title>CPU April 2026</title><link>https://www.oracle.com/docs/tech/security-alerts/cpuapr2026csaf.json</link></item>
</channel></rss>`

// A pull reads the feed and each document it links, on the feed's own host, larger than a usual pull's 5 MB (the source's own cap),
// and stores the statements of the catalogue's CVEs with the document's day; LineData gives findings the source's convention and the
// builds it numbers. The next pull asks each document with its validators: unchanged ones answer 304 and the rows stay as they were.
// A document that cannot be read is counted and leaves no convention row.
func TestOracleLinesPull(t *testing.T) {
	e, o := pullEnv(t)
	e.only(oracleLineFeedID)
	e.setURL(oracleLineFeedID, o.url("/a/tech/docs/security-alerts/oracle-cpu-csaf-rss.xml"))
	o.body("/a/tech/docs/security-alerts/oracle-cpu-csaf-rss.xml", `"r1"`, oracleRSS)
	// July grows past 5 MB with vulnerabilities of other products, as the real one is 5.6 MB
	jul := testFile(t, "lines/oracle-cpujul2026.json")
	var pad strings.Builder
	for i := 0; pad.Len() < 6<<20; i++ {
		fmt.Fprintf(&pad, `{"cve":"CVE-2026-9%05d","notes":[{"category":"summary","text":"%s"}],"product_status":{"known_affected":["P-1V-1.0"]}},`, i, strings.Repeat("x", 400))
	}
	jul = strings.Replace(jul, `"vulnerabilities": [`, `"vulnerabilities": [`+pad.String(), 1)
	if len(jul) < 6<<20 {
		t.Fatal("the padded document is not larger than 6 MB")
	}
	served := map[string]string{
		"/a/tech/docs/security-alerts/cspuaug2026csaf.json": testFile(t, "lines/oracle-cspuaug2026.json"),
		"/a/tech/docs/security-alerts/cpujul2026csaf.json":  jul,
		"/docs/tech/security-alerts/cpuapr2026csaf.json":    testFile(t, "lines/oracle-cpuapr2026.json"),
	}
	for path, body := range served {
		o.serve(path, func(w http.ResponseWriter, r *http.Request) {
			const lm = "Tue, 18 Aug 2026 18:52:59 GMT"
			if r.Header.Get("If-Modified-Since") == lm {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Last-Modified", lm)
			_, _ = w.Write([]byte(body))
		})
	}
	write(t, e.db, func(tx *sql.Tx) error {
		for _, c := range []string{"CVE-2026-46968", "CVE-2026-46917", "CVE-2026-22008", "CVE-2026-62574"} {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, nvd_status, updated_at) VALUES (?, '2026-04-21T20:15:00.000Z', 'Analyzed', '2026-11-01T00:00:00.000Z')`, c); err != nil {
				return err
			}
		}
		return nil
	})
	if err := e.svc.Fetch(t.Context(), oracleLineFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(oracleLineFeedID); f.Status != "ok" {
		t.Fatalf("%+v", f)
	}
	if n := rowsOf(t, e.db, "feeds_line_cve"); n != 4 {
		t.Fatalf("covers %d, want the 4 catalogue CVEs", n)
	}
	var day string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT stated_at FROM feeds_line_cve WHERE cve = 'CVE-2026-62574'`).Scan(&day); err != nil || day != "2026-08-18" {
		t.Errorf("stated %q %v", day, err)
	}
	st := NewStore(e.db)
	rows, covers, _, err := st.LineData(t.Context(), []string{"CVE-2026-46917"}, e.clock())
	if err != nil {
		t.Fatal(err)
	}
	if len(covers) != 1 || covers[0].Absent != AbsentUnaffectedIfAssessed || !slices.Equal(covers[0].Builds, []string{"Oracle"}) || covers[0].Name != "Oracle" || covers[0].Stale {
		t.Errorf("covers %+v", covers)
	}
	if len(rows) != 6 {
		t.Errorf("rows %+v", rows)
	}
	if len(covers) == 1 && len(covers[0].OnlyBuilds) != 0 {
		t.Errorf("a CVE of the JSSE limited to builds %v", covers[0].OnlyBuilds)
	}
	// the August CVE is in Oracle's installer: a part only Oracle's own build ships
	if _, covers, _, err := st.LineData(t.Context(), []string{"CVE-2026-62574"}, e.clock()); err != nil || len(covers) != 1 || !slices.Equal(covers[0].OnlyBuilds, []string{"Oracle"}) {
		t.Errorf("installer CVE covers %+v %v", covers, err)
	}
	for path := range served {
		if n := o.count(path); n != 1 {
			t.Errorf("%s asked %d times", path, n)
		}
	}
	// the next pull: every document unchanged (304), nothing changes
	e.setNow(e.clock().Add(7 * 60 * 60 * 1e9))
	if err := e.svc.Fetch(t.Context(), oracleLineFeedID); err != nil {
		t.Fatal(err)
	}
	for _, h := range o.all()[len(o.all())-3:] {
		if h.header.Get("If-Modified-Since") == "" {
			t.Errorf("%s asked without its validator", h.path)
		}
	}
	if n := rowsOf(t, e.db, "feeds_line_status"); n == 0 {
		t.Error("an unchanged feed dropped its rows")
	}
	before := rowsOf(t, e.db, "feeds_line_status")
	// April is gone now: counted, and no line is not affected by the convention any more
	o.serve("/docs/tech/security-alerts/cpuapr2026csaf.json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	e.setNow(e.clock().Add(7 * 60 * 60 * 1e9))
	if err := e.svc.Fetch(t.Context(), oracleLineFeedID); err != nil {
		t.Fatal(err)
	}
	var conv int
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM feeds_line_status WHERE explicit = 0`).Scan(&conv); err != nil || conv != 0 {
		t.Errorf("convention rows %d %v after a document could not be read", conv, err)
	}
	if after := rowsOf(t, e.db, "feeds_line_status"); after >= before {
		t.Errorf("rows %d, then %d", before, after)
	}
	if f := e.feed(oracleLineFeedID); f.Status != "ok" {
		t.Errorf("%+v", f)
	}
}

// oracleNotedDoc is a CSAF document of Oracle Java SE 8u491 and 21.0.11 whose vulnerabilities (cve -> description notes) all affect both.
func oracleNotedDoc(id string, vulns map[string][]string) string {
	var vs []string
	for _, cve := range slices.Sorted(maps.Keys(vulns)) {
		var notes []string
		for _, n := range vulns[cve] {
			notes = append(notes, fmt.Sprintf(`{"category":"description","text":%q}`, n))
		}
		vs = append(vs, fmt.Sprintf(`{"cve":%q,"notes":[%s],"product_status":{"known_affected":["J8","J21"]}}`, cve, strings.Join(notes, ",")))
	}
	return fmt.Sprintf(`{"document":{"tracking":{"id":%q,"initial_release_date":"2026-10-20T13:00:00-07:00"}},"vulnerabilities":[%s],
"product_tree":{"branches":[{"category":"vendor","name":"Oracle","branches":[{"category":"product_name","name":"Oracle Java SE","branches":[
{"category":"product_version","name":"8u491","product":{"name":"Oracle Java SE Version 8u491","product_id":"J8","product_identification_helper":{"cpe":"cpe:2.3:a:oracle:java_se:8u491:*:*:*:*:*:*:*"}}},
{"category":"product_version","name":"21.0.11","product":{"name":"Oracle Java SE Version 21.0.11","product_id":"J21","product_identification_helper":{"cpe":"cpe:2.3:a:oracle:java_se:21.0.11:*:*:*:*:*:*:*"}}}]}]}]}}`,
		id, strings.Join(vs, ","))
}

// A CVE in a part of Java only Oracle's own build ships (line-sources.json csaf own_components: its installer, the Java plugin, JavaFX
// in Java 8), as the description of the Java SE family names it, is stated for Oracle's builds only: Temurin, Zulu or Corretto ship no
// such part. The component is read from the Java SE family's description only (one vulnerability carries one description per product
// family); a CVE whose components are not all such parts, or whose Java SE description names none, is stated for every build, and so is
// one that any document states for every build.
func TestOracleLines_OwnBuildParts(t *testing.T) {
	t.Parallel()
	const java = "Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK product of Oracle Java SE (component: %s).  Supported versions that are affected are ..."
	oct := oracleNotedDoc("cpuoct2026csaf", map[string][]string{
		"CVE-2026-90001": {fmt.Sprintf(java, "Install")},
		"CVE-2026-90002": {"Vulnerability in the Oracle Hyperion product of Oracle Hyperion (component: Installation and Configuration (libpng)).", fmt.Sprintf(java, "JavaFX (WebKitGTK)")},
		"CVE-2026-90003": {"Vulnerability in Oracle Java SE (component: Java plugin).  Supported versions that are affected are ..."},
		"CVE-2026-90004": {fmt.Sprintf(java, "AWT, JavaFX")},
		"CVE-2026-90005": {fmt.Sprintf(java, "Libraries")},
		"CVE-2026-90006": {},
		"CVE-2026-90007": {"Vulnerability in the Oracle Hyperion product of Oracle Hyperion (component: Install)."},
		"CVE-2026-90008": {fmt.Sprintf(java, "Install")},
	})
	nov := oracleNotedDoc("cspunov2026csaf", map[string][]string{"CVE-2026-90008": {fmt.Sprintf(java, "2D")}})
	sts := combineOracle([]oracleDoc{oracleDocOf(t, oct), oracleDocOf(t, nov)}, true)
	got := map[string][]string{}
	for _, st := range sts {
		got[st.CVE] = st.OnlyBuilds
	}
	want := map[string][]string{"CVE-2026-90001": {"Oracle"}, "CVE-2026-90002": {"Oracle"}, "CVE-2026-90003": {"Oracle"}, "CVE-2026-90004": nil,
		"CVE-2026-90005": nil, "CVE-2026-90006": nil, "CVE-2026-90007": nil, "CVE-2026-90008": nil}
	if len(sts) != len(want) {
		t.Errorf("%d statements, want %d", len(sts), len(want))
	}
	for cve, w := range want {
		if !slices.Equal(got[cve], w) {
			t.Errorf("%s: limited to %v, want %v", cve, got[cve], w)
		}
	}
}

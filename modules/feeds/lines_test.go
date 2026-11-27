package feeds

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"
)

// Count test of the Node.js line source over its public index cut to facts (testdata/lines/node-index.json: 24 entries of
// nodejs/security-wg vuln/core/index.json, 27 Nov 2026, MIT): every entry is read into one row per release line or dropped whole with
// its reason, never in part.
func TestParseNodeLines_Count(t *testing.T) {
	t.Parallel()
	sts, st, err := ParseNodeLines([]byte(testFile(t, "lines/node-index.json")), "node.js|node.js")
	if err != nil {
		t.Fatal(err)
	}
	// 24 entries: 2 dropped ("0.10.x" and "<= 10" name no one release line), 22 read; 3 limited to some platforms (7 rows)
	if st.Accepted != 22 || st.Rejected != 2 || len(sts) != 22 {
		t.Fatalf("accepted %d, rejected %d (%+v), statements %d", st.Accepted, st.Rejected, st.Reasons, len(sts))
	}
	by := map[string]lineStatement{}
	lines, platformRows := 0, 0
	for _, s := range sts {
		by[s.CVE] = s
		lines += len(s.Rows)
		for _, r := range s.Rows {
			if len(r.Platforms) > 0 {
				platformRows++
			}
		}
	}
	if lines != 53 || platformRows != 7 {
		t.Errorf("rows %d, platform-limited rows %d", lines, platformRows)
	}
	rowOf := func(cve, line string) lineRow {
		i := slices.IndexFunc(by[cve].Rows, func(r lineRow) bool { return r.Line == line })
		if i < 0 {
			return lineRow{}
		}
		return by[cve].Rows[i]
	}
	for _, tc := range []struct {
		cve, line string
		want      lineRow
	}{
		{"CVE-2026-105481", "22", lineRow{Line: "22", Status: "affected", Fixed: "22.23.4", Explicit: true}},
		{"CVE-2026-105481", "26", lineRow{Line: "26", Status: "affected", Fixed: "26.12.1", Explicit: true}},
		{"CVE-2026-105483", "22", lineRow{}}, // "24.x || 26.x": line 22 not listed
		{"CVE-2026-48936", "26", lineRow{Line: "26", Status: "affected", Fixed: "26.3.1", Explicit: true,
			Platforms: []string{"aix", "android", "darwin", "freebsd", "linux", "openbsd", "sunos"}}},
		{"CVE-2016-1669", "6", lineRow{Line: "6", Status: "affected", Introduced: "6.0.0", Fixed: "6.2.0", Explicit: true}},
		{"CVE-2017-14849", "8", lineRow{Line: "8", Status: "affected", Introduced: "8.5.0", LastAffected: "8.5.0", Fixed: "8.6.0", Explicit: true}},
	} {
		if got := rowOf(tc.cve, tc.line); !rowEqual(got, tc.want) {
			t.Errorf("%s line %s = %+v, want %+v", tc.cve, tc.line, got, tc.want)
		}
	}
	if r := by["CVE-2026-105481"].Ref; r != "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases" {
		t.Errorf("ref = %q", r)
	}
}

func rowEqual(a, b lineRow) bool {
	return a.Line == b.Line && a.Status == b.Status && a.Introduced == b.Introduced && a.LastAffected == b.LastAffected && a.Fixed == b.Fixed &&
		a.Explicit == b.Explicit && slices.Equal(a.Platforms, b.Platforms)
}

// Hostile or odd entries never become rows: a range on two lines, two ranges on one line, a patched range Vedette does not read, a
// vulnerable and patched range that disagree.
func TestParseNodeLines_FailsClosed(t *testing.T) {
	t.Parallel()
	body := `{"1":{"cve":["CVE-2026-1001"],"vulnerable":">=4.0.0 <7.10.1","patched":"^7.10.1","affectedEnvironments":["all"]},
"2":{"cve":["CVE-2026-1002"],"vulnerable":"22.x || 22.x","patched":"^22.1.0","affectedEnvironments":["all"]},
"3":{"cve":["CVE-2026-1003"],"vulnerable":"22.x","patched":"~22.1.0","affectedEnvironments":["all"]},
"4":{"cve":["CVE-2026-1004"],"vulnerable":">=22.0.0 <22.3.0","patched":"^22.4.0","affectedEnvironments":["all"]},
"5":{"cve":["not-a-cve"],"vulnerable":"22.x","patched":"^22.4.0","affectedEnvironments":["all"]},
"6":{"cve":["CVE-2026-1006"],"vulnerable":"22.x","patched":"","affectedEnvironments":[]},
"7":"x"}`
	sts, st, err := ParseNodeLines([]byte(body), "node.js|node.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != 0 || st.Rejected != 6 {
		t.Fatalf("statements %+v, stats %+v", sts, st)
	}
	if _, _, err := ParseNodeLines([]byte(`[]`), "node.js|node.js"); err == nil {
		t.Error("an array was read")
	}
}

// Count test of the support source over endoflife.date's products/full cut to Node.js and .NET (27 Nov 2026, MIT): only the
// catalogue products line-sources.json names are kept, every line with its release day and end of security support; a line past its
// end with no day is not stored.
func TestParseEOL_Count(t *testing.T) {
	t.Parallel()
	cat, err := lineCat()
	if err != nil {
		t.Fatal(err)
	}
	sup, st, err := ParseEOL([]byte(testFile(t, "lines/eol-products-full.json")), cat.support[eolFeedID])
	if err != nil {
		t.Fatal(err)
	}
	// Node.js lists 26 lines; 1, 2 and 3 are past their end with no day
	if len(sup) != 23 || st.Rejected != 3 {
		t.Fatalf("lines %d, stats %+v", len(sup), st)
	}
	for _, l := range sup {
		if l.Product != "node.js|node.js" {
			t.Fatalf("a product line-sources.json does not name: %+v", l)
		}
		if l.Line == "22" && (l.Released != "2024-04-24" || l.AssessedUntil != "2027-04-30" || l.EOL != "2027-04-30" || l.Last != "2026-11-11") {
			t.Errorf("Node.js 22 = %+v", l)
		}
		if l.Line == "26" && l.AssessedUntil != "2029-04-30" {
			t.Errorf("Node.js 26 = %+v", l)
		}
	}
}

// A pull of the two sources stores the line statements of the catalogue's CVEs only (INV-34) and the line support; LineData reads
// them for findings with the source's convention, and nothing of a source switched off. A second pull of the same index changes
// nothing (no CVE named for findings, the day stated kept).
func TestLineSourcesPull(t *testing.T) {
	e, o := pullEnv(t)
	e.only(nodeLineFeedID, eolFeedID)
	e.setURL(nodeLineFeedID, o.url("/node/index.json"))
	e.setURL(eolFeedID, o.url("/eol/products/full"))
	o.body("/node/index.json", `"n1"`, testFile(t, "lines/node-index.json"))
	o.body("/eol/products/full", `"e1"`, testFile(t, "lines/eol-products-full.json"))
	write(t, e.db, func(tx *sql.Tx) error {
		for _, c := range []string{"CVE-2026-105481", "CVE-2026-105483", "CVE-2026-48936"} {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, nvd_status, updated_at) VALUES (?, '2026-10-14T00:00:00.000Z', 'Analyzed', '2026-11-01T00:00:00.000Z')`, c); err != nil {
				return err
			}
		}
		return nil
	})
	for _, id := range []string{nodeLineFeedID, eolFeedID} {
		if err := e.svc.Fetch(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		if f := e.feed(id); f.Status != "ok" {
			t.Fatalf("%s: %+v", id, f)
		}
	}
	if n := rowsOf(t, e.db, "feeds_line_cve"); n != 3 {
		t.Fatalf("covers %d, want the 3 catalogue CVEs", n)
	}
	st := NewStore(e.db)
	rows, covers, sup, err := st.LineData(t.Context(), []string{"CVE-2026-105483", "CVE-2026-48936"}, e.clock())
	if err != nil {
		t.Fatal(err)
	}
	if len(covers) != 2 || covers[0].Absent != AbsentUnaffectedIfSupported || covers[0].Stale || covers[0].Product != "node.js|node.js" {
		t.Errorf("covers %+v", covers)
	}
	if len(rows) != 3 || len(sup) != 23 {
		t.Errorf("rows %+v, support %d", rows, len(sup))
	}
	if got, err := st.LineCVEs(t.Context(), LineProducts()); err != nil || !slices.Equal(got, []string{"CVE-2026-105481", "CVE-2026-105483", "CVE-2026-48936"}) {
		t.Errorf("line CVEs %v %v", got, err)
	}
	var before string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT group_concat(stated_at) FROM feeds_line_cve`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	e.setNow(e.clock().Add(25 * time.Hour))
	write(t, e.db, func(tx *sql.Tx) error {
		changed, err := applyLines(t.Context(), tx, e.clock(), nodeLineFeedID, mustNode(t))
		if len(changed) != 0 {
			t.Errorf("an unchanged index changed %v", changed)
		}
		return err
	})
	var after string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT group_concat(stated_at) FROM feeds_line_cve`).Scan(&after); err != nil || after != before {
		t.Errorf("stated days %q, then %q", before, after)
	}
	// stale after its interval and a day: covers say so; switched off: nothing is read
	_, covers, _, _ = st.LineData(t.Context(), []string{"CVE-2026-105483"}, e.clock().Add(50*time.Hour))
	if len(covers) != 1 || !covers[0].Stale {
		t.Errorf("stale covers %+v", covers)
	}
	if c, b := e.put(nodeLineFeedID, `{"enabled":false}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if rows, covers, _, _ := st.LineData(t.Context(), []string{"CVE-2026-105483"}, e.clock()); len(rows)+len(covers) != 0 {
		t.Errorf("a source switched off still says %+v %+v", rows, covers)
	}
	if note := e.shown(eolFeedID).Error; note == nil || !strings.Contains(*note, "23 release lines") {
		t.Errorf("support note %v", note)
	}
}

func mustNode(t *testing.T) []lineStatement {
	t.Helper()
	sts, _, err := ParseNodeLines([]byte(testFile(t, "lines/node-index.json")), "node.js|node.js")
	if err != nil {
		t.Fatal(err)
	}
	return sts
}

// line-sources.json reads: each source a built-in feed with a known convention and catalogue products.
func TestLineSources_Data(t *testing.T) {
	t.Parallel()
	cat, err := lineCat()
	if err != nil {
		t.Fatal(err)
	}
	if s := cat.sources[nodeLineFeedID]; s.Absent != AbsentUnaffectedIfSupported || !slices.Equal(cat.keys[nodeLineFeedID], []string{"node.js|node.js"}) {
		t.Errorf("node source %+v %v", s, cat.keys)
	}
	for _, bad := range []string{`{"sources":[{"source":"nope","products":["nodejs"],"listed":"semver_range","absent":"unknown"}]}`,
		`{"sources":[{"source":"nodejs-security-wg","products":["nodejs"],"listed":"semver_range","absent":"maybe"}]}`,
		`{"sources":[{"source":"nodejs-security-wg","products":["no-such-product"],"listed":"semver_range","absent":"unknown"}]}`,
		`{"sources":[],"support":[{"source":"endoflife-date","products":{"no-such-product":"x"}}]}`,
		`{"sources":[],"extra":1}`} {
		if _, err := parseLineSources([]byte(bad)); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
}

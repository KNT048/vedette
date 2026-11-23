package feeds

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The catalogue keeps the time NVD published each CVE from the same answer as the ranges; a record whose dates are not NVD timestamps
// is rejected whole.
func TestParseNVD_Published(t *testing.T) {
	t.Parallel()
	d, err := ParseNVD([]byte(testFile(t, "nvd-kev-page.json")))
	if err != nil {
		t.Fatal(err)
	}
	recs := byCVE(d)
	if recs["CVE-2016-4655"].Published.Format(time.DateOnly) != "2016-08-25" || recs["CVE-2024-21762"].Published.Format(time.DateOnly) != "2024-02-09" {
		t.Fatalf("published = %+v", recs)
	}
	d, err = ParseNVD([]byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2020-0001","published":"x'; DROP TABLE","lastModified":"2020-01-01T00:00:00.000","vulnStatus":"Analyzed","configurations":[]}},{"cve":{"id":"CVE-2020-0002","configurations":[]}}]}`))
	if err != nil || len(d.Records) != 0 || d.Rejected != 2 {
		t.Fatalf("records %+v, rejected %d, %v", d.Records, d.Rejected, err)
	}
}

// A pull stores every CVE's day; the next day only an update is asked for.
func TestNVDPull_Published(t *testing.T) {
	t.Parallel()
	e, n := nvdEnv(t)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	pub, err := e.svc.st.KevPublished(t.Context())
	if err != nil || len(pub) != 250 || !pub["CVE-2024-0007"].Equal(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("published %d %v", len(pub), err)
	}
	full := n.count(0)
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if n.count(0) != full+1 || n.count(200) != 2 { // the script answers an update with the whole list: page by page again
		t.Fatalf("pages: page 0 asked %d times, page 200 %d", n.count(0), n.count(200))
	}
	if pub, _ := e.svc.st.KevPublished(t.Context()); len(pub) != 250 {
		t.Fatalf("published after the update: %d", len(pub))
	}
}

// The tier feeds' state, and one CVE from them: on by default and loading until filled, off when an admin turns
// them off, then likely (EPSS ≥ 0.1, published in the last 12 months), recent, or no tier when older; 404 not_in_data when neither
// holds it.
func TestTierStatusAndTierCVE(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	st, err := e.svc.st.TierStatus(t.Context(), now)
	if err != nil || st.EPSS != TierLoading || st.Recent != TierLoading {
		t.Fatalf("seeded on, empty: %+v %v", st, err)
	}
	for _, id := range []string{epssAllFeedID, recentFeedID} {
		if c, b := e.put(id, `{"enabled":false}`); c != 200 {
			t.Fatalf("%s: %d %v", id, c, b)
		}
	}
	if st, _ = e.svc.st.TierStatus(t.Context(), now); st.EPSS != TierOff || st.Recent != TierOff {
		t.Fatalf("turned off: %+v", st)
	}
	if c, b := e.get("/feeds/cve/CVE-2026-0001/tier"); c != http.StatusNotFound || code(b) != "not_in_data" {
		t.Fatalf("feeds off: %d %v", c, b)
	}
	for _, id := range []string{epssAllFeedID, recentFeedID} {
		if c, b := e.put(id, `{"enabled":true}`); c != 200 {
			t.Fatalf("%s: %d %v", id, c, b)
		}
	}
	seedTierData(t, e, now)
	if st, _ = e.svc.st.TierStatus(t.Context(), now); st.EPSS != TierReady || st.Recent != TierReady || st.EPSSDate.IsZero() || st.RecentSince.IsZero() {
		t.Fatalf("filled: %+v", st)
	}
	c, b := e.get("/feeds/cve/CVE-2026-0001/tier")
	if c != 200 || b["tier"] != "likely" || b["severity"] != "high" || b["ranges"] != true || b["published"] == nil {
		t.Fatalf("likely: %d %v", c, b)
	}
	if p, _ := b["products"].([]any); len(p) != 1 || p[0] != "f5 nginx" {
		t.Fatalf("products %v", b["products"])
	}
	if c, b = e.get("/feeds/cve/CVE-2026-0002/tier"); c != 200 || b["tier"] != "recent" || b["severity"] != nil || b["ranges"] != false {
		t.Fatalf("recent: %d %v", c, b)
	}
	if c, b = e.get("/feeds/cve/CVE-2020-0003/tier"); c != 200 || b["tier"] != nil || b["published"] != nil || b["epss"] != 0.5 { // EPSS only: older, no tier
		t.Fatalf("old: %d %v", c, b)
	}
	// A CVE outside the window still shows the day the catalogue has (NVD's or the CVE record's), with no tier
	write(t, e.db, func(tx *sql.Tx) error {
		return applyPublished(t.Context(), tx, map[string]string{"CVE-2020-0003": "2020-03-10"})
	})
	if c, b = e.get("/feeds/cve/CVE-2020-0003/tier"); c != 200 || b["tier"] != nil || b["published"] == nil || !strings.HasPrefix(b["published"].(string), "2020-03-10") {
		t.Fatalf("published from the catalogue: %d %v", c, b)
	}
	if c, b = e.get("/feeds/cve/CVE-2026-9999/tier"); c != http.StatusNotFound || code(b) != "not_in_data" {
		t.Fatalf("absent: %d %v", c, b)
	}
}

// Only existence matters: scores alone make EPSS ready while nvd-recent stays loading when the catalogue holds no NVD record inside
// the window (an old record, or a record NVD never filled, does not count).
func TestTierStatusExistence(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	ts := func(d time.Time) string { return d.UTC().Format("2006-01-02T15:04:05.000Z") }
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_epss (cve, epss, percentile, gen) VALUES ('CVE-2020-0003', 0.5, 0.99, 1)`, nil},
			{`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES ('CVE-2020-0003', ?, ?, 'Analyzed', ?, ?)`,
				[]any{ts(now.AddDate(-3, 0, 0)), ts(now), ts(now), ts(now)}},
			{`INSERT INTO feeds_cve (cve, published, modified, updated_at) VALUES ('CVE-2026-0009', ?, ?, ?)`, []any{ts(now.AddDate(0, -1, 0)), ts(now), ts(now)}},
			{`INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total) VALUES ('recent', 'https://x.test/nvd', 'done', ?, ?, ?, 0, 0)`, []any{ts(now), ts(now), ts(now)}},
			{`UPDATE feeds_source SET last_success = ?, status = 'ok' WHERE id = ?`, []any{ts(now), epssAllFeedID}},
		} {
			if _, err := tx.ExecContext(t.Context(), q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.st.TierStatus(t.Context(), now)
	if err != nil || st.EPSS != TierReady || st.Recent != TierLoading {
		t.Fatalf("scores, no NVD record in the window: %+v %v", st, err)
	}
}

// seedTierData writes a small filled state of epss-all and nvd-recent: CVE-2026-0001 (likely, nginx < 1.28.1), CVE-2026-0002 (recent, no
// entry), CVE-2020-0003 (EPSS only).
func seedTierData(t *testing.T, e *env, now time.Time) {
	t.Helper()
	ts := func(d time.Time) string { return d.UTC().Format("2006-01-02T15:04:05.000Z") }
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_epss (cve, epss, percentile, gen) VALUES ('CVE-2026-0001', 0.34, 0.97, 1), ('CVE-2026-0002', 0.02, 0.6, 1), ('CVE-2020-0003', 0.5, 0.99, 1)`, nil},
			{`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES ('CVE-2026-0001', ?, ?, 'Analyzed', ?, ?), ('CVE-2026-0002', ?, ?, 'Awaiting Analysis', ?, ?)`,
				[]any{ts(now.AddDate(0, -2, 0)), ts(now.AddDate(0, -1, 0)), ts(now), ts(now), ts(now.AddDate(0, -3, 0)), ts(now.AddDate(0, -3, 0)), ts(now), ts(now)}},
			{`INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES ('CVE-2026-0001', 'nvd', '3.1', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')`, nil},
			{`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl) VALUES ('CVE-2026-0001', 'nvd', 'a', 'f5', 'nginx', 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', '', '', '', '1.28.1')`, nil},
			{`INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total) VALUES ('recent', 'https://x.test/nvd', 'done', ?, ?, ?, 0, 0)`, []any{ts(now), ts(now), ts(now)}},
			{`UPDATE feeds_source SET last_success = ?, status = 'ok' WHERE id = ?`, []any{ts(now), epssAllFeedID}},
		} {
			if _, err := tx.ExecContext(t.Context(), q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

package feeds

import (
	"database/sql"
	"net/http"
	"testing"
	"time"
)

// D-615: nvd-kev keeps the day NVD published each CVE from the same answer as the ranges; a value that is not a date is dropped.
func TestParseNVD_Published(t *testing.T) {
	t.Parallel()
	d, err := ParseNVD([]byte(testFile(t, "nvd-kev-page.json")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Published["CVE-2016-4655"] != "2016-08-25" || d.Published["CVE-2024-21762"] != "2024-02-09" {
		t.Fatalf("published = %+v", d.Published)
	}
	d, err = ParseNVD([]byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2020-0001","published":"x'; DROP TABLE","configurations":[]}},{"cve":{"id":"CVE-2020-0002","configurations":[]}}]}`))
	if err != nil || len(d.Published) != 0 || d.Accepted != 2 {
		t.Fatalf("published %+v, accepted %d, %v", d.Published, d.Accepted, err)
	}
}

// D-615: a pull stores every day; a box from before the table (rows of ranges, no day) makes its next pull a full one, once.
func TestNVDPull_PublishedAndOneFullPullForOldBoxes(t *testing.T) {
	t.Parallel()
	e, n := nvdEnv(t)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	pub, err := e.svc.st.KevPublished(t.Context())
	if err != nil || len(pub) != 250 || !pub["CVE-2024-0007"].Equal(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("published %d %v", len(pub), err)
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_published`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	full := n.count(0)
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if n.count(0) != full+1 || n.count(200) != 2 { // the whole list again, page by page
		t.Fatalf("not a full pull: page 0 asked %d times, page 200 %d", n.count(0), n.count(200))
	}
	if pub, _ := e.svc.st.KevPublished(t.Context()); len(pub) != 250 {
		t.Fatalf("published after the full pull: %d", len(pub))
	}
}

// D-613, D-616: the tier feeds' state, and one CVE from them: off until turned on, loading until filled, then likely
// (EPSS ≥ 0.1, published in the last 12 months), recent, or no tier when older; 404 not_in_data when neither holds it.
func TestTierStatusAndTierCVE(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	st, err := e.svc.st.TierStatus(t.Context(), now)
	if err != nil || st.EPSS != TierOff || st.Recent != TierOff {
		t.Fatalf("seeded off: %+v %v", st, err)
	}
	if c, b := e.get("/feeds/cve/CVE-2026-0001/tier"); c != http.StatusNotFound || code(b) != "not_in_data" {
		t.Fatalf("feeds off: %d %v", c, b)
	}
	for _, id := range []string{epssAllFeedID, recentFeedID} {
		if c, b := e.put(id, `{"enabled":true}`); c != 200 {
			t.Fatalf("%s: %d %v", id, c, b)
		}
	}
	if st, _ = e.svc.st.TierStatus(t.Context(), now); st.EPSS != TierLoading || st.Recent != TierLoading {
		t.Fatalf("on, empty: %+v", st)
	}
	ts := func(d time.Time) string { return d.UTC().Format("2006-01-02T15:04:05.000Z") }
	err = e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_epss (cve, epss, percentile, gen) VALUES ('CVE-2026-0001', 0.34, 0.97, 1), ('CVE-2026-0002', 0.02, 0.6, 1), ('CVE-2020-0003', 0.5, 0.99, 1)`, nil},
			{`INSERT INTO feeds_recent_cve (cve, published, last_modified, status, severity, score) VALUES ('CVE-2026-0001', ?, ?, 'Analyzed', 'HIGH', 7.5), ('CVE-2026-0002', ?, ?, 'Awaiting Analysis', NULL, NULL)`,
				[]any{ts(now.AddDate(0, -2, 0)), ts(now.AddDate(0, -1, 0)), ts(now.AddDate(0, -3, 0)), ts(now.AddDate(0, -3, 0))}},
			{`INSERT INTO feeds_recent_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES ('CVE-2026-0001', 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', '', '', '', '1.28.1')`, nil},
			{`INSERT INTO feeds_recent_cursor (id, url, mode, win_from, win_to, until, next_index, total) VALUES (1, 'https://x.test/nvd', 'done', ?, ?, ?, 0, 0)`, []any{ts(now), ts(now), ts(now)}},
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
	if c, b = e.get("/feeds/cve/CVE-2026-9999/tier"); c != http.StatusNotFound || code(b) != "not_in_data" {
		t.Fatalf("absent: %d %v", c, b)
	}
}

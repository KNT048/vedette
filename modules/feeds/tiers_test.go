package feeds

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
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

// D-613, D-616, D-617: the tier feeds' state, and one CVE from them: on by default and loading until filled, off when an admin turns
// them off, then likely (EPSS ≥ 0.1, published in the last 12 months), recent, or no tier when older; 404 not_in_data when neither
// holds it.
func TestTierStatusAndTierCVE(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	st, err := e.svc.st.TierStatus(t.Context(), now)
	if err != nil || st.EPSS != TierLoading || st.Recent != TierLoading {
		t.Fatalf("seeded on (D-617), empty: %+v %v", st, err)
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
	// N100 n54: a CVE nvd-recent does not hold still shows the day feeds_published has (nvd-kev or CVE.org), with no tier
	write(t, e.db, func(tx *sql.Tx) error { return applyPublished(t.Context(), tx, map[string]string{"CVE-2020-0003": "2020-03-10"}) })
	if c, b = e.get("/feeds/cve/CVE-2020-0003/tier"); c != 200 || b["tier"] != nil || b["published"] == nil || !strings.HasPrefix(b["published"].(string), "2020-03-10") {
		t.Fatalf("published from feeds_published: %d %v", c, b)
	}
	if c, b = e.get("/feeds/cve/CVE-2026-9999/tier"); c != http.StatusNotFound || code(b) != "not_in_data" {
		t.Fatalf("absent: %d %v", c, b)
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
}

// D-617: the plan reads only the NVD entries of the products the devices run, with the CVE's day, severity and EPSS; nothing while
// nvd-recent is not ready, no EPSS (and no tier 2) while epss-all is not. The match stamp moves when either tier feed pulls.
func TestTierRecords(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	nginx := func(cpe string) bool { return strings.Contains(cpe, ":f5:nginx:") }
	if got, err := e.svc.st.TierRecords(t.Context(), now, nginx); err != nil || got != nil {
		t.Fatalf("not ready: %+v %v", got, err)
	}
	seedTierData(t, e, now)
	got, err := e.svc.st.TierRecords(t.Context(), now, nginx)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	r := got[0]
	if r.CVE != "CVE-2026-0001" || r.Tier != "likely" || r.Severity != "HIGH" || r.Score == nil || *r.Score != 7.5 || r.EPSS == nil || *r.EPSS != 0.34 ||
		len(r.Affected) != 1 || r.Affected[0].EndExcl != "1.28.1" || !r.Published.Equal(now.AddDate(0, -2, 0).UTC().Truncate(time.Millisecond)) {
		t.Fatalf("record %+v", r)
	}
	if got, _ = e.svc.st.TierRecords(t.Context(), now, func(string) bool { return false }); len(got) != 0 {
		t.Fatalf("nothing kept: %+v", got)
	}
	if got, _ = e.svc.st.TierRecords(t.Context(), now.AddDate(0, 11, 0), nginx); len(got) != 0 {
		t.Fatalf("published more than 12 months before now: %+v", got)
	}
	before, err := e.svc.st.MatchStamp(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if c, b := e.put(epssAllFeedID, `{"enabled":false}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if got, _ = e.svc.st.TierRecords(t.Context(), now, nginx); len(got) != 1 || got[0].EPSS != nil || got[0].Tier != "recent" {
		t.Fatalf("epss-all off: %+v", got)
	}
	if after, _ := e.svc.st.MatchStamp(t.Context()); after == before {
		t.Fatal("the match stamp did not move with epss-all")
	}
	before, _ = e.svc.st.MatchStamp(t.Context())
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET last_fetch = ? WHERE id = ?`, "2026-11-10T00:00:00.000Z", recentFeedID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if after, _ := e.svc.st.MatchStamp(t.Context()); after == before {
		t.Fatal("the match stamp did not move with nvd-recent")
	}
}

// Measured for the PR (D-617): the tier read of one plan pass on data sized like the N100 (104,448 CVEs of nvd-recent, two NVD entries
// each over 5,000 or 50,000 products, every CVE with an EPSS score) when the 21 devices run 840 of those products. Run:
// go test ./modules/feeds -run '^$' -bench TierRecords -benchmem
func BenchmarkTierRecords(b *testing.B) {
	for _, products := range []int{5_000, 50_000} {
		b.Run(fmt.Sprintf("products_%d", products), func(b *testing.B) { benchTierRecords(b, products) })
	}
}

func benchTierRecords(b *testing.B, products int) {
	db := storetest.Migrated(b, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "feeds", FS: Migrations})
	s := &Store{db: db}
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	if err := s.SeedBuiltins(b.Context(), now); err != nil {
		b.Fatal(err)
	}
	const cves = 104_448
	ts := func(d time.Time) string { return d.UTC().Format("2006-01-02T15:04:05.000Z") }
	err := db.Write(b.Context(), func(tx *sql.Tx) error {
		for i := range cves {
			cve := fmt.Sprintf("CVE-2026-%06d", i)
			p := i % products
			pub := ts(now.AddDate(0, 0, -(i % 360)))
			if _, err := tx.ExecContext(b.Context(), `INSERT INTO feeds_recent_cve (cve, published, last_modified, status, severity, score) VALUES (?, ?, ?, 'Analyzed', 'HIGH', 7.5)`, cve, pub, pub); err != nil {
				return err
			}
			for _, q := range []int{p, p + 1} {
				if _, err := tx.ExecContext(b.Context(), `INSERT INTO feeds_recent_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, ?, '', '', '', '2.0')`,
					cve, fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", q, q)); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(b.Context(), `INSERT INTO feeds_epss (cve, epss, percentile, gen) VALUES (?, ?, 0.5, 1)`, cve, float64(i%100)/100); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(b.Context(), `INSERT INTO feeds_recent_cursor (id, url, mode, win_from, win_to, until, next_index, total) VALUES (1, 'https://x.test/nvd', 'done', ?, ?, ?, 0, 0)`, ts(now), ts(now), ts(now)); err != nil {
			return err
		}
		_, err := tx.ExecContext(b.Context(), `UPDATE feeds_source SET enabled = 1, last_success = ?, status = 'ok' WHERE id IN ('epss-all', 'nvd-recent')`, ts(now))
		return err
	})
	if err != nil {
		b.Fatal(err)
	}
	keep := func(cpe string) bool { // 840 products: vendor0..vendor839
		var n int
		_, err := fmt.Sscanf(cpe, "cpe:2.3:a:vendor%d:", &n)
		return err == nil && n < 840
	}
	b.ReportAllocs()
	for b.Loop() {
		got, err := s.TierRecords(b.Context(), now, keep)
		if err != nil || len(got) == 0 {
			b.Fatal(len(got), err)
		}
	}
}

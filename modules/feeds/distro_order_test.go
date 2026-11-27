package feeds

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
)

// A new box: the first distribution pull comes before the catalogue's last 12 months are loaded, so it keeps the exploited-list CVEs
// alone. The Feeds page calls that state an error as soon as the window and the devices' packages are there, and the next check (not a
// day later, not after the 6-hour floor) pulls the whole file again, keeping the rows of the window's CVEs for the devices' packages in
// the devices' release only; findings' match pass, their one reader, runs at once (Catalogue).
func TestDistroPullRunsAgainWhenTheWindowAppears(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(debianTrackerFeedID, recentFeedID, epssAllFeedID)
	e.mirror(debianTrackerFeedID, o.url("/tracker.json"))
	o.body("/tracker.json", `"v1"`, debianTierJSON)
	var got []RangesUpdatedEvent
	e.svc.Events = publishFunc(func(ev events.Event) {
		if r, ok := ev.Data.(RangesUpdatedEvent); ok {
			got = append(got, r)
		}
	})
	e.loadKEV()
	e.svc.Inventory = &distroInv{got: map[string]map[string]bool{DistroDebian: {"sudo": true, "openssl": true}},
		rel: map[string]map[string]bool{DistroDebian: {"12": true}}}
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	if n := rowsOf(t, e.db, "feeds_distro_fix"); n != 2 || e.svc.distroBehind(t.Context(), e.feed(debianTrackerFeedID)) {
		t.Fatalf("before the window: %d rows (want the CISA list's 2), behind %v", n, e.svc.distroBehind(t.Context(), e.feed(debianTrackerFeedID)))
	}
	if f := e.svc.live(t.Context(), e.feed(debianTrackerFeedID)); f.Status != "ok" {
		t.Fatalf("no window yet, nothing missing: %+v", f)
	}
	// the window loads a few minutes later; nvd-recent and epss-all are not due, so the job pulls only the distribution feed
	e.setNow(e.clock().Add(5 * time.Minute))
	now := e.clock()
	seedTierData(t, e, now)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_nvd_cursor SET url = (SELECT url FROM feeds_source WHERE id = ?)`, recentFeedID)
		if err == nil {
			_, err = tx.ExecContext(t.Context(), `UPDATE feeds_source SET last_success = ?, status = 'ok' WHERE id = ?`, store.FormatTS(now), recentFeedID)
		}
		return err
	})
	f := e.svc.live(t.Context(), e.feed(debianTrackerFeedID))
	if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, distroPartialNote) {
		t.Fatalf("partly loaded: %+v", f)
	}
	if !e.svc.distroBehind(t.Context(), e.feed(debianTrackerFeedID)) {
		t.Fatal("not behind once the window is there")
	}
	got = nil
	if err := e.runPull(t.Context()); err != nil || o.count("/tracker.json") != 2 {
		t.Fatalf("the next check: %v, %d requests", err, o.count("/tracker.json"))
	}
	hits := o.all()
	if last := hits[len(hits)-1]; last.header.Get("If-None-Match") != "" {
		t.Fatalf("a conditional pull would keep the rows without the window: %v", last.header)
	}
	// the CISA list's 2 rows, and of the window's CVEs the packages the devices run in Debian 12 only: sudo's fix of CVE-2026-0001 and
	// openssl's of CVE-2026-0002 (not trixie's "not affected", not curl, not glibc)
	var tier []string
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve || '/' || release || '/' || package FROM feeds_distro_fix WHERE cve NOT IN ('CVE-2026-10001') ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		tier = append(tier, s)
	}
	_ = rows.Close()
	if !slices.Equal(tier, []string{"CVE-2026-0001/12/sudo", "CVE-2026-0002/12/openssl"}) {
		t.Fatalf("tier rows %v", tier)
	}
	if len(got) != 1 || !got[0].Catalogue || len(got[0].CVEs) != 0 {
		t.Fatalf("events %+v, want one that runs findings' match pass", got)
	}
	if kept, _ := e.svc.st.distroKept(t.Context(), debianTrackerFeedID); !slices.Equal(kept, []string{"@12", "openssl", "sudo"}) {
		t.Fatalf("kept %v", kept)
	}
	if f := e.svc.live(t.Context(), e.feed(debianTrackerFeedID)); f.Status != "ok" || e.svc.distroBehind(t.Context(), e.feed(debianTrackerFeedID)) {
		t.Fatalf("after the pull: %+v", f)
	}
	// a device moves to Debian 13: its release's rows are needed, after the 6-hour floor
	e.svc.Inventory.(*distroInv).rel[DistroDebian]["13"] = true
	if e.svc.distroBehind(t.Context(), e.feed(debianTrackerFeedID)) {
		t.Fatal("a new release within 6 hours of the last pull")
	}
	e.setNow(e.clock().Add(7 * time.Hour))
	if !e.svc.distroBehind(t.Context(), e.feed(debianTrackerFeedID)) {
		t.Fatal("not behind after a new release")
	}
}

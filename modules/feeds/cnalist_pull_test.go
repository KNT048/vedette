package feeds

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The CNA list is a built-in feed: a good pull replaces the stored list, emits RangesUpdatedEvent (findings matches every CVE again) and
// changes how every reader of the stored ranges weighs a record's "unaffected" for the versions it does not list. Only the vendor's
// own CNA's word counts: here "qwz" of "Quasar Widgets Corp", whose short name alone does not say so. A researcher CNA ("labx") and a
// CNA whose scope takes other CNAs' reports ("kitecna", even with the vendor's organization name) stay third parties through every
// reader: the ranges, the catalogue's completeness, the exploited list's record view and the record stamps. An unchanged list emits
// nothing; a list cut to less than half is refused and the stored one kept; a list whose feed has had no good pull for 30 days while
// the box pulled other feeds is not read.
func TestCNAList_PullDecidesWhoseUnaffectedCounts(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(cnaFeedID)
	e.setURL(cnaFeedID, o.url("/cnas.json"))
	full := string(cnaListOf(t,
		[4]string{"qwz", "Quasar Widgets Corp", "Quasar Widgets products only.", "Vendor"},
		[4]string{"labx", "Labx Security Research", "Vulnerabilities discovered by Labx that are not in another CNA's scope.", "Researcher"},
		[4]string{"kitecna", "Kite Corporation", "Kite products and vulnerabilities discovered by Kite that are not in another CNA's scope.", "Vendor,Researcher"},
		[4]string{"other", "Other Org", "Other products.", "Vendor"},
	))
	o.body("/cnas.json", `"c1"`, full)
	entry := func(vendor string) string {
		return `{"vendor":"` + vendor + `","product":"Beacon","defaultStatus":"unaffected","versions":[{"version":"5.0.0","lessThan":"5.0.3","status":"affected","versionType":"semver"}]}`
	}
	recs := map[string][2]string{ // cve: assigner, the entry's vendor
		"CVE-2026-0301": {"qwz", "Quasar Widgets"},
		"CVE-2026-0302": {"labx", "Quasar Widgets"},
		"CVE-2026-0303": {"kitecna", "Kite Corporation"},
	}
	now := e.clock()
	write(t, e.db, func(tx *sql.Tx) error {
		var parsed []CVERecord
		var nvd []NVDRecord
		for cve, r := range recs {
			raw := strings.Replace(string(recordJSON(cve, "2026-11-01", entry(r[1]))), `"assignerShortName":"acme"`, `"assignerShortName":"`+r[0]+`"`, 1)
			rec, err := ParseCVERecord([]byte(raw), cve)
			if err != nil {
				return err
			}
			parsed = append(parsed, rec)
			nvd = append(nvd, NVDRecord{CVE: cve, Published: now.AddDate(0, 0, -5), LastModified: now, Status: "Received", Affected: []AffectedRow{}})
		}
		if err := storeRecords(t.Context(), tx, nvd, now); err != nil {
			return err
		}
		for cve, r := range recs {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, updated_at)
VALUES (?, 'cisa', 'cisa-kev', ?, 'Beacon', 'x', '2026-11-01', '2026-11-01T00:00:00.000Z')`, cve, r[1]); err != nil {
				return err
			}
		}
		k, err := recordKeepOf(t.Context(), tx, now, nil)
		if err != nil {
			return err
		}
		w, err := writeRecords(t.Context(), tx, parsed, k, now)
		if err == nil && w.Stored != 3 {
			err = fmt.Errorf("stored %d records", w.Stored)
		}
		return err
	})
	st := NewStore(e.db)
	cves := []string{"CVE-2026-0301", "CVE-2026-0302", "CVE-2026-0303"}
	type view struct {
		def       string
		vendorCNA bool
		complete  bool   // Catalogue: the record's rows make a complete list
		kevSource string // RangesFromCVEOrg: cve.org (complete) or cve.org-partial
		vendorRow bool   // KevAffected: the record's row is the vendor's own list
	}
	read := func() (map[string]view, map[string]string) {
		t.Helper()
		out := map[string]view{}
		rows, err := st.RangesOf(t.Context(), cves)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			out[r.CVE] = view{def: r.DefaultStatus, vendorCNA: r.VendorCNA}
		}
		cat, err := st.Catalogue(t.Context(), cves)
		if err != nil {
			t.Fatal(err)
		}
		src, err := st.RangesFromCVEOrg(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		aff, err := st.KevAffected(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cves {
			v := out[c]
			v.complete, v.kevSource = cat[c].RangesComplete, src[c]
			v.vendorRow = len(aff[c]) > 0 && aff[c][0].VendorList && aff[c][0].VendorCNA
			out[c] = v
		}
		stamps, err := st.RecordStamps(t.Context(), cves)
		if err != nil {
			t.Fatal(err)
		}
		return out, stamps
	}
	third := view{def: DefaultUnknown, kevSource: rangesCVEOrgPartial}
	own := view{def: DefaultUnaffected, vendorCNA: true, complete: true, kevSource: rangesCVEOrg, vendorRow: true}
	check := func(when string, got map[string]view, want0301 view) {
		t.Helper()
		for _, c := range cves {
			want := third
			if c == "CVE-2026-0301" {
				want = want0301
			}
			if got[c] != want {
				t.Errorf("%s: %s read as %+v, want %+v", when, c, got[c], want)
			}
		}
	}
	before, stamps0 := read()
	check("without the list", before, third)

	events := len(e.pub.named(EventRangesUpdated)) // turning the other feeds off announced its own
	if err := e.svc.Fetch(t.Context(), cnaFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(cnaFeedID); f.Status != "ok" || f.Records == nil || *f.Records != 4 {
		t.Fatalf("feed %+v", f)
	}
	if n := len(e.pub.named(EventRangesUpdated)) - events; n != 1 {
		t.Fatalf("%d ranges events after the list arrived, want 1", n)
	}
	if ev, _ := e.pub.named(EventRangesUpdated)[events].(RangesUpdatedEvent); !ev.Catalogue {
		t.Errorf("event %+v does not ask findings to match every CVE again", ev)
	}
	after, stamps1 := read()
	check("with the list", after, own)
	if stamps1["CVE-2026-0301"] == stamps0["CVE-2026-0301"] || stamps1["CVE-2026-0302"] != stamps0["CVE-2026-0302"] || stamps1["CVE-2026-0303"] != stamps0["CVE-2026-0303"] {
		t.Errorf("stamps %v, then %v: only the record whose word now counts changes", stamps0, stamps1)
	}

	// a list whose feed a person turned off is not read
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 0 WHERE id = ?`, cnaFeedID)
		return err
	})
	off, _ := read()
	check("with the list's feed off", off, third)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 1 WHERE id = ?`, cnaFeedID)
		return err
	})

	// the same list again: nothing changes, nothing is announced
	e.setNow(e.clock().Add(8 * 24 * time.Hour))
	o.body("/cnas.json", `"c2"`, full)
	if err := e.svc.Fetch(t.Context(), cnaFeedID); err != nil {
		t.Fatal(err)
	}
	if n := len(e.pub.named(EventRangesUpdated)) - events; n != 1 {
		t.Errorf("an unchanged list emitted %d ranges events, want still 1", n)
	}
	// a list cut to less than half of the stored one is refused, the stored list stays
	o.body("/cnas.json", `"c3"`, string(cnaListOf(t, [4]string{"other", "Other Org", "Other products.", "Vendor"})))
	_ = e.svc.Fetch(t.Context(), cnaFeedID)
	if f := e.feed(cnaFeedID); f.Status != "error" || rowsOf(t, e.db, "feeds_cna") != 4 {
		t.Errorf("a cut list: feed %+v, %d CNAs stored", f, rowsOf(t, e.db, "feeds_cna"))
	}
	// stale: the list's last good pull is more than 30 days before the box's newest pull of any feed
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET last_fetch = strftime('%Y-%m-%dT%H:%M:%fZ', (SELECT last_success FROM feeds_source WHERE id = ?), '+31 days') WHERE id = 'cisa-kev'`, cnaFeedID)
		return err
	})
	stale, _ := read()
	check("with a stale list", stale, third)
}

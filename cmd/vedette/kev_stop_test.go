package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// listOrigin serves an exploited list (the CISA list at /kev.json, VulnCheck KEV at /vc) and the feeds a pull of it brings next (NVD,
// the CVE records) on loopback; e2eOffline sends e2eLoopbackName there. A follow-up request can stop the box: it cancels the context
// of the pull that asked and waits for the request to be dropped.
type listOrigin struct {
	srv  *httptest.Server
	mu   sync.Mutex
	kev  string // the CISA list
	vc   string // VulnCheck KEV's one page
	stop func() // non-nil: the next follow-up request stops the box
}

func newListOrigin(t *testing.T) *listOrigin {
	t.Helper()
	o := &listOrigin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		kev, vc, stop := o.kev, o.vc, o.stop
		list := r.URL.Path == "/kev.json" || r.URL.Path == "/vc"
		if !list {
			o.stop = nil
		}
		o.mu.Unlock()
		switch {
		case r.URL.Path == "/kev.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, kev)
		case r.URL.Path == "/vc":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, vc)
		case stop != nil:
			stop()
			<-r.Context().Done()
		default:
			http.Error(w, "not here", http.StatusNotFound)
		}
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *listOrigin) url(path string) string {
	_, port, _ := net.SplitHostPort(o.srv.Listener.Addr().String())
	return "http://" + e2eLoopbackName + ":" + port + path
}

// serve sets what the list of feed says: entries are "CVE vendor/product", all added today.
func (o *listOrigin) serve(feed string, entries ...string) {
	day := time.Now().UTC().Format(time.DateOnly)
	var vs []string
	for _, e := range entries {
		cve, vp, _ := strings.Cut(e, " ")
		vendor, product, _ := strings.Cut(vp, "/")
		name := vendor + " " + product + " Out-of-Bounds Write Vulnerability"
		if feed == "cisa-kev" {
			vs = append(vs, fmt.Sprintf(`{"cveID":%q,"vendorProject":%q,"product":%q,"vulnerabilityName":%q,"dateAdded":%q,"shortDescription":"An out-of-bounds write lets a remote attacker run code.","requiredAction":"Apply updates per vendor instructions.","dueDate":"","knownRansomwareCampaignUse":"Unknown","notes":"","cwes":[]}`,
				cve, vendor, product, name, day))
		} else {
			vs = append(vs, fmt.Sprintf(`{"vendorProject":%q,"product":%q,"shortDescription":"An out-of-bounds write lets a remote attacker run code.","vulnerabilityName":%q,"required_action":"Apply updates.","knownRansomwareCampaignUse":"Unknown","cve":[%q],"vulncheck_reported_exploitation":[{"url":"https://example.org/%s","date_added":%q}],"date_added":%q}`,
				vendor, product, name, cve, cve, day+"T00:00:00.000Z", day+"T00:00:00.000Z"))
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if feed == "cisa-kev" {
		o.kev = fmt.Sprintf(`{"title":"t","catalogVersion":"2026.11.20","dateReleased":"2026-11-20T00:00:00.000Z","count":%d,"vulnerabilities":[%s]}`, len(vs), strings.Join(vs, ","))
		return
	}
	// the one page of a cursor read: total_documents and no next_cursor
	o.vc = fmt.Sprintf(`{"_benchmark":0.01,"_meta":{"timestamp":"2026-11-20T00:00:00Z","index":"vulncheck-kev","limit":100,"total_documents":%d,"sort":"_id","order":"desc"},"data":[%s]}`, len(vs), strings.Join(vs, ","))
}

// noticesOf counts the queued notices that name cve.
func (s *stack) noticesOf(cve string) int {
	s.t.Helper()
	n := 0
	for _, x := range s.queuedNotices() {
		if slices.Contains(x.CVEs, cve) {
			n++
		}
	}
	return n
}

// A new entry of an exploited list is announced exactly once, end to end, even when the box stops while the pull of the list waits
// for the feeds it brings next (NVD for the CISA list, the CVE records for VulnCheck KEV): the list's rows are committed by then, the
// events are not, and the entry is no longer new to any later pull. After the restart (the same database file, every service built
// again, the jobs a start runs) the device's alert is queued once and the rescan of the entry's template is queued once; a further
// round of the same jobs adds nothing. When the pull ended normally, the restart adds nothing to what its events did.
func TestWiringNewKEVEntryIsAnnouncedOnceAcrossAStopDuringTheFollowUpPulls(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		feed, path, cve string
		follow          string // the feed the list's pull brings next, where the box stops
		stops           bool   // false: the pull ends normally and the events reach every handler before the restart
	}{
		{feed: "cisa-kev", path: "/kev.json", cve: "CVE-2026-0102", follow: "nvd-kev", stops: true},
		{feed: "vulncheck-kev", path: "/vc", cve: "CVE-2026-0202", follow: "cve-org", stops: true},
		{feed: "cisa-kev", path: "/kev.json", cve: "CVE-2026-0103", follow: "nvd-kev"},
		{feed: "vulncheck-kev", path: "/vc", cve: "CVE-2026-0203", follow: "cve-org"},
	} {
		t.Run(fmt.Sprintf("%s/stops=%v", tc.feed, tc.stops), func(t *testing.T) {
			t.Parallel()
			log := slog.New(slog.DiscardHandler)
			path := filepath.Join(t.TempDir(), "v.db")
			db, err := openMigrated(t.Context(), path, log)
			if err != nil {
				t.Fatal(err)
			}
			s := stackOn(t, db, log, nil)
			o := newListOrigin(t)
			s.setModule("scan", true)
			if tc.feed == "vulncheck-kev" {
				if c, b := s.do("PUT", "/feeds/sources/vulncheck-kev", "admin", `{"api_key":"vckey-ABCDEF123456"}`); c != 200 {
					t.Fatalf("VulnCheck key: %d %v", c, b)
				}
			}
			if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
				for _, id := range []string{tc.feed, tc.follow} {
					url := o.url("/follow")
					if id == tc.feed {
						url = o.url(tc.path)
					}
					if _, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET url = ? WHERE id = ?`, url, id); err != nil {
						return err
					}
				}
				if _, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = (id IN (?, ?))`, tc.feed, tc.follow); err != nil {
					return err
				}
				_, err := tx.ExecContext(t.Context(), `UPDATE scan_setting SET auto_rescan = 0`) // the rescan is queued and closed; no scan runs here
				return err
			}); err != nil {
				t.Fatal(err)
			}
			s.telegramOn()
			s.addFortiGate()
			fs, err := feedsService(*s.d)
			if err != nil {
				t.Fatal(err)
			}
			o.serve(tc.feed, "CVE-2026-0101 Acme/Box")
			if err := fs.Fetch(t.Context(), tc.feed); err != nil { // the first fill: silent
				t.Fatal(err)
			}
			if n := s.count(`SELECT count(*) FROM feeds_kev WHERE source_id = ?`, tc.feed); n != 1 {
				t.Fatalf("the first fill stored %d entries", n)
			}

			// The next pull lists a Fortinet entry that has a public scan template (so the device's finding does not wait for versions,
			// and scan rescans it); the box stops while the next feed is asked about the entry.
			if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
				now := store.FormatTS(time.Now().UTC())
				_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies)
VALUES (?, 'public_exploit', 'nuclei-templates', ?, ?, ?, 1)`, tc.cve, now, now, now)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			o.serve(tc.feed, "CVE-2026-0101 Acme/Box", tc.cve+" Fortinet/FortiOS")
			ctx, stop := context.WithCancel(t.Context())
			if tc.stops {
				o.mu.Lock()
				o.stop = stop
				o.mu.Unlock()
			}
			err = fs.Fetch(ctx, tc.feed)
			stopped := ctx.Err() != nil
			stop()
			if stopped != tc.stops {
				t.Fatalf("the box stopped during the pull: %v, want %v (%v)", stopped, tc.stops, err)
			}
			if n := s.count(`SELECT count(*) FROM feeds_kev WHERE cve = ?`, tc.cve); n != 1 {
				t.Fatalf("the stopped pull did not commit the entry (%d rows): the stop came too early to test anything", n)
			}
			rescans := func(s *stack) int { return s.count(`SELECT count(*) FROM scan_event WHERE cve = ?`, tc.cve) }
			t.Logf("before the restart: %d notices, %d findings, %d rescans of %s", s.noticesOf(tc.cve), s.nf("", tc.cve), rescans(s), tc.cve)
			if n, m := s.noticesOf(tc.cve), rescans(s); !tc.stops && (n != 1 || m != 1) {
				t.Fatalf("a pull that ended normally: %d notices and %d rescans of %s, want 1 and 1", n, m, tc.cve)
			}
			if err := s.d.DB.Close(); err != nil {
				t.Fatal(err)
			}

			// The restart: the same file, every service built again, then what a start runs (each job once).
			db2, err := store.Open(t.Context(), path, log)
			if err != nil {
				t.Fatal(err)
			}
			r := stackOn(t, db2, log, nil)
			fs2, err := feedsService(*r.d)
			if err != nil {
				t.Fatal(err)
			}
			start := func() {
				t.Helper()
				for _, j := range []func(context.Context) error{fs2.RunPull, findingsJobs(*r.d)[0].Run, scanJobs(*r.d)[0].Run} {
					if err := j(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
			}
			start()
			t.Logf("after the restart: %d notices, %d findings, %d rescans of %s", r.noticesOf(tc.cve), r.nf("", tc.cve), rescans(r), tc.cve)
			if n, m := r.noticesOf(tc.cve), rescans(r); n != 1 || m != 1 {
				t.Fatalf("after the restart: %d notices and %d rescans of %s, want exactly 1 and 1", n, m, tc.cve)
			}
			start()
			if n, m := r.noticesOf(tc.cve), rescans(r); n != 1 || m != 1 {
				t.Fatalf("a later round of the jobs: %d notices and %d rescans of %s, want still 1 and 1", n, m, tc.cve)
			}
		})
	}
}

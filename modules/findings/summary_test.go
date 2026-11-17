package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
)

// sumRow is a finding the summary tests write straight into fnd_finding (the shape the matcher and scans leave).
type sumRow struct {
	id, asset, cve string
	status         Status
	firstSeen      time.Time
	resolvedAt     time.Time // zero = not closed
}

func (e *env) insertRows(rows ...sumRow) {
	e.t.Helper()
	err := e.db.Write(e.t.Context(), func(tx *sql.Tx) error {
		for _, r := range rows {
			basis, evidence := "product", sql.NullString{}
			if r.status == StatusConfirmed {
				basis, evidence = "scan", sql.NullString{String: `{"template":"t"}`, Valid: true}
			}
			var resolved, accepted sql.NullString
			if !r.resolvedAt.IsZero() {
				resolved = sql.NullString{String: store.FormatTS(r.resolvedAt), Valid: true}
			}
			if r.status == StatusRiskAccepted {
				accepted = sql.NullString{String: "2027-01-01", Valid: true}
			}
			if _, err := tx.ExecContext(e.t.Context(), `INSERT INTO fnd_finding (id, asset_id, cve, status, severity, confidence, basis, evidence,
				first_seen, last_seen, resolved_at, accepted_until) VALUES (?, ?, ?, ?, 'high', 0.5, ?, ?, ?, ?, ?, ?)`,
				r.id, r.asset, r.cve, r.status, basis, evidence, store.FormatTS(r.firstSeen), store.FormatTS(r.firstSeen), resolved, accepted); err != nil {
				return fmt.Errorf("%s: %w", r.id, err)
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// homeCalls counts the calls to the other modules' counts, so a test sees when the summary was computed again.
type homeCalls struct{ devices, alerts, incidents atomic.Int32 }

func (c *homeCalls) sources(total, pending, sent, failed int) HomeSources {
	return HomeSources{
		Devices:   func(context.Context) (int, int, error) { c.devices.Add(1); return total, pending, nil },
		Alerts:    func(context.Context, time.Time) (int, int, error) { c.alerts.Add(1); return sent, failed, nil },
		Incidents: func(context.Context) (int, int, error) { c.incidents.Add(1); return 3, 1, nil },
	}
}

func sumEnv(t testing.TB) (*env, *FindingHandlers, *servertest.Gate) {
	t.Helper()
	e := newEnv(t)
	gate := servertest.NewGate()
	return e, NewFindingHandlers(e.svc, e.inv, e.feeds, gate), gate
}

func mustSummary(t *testing.T, h *FindingHandlers) *Summary {
	t.Helper()
	s, err := h.Summary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// #825, INV-23: the counts, the order and the fields of "Fix first", and the 30-day trend, from the open rows (status index) and the
// rows closed inside the window.
func TestContract_INV23_SummaryCountsTopAndTrend(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	e.inv.assets["a-2"] = AssetView{ID: "a-2", Name: "web01", IP: "192.168.10.30", Kind: "server", Display: "nginx"}
	old := t0.AddDate(0, 0, -60)
	e.feeds.kev = map[string]KevInfo{
		"CVE-2024-0001": {Vendor: "Acme", Product: "Router", Ransomware: true},
		"CVE-2024-0002": {Vendor: "Acme", Product: "NAS", Display: "Acme NAS", Source: "vulncheck-kev"},
		"CVE-2024-0003": {Vendor: "Acme", Product: "Web"},
		"CVE-2024-0004": {Vendor: "Acme", Product: "Mail", Ransomware: true},
	}
	e.feeds.cvss = map[string]CVSS{"CVE-2024-0002": {Score: 9.8}, "CVE-2024-0003": {Score: 5.0}, "CVE-2024-0004": {Score: 7.5}}
	e.insertRows(
		sumRow{"f-sus-0003", "a-1", "CVE-2024-0003", StatusSuspected, old, time.Time{}},                   // suspected, 5.0
		sumRow{"f-sus-0005", "a-2", "CVE-2024-0005", StatusSuspected, t0.AddDate(0, 0, -2), time.Time{}},  // suspected, not on the list, no score
		sumRow{"f-con-0002", "a-2", "CVE-2024-0002", StatusConfirmed, old, time.Time{}},                   // confirmed, 9.8
		sumRow{"f-sus-0004", "a-1", "CVE-2024-0004", StatusSuspected, old, time.Time{}},                   // suspected, ransomware, 7.5
		sumRow{"f-con-0001", "a-1", "CVE-2024-0001", StatusConfirmed, old, time.Time{}},                   // confirmed, ransomware, no score
		sumRow{"f-sus-0006", "a-gone", "CVE-2024-0006", StatusSuspected, old.Add(time.Hour), time.Time{}}, // device removed
		// closed inside the window: counts until the day it closed
		sumRow{"f-pat-0007", "a-1", "CVE-2024-0007", StatusPatched, t0.AddDate(0, 0, -40), t0.AddDate(0, 0, -5)},
		// closed before the window: counts on no day
		sumRow{"f-fp-0008", "a-1", "CVE-2024-0008", StatusFalsePositive, t0.AddDate(0, 0, -50), t0.AddDate(0, 0, -35)},
		sumRow{"f-ra-0009", "a-2", "CVE-2024-0009", StatusRiskAccepted, t0.AddDate(0, 0, -50), t0.AddDate(0, 0, -45)},
	)
	var calls homeCalls
	h.SetHome(calls.sources(12, 3, 4, 1))
	s := mustSummary(t, h)

	if s.Open != (SummaryOpen{Total: 6, Confirmed: 2, Devices: 3, Ransomware: 2}) {
		t.Fatalf("open = %+v", s.Open)
	}
	var order []string
	for _, it := range s.Top {
		order = append(order, it.ID)
	}
	// confirmed first (ransomware, then the higher CVSS), then suspected: ransomware, then CVSS 5.0, then no score: the newest first
	want := []string{"f-con-0001", "f-con-0002", "f-sus-0004", "f-sus-0003", "f-sus-0005"}
	if strings.Join(order, " ") != strings.Join(want, " ") {
		t.Fatalf("top = %v, want %v", order, want)
	}
	first, second, fifth := s.Top[0], s.Top[1], s.Top[4]
	if first.Product != "Acme Router" || !first.Ransomware || first.CVSS != nil || first.Source == nil || *first.Source != "cisa-kev" || first.Asset == nil || first.Asset.ID != "a-1" {
		t.Fatalf("top[0] = %+v", first)
	}
	if second.Product != "Acme NAS" || second.CVSS == nil || second.CVSS.Score != 9.8 || *second.Source != "vulncheck-kev" || second.Asset.Name != "web01" || second.Status != StatusConfirmed {
		t.Fatalf("top[1] = %+v", second)
	}
	if fifth.Product != "" || fifth.Source != nil || fifth.CVSS != nil || fifth.FirstSeen != store.FormatTS(t0.AddDate(0, 0, -2)) {
		t.Fatalf("top[4] (CVE left the list) = %+v", fifth)
	}
	if len(s.Trend) != SummaryDays {
		t.Fatalf("trend has %d days", len(s.Trend))
	}
	// Days end at midnight UTC from 2026-10-12 (the window starts 2026-10-11); the last is now (t0 = 2026-11-09 10:00).
	// 5 old open rows every day; the patched one until its close on 11-04 10:00 (days 0-23); the new one from 11-07 10:00 (days 27-29).
	for i, n := range s.Trend {
		want := 5
		switch {
		case i <= 23:
			want++
		case i >= 27:
			want++
		}
		if n != want {
			t.Fatalf("trend[%d] = %d, want %d (trend %v)", i, n, want, s.Trend)
		}
	}
	if s.Trend[SummaryDays-1] != s.Open.Total {
		t.Fatalf("today's point %d != open %d", s.Trend[SummaryDays-1], s.Open.Total)
	}
	if s.Devices != (SummaryDevices{Total: 12, Pending: 3}) || s.Alerts == nil || *s.Alerts != (SummaryAlerts{Sent: 4, Failed: 1, Days: 7}) {
		t.Fatalf("devices/alerts = %+v %+v", s.Devices, s.Alerts)
	}
	if s.Incidents == nil || *s.Incidents != (SummaryIncidents{Open: 3, Urgent: 1}) {
		t.Fatalf("incidents = %+v", s.Incidents)
	}
	if s.GeneratedAt != store.FormatTS(t0) {
		t.Fatalf("generated_at = %s", s.GeneratedAt)
	}
}

// INV-23: "Fix first" carries at most SummaryTop items however many findings are open, and the answer stays small.
func TestContract_INV23_SummaryTopIsBounded(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	rows := make([]sumRow, 0, 2000)
	for i := range 2000 {
		rows = append(rows, sumRow{fmt.Sprintf("f-%04d", i), fmt.Sprintf("a-%d", i%150), fmt.Sprintf("CVE-2024-%04d", 1000+i), StatusSuspected, t0.Add(-time.Duration(i) * time.Hour), time.Time{}})
	}
	e.insertRows(rows...)
	s := mustSummary(t, h)
	if s.Open.Total != 2000 || s.Open.Devices != 150 || len(s.Top) != SummaryTop || len(s.Trend) != SummaryDays {
		t.Fatalf("open %+v, top %d, trend %d", s.Open, len(s.Top), len(s.Trend))
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 4096 {
		t.Fatalf("summary of 2000 open findings is %d bytes, want ≤ 4 KB", len(b))
	}
}

// INV-23: the answer is kept in memory; it is computed again after a finding write (Service.write), after summaryTTL (device and alert
// counts, feeds data), and when Notifications is switched; concurrent views while it is fresh cost nothing.
func TestContract_INV23_SummaryCacheAndInvalidation(t *testing.T) {
	t.Parallel()
	e, h, gate := sumEnv(t)
	var calls homeCalls
	h.SetHome(calls.sources(1, 0, 2, 0))
	id := e.seed()
	if s := mustSummary(t, h); s.Open.Total != 1 || calls.devices.Load() != 1 {
		t.Fatalf("first read: open %d, computed %d times", s.Open.Total, calls.devices.Load())
	}
	for range 20 {
		mustSummary(t, h)
	}
	e.advance(summaryTTL - time.Second)
	mustSummary(t, h)
	if n := calls.devices.Load(); n != 1 {
		t.Fatalf("fresh answer computed again: %d", n)
	}
	// A finding write drops it.
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if s := mustSummary(t, h); s.Open.Total != 0 || len(s.Top) != 0 || calls.devices.Load() != 2 {
		t.Fatalf("after a status change: open %d, top %d, computed %d times", s.Open.Total, len(s.Top), calls.devices.Load())
	}
	// The TTL drops it (the counts of other modules change without a findings write).
	e.advance(summaryTTL)
	mustSummary(t, h)
	if n := calls.devices.Load(); n != 3 {
		t.Fatalf("after the TTL: computed %d times", n)
	}
	// Notifications off: alerts and incidents null at once, not after the TTL; notify's counts are not read.
	gate.Set(NotifyModule, false)
	if s := mustSummary(t, h); s.Alerts != nil || s.Incidents != nil || calls.alerts.Load() != 3 || calls.incidents.Load() != 3 {
		t.Fatalf("notify off: alerts %+v, incidents %+v, reads %d/%d", s.Alerts, s.Incidents, calls.alerts.Load(), calls.incidents.Load())
	}
	gate.Set(NotifyModule, true)
	if s := mustSummary(t, h); s.Alerts == nil || s.Alerts.Sent != 2 || s.Incidents == nil || s.Incidents.Open != 3 {
		t.Fatalf("notify on again: alerts %+v, incidents %+v", s.Alerts, s.Incidents)
	}
	// A clock set back never serves an answer "from the future".
	e.advance(-time.Hour)
	before := calls.devices.Load()
	mustSummary(t, h)
	if calls.devices.Load() != before+1 {
		t.Fatal("clock set back: the cached answer was served")
	}
}

// INV-23: without the binary's sources the devices come from Inventory.AssetIDs and alerts are null; an empty box answers zeros, an empty
// top and a flat trend, never null lists.
func TestContract_INV23_SummaryWithoutSources(t *testing.T) {
	t.Parallel()
	_, h, _ := sumEnv(t)
	s := mustSummary(t, h)
	if s.Devices.Total != 1 || s.Devices.Pending != 0 || s.Alerts != nil || s.Incidents != nil || s.Top == nil || len(s.Top) != 0 || s.Open != (SummaryOpen{}) {
		t.Fatalf("summary = %+v", s)
	}
	for _, n := range s.Trend {
		if n != 0 {
			t.Fatalf("trend = %v", s.Trend)
		}
	}
}

// INV-23 / modules.md: the summary reads only findings' own tables; other modules' counts come through HomeSources and the ports. The
// tests above run on a database with only core and findings migrated; this one checks the SQL of summary.go names no other table.
func TestContract_INV23_SummaryReadsOnlyFindingsTables(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("summary.go")
	if err != nil {
		t.Fatal(err)
	}
	// SQL keywords are upper case; prose is not.
	tables := regexp.MustCompile(`\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)`).FindAllStringSubmatch(string(src), -1)
	n := 0
	for _, m := range tables {
		if !strings.HasPrefix(m[1], "fnd_") {
			t.Errorf("summary.go reads table %q, not a findings table", m[1])
		}
		n++
	}
	if n == 0 {
		t.Fatal("no fnd_ table found: the check reads nothing")
	}
}

// The trend's closed-row query lists the closed statuses (so the status index serves it): every status but the two open ones.
func TestSummaryClosedStatusesAreEveryClosedStatus(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("summary.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []Status{StatusMitigated, StatusPatched, StatusFalsePositive, StatusNotRelevant, StatusRiskAccepted} {
		if st.Open() || !strings.Contains(string(src), "'"+string(st)+"'") {
			t.Errorf("closed status %q missing from the trend query", st)
		}
	}
}

// GET /findings/summary is a viewer read through the generated API.
func TestContract_INV23_SummaryEndpoint(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.seed()
	if code, _ := e.call("GET", "/findings/summary", "", ""); code != 401 {
		t.Fatalf("signed out: %d", code)
	}
	code, b := e.call("GET", "/findings/summary", "viewer", "")
	if code != 200 {
		t.Fatalf("status %d: %v", code, b)
	}
	open, _ := b["open"].(map[string]any)
	top, _ := b["top"].([]any)
	trend, _ := b["trend"].([]any)
	if open["total"] != 1.0 || len(top) != 1 || len(trend) != SummaryDays || b["alerts"] != nil || b["incidents"] != nil {
		t.Fatalf("body = %v", b)
	}
	it, _ := top[0].(map[string]any)
	if it["cve"] != "CVE-2022-27593" || it["product"] != "QNAP Photo Station" || it["ransomware"] != true || it["source"] != "cisa-kev" || it["cvss"] != nil {
		t.Fatalf("top[0] = %v", it)
	}
	if a, _ := it["asset"].(map[string]any); a["hostname"] != "nas01" {
		t.Fatalf("asset = %v", it["asset"])
	}
}

// INV-23: both reads of the summary go through an index on status, never a scan of fnd_finding; the trend's closed read is a range on
// (status, resolved_at) (migration 0006).
func TestContract_INV23_SummaryReadsUseTheStatusIndex(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src, err := os.ReadFile("summary.go")
	if err != nil {
		t.Fatal(err)
	}
	queries := regexp.MustCompile("`(SELECT [^`]*FROM fnd_finding[^`]*)`").FindAllStringSubmatch(string(src), -1)
	if len(queries) != 2 {
		t.Fatalf("found %d summary queries, want 2", len(queries))
	}
	for _, q := range queries {
		args := make([]any, strings.Count(q[1], "?"))
		for i := range args {
			args[i] = store.FormatTS(t0)
		}
		rows, err := e.db.Reader().QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+q[1], args...)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		_ = rows.Close()
		p := strings.Join(plan, "; ")
		switch {
		case strings.Contains(q[1], "resolved_at"): // the closed rows of the window: a range on (status, resolved_at), not every closed row
			if !strings.Contains(p, "USING INDEX fnd_finding_status_resolved_idx (status=? AND resolved_at>?)") {
				t.Errorf("query %q: plan %q is not a range on (status, resolved_at)", q[1], p)
			}
		case !strings.Contains(p, "USING INDEX fnd_finding_status"): // the open rows: either index on status
			t.Errorf("query %q: plan %q does not use a status index", q[1], p)
		}
	}
}

// BenchmarkSummaryCold measures one computation of the summary (the cache bypassed) on 2 000 open and 2 000 closed findings over 150
// devices: the cost of the first Home view after a finding change.
func BenchmarkSummaryCold(b *testing.B) {
	e, h, _ := sumEnv(b)
	rows := make([]sumRow, 0, 4000)
	for i := range 4000 {
		st, resolved := StatusSuspected, time.Time{}
		if i%2 == 1 {
			st, resolved = StatusPatched, t0.Add(-time.Duration(i)*time.Hour/4)
		}
		rows = append(rows, sumRow{fmt.Sprintf("f-%04d", i), fmt.Sprintf("a-%d", i%150), fmt.Sprintf("CVE-2024-%04d", 1000+i), st, t0.Add(-time.Duration(i) * time.Hour), resolved})
	}
	e.insertRows(rows...)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.computeSummary(b.Context(), HomeSources{}, true, t0); err != nil {
			b.Fatal(err)
		}
	}
}

// INV-23, D-484: "Fix first" shows a device as GET /findings does (shownAsset): never the internal id, a kind outside the device types is
// "unknown".
func TestContract_INV23_SummaryDeviceAsTheListShowsIt(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	e.inv.assets["a-7"] = AssetView{ID: "a-7", Name: "a-7", IP: NoIP, Kind: "bogus-kind", Display: "Acme NAS"}
	e.inv.assets["a-8"] = AssetView{ID: "a-8", Name: "", IP: NoIP, Kind: "bogus-kind"}
	e.insertRows(
		sumRow{"f-7", "a-7", "CVE-2024-0007", StatusConfirmed, t0.Add(-time.Hour), time.Time{}},
		sumRow{"f-8", "a-8", "CVE-2024-0008", StatusConfirmed, t0.Add(-2 * time.Hour), time.Time{}},
	)
	s := mustSummary(t, h)
	if len(s.Top) != 2 || s.Top[0].Asset == nil || s.Top[1].Asset == nil {
		t.Fatalf("top = %+v", s.Top)
	}
	if a := s.Top[0].Asset; a.Name != "Acme NAS" || a.Kind != "unknown" {
		t.Fatalf("name = id: asset %+v, want the software name and kind unknown", a)
	}
	if a := s.Top[1].Asset; a.Name != "unknown" || a.Kind != "unknown" {
		t.Fatalf("no name, no software: asset %+v, want the kind", a)
	}
	if want := shownAsset(e.inv.assets["a-7"]); *s.Top[0].Asset != want {
		t.Fatalf("summary %+v != list %+v", *s.Top[0].Asset, want)
	}
}

// INV-23: the last trend point is the open count even when the clock was set back (a finding first seen "after now", one closed
// "after now").
func TestContract_INV23_SummaryLastPointIsTheOpenCount(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	e.insertRows(
		sumRow{"f-1", "a-1", "CVE-2024-0001", StatusSuspected, t0.AddDate(0, 0, -3), time.Time{}},
		sumRow{"f-2", "a-1", "CVE-2024-0002", StatusSuspected, t0.Add(time.Hour), time.Time{}},            // first seen after now
		sumRow{"f-3", "a-1", "CVE-2024-0003", StatusPatched, t0.AddDate(0, 0, -3), t0.Add(2 * time.Hour)}, // closed after now
	)
	s := mustSummary(t, h)
	if last := s.Trend[SummaryDays-1]; s.Open.Total != 2 || last != 2 {
		t.Fatalf("open %d, last point %d (trend %v)", s.Open.Total, last, s.Trend)
	}
	if day := s.Trend[SummaryDays-2]; day != 2 { // f-1 and f-3 (closed later) at the end of yesterday
		t.Fatalf("yesterday = %d, want 2 (trend %v)", day, s.Trend)
	}
}

// INV-23: views that arrive together on an empty cache share one computation (sumMu): the computation holds until every view has
// called Summary, then each gets the same answer.
func TestContract_INV23_SummaryConcurrentViewsComputeOnce(t *testing.T) {
	t.Parallel()
	_, h, _ := sumEnv(t)
	const n = 16
	var arrived atomic.Int32
	all := make(chan struct{})
	var computed atomic.Int32
	h.SetHome(HomeSources{Devices: func(context.Context) (int, int, error) {
		computed.Add(1)
		<-all // every view has arrived (and calls Summary) before this computation ends
		return 4, 1, nil
	}})
	start := make(chan struct{})
	got := make(chan *Summary, n)
	errs := make(chan error, n)
	for range n {
		go func() {
			<-start
			if arrived.Add(1) == n {
				close(all)
			}
			s, err := h.Summary(t.Context())
			if err != nil {
				errs <- err
				return
			}
			got <- s
		}()
	}
	close(start)
	var first *Summary
	for range n {
		select {
		case err := <-errs:
			t.Fatal(err)
		case s := <-got:
			if first == nil {
				first = s
			} else if s != first {
				t.Fatal("two views got two computations")
			}
		}
	}
	if c := computed.Load(); c != 1 || first.Devices.Total != 4 {
		t.Fatalf("computed %d times, devices %+v", c, first.Devices)
	}
}

// n73: "Fix first" names the device's software the entry is keyed to, as the finding's page does (matchedOn); the KEV group stays
// in product. A device the matcher cannot read, or no row keyed to the entry, leaves software empty.
func TestSummary_TopNamesTheMatchedSoftware(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	e.inv.assets["a-2"] = AssetView{ID: "a-2", Name: "web01", IP: "192.168.10.30", Kind: "server"}
	e.inv.match["a-1"] = Asset{ID: "a-1", Name: "winlab01", Software: []Software{
		{ID: "s-edge", Display: "Microsoft Edge", KevKeys: []string{"microsoft|edge"}},
		{ID: "s-win", Display: "Windows Server 2025", KevKeys: []string{"microsoft|windows"}},
	}}
	e.feeds.kev = map[string]KevInfo{
		"CVE-2024-0001": {Vendor: "Microsoft", Product: "Windows", Display: "Windows PCs and servers"},
		"CVE-2024-0002": {Vendor: "Acme", Product: "NAS"},
	}
	e.insertRows(
		sumRow{"f-con-0001", "a-1", "CVE-2024-0001", StatusSuspected, t0.AddDate(0, 0, -1), time.Time{}},
		sumRow{"f-con-0002", "a-2", "CVE-2024-0002", StatusSuspected, t0.AddDate(0, 0, -2), time.Time{}}, // a-2: no match input
	)
	s := mustSummary(t, h)
	if len(s.Top) != 2 {
		t.Fatalf("top = %+v", s.Top)
	}
	if got := s.Top[0]; got.Software != "Windows Server 2025" || got.Product != "Windows PCs and servers" {
		t.Fatalf("top[0] software %q product %q, want the Windows row and the group", got.Software, got.Product)
	}
	if got := s.Top[1]; got.Software != "" || got.Product != "Acme NAS" {
		t.Fatalf("top[1] software %q product %q, want no software", got.Software, got.Product)
	}
}

// #910 (review r2 M1 of #913): an entry reached only through NVD's list (CISA "Google | Chromium V8", no row keyed to it) names the
// matcher's row on Home, as on the finding's page.
func TestSummary_TopNamesTheRowReachedThroughNVD(t *testing.T) {
	t.Parallel()
	e, h, _ := sumEnv(t)
	e.inv.match["a-1"] = Asset{ID: "a-1", Name: "pc", OS: "Microsoft Windows 11 Pro", Software: []Software{chromeRow("150.0.7871.4")}}
	v := cve202687491()
	e.feeds.vulns = append(e.feeds.vulns, v)
	e.feeds.kev = map[string]KevInfo{v.CVE: {Vendor: v.Vendor, Product: v.Product}}
	e.insertRows(sumRow{"f-con-0001", "a-1", v.CVE, StatusSuspected, t0.AddDate(0, 0, -1), time.Time{}})
	s := mustSummary(t, h)
	if len(s.Top) != 1 || s.Top[0].Software != "Google Chrome" {
		t.Fatalf("top = %+v, want the Chrome row named", s.Top)
	}
}

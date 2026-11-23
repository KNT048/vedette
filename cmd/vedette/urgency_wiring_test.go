package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
)

// seedUrgencyCatalogue stores three catalogue CVEs of FortiOS 7.2.0 to 7.2.8 on no list: one critical over the network with no login
// (layer 4 on a firewall), one with a Metasploit module seen this week (layer 3; the source loaded before, so it is not its first load),
// one with neither (layer 5).
func seedUrgencyCatalogue(t *testing.T, s *stack) {
	t.Helper()
	ctx := t.Context()
	s.kevAdded("CVE-2024-1111", "Acme", "Gizmo", time.Now().AddDate(0, -2, 0)) // the exploited list is loaded, with nothing of this device
	now := time.Now().UTC()
	ts := store.FormatTS
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, c := range []struct {
			cve   string
			score float64
			vec   string
		}{
			{"CVE-2026-50001", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			{"CVE-2026-50002", 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
			{"CVE-2026-50003", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		} {
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at, ssvc_automatable) VALUES (?1, ?2, ?3, 'Analyzed', ?3, ?3, 'yes')`,
					[]any{c.cve, ts(now.AddDate(0, 0, -30)), ts(now.AddDate(0, 0, -20))}},
				{`INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES (?1, 'nvd', '3.1', ?2, ?3)`, []any{c.cve, c.score, c.vec}},
				{`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms) VALUES (?1, 'nvd', 'o', 'fortinet', 'fortios', 'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', '7.2.0', '', '', '7.2.9', '[]')`,
					[]any{c.cve}},
			} {
				if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
					return err
				}
			}
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total) VALUES ('recent', 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'done', ?1, ?1, ?1, 0, 0)`,
				[]any{ts(now)}},
			// the source's first load, a month ago, then this week's module
			{`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url) VALUES ('CVE-2019-0001', 'public_exploit', 'metasploit', ?1, ?2, ?3, 1, 'https://example.com/msf/1')`,
				[]any{ts(now.AddDate(-5, 0, 0)), ts(now.AddDate(0, -1, 0)), ts(now)}},
			{`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url) VALUES ('CVE-2026-50002', 'public_exploit', 'metasploit', ?1, ?1, ?1, 1, 'https://example.com/msf/2')`,
				[]any{ts(now.Add(-48 * time.Hour))}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// urgencyJob is findings' hourly urgency pass as the module wires it, found by its name.
func urgencyJob(t *testing.T, s *stack) jobs.Job {
	t.Helper()
	for _, j := range findingsJobs(*s.d) {
		if j.Name == findings.UrgencyJob {
			return j
		}
	}
	t.Fatalf("no %q job among the findings jobs", findings.UrgencyJob)
	return jobs.Job{}
}

// layersOf is the stored urgency of each finding of a device, by CVE.
func layersOf(t *testing.T, s *stack, id string) map[string]int {
	t.Helper()
	fs, err := s.d.Findings.Findings(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, f := range fs {
		out[f.CVE] = f.Urgency
	}
	return out
}

// The urgency pass through the real wiring: feeds' signals, CVSS and SSVC, the device's type and the product's class rate a device's
// findings as soon as its match is written, and the selfcheck recomputes the stored layers as of the last pass: 0 when they agree, 1
// for a layer changed by hand; a signal that arrives after the pass is not held against it.
func TestUrgencyWiring_StoresTheLayersAndTheSelfcheckAgrees(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	seedUrgencyCatalogue(t, s)
	id := s.addFortiGate() // FortiOS 7.2.5: its match write rates its findings at once
	want := map[string]int{"CVE-2026-50001": findings.UrgencyCriticalEdge, "CVE-2026-50002": findings.UrgencyPublicExploit, "CVE-2026-50003": findings.UrgencyUpdate}
	got := layersOf(t, s, id)
	perLayer := map[int]int{}
	for cve, w := range want {
		if got[cve] != w {
			t.Errorf("%s: urgency %d, want %d", cve, got[cve], w)
		}
		perLayer[got[cve]]++
	}
	t.Logf("findings per urgency layer: %v", perLayer)

	mismatches := func() int64 {
		t.Helper()
		n, err := urgencyMismatches(ctx, s.d.DB.Reader())
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := mismatches(); n != 1 {
		t.Fatalf("no pass recorded yet: %d mismatches, want 1 (the pass has not run; the stored layers agree)", n)
	}
	s.exec(`INSERT INTO core_job_run (id, module, job, started_at, finished_at, status) VALUES ('jr-urgency-0', 'findings', ?, ?, ?, 'ok')`,
		findings.UrgencyJob, store.FormatTS(time.Now().Add(-3*time.Hour)), store.FormatTS(time.Now().Add(-3*time.Hour)))
	if n := mismatches(); n != 1 {
		t.Fatalf("a pass three hours old: %d mismatches, want 1", n)
	}
	started := time.Now().UTC()
	job := urgencyJob(t, s)
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	finished := time.Now().UTC().Add(time.Millisecond)
	s.exec(`INSERT INTO core_job_run (id, module, job, started_at, finished_at, status) VALUES ('jr-urgency-1', 'findings', ?, ?, ?, 'ok')`,
		findings.UrgencyJob, store.FormatTS(started), store.FormatTS(finished))
	if n := mismatches(); n != 0 {
		t.Fatalf("after the pass: %d mismatches, want 0", n)
	}
	// a signal stored after the pass: the next pass rates it, the selfcheck does not count it now
	s.exec(`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url) VALUES ('CVE-2026-50003', 'exploited', 'rapid7', ?1, ?2, ?2, 1, 'https://example.com/blog')`,
		store.FormatTS(started.Add(-time.Hour)), store.FormatTS(finished.Add(time.Second)))
	if n := mismatches(); n != 0 {
		t.Fatalf("a signal newer than the pass: %d mismatches, want 0", n)
	}
	s.exec(`UPDATE fnd_finding SET urgency = 2 WHERE asset_id = ? AND cve = 'CVE-2026-50001'`, id)
	if n := mismatches(); n != 1 {
		t.Fatalf("a layer changed by hand: %d mismatches, want 1", n)
	}
}

// The facts the pass reads: a source's first pull is its first load (its date says nothing about when the box learned it); a list's
// entry is an exploited signal even without its row.
func TestUrgencyWiring_FactsMarkTheFirstLoad(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	seedUrgencyCatalogue(t, s)
	s.kev("CVE-2026-50009", "Fortinet", "FortiOS")
	s.exec(`DELETE FROM feeds_signal WHERE cve = 'CVE-2026-50009'`)
	facts, err := urgencyFacts(context.Background(), feeds.NewUrgencyReader(s.d.DB.Reader()), []string{"CVE-2019-0001", "CVE-2026-50002", "CVE-2026-50001", "CVE-2026-50009"})
	if err != nil {
		t.Fatal(err)
	}
	if g := facts["CVE-2019-0001"].Signals; len(g) != 1 || !g[0].FirstLoad {
		t.Errorf("first load: %+v", g)
	}
	if g := facts["CVE-2026-50002"].Signals; len(g) != 1 || g[0].FirstLoad || !g[0].Qualifies {
		t.Errorf("a later signal: %+v", g)
	}
	if c := facts["CVE-2026-50001"]; c.CVSS == nil || c.CVSS.Score != 9.8 || c.Automatable != "yes" || c.Published.IsZero() {
		t.Errorf("CVSS, SSVC, publication: %+v", c)
	}
	if g := facts["CVE-2026-50009"].Signals; len(g) != 1 || g[0].Kind != findings.SignalExploited || g[0].Source != "cisa-kev" || !g[0].Qualifies {
		t.Errorf("a list entry without its row: %+v", g)
	}
	// a feed turned off raises nothing (its rows stay for when it is on again); an exploited list's entry still counts
	s.exec(`UPDATE feeds_source SET enabled = 0 WHERE id IN ('metasploit', 'cisa-kev')`)
	facts, err = urgencyFacts(context.Background(), feeds.NewUrgencyReader(s.d.DB.Reader()), []string{"CVE-2026-50002", "CVE-2026-50009"})
	if err != nil {
		t.Fatal(err)
	}
	if g := facts["CVE-2026-50002"].Signals; len(g) != 0 {
		t.Errorf("a feed that is off: %+v", g)
	}
	if g := facts["CVE-2026-50009"].Signals; len(g) != 1 {
		t.Errorf("a list's entry while its feed is off: %+v", g)
	}
}

// A rise is one alert with its own id and a reasons line in the feeds' own names: the device's public-exploit finding is told when the
// device is added (a new finding), and again when a researcher's claim makes it exploited (3→2), "not yet in CISA KEV".
func TestUrgencyWiring_ARiseIsOneAlertWithItsReasons(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.telegramOn()
	s.exec(`UPDATE notify_box SET first_run_at = ?`, store.FormatTS(time.Now().AddDate(0, 0, -3))) // past the box's first run
	seedUrgencyCatalogue(t, s)
	id := s.addFortiGate()
	byID := func(prefix string) []notify.Notice {
		var out []notify.Notice
		for _, n := range s.queuedNotices() {
			if strings.HasPrefix(n.ID, prefix) {
				out = append(out, n)
			}
		}
		return out
	}
	var fid string
	fs, err := s.d.Findings.Findings(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.CVE == "CVE-2026-50002" {
			fid = f.ID
		}
	}
	if got := byID("nt-" + fid + "-urgency_changed-3"); len(got) != 1 || !strings.Contains(got[0].What, "Why: Public exploit available: Metasploit") ||
		strings.Contains(got[0].Title+got[0].What, "exploited in") {
		t.Fatalf("the public-exploit rise: %+v", got)
	}
	s.exec(`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES ('CVE-2019-0002', 'exploited', 'rapid7-blog', ?1, ?2, ?2, 1)`,
		store.FormatTS(time.Now().AddDate(0, -2, 0)), store.FormatTS(time.Now().AddDate(0, -1, 0))) // the source's first load, long ago
	s.exec(`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES ('CVE-2026-50002', 'exploited', 'rapid7-blog', ?1, ?1, ?1, 1)`,
		store.FormatTS(time.Now().Add(-time.Hour)))
	if err := urgencyJob(t, s).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := byID("nt-" + fid + "-urgency_changed-2")
	if len(got) != 1 || !strings.Contains(got[0].What, "Why: Exploited in the wild: Rapid7") || !strings.Contains(got[0].What, "not yet in CISA KEV") ||
		strings.Contains(got[0].What, "rapid7-blog") {
		t.Fatalf("the exploited rise: %+v", got)
	}
}

// In the box's own first run, what the urgency pass rates urgent is one summary notice, not one alert per finding.
func TestUrgencyWiring_TheFirstRunIsOneSummaryNotice(t *testing.T) {
	t.Parallel()
	s := newStack(t) // notify first ran now: the box's first run
	s.telegramOn()
	seedUrgencyCatalogue(t, s)
	s.addFortiGate()
	var sums, alerts []notify.Notice
	for _, n := range s.queuedNotices() {
		switch {
		case strings.HasPrefix(n.ID, "nt-first-run-install-"):
			sums = append(sums, n)
		case n.Event == notify.NoticeUrgencyChanged:
			alerts = append(alerts, n)
		}
	}
	if len(sums) != 1 || len(alerts) != 0 || sums[0].Title != "Patch first: 2 urgent findings on 1 device" || len(sums[0].CVEs) != 2 || len(sums[0].Devices) != 1 {
		t.Fatalf("summaries %+v, alerts %+v", sums, alerts)
	}
	// a second device added while that summary still waits in the queue: what it brings joins it (one message for one load), never dropped
	if _, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "192.168.30.2"}); err != nil {
		t.Fatal(err)
	}
	sums = sums[:0]
	for _, n := range s.queuedNotices() {
		if strings.HasPrefix(n.ID, "nt-first-run-install-") {
			sums = append(sums, n)
		}
	}
	if len(sums) != 1 || sums[0].Title != "Patch first: 4 urgent findings on 2 devices" || len(sums[0].FindingIDs) != 4 || len(sums[0].Lines) != 4 {
		t.Fatalf("after a second device: %+v", sums)
	}
	for _, l := range sums[0].Lines { // each line says why and how Vedette knows, as the finding page does
		if !strings.Contains(l, " — ") || !strings.Contains(l, "Not confirmed yet:") {
			t.Errorf("summary line %q", l)
		}
	}
}

// A CVE that joins an exploited list makes its finding exploited: the response rules get exactly one finding event of the rise, inside the
// box's first-run window (where the rise is a line of the summary, not an alert) and after it (an alert), as for a new exploited finding.
func TestUrgencyWiring_AJoinIsOneResponseEvent(t *testing.T) {
	t.Parallel()
	for _, firstRun := range []bool{true, false} {
		s := responseOn(t)
		if !firstRun {
			s.exec(`UPDATE notify_box SET first_run_at = ?`, store.FormatTS(time.Now().AddDate(0, 0, -3)))
		}
		seedUrgencyCatalogue(t, s)
		id := s.addFortiGate()
		fid := ""
		fs, err := s.d.Findings.Findings(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.CVE == "CVE-2026-50003" {
				fid = f.ID
			}
		}
		before := s.count(`SELECT count(*) FROM resp_events WHERE finding_id = ?`, fid)
		s.kevAdded("CVE-2026-50003", "Fortinet", "FortiOS", time.Now().AddDate(0, -2, 0)) // an old entry: in the first run, a summary line
		if err := findingsJobs(*s.d)[0].Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := urgencyJob(t, s).Run(t.Context()); err != nil { // the hourly pass after: nothing more
			t.Fatal(err)
		}
		if got := layersOf(t, s, id)["CVE-2026-50003"]; got != findings.UrgencyExploited {
			t.Fatalf("first run %v: urgency %d", firstRun, got)
		}
		if n := s.count(`SELECT count(*) FROM resp_events WHERE finding_id = ? AND trigger = 'finding' AND id LIKE 'finding:%:urgency-2-%'`, fid); n != 1 || before != 0 {
			t.Fatalf("first run %v: %d response events of the rise (%d before), want 1", firstRun, n, before)
		}
	}
}

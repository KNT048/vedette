package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
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
				[]any{ts(now.Add(-2 * time.Hour))}},
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
	if n := mismatches(); n != 0 {
		t.Fatalf("no pass recorded yet: %d mismatches", n)
	}
	started := time.Now().UTC()
	job := findingsJobs(*s.d)[2]
	if job.Name != findings.UrgencyJob {
		t.Fatalf("job %q", job.Name)
	}
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
	facts, err := urgencyFacts(context.Background(), s.d.DB.Reader(), []string{"CVE-2019-0001", "CVE-2026-50002", "CVE-2026-50001", "CVE-2026-50009"})
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
}

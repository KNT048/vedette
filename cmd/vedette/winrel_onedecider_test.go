package main

import (
	"database/sql"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/winrel"
)

// A device on a Windows release only Microsoft's release list names (a build newer than core/winrel's table) is decided the same way
// by every path that matches it: the match a software change starts and the hourly pass. The box starts on a database that already
// stores the release (a restart); the device's build carries the month Microsoft fixed an exploited flaw of a server role, so neither
// path may open it: a finding that opens on one path and closes as "data corrected" on the next is an alert that fires and disappears.
// Not parallel: the learned releases are one table for the process.
func TestWiringStoredWindowsReleaseOneDecisionOnEveryPath(t *testing.T) {
	ctx := t.Context()
	t.Cleanup(func() { winrel.Learn(nil); winrel.LearnUpdates(nil) })
	winrel.Learn(nil) // the process starts knowing only the hand table
	winrel.LearnUpdates(nil)
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	const (
		serverRole = "CVE-2025-90001" // an exploited flaw NVD lists only for server releases, fixed in the month the build carries
		clientFix  = "CVE-2025-90002" // a client fix of the next month: it tells which month's update the build carries
	)
	err = db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_winrel (build, server, product, display, line, ga, ga_rev) VALUES (26300, 0, 'windows_11_26h2', 'Windows 11 26H2', 26100, '2026-09-29', 9457)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	s := stackOn(t, db, log, nil) // the box starts on the stored release
	err = db.Write(ctx, func(tx *sql.Tx) error {
		for _, e := range []struct {
			cve       string
			published time.Time
		}{{serverRole, time.Date(2025, 10, 14, 17, 0, 0, 0, time.UTC)}, {clientFix, time.Date(2025, 11, 11, 18, 0, 0, 0, time.UTC)}} {
			if err := seedKEVRow(ctx, tx, e.cve, "Microsoft", "Windows", "Microsoft Windows flaw", e.published.AddDate(0, 0, 10), false, false); err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, e.cve, e.published, 9.8); err != nil {
				return err
			}
		}
		for _, r := range []struct{ cve, cpe, end string }{
			{serverRole, "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "10.0.20348.4297"},
			{serverRole, "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", "10.0.26100.6905"},
			{clientFix, "cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*", "10.0.26100.7171"},
			{clientFix, "cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:*:*", "10.0.26200.7171"},
		} {
			if err := seedRange(ctx, tx, r.cve, r.cpe, "", "", "", r.end); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hint := observe.AssetHint{IP: netip.MustParseAddr("100.66.254.20"), Agent: "osquery:node-26h2"}
	report := func(appVersion string) string {
		t.Helper()
		if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: hint, Field: observe.OS, Value: "Microsoft Windows 11 Pro 10.0.26300.10075",
			Source: observe.Agent, Confidence: 0.95}}); err != nil {
			t.Fatal(err)
		}
		rows := []observe.Software{
			{Display: "Windows 11 26H2", Vendor: "microsoft", Product: "Windows 11 26H2", Version: "10.0.26300.10075",
				CPE: "cpe:2.3:o:microsoft:windows_11_26h2:10.0.26300.10075:*:*:*:*:*:x64:*", KevKeys: []string{"microsoft|windows"}, Confidence: 0.95},
			{Display: "Example Notes", Vendor: "Example Corp", Product: "Example Notes", Version: appVersion, Confidence: 0.95},
		}
		if err := s.d.Inventory.ReplaceSoftware(ctx, hint, observe.Osquery, nil, rows); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := db.Reader().QueryRowContext(ctx, `SELECT asset_id FROM inv_software WHERE product = 'Example Notes'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// decision is what the box says about the device and the two flaws: a finding, a question for a person, or nothing.
	decision := func() string {
		t.Helper()
		var f, q string
		if err := db.Reader().QueryRowContext(ctx, `SELECT ifnull(group_concat(cve || ' ' || state || ' ' || ifnull(via, ''), '; '), '') FROM fnd_finding`).Scan(&f); err != nil {
			t.Fatal(err)
		}
		if err := db.Reader().QueryRowContext(ctx, `SELECT ifnull(group_concat(ifnull(cve, '') || ' ' || kind, '; '), '') FROM fnd_question`).Scan(&q); err != nil {
			t.Fatal(err)
		}
		return "findings [" + f + "] questions [" + q + "]"
	}
	steps := []struct {
		name string
		run  func(id string)
	}{
		{"the match of the agent's report", func(id string) {
			if _, err := s.d.Findings.OnMatchChanged(ctx, id); err != nil {
				t.Fatal(err)
			}
		}},
		{"the feeds module reading its stored lists", func(string) { // as its first request or a good pull does
			fs, err := feedsService(*s.d)
			if err != nil {
				t.Fatal(err)
			}
			if err := fs.LearnWindowsReleases(ctx); err != nil {
				t.Fatal(err)
			}
		}},
		{"the hourly pass", func(string) {
			if _, err := s.d.Findings.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
		}},
		{"the match of a changed software line", func(string) {
			if _, err := s.d.Findings.OnMatchChanged(ctx, report("2.1")); err != nil {
				t.Fatal(err)
			}
		}},
		{"the next hourly pass", func(string) {
			if _, err := s.d.Findings.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
		}},
	}
	id := report("2.0")
	for _, st := range steps {
		st.run(id)
		// Microsoft fixed the server-role flaw in a month the build carries, and the client fix of the next month is below the build:
		// not affected on every path, never a finding or a question that one path makes and the next takes back
		if got, want := decision(), "findings [] questions []"; got != want {
			t.Fatalf("after %s: %s, want %s", st.name, got, want)
		}
	}
	var handled int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM fnd_finding_event WHERE kind = 'handled'`).Scan(&handled); err != nil {
		t.Fatal(err)
	}
	if handled != 0 {
		t.Fatalf("%d findings were opened and closed again by the matches", handled)
	}
}

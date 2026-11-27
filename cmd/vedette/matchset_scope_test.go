package main

import (
	"database/sql"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
)

// One CVE is one entry, whichever devices a match reads and whichever findings they hold: the match after one device's change asks
// for that device's products and findings, the hourly pass for every device's, and both must hand the matcher the same rows of a CVE,
// or the same (device, CVE) is decided twice, differently. The catalogue CVE names a product of each of two devices.
func TestWiringMatchSetEntryIsTheSameForEveryScope(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-90101"
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -2, 0), 7.5); err != nil {
			return err
		}
		for _, r := range []struct{ cpe, end string }{
			{"cpe:2.3:o:acme:router_os:*:*:*:*:*:*:*:*", "5.4.0"},
			{"cpe:2.3:a:globex:switch_manager:*:*:*:*:*:*:*:*", "2.0.0"},
		} {
			if err := seedRange(ctx, tx, cve, r.cpe, "", "", "", r.end); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	router := findings.Asset{ID: "a-router", Software: []findings.Software{{ID: "s-1", Display: "Router OS", Vendor: "acme", Product: "router_os", Version: "5.3.0",
		CPE: "cpe:2.3:o:acme:router_os:5.3.0:*:*:*:*:*:*:*", Source: "agent"}}}
	switcher := findings.Asset{ID: "a-switch", Software: []findings.Software{{ID: "s-2", Display: "Switch Manager", Vendor: "globex", Product: "switch_manager",
		Version: "1.0.0", CPE: "cpe:2.3:a:globex:switch_manager:1.0.0:*:*:*:*:*:*:*", Source: "agent"}}}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	feed := findingsFeeds{st: fs.Store(), cache: &vulnCache{}}
	entry := func(name string, scope findings.MatchScope) findings.Vuln {
		t.Helper()
		vs, err := feed.MatchSet(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			if v.CVE == cve {
				return v
			}
		}
		t.Fatalf("%s: %s is not in the match set", name, cve)
		return findings.Vuln{}
	}
	whole := entry("every device", findings.NewMatchScope([]findings.Asset{router, switcher}, nil))
	for _, c := range []struct {
		name  string
		scope findings.MatchScope
	}{
		{"the router's own match", findings.NewMatchScope([]findings.Asset{router}, nil)},
		{"the switch's own match", findings.NewMatchScope([]findings.Asset{switcher}, nil)},
		{"the router's match once it holds a finding of the CVE", findings.NewMatchScope([]findings.Asset{router}, []string{cve})},
		{"every device once one holds a finding of the CVE", findings.NewMatchScope([]findings.Asset{router, switcher}, []string{cve})},
	} {
		if got := entry(c.name, c.scope); !reflect.DeepEqual(got, whole) {
			t.Errorf("%s reads %s with rows %+v, the pass over every device with %+v", c.name, cve, got.Affected, whole.Affected)
		}
	}
}

// A CVE record's list is complete when its author (the CNA) says what it does not list: another publisher's row beside it (an ADP's row
// of another product, with no status for the rest) neither completes nor breaks it, as for an exploited-list entry. Read on every row
// of the CVE, such a row would otherwise turn the vendor's clear "not affected" for an older release into a question.
func TestWiringRecordListCompletenessIsItsAuthors(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-90102"
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, published, updated_at) VALUES (?, ?, ?)`, cve, "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, version_type, default_status, platforms) VALUES
(?, 'cna', 'o', 'acme', 'router_os', 'cpe:2.3:o:acme:router_os:*:*:*:*:*:*:*:*', '7.6.1', '', '7.6.6', '', 'semver', 'unaffected', NULL),
(?, 'adp', '', 'globex', 'edge_appliance', '', '', '', '', '', 'custom', 'unknown', NULL)`, cve, cve)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	router := findings.Asset{ID: "a-router", Software: []findings.Software{{ID: "s-1", Display: "Router OS", Vendor: "acme", Product: "router_os", Version: "7.2.13",
		CPE: "cpe:2.3:o:acme:router_os:7.2.13:*:*:*:*:*:*:*", Source: "agent"}}}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := findingsFeeds{st: fs.Store(), cache: &vulnCache{}}.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{router}, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.CVE == cve {
			if v.RangesFrom != findings.RangesCVEOrg {
				t.Fatalf("%s is read as %q, want the CNA's complete list %q", cve, v.RangesFrom, findings.RangesCVEOrg)
			}
			return
		}
	}
	t.Fatalf("%s is not in the match set", cve)
}

// Another publisher's row (an ADP's) of a product the CNA's complete list does not name, with no status for the versions it does not
// list, only ever says "affected": a version outside it is not proved unaffected by the CNA's word about its own product, so a finding
// of that product stays open. A version inside it is still affected.
func TestWiringOtherPublishersOpenRowNeverClosesItsProduct(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2026-90103"
	for _, c := range []struct{ name, startIncl, endIncl, endExcl, version string }{
		{"after an inclusive end", "2.4.0", "2.4.1", "", "2.4.3"},
		{"below the start", "2.0.0", "", "2.5.0", "1.9.0"},
		{"on a later train than the end", "1.0.0", "", "2.0.0", "3.0.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			ctx := t.Context()
			err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, published, updated_at) VALUES (?, ?, ?)`, cve, "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z"); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, version_type, default_status, platforms) VALUES
(?, 'cna', 'o', 'acme', 'router_os', 'cpe:2.3:o:acme:router_os:*:*:*:*:*:*:*:*', '7.6.1', '', '7.6.6', '', 'semver', 'unaffected', NULL),
(?, 'adp', 'a', 'globex', 'edge_appliance', 'cpe:2.3:a:globex:edge_appliance:*:*:*:*:*:*:*:*', ?, '', ?, ?, 'semver', 'unknown', NULL)`,
					cve, cve, c.startIncl, c.endIncl, c.endExcl)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			device := func(version string) findings.Asset {
				return findings.Asset{ID: "a-edge", Software: []findings.Software{{ID: "s-1", Display: "Edge Appliance", Vendor: "globex", Product: "edge_appliance",
					Version: version, CPE: "cpe:2.3:a:globex:edge_appliance:" + version + ":*:*:*:*:*:*:*", Source: "agent"}}}
			}
			fs, err := feedsService(*s.d)
			if err != nil {
				t.Fatal(err)
			}
			feed := findingsFeeds{st: fs.Store(), cache: &vulnCache{}}
			outside := device(c.version)
			vs, err := feed.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{outside}, []string{cve}))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range findings.MatchAsset(outside, vs, map[string]bool{cve: true}, time.Now()).NotAffected {
				t.Errorf("%s %s is closed on the CNA's word about another product: %s", c.version, m.CVE, m.Evidence.Summary)
			}
			inside := device(c.startIncl)
			if res := findings.MatchAsset(inside, vs, nil, time.Now()); !slices.ContainsFunc(res.New, func(m findings.Match) bool { return m.CVE == cve }) {
				t.Errorf("%s, inside the row, is not affected by %s", c.startIncl, cve)
			}
		})
	}
}

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// The status a CVE JSON 5 record gives a version, end to end on the binary's wiring (record parsed by feeds, stored, read by the match
// pass): https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md . A version takes the status of the entry or range
// that matches it, else the product's defaultStatus; without either it is unknown (a question, never "not affected"). A CNA that is not
// the product's vendor states what it tested: its "unaffected" for the versions it does not list decides nothing. When the record and
// NVD disagree, "affected" wins. Each case is the shape of a real record, cut to the fields that decide it.
func TestCVE5Status_EndToEnd(t *testing.T) {
	t.Parallel()
	type nvdRow struct{ cpe, startIncl, endExcl string }
	cases := []struct {
		name            string
		assigner        string
		affected        string // the CNA's affected list
		nvd             []nvdRow
		vendor, product string    // the device's software
		kev             [2]string // the exploited-list entry's vendor and product when it is listed; empty: the device's
		offList         bool      // the case holds for a CVE on no exploited list (NVD's exact rows decide a listed one their own way)
		version         string
		want            string // open (a finding), question (possible), none (decided not affected)
	}{
		{
			name: "defaultStatus affected and every version: affected", assigner: "icscert",
			affected: `{"vendor":"MikroTik","product":"RouterOS","defaultStatus":"affected","versions":[{"status":"affected","version":"All versions"}]}`,
			vendor:   "MikroTik", product: "RouterOS", version: "7.25.2", want: "open",
		},
		{
			name: "defaultStatus affected beside a custom range: affected", assigner: "VulnCheck",
			affected: `{"vendor":"Nmap Project","product":"Nmap","defaultStatus":"affected","versions":[{"status":"affected","version":"0","versionType":"custom","lessThanOrEqual":"7.99"}]}`,
			vendor:   "Nmap", product: "Nmap", kev: [2]string{"Nmap Project", "Nmap"}, version: "7.94", want: "open",
		},
		{
			name: "the record's range is affected where NVD pins an edition the record does not name", assigner: "VulnCheck",
			affected: `{"vendor":"Mobatek","product":"MobaXterm","defaultStatus":"unaffected","versions":[{"status":"affected","version":"0","lessThan":"26.1","versionType":"custom"}]}`,
			nvd:      []nvdRow{{cpe: "cpe:2.3:a:mobatek:mobaxterm:*:*:*:*:home:*:*:*", endExcl: "26.1"}},
			vendor:   "Mobatek", product: "MobaXterm", version: "25.1.0.5288", want: "open",
		},
		{
			name: "the record's range is affected where NVD lists one exact release", assigner: "VulnCheck",
			affected: `{"vendor":"Acme","product":"Editor","defaultStatus":"unaffected","versions":[{"status":"affected","version":"0","lessThan":"8.9.4","versionType":"semver"}]}`,
			nvd:      []nvdRow{{cpe: "cpe:2.3:a:acme:editor:8.9.3:*:*:*:*:*:*:*"}},
			vendor:   "Acme", product: "Editor", version: "8.6.5", want: "open",
		},
		{
			name: "the vendor's own CNA says unlisted versions are unaffected, beside NVD's exact release: not affected", assigner: "openssl",
			affected: `{"vendor":"OpenSSL","product":"OpenSSL","defaultStatus":"unaffected","versions":[{"lessThan":"4.0.1","status":"affected","version":"4.0.0","versionType":"semver"}]}`,
			nvd:      []nvdRow{{cpe: "cpe:2.3:a:openssl:openssl:4.0.0:-:*:*:*:*:*:*"}},
			vendor:   "OpenSSL", product: "OpenSSL", version: "3.5.0", want: "none",
		},
		{
			name: "the vendor's own CNA lists exact releases only, unlisted unaffected: not affected", assigner: "acme",
			affected: `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"7.6.0","status":"affected"},{"version":"7.4.4","status":"affected"},{"version":"7.2.7","status":"affected"}]}`,
			nvd:      []nvdRow{{cpe: "cpe:2.3:a:acme:gateway:7.2.7:*:*:*:*:*:*:*"}, {cpe: "cpe:2.3:a:acme:gateway:7.4.4:*:*:*:*:*:*:*"}, {cpe: "cpe:2.3:a:acme:gateway:7.6.0:*:*:*:*:*:*:*"}},
			vendor:   "Acme", product: "Gateway", version: "7.2.13", want: "none",
		},
		{
			name: "a third-party CNA's unaffected for what it did not test decides nothing", assigner: "VulnCheck",
			affected: `{"vendor":"OpenSSL","product":"OpenSSL","defaultStatus":"unaffected","versions":[{"lessThan":"4.0.1","status":"affected","version":"4.0.0","versionType":"semver"}]}`,
			vendor:   "OpenSSL", product: "OpenSSL", version: "3.5.0", want: "question",
		},
		{
			name: "a third-party CNA's one release with lessThanOrEqual equal to it is that release only", assigner: "hackerone",
			affected: `{"vendor":"nodejs","product":"node","defaultStatus":"unaffected","versions":[{"version":"26.3.0","status":"affected","lessThanOrEqual":"26.3.0","versionType":"semver"}]}`,
			nvd:      []nvdRow{{cpe: "cpe:2.3:a:nodejs:node.js:26.3.0:*:*:*:-:*:*:*"}},
			vendor:   "Node.js", product: "Node.js", offList: true, version: "22.19.0", want: "question",
		},
		{
			name: "no defaultStatus and outside the listed range: unknown, never not affected", assigner: "VulnCheck",
			affected: `{"vendor":"Acme","product":"Router","defaultStatus":"unknown","versions":[{"status":"affected","version":"7.0.0","versionType":"semver","lessThan":"7.23.4"}]}`,
			vendor:   "Acme", product: "Router", version: "7.25.2", want: "question",
		},
	}
	for i, c := range cases {
		for _, listed := range []bool{false, true} {
			if listed && c.offList {
				continue
			}
			t.Run(fmt.Sprintf("%s/listed=%v", c.name, listed), func(t *testing.T) {
				t.Parallel()
				s := newStack(t)
				ctx := t.Context()
				cve := fmt.Sprintf("CVE-2026-%d", 70100+i)
				raw := []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + cve + `","state":"PUBLISHED","assignerShortName":"` +
					c.assigner + `"},"containers":{"cna":{"affected":[` + c.affected + `]}}}`)
				rec, err := feeds.ParseCVERecord(raw, cve)
				if err != nil {
					t.Fatal(err)
				}
				err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
					if listed {
						kev := c.kev
						if kev[0] == "" {
							kev = [2]string{c.vendor, c.product}
						}
						if err := seedKEVRow(ctx, tx, cve, kev[0], kev[1], kev[1]+" flaw", time.Now().AddDate(0, 0, -3), false, false); err != nil {
							return err
						}
					}
					if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
						return err
					}
					for _, n := range c.nvd {
						if err := seedRange(ctx, tx, cve, n.cpe, n.startIncl, "", "", n.endExcl); err != nil {
							return err
						}
					}
					return storeRecordRanges(ctx, tx, cve, rec.Assigner, rec.Ranges)
				})
				if err != nil {
					t.Fatal(err)
				}
				r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{Vendor: c.vendor, Product: c.product, Version: c.version, Name: "dev", IP: "192.0.2.40"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.d.Findings.Reconcile(ctx); err != nil {
					t.Fatal(err)
				}
				got := "none"
				switch {
				case slices.Contains(openFindings(t, s, r.ID), cve):
					got = "open"
				case s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, r.ID, cve) > 0:
					got = "question"
				}
				if got != c.want {
					t.Errorf("%s %s: %s, want %s (rows %s)", c.product, c.version, got, c.want, rowsText(rec.Ranges))
				}
				if got == "open" && len(c.nvd) > 0 { // the record's range decided where NVD's did not: the finding names its origin
					var origin string
					if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT range_origin FROM fnd_finding WHERE asset_id = ? AND cve = ?`, r.ID, cve).Scan(&origin); err != nil || origin != feeds.OriginCNA {
						t.Errorf("%s %s: range origin %q %v, want cna", c.product, c.version, origin, err)
					}
				}
			})
		}
	}
}

// storeRecordRanges writes a parsed record's ranges and its assigner as the record pull stores them.
func storeRecordRanges(ctx context.Context, tx *sql.Tx, cve, assigner string, rows []feeds.Range) error {
	if _, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET assigner = ? WHERE cve = ?`, strings.ToLower(assigner), cve); err != nil {
		return err
	}
	for _, r := range rows {
		var plats any
		if len(r.Platforms) > 0 {
			b, err := json.Marshal(r.Platforms)
			if err != nil {
				return err
			}
			plats = string(b)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status, platforms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus, plats); err != nil {
			return err
		}
	}
	return nil
}

func rowsText(rows []feeds.Range) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "[%s %s/%s %q..%q|%q %s] ", r.Origin, r.Vendor, r.Product, r.StartIncl, r.EndIncl, r.EndExcl, r.DefaultStatus)
	}
	return b.String()
}

// A box upgraded from a reader that kept a third-party CNA's defaultStatus "unaffected" (before ranges-6) holds those rows until the
// whole list is read again, which can take hours or never come when the CVE records source is off. Feeds' migration 0003 stores them
// unknown at once, so from the first match pass a third party's exact list decides nothing negative: Notepad++ 8.6.5 against CSA's
// record of CVE-2026-3008 (affected 8.9.3 only) and AnyDesk 9.7.6 against VulnCheck's of CVE-2025-34499 (7.0.15 and 9.0.1) stay
// questions, as before ranges-6.
func TestCVE5Status_StoredBeforeTheReRead(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		cve, vendor, product, version string
		exact                         []string
	}{
		{"CVE-2026-3008", "notepad", "notepad", "8.6.5", []string{"8.9.3"}},
		{"CVE-2025-34499", "anydesk", "anydesk", "ad 9.7.6", []string{"7.0.15", "9.0.1"}}, // as the agent reads AnyDesk's version
	} {
		t.Run(c.cve, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			ctx := t.Context()
			err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
				if err := seedNVD(ctx, tx, c.cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
					return err
				}
				for _, v := range c.exact { // as the older reader stored the third party's list: unlisted versions "unaffected"
					if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, default_status)
VALUES (?, 'cna', '', ?, ?, '', ?, '', ?, '', 'unaffected')`, c.cve, c.vendor, c.product, v, v); err != nil {
						return err
					}
				}
				return applyFeedsMigration(ctx, tx, "0003_")
			})
			if err != nil {
				t.Fatal(err)
			}
			id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "pc-01"})
			if err != nil {
				t.Fatal(err)
			}
			items := []inventory.SoftwareItem{{Display: c.product, Vendor: c.vendor, Product: c.product, Version: c.version, Confidence: 0.9}}
			if err := s.d.Inventory.UpsertSoftware(ctx, id, items, "osquery"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.d.Findings.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			if q := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, id, c.cve); q != 1 {
				t.Errorf("%s %s: %d questions, want 1 (a third party's list proves nothing about the versions it did not list)", c.product, c.version, q)
			}
		})
	}
}

// applyFeedsMigration runs the up statements of the feeds migration whose file name starts with prefix on rows written after the
// test box migrated (a box's rows before the upgrade).
func applyFeedsMigration(ctx context.Context, tx *sql.Tx, prefix string) error {
	names, err := fs.Glob(feeds.Migrations, prefix+"*.sql")
	if err != nil || len(names) != 1 {
		return fmt.Errorf("feeds migration %s: %v: %w", prefix, names, err)
	}
	b, err := fs.ReadFile(feeds.Migrations, names[0])
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, string(b))
	return err
}

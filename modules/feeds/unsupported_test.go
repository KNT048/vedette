package feeds

import (
	"database/sql"
	"maps"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// A record tagged unsupported when assigned carries the CVE Program's mark at the start of its description, in any case; a record that
// only mentions support in its words, or has an empty description, is not tagged.
func TestStore_UnsupportedWhenAssignedReadsTheRecordsMark(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{
		"CVE-2026-4001": "** UNSUPPORTED WHEN ASSIGNED ** A flaw in Quillfeather Mail 2.x.",
		"CVE-2026-4002": "** Unsupported When Assigned ** A flaw in Quillfeather Mail 3.x.",
		"CVE-2026-4003": "A flaw in Quillfeather Mail; this release is no longer supported.",
		"CVE-2026-4004": "",
	}
	write(t, db, func(tx *sql.Tx) error {
		for cve, desc := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, description, updated_at) VALUES (?, ?, '2026-11-27T00:00:00.000Z')`, cve, desc); err != nil {
				return err
			}
		}
		return nil
	})
	got, err := NewStore(db).UnsupportedWhenAssigned(ctx, append(slices.Sorted(maps.Keys(rows)), "CVE-2026-4999"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CVE-2026-4001", "CVE-2026-4002"}; !slices.Equal(slices.Sorted(maps.Keys(got)), want) {
		t.Errorf("tagged %v, want %v", slices.Sorted(maps.Keys(got)), want)
	}
}

// Any exploitation signal of any age keeps a CVE out of findings' deferred group: an exploited-list entry, a vendor's exploited
// statement, a public exploit or scan template dated years before the reporting window, a source this box only just began to watch.
// A claim that does not pass its source's quality rule (an unverified proof of concept) is no signal.
func TestStore_ExploitationSignalledReadsEverySignalOfAnyAge(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	const recent = "2026-11-27T00:00:00.000Z"
	signals := []struct {
		cve, kind, source, firstSeen string
		qualifies                    bool
	}{
		{"CVE-2019-5002", SignalExploited, "vendor-psirt", "2019-03-01T00:00:00.000Z", true},
		{"CVE-2019-5003", SignalPublicExploit, "exploit-db", "2019-06-01T00:00:00.000Z", true},
		{"CVE-2018-5004", SignalPublicExploit, "metasploit", recent, true},
		{"CVE-2026-5005", SignalPublicExploit, "poc-in-github", recent, false},
	}
	all := []string{"CVE-2019-5001", "CVE-2019-5002", "CVE-2019-5003", "CVE-2018-5004", "CVE-2026-5005", "CVE-2026-5006"}
	write(t, db, func(tx *sql.Tx) error {
		for _, c := range all {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, published, description, updated_at) VALUES (?, '2018-01-01T00:00:00.000Z', '', ?)`, c, recent); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_source (id, builtin, name, kind, format, url, parser, created_at)
VALUES ('cf-own', 0, 'Own list', 'vulnerabilities', 'json', 'https://feeds.example.com/x.json', '{}', ?)`, recent); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, updated_at)
VALUES ('CVE-2019-5001', 'custom:cf-own', 'cf-own', 'Quillfeather', 'Mail', 'x', '2019-01-01', ?)`, recent); err != nil {
			return err
		}
		for _, s := range signals {
			if err := putSignal(ctx, tx, s.cve, s.kind, s.source, s.firstSeen, recent, s.qualifies, ""); err != nil {
				return err
			}
		}
		return nil
	})
	got, err := NewStore(db).ExploitationSignalled(ctx, all)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CVE-2018-5004", "CVE-2019-5001", "CVE-2019-5002", "CVE-2019-5003"}; !slices.Equal(slices.Sorted(maps.Keys(got)), want) {
		t.Errorf("signalled %v, want %v", slices.Sorted(maps.Keys(got)), want)
	}
}

package findings

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// loadByPair is the first finding of a (device, CVE) pair in the older read model, or an error wrapping ErrNotFound.
func loadByPair(ctx context.Context, q querier, assetID, cve string) (Record, error) {
	fs, err := queryFindings(ctx, q, `asset_id = ? AND cve = ?`, assetID, cve)
	if err != nil {
		return Record{}, err
	}
	if len(fs) == 0 {
		return Record{}, ErrNotFound
	}
	evs, err := eventsOf(ctx, q, `f.id = ?`, fs[0].ID)
	if err != nil {
		return Record{}, err
	}
	return record(fs[0], evs[fs[0].ID], ""), nil
}

// NewFinding is the finding a match creates, in the older read model: Transition's created finding for the match's detection.
func NewFinding(m Match, at time.Time) (Record, []Event) {
	f, evs, err := Transition(Finding{ID: "f-test", AssetID: "a-test", CVE: m.CVE}, Trigger{Kind: TrDetected, At: at, Detection: detectionOf(m, nil)})
	if err != nil {
		panic(err)
	}
	return record(f, evs, ""), evs
}

// Validate checks the finding behind a record.
func (r Record) Validate() error { return r.Row.Validate() }

// migrateWithInventory migrates core, inventory and findings, and adds test-only triggers that create the device and software line
// rows a finding or a question points at when the test's fake inventory did not: the findings tables have real foreign keys to
// inventory's, and these tests describe devices only through the fake ports.
func migrateWithInventory(t testing.TB, db *store.DB) {
	t.Helper()
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "inventory", FS: inventory.Migrations}, {Module: "findings", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	const ts = `'2026-01-01T00:00:00.000Z'`
	asset := func(col string) string {
		return `INSERT OR IGNORE INTO inv_asset (id, origin, first_seen, last_seen) VALUES (NEW.` + col + `, 'discovered', ` + ts + `, ` + ts + `);`
	}
	line := `INSERT OR IGNORE INTO inv_software (id, asset_id, product_key, line, display, vendor, product, source, confidence, seen_at, first_seen, last_seen)
		SELECT NEW.software_id, NEW.asset_id, 'test|' || NEW.software_id, '', NEW.software_id, 'test', NEW.software_id, 'agent', 1, ` + ts + `, ` + ts + `, ` + ts + `
		WHERE NEW.software_id IS NOT NULL;`
	for _, q := range []string{
		`CREATE TRIGGER test_fnd_finding_parents BEFORE INSERT ON fnd_finding BEGIN ` + asset("asset_id") + line + ` END`,
		`CREATE TRIGGER test_fnd_finding_parents_moved BEFORE UPDATE OF asset_id, software_id ON fnd_finding BEGIN ` + asset("asset_id") + line + ` END`,
		`CREATE TRIGGER test_fnd_question_parents BEFORE INSERT ON fnd_question BEGIN ` + asset("asset_id") + line + ` END`,
	} {
		if err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err }); err != nil {
			t.Fatal(err)
		}
	}
}

// writeTestFinding inserts f straight into fnd_finding inside tx, the unset detection and urgency columns filled with plain values.
func writeTestFinding(ctx context.Context, tx *sql.Tx, f Finding) error {
	if f.Basis == "" {
		f.Basis = DetectBannerVersion
	}
	if f.Verified == "" {
		f.Verified = VerifiedNo
	}
	if f.RangeOrigin == "" {
		f.RangeOrigin = RangeNVD
	}
	if f.Fix.Kind == "" {
		f.Fix.Kind = FixUnknown
	}
	if f.FixKey == "" {
		f.FixKey = FixKey("", f.Fix)
	}
	if f.Urgency == 0 {
		f.Urgency = 2
	}
	if f.State == "" {
		f.State = StateOpen
	}
	if f.State == StateHandled {
		if f.Via == "" {
			f.Via = ViaPerson
		}
		if f.ResolvedBy == "" {
			f.ResolvedBy = "it@acme.example"
		}
		if f.ResolvedAt.IsZero() {
			f.ResolvedAt = f.FirstSeen
		}
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	f.UrgencyAt, f.UpdatedAt = f.FirstSeen, f.LastSeen
	f.Detected = f.State == StateOpen || f.Detected
	return writeFinding(ctx, tx, f, true, nil)
}

// legacyRow is the finding of an older status, for the tests that seed rows by status.
func legacyRow(id, asset, cve string, st Status, first, resolved time.Time) Finding {
	f := Finding{ID: id, AssetID: asset, CVE: cve, FirstSeen: first, ResolvedAt: resolved}
	switch st {
	case StatusConfirmed:
		f.State, f.Verified, f.Basis = StateOpen, VerifiedScan, DetectScan
	case StatusSuspected:
		f.State = StateOpen
	case StatusRiskAccepted:
		f.State, f.Resolution, f.AcceptedUntil = StateHandled, ResolutionAccepted, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	default:
		f.State, f.Resolution = StateHandled, Resolution(st)
	}
	return f
}

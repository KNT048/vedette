package findings

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/findings/findingstest"
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

// migrateWithInventory migrates core, inventory and findings, with the test-only triggers that create the device and software line
// rows a finding or a question points at (findingstest.ParentRows): these tests describe devices only through the fake ports.
func migrateWithInventory(t testing.TB, db *store.DB) {
	t.Helper()
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "inventory", FS: inventory.Migrations}, {Module: "findings", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	findingstest.ParentRows(t, db)
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

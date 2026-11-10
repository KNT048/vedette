package mitigation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// A box has no way yet to load packs (the Loader needs the update signature Verifier, core/updates), so the GUI checks on a
// real box (make dev-api, web/e2e/qa/real-box.mjs) have no recommendation to show. This puts the packs of testdata/ into
// mit_pack of a box database, as a developer's seed: it does not go through Loader and writes no audit row. It runs only when
// VEDETTE_SEED_PACKS_DB names the database file of a box that has been started once (so its migrations ran), absolute or
// relative to the repo root (go test itself runs in this directory):
//
//	VEDETTE_SEED_PACKS_DB=.dev/vedette.db go test ./modules/mitigation -run TestGUIReal_SeedBoxWithTestdataPacks
func TestGUIReal_SeedBoxWithTestdataPacks(t *testing.T) {
	path := os.Getenv("VEDETTE_SEED_PACKS_DB")
	if path == "" {
		t.Skip("set VEDETTE_SEED_PACKS_DB to a box database to seed it")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join("..", "..", path) // go test runs in the package directory; a relative path is relative to the repo root
	}
	ctx := context.Background()
	db, err := store.Open(ctx, path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	files, err := filepath.Glob("testdata/CVE-*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no pack files in testdata: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // a fixed glob under testdata
		if err != nil {
			t.Fatal(err)
		}
		var p packDoc
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		body, err := json.Marshal(packBody{Sources: p.Sources, Patch: p.Patch, Workaround: p.Workaround, Firewall: p.Firewall, Checklist: p.Checklist, Recheck: p.Recheck})
		if err != nil {
			t.Fatal(err)
		}
		var comp any
		if p.Compromise != nil {
			b, err := json.Marshal(p.Compromise)
			if err != nil {
				t.Fatal(err)
			}
			comp = string(b)
		}
		err = db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO mit_pack (cve, body, compromise, confirmed_by, confirmed_at, drafted_with, pack_version) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				p.CVE, string(body), comp, p.ConfirmedBy, store.FormatTS(p.ConfirmedAt), p.DraftedWith, "gui-real-seed")
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Logf("seeded %s", p.CVE)
	}
}

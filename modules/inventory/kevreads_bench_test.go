package inventory_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// storeKEV is the inventory.KEV the box wires (cmd/vedette feedsKEV), over a real feeds store.
type storeKEV struct{ st *feeds.Store }

func (k storeKEV) Products(ctx context.Context) (string, []inventory.KEVProduct, error) {
	version, list, err := k.st.KevProducts(ctx)
	if err != nil {
		return "", nil, err
	}
	out := make([]inventory.KEVProduct, len(list))
	for i, p := range list {
		out[i] = inventory.KEVProduct{Vendor: p.Vendor, Product: p.Product, Count: p.Count}
	}
	return version, out, nil
}

func (k storeKEV) CVEIndex(ctx context.Context) (inventory.KEVIndex, error) {
	idx, err := k.st.KevIndex(ctx)
	if err != nil {
		return nil, err
	}
	return idx.CVEs, nil
}

// BenchmarkDetail_ServerWithManyPackages times the page of a device with 922 packages, 60 of them products of the exploited list,
// against a migrated store holding 1,500 exploited-list entries (about the size of the CISA list).
func BenchmarkDetail_ServerWithManyPackages(b *testing.B) {
	const lines, entries, listed = 922, 1500, 60
	ctx := b.Context()
	db := storetest.Migrated(b, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: inventory.Migrations},
		storetest.Migration{Module: "feeds", FS: feeds.Migrations})
	st := feeds.NewStore(db)
	if err := st.SeedBuiltins(ctx, time.Now()); err != nil {
		b.Fatal(err)
	}
	now := store.FormatTS(time.Now().UTC())
	desc := strings.Repeat("A flaw in the product lets a remote attacker run code. ", 6)
	err := db.Write(ctx, func(tx *sql.Tx) error {
		for i := range entries {
			cve := fmt.Sprintf("CVE-2025-%05d", 10000+i)
			vendor, product := fmt.Sprintf("Vendor%03d", i%500), fmt.Sprintf("Product%04d", i)
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, updated_at) VALUES (?, ?)`, cve, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, description, required_action, links, date_added, updated_at)
VALUES (?, 'cisa', 'cisa-kev', ?, ?, ?, ?, 'Apply the vendor update.', '["https://example.com/advisory"]', '2025-01-02', ?)`,
				cve, vendor, product, vendor+" "+product+" flaw", desc, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	svc, err := inventory.New(inventory.Config{DB: db, Audit: audit.New(nil), Events: &recorder{}, Findings: fakeFindings{}, KEV: storeKEV{st}})
	if err != nil {
		b.Fatal(err)
	}
	items := make([]observe.Software, lines)
	for i := range items {
		vendor, product := fmt.Sprintf("debian-pkg%04d", i), fmt.Sprintf("pkg%04d", i)
		if i < listed { // a product of the exploited list
			vendor, product = fmt.Sprintf("Vendor%03d", i%500), fmt.Sprintf("Product%04d", i)
		}
		items[i] = observe.Software{Display: product, Vendor: vendor, Product: product, Version: "1.0-1", Confidence: 1, Packaged: true}
	}
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.90")}
	if err := svc.ReplaceSoftware(ctx, hint, observe.Osquery, nil, items); err != nil {
		b.Fatal(err)
	}
	addrs, err := svc.AddressMap(ctx)
	if err != nil {
		b.Fatal(err)
	}
	id := addrs[hint.IP.String()]
	d, err := svc.Detail(ctx, id)
	if err != nil {
		b.Fatal(err)
	}
	withCVEs := 0
	for _, l := range d.Asset.Software {
		if len(l.KevCVEs) > 0 {
			withCVEs++
		}
	}
	if len(d.Asset.Software) != lines || withCVEs != listed {
		b.Fatalf("%d lines, %d with exploited CVEs; want %d and %d", len(d.Asset.Software), withCVEs, lines, listed)
	}
	for b.Loop() {
		if _, err := svc.Detail(ctx, id); err != nil {
			b.Fatal(err)
		}
	}
}

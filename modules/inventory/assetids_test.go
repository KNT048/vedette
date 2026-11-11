package inventory_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// AssetIDs is the unfiltered, uncapped read a reconcile compares against (findings, D-144): every device of every kind, sorted,
// beyond MaxListed. An empty inventory is an empty answer, never an error.
func TestAssetIDsListsEveryDeviceOfEveryKind(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if ids, err := e.svc.AssetIDs(e.ctx()); len(ids) != 0 || err != nil {
		t.Fatalf("empty inventory: %v %v", ids, err)
	}
	fw := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.1"})
	nas := e.addDevice(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager", IP: "192.168.10.21"})
	e.exec(`WITH RECURSIVE c(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM c WHERE n < ?)
INSERT INTO inv_asset (id, kind, origin, first_seen, last_seen) SELECT 'bulk-' || n, 'unknown', 'manual', '2026-11-09T10:00:00.000Z', '2026-11-09T10:00:00.000Z' FROM c`, inventory.MaxListed+9)
	ids, err := e.svc.AssetIDs(e.ctx())
	if err != nil || len(ids) != inventory.MaxListed+10+2 {
		t.Fatalf("%d ids, want %d (no cap, every kind): %v", len(ids), inventory.MaxListed+12, err)
	}
	if !slices.Contains(ids, fw) || !slices.Contains(ids, nas) || !slices.IsSorted(ids) {
		t.Fatal("a device is missing or the ids are not sorted")
	}
}

// Kinds is the list of every kind a device can have: it must equal the CHECK of inv_asset.kind, or a read that filters on Kinds
// (DevicesOfKind with Kinds) silently misses devices of a kind added to the schema only.
func TestKindsEqualsTheSchemaCheck(t *testing.T) {
	t.Parallel()
	sqlText, err := os.ReadFile("migrations/sqlite/0001_inventory.sql")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)kind\s+TEXT\s+NOT NULL DEFAULT 'unknown' CHECK \(kind IN \(([^)]*)\)\)`).FindSubmatch(sqlText)
	if m == nil {
		t.Fatal("the inv_asset.kind CHECK was not found: update this test with the schema")
	}
	var schema []string
	for _, k := range strings.Split(string(m[1]), ",") {
		schema = append(schema, strings.Trim(strings.TrimSpace(k), "'"))
	}
	got, want := slices.Sorted(slices.Values(inventory.Kinds)), slices.Sorted(slices.Values(schema))
	if !slices.Equal(got, want) {
		t.Fatalf("inventory.Kinds %v != schema CHECK %v", got, want)
	}
}

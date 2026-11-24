package core_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// GET /scanning/history lists the runs of every source newest first, at most 200, and an empty list without a source.
func TestScanningHistory_NewestFirstCappedAndEmptyWithoutSource(t *testing.T) {
	db := migrated(t)
	reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: "test", Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	runs := []core.HistoryRun{}
	for i := range 205 {
		runs = append(runs, core.HistoryRun{ID: fmt.Sprintf("r%03d", i), Kind: "device", Engine: "nmap-versions", Trigger: "person", Label: "10.142.0.20", StartedAt: base.Add(time.Duration(i) * time.Minute), Outcome: "ok", Text: "Scanned 10.142.0.20"})
	}
	mk := func(src func(context.Context, string) ([]core.HistoryRun, error)) *core.ScanningHandlers {
		h, err := core.NewScanningHandlers(core.ScanningConfig{DB: db, Reg: reg, Audit: audit.New(nil), Safety: &fakeSafety{}, History: src})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	var asked []string
	src := func(_ context.Context, asset string) ([]core.HistoryRun, error) {
		asked = append(asked, asset)
		return runs, nil
	}
	got, err := mk(src).ScanningGetScanningHistory(t.Context(), oas.ScanningGetScanningHistoryParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 200 || got.Items[0].ID != "r204" || got.Items[199].ID != "r005" {
		t.Fatalf("items: %d, first %s, last %s", len(got.Items), got.Items[0].ID, got.Items[len(got.Items)-1].ID)
	}
	if got.Items[0].TargetID.Null != true || got.Items[0].EndedAt.Null != true || got.Items[0].Text != "Scanned 10.142.0.20" {
		t.Errorf("item: %+v", got.Items[0])
	}
	// ?asset= hands the device to the source, which caps its runs per kind: core does not cut them at 200
	dev, err := mk(src).ScanningGetScanningHistory(t.Context(), oas.ScanningGetScanningHistoryParams{Asset: oas.NewOptString("a-bn340")})
	if err != nil || len(dev.Items) != 205 || asked[0] != "" || asked[1] != "a-bn340" {
		t.Errorf("asset: %d items, sources asked %q, %v", len(dev.Items), asked, err)
	}
	empty, err := mk(nil).ScanningGetScanningHistory(t.Context(), oas.ScanningGetScanningHistoryParams{})
	if err != nil || empty.Items == nil || len(empty.Items) != 0 {
		t.Errorf("no source: %+v %v", empty, err)
	}
}

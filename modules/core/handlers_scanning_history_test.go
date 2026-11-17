package core_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// kien G7a: GET /scanning/history lists the runs of every source newest first, at most 200, and an empty list without a source.
func TestScanningHistory_NewestFirstCappedAndEmptyWithoutSource(t *testing.T) {
	db := migrated(t)
	reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: "test", Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	runs := []core.HistoryRun{}
	for i := range 205 {
		runs = append(runs, core.HistoryRun{ID: fmt.Sprintf("r%03d", i), Kind: "device", Engine: "nmap-versions", Trigger: "person", Label: "192.168.18.20", StartedAt: base.Add(time.Duration(i) * time.Minute), Outcome: "ok", Text: "Scanned 192.168.18.20"})
	}
	mk := func(src func(context.Context) ([]core.HistoryRun, error)) *core.ScanningHandlers {
		h, err := core.NewScanningHandlers(core.ScanningConfig{DB: db, Reg: reg, Audit: audit.New(nil), Safety: &fakeSafety{}, History: src})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	got, err := mk(func(context.Context) ([]core.HistoryRun, error) { return runs, nil }).ScanningGetScanningHistory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 200 || got.Items[0].ID != "r204" || got.Items[199].ID != "r005" {
		t.Fatalf("items: %d, first %s, last %s", len(got.Items), got.Items[0].ID, got.Items[len(got.Items)-1].ID)
	}
	if got.Items[0].TargetID.Null != true || got.Items[0].EndedAt.Null != true || got.Items[0].Text != "Scanned 192.168.18.20" {
		t.Errorf("item: %+v", got.Items[0])
	}
	empty, err := mk(nil).ScanningGetScanningHistory(t.Context())
	if err != nil || empty.Items == nil || len(empty.Items) != 0 {
		t.Errorf("no source: %+v %v", empty, err)
	}
}

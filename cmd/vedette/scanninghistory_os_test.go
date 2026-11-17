package main

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/observe"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// A device check's words read the OS the device page shows from the inventory's own ranking (DeviceRefs): a scan guess alone is
// said as the guess; once the device states its OS over SNMP, the same check names that OS and says the guess was not used.
func TestScanningHistoryReadsTheOSThePageShows(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d := deps{Log: log, DB: db, Audit: audit.New(nil), Clock: time.Now, Bus: events.NewBus(log)}
	d.Inventory = newInventory(&d)
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.10.47")}
	record := func(source observe.Source, value string, conf float64) {
		t.Helper()
		if err := d.Inventory.Record(context.WithoutCancel(ctx), []observe.Observation{{AssetHint: hint, Field: observe.OS, Value: value, Source: source, Confidence: conf}}); err != nil {
			t.Fatal(err)
		}
	}
	record(observe.Nmap, "Network switch OS (8.5 - 11.2)", 0.95)
	ids, err := d.Inventory.AssetIDs(ctx)
	if err != nil || len(ids) != 1 {
		t.Fatalf("devices: %v %v", ids, err)
	}
	id := ids[0]
	end := "2026-11-17T03:19:00.000Z"
	j := sensoractive.JobRow{JobHead: sensoractive.JobHead{ID: "j", Kind: "device", Status: "done", Reason: "check_now", StartedAt: "2026-11-17T03:18:00.000Z", FinishedAt: &end, Targets: 1},
		AssetID: id, Probes: []sensoractive.JobProbe{{Targets: "192.168.10.47", Result: "ok: 1 hosts up"}},
		Found: &sensoractive.DeviceFound{Reach: "top1000", OS: "Network switch OS (8.5 - 11.2)"}}
	text := func() string {
		t.Helper()
		shown, err := scanningEngines{d: d}.osShown(ctx, []sensoractive.JobRow{j})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := jobHistory(j, shown)
		return r.Text
	}
	if got, want := text(), "Scanned 192.168.10.47: no open port; OS guess Network switch OS (8.5 - 11.2)"; got != want {
		t.Fatalf("guess on the page:\n got %q\nwant %q", got, want)
	}
	record(observe.SNMP, "NetOS 15.1R7.9", 0.9)
	if got, want := text(), "Scanned 192.168.10.47: no open port; OS NetOS 15.1R7.9, as the device states over SNMP (scan guess not used)"; got != want {
		t.Fatalf("SNMP on the page:\n got %q\nwant %q", got, want)
	}
}

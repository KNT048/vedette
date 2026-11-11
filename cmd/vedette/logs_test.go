package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

// The logs module on the real wiring: its sources are named after the inventory device with the same IP, lines go to
// logs.db (a file of its own, not the main database), and they come out in the "device_logs" log export (D-132).
func TestWiringLogsSourcesLinesAndExport(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := logsService(*s.d)
	src, err := svc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.30.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	if src.AssetID == nil || *src.AssetID != r.ID || src.AssetName == nil || *src.AssetName != "fw-hq" {
		t.Fatalf("source %+v: the device with the same IP is %s", src, r.ID)
	}
	if res, err := svc.Ingest(ctx, []logs.Line{{SourceID: src.ID, At: time.Now().Add(-time.Second), Text: "type=traffic srcip=10.0.0.1"}}); err != nil || res.Stored != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if s.count(`SELECT count(*) FROM sqlite_master WHERE name = 'logs_events'`) != 0 {
		t.Fatal("logs_events is in the main database")
	}
	if !s.d.Logs.Has("device_logs") {
		t.Fatal("device_logs has no log source")
	}
	var out strings.Builder
	if err := svc.ExportDeviceLogs(ctx, time.Time{}, time.Time{}, &out); err != nil || !strings.Contains(out.String(), `"line":"type=traffic srcip=10.0.0.1"`) {
		t.Fatalf("%q %v", out.String(), err)
	}
	if jobs := logsJobs(*s.d); len(jobs) != 1 || jobs[0].Module != "logs" || jobs[0].Name != "purge" {
		t.Fatalf("jobs = %+v", jobs)
	}
	box, err := (logsBox{*s.d}).Info(ctx)
	if err != nil || box.Hostname == "" || box.IP != nil || box.LAN != nil {
		t.Fatalf("no LAN range is declared yet: %+v %v", box, err)
	}
}

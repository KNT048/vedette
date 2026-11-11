package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
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
	if jobs := logsJobs(*s.d); len(jobs) != 4 || jobs[0].Module != "logs" || jobs[0].Name != "purge" || jobs[1].Module != "logs" || jobs[1].Name != "syslog" || jobs[1].Housekeeping || jobs[2].Name != "anomaly" || jobs[2].Housekeeping || jobs[3].Name != "siem" || jobs[3].Housekeeping {
		t.Fatalf("jobs = %+v", jobs)
	}
	box, err := (logsBox{*s.d}).Info(ctx)
	if err != nil || box.Hostname == "" || box.IP != nil || box.LAN != nil {
		t.Fatalf("no LAN range is declared yet: %+v %v", box, err)
	}
}

// -syslog-port reaches the listener: the job of the real wiring takes syslog on that port and the line is searchable.
func TestWiringLogsSyslogListensOnTheConfiguredPort(t *testing.T) {
	t.Parallel()
	hold, err := listenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := hold.LocalAddr().(*net.UDPAddr).Port
	_ = hold.Close()
	s := newStackWith(t, func(d *deps) { d.SyslogPort = port })
	svc := logsService(*s.d)
	if _, err := svc.AddSource(t.Context(), "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-LAB", SenderIP: "127.0.0.1", Proto: "udp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- logsJobs(*s.d)[1].Run(ctx) }()
	defer func() {
		cancel()
		<-done //nolint:errcheck // cancelled run
	}()
	c, err := dialCtx("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	deadline := time.After(10 * time.Second)
	for {
		_, _ = c.Write([]byte("<189>devname=fg-lab logid=0000000013")) // until the socket is up the datagram is refused or lost: repeat
		v, err := svc.Events(ctx, logs.EventQuery{Window: "1h", Q: "fg-lab"})
		if err != nil {
			t.Fatal(err)
		}
		if v.Total > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("no line arrived on the configured port")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Network helpers with a context, as the linter wants (loopback only).
func dialCtx(network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(context.Background(), network, addr)
}

func listenPacket(network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), network, addr)
}

// D-210: logs' NeverCount lists the box's own addresses from the sources the box has: the -hosts literals and the container's addresses
// (an install without vedette-host has nothing more to ask; a host that has not answered is an error, which logs answers by keeping its last set).
func TestLogsNeverCountListsTheBox(t *testing.T) {
	t.Parallel()
	d := &deps{Hosts: []string{"198.51.100.77", "[2001:db8::77]", "box.example"}}
	got, err := logsNeverCount(d)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, a := range got {
		have[a.String()] = true
	}
	if !have["198.51.100.77"] || !have["2001:db8::77"] || have["box.example"] {
		t.Fatalf("%v", got)
	}
}

// L4 on the real wiring: a FortiGate line from an inventory device to an address that a feed lists is a hit with the device named,
// shown in the digest, announced on the bus, exported as "known_bad" and found by the evidence adapter of response; with the feeds module off
// the port says so and no hit is made (PRE-3).
func TestWiringLogsIocHitsFromTheFeedsModule(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("feeds", true)
	s.setModule("logs", true)
	dev, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	var feedID, feedName string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id, name FROM feeds_source ORDER BY id LIMIT 1`).Scan(&feedID, &feedName); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc (id, type, value, first_seen, last_seen) VALUES ('ioc-t1', 'ip', '185.220.101.47', ?1, ?1), ('ioc-t2', 'domain', 'bad.example.net', ?1, ?1)`, stamp); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc_source (ioc_id, source_id, last_seen, confidence) VALUES ('ioc-t1', ?1, ?2, 0.4), ('ioc-t2', ?1, ?2, 0.8)`, feedID, stamp)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var got []logs.BadAddressEvent
	var ioc []logs.IocHit
	s.d.Bus.Subscribe(logs.EventBadAddress, func(_ context.Context, e events.Event) error {
		got = append(got, e.Data.(logs.BadAddressEvent))
		return nil
	})
	s.d.Bus.Subscribe(logs.EventIocHit, func(_ context.Context, e events.Event) error { ioc = append(ioc, e.Data.(logs.IocHit)); return nil })

	svc := logsService(*s.d)
	src, err := svc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.30.1", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	line := func(local, dst string) string {
		return `date=2026-11-09 time=10:20:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=` + local + ` dstip=` + dst + ` dstport=443 action="accept"`
	}
	in := []logs.Line{
		{SourceID: src.ID, At: time.Now(), Text: line("192.168.30.1", "185.220.101.47")},
		{SourceID: src.ID, At: time.Now(), Text: line("192.168.30.1", "185.220.101.48")}, // not listed
		{SourceID: src.ID, At: time.Now(), Text: line("192.168.30.1", "10.1.1.1")},       // private
	}
	if res, err := svc.Ingest(ctx, in); err != nil || res.Stored != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	d, err := svc.Digest(ctx)
	if err != nil || len(d.BadConnections) != 1 {
		t.Fatalf("%+v %v", d.BadConnections, err)
	}
	h := d.BadConnections[0]
	if h.Dest != "185.220.101.47" || h.DestKind != "ip" || h.Confidence != 0.4 || len(h.Feeds) != 1 || h.Feeds[0] != feedName || h.AssetID == nil || *h.AssetID != dev.ID || h.SeenVia != "syslog:FW-HQ" {
		t.Fatalf("hit %+v (feed %s, device %s)", h, feedName, dev.ID)
	}
	if len(got) != 1 || len(ioc) != 1 || got[0].ID != h.ID || ioc[0].ID != h.ID || got[0].Target != "ioc:185.220.101.47" {
		t.Fatalf("events %+v %+v", got, ioc)
	}
	// the export source
	if !s.d.Logs.Has("known_bad") {
		t.Fatal("known_bad has no log source")
	}
	var out strings.Builder
	if err := svc.ExportKnownBad(ctx, time.Time{}, time.Time{}, &out); err != nil || !strings.Contains(out.String(), `"dest":"185.220.101.47"`) || !strings.Contains(out.String(), `"feeds":["`+feedName+`"]`) {
		t.Fatalf("%q %v", out.String(), err)
	}
	// response's evidence port (not wired yet: the adapter is the part that is ours)
	ev := logsIocEvidence(svc, func() bool { return true })
	ref, ok, err := ev(ctx, h.ID)
	if err != nil || !ok || ref.ID != h.ID || len(ref.Relates) != 2 || ref.Relates[0] != "192.168.30.1" || ref.Relates[1] != "185.220.101.47" || !strings.Contains(ref.Summary, "fw-hq") {
		t.Fatalf("%+v %v %v", ref, ok, err)
	}
	if _, ok, err := ev(ctx, "ih-unknown"); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if _, ok, _ := logsIocEvidence(svc, func() bool { return false })(ctx, h.ID); ok {
		t.Fatal("evidence with the module off")
	}
	// the port: a listed domain, a name no feed lists, and the module off
	f := logsFeeds{s.d}
	if l, ok, err := f.Lookup(ctx, "domain", "Bad.Example.NET"); err != nil || !ok || l.Confidence != 0.8 {
		t.Fatalf("%+v %v %v", l, ok, err)
	}
	if _, ok, err := f.Lookup(ctx, "domain", "fine.example.org"); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if _, ok, err := f.Lookup(ctx, "ip", "10.0.0.1"); ok || err != nil {
		t.Fatalf("a private address is listed: %v %v", ok, err)
	}
	s.setModule("feeds", false)
	if _, _, err := f.Lookup(ctx, "ip", "185.220.101.47"); !errors.Is(err, logs.ErrFeedsOff) {
		t.Fatalf("feeds off: %v", err)
	}
	before := len(got)
	if _, err := svc.Ingest(ctx, []logs.Line{{SourceID: src.ID, At: time.Now(), Text: line("192.168.30.9", "185.220.101.47")}}); err != nil {
		t.Fatal(err)
	}
	if len(got) != before {
		t.Fatal("a hit with the feeds module off")
	}
}

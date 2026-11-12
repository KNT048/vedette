package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/response"
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

// #266 item 2: the TLS seam. On a box that serves TLS, deps.SyslogTLS is the HTTPS listener's own certificate source (a renewal is picked
// up: it is the same GetCertificate), without the HTTPS-only ALPN, TLS 1.2 or later, no client certificate; on a loopback box it is nil.
func TestSyslogTLSFollowsTheHTTPSCertificateAndIsNilOnLoopback(t *testing.T) {
	t.Parallel()
	if got := syslogTLS(nil); got != nil {
		t.Fatalf("no HTTPS TLS must give no syslog TLS, got %v", got)
	}
	dir := t.TempDir()
	cfg, _, _, renew, err := testTransport(t, options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "box.example"})
	if err != nil || cfg == nil || renew == nil {
		t.Fatalf("transport: cfg=%v renew=%v err=%v", cfg, renew, err)
	}
	got := syslogTLS(cfg)
	if got == nil || got == cfg {
		t.Fatalf("syslogTLS = %p, want a clone of %p", got, cfg)
	}
	if got.GetCertificate == nil || len(got.Certificates) != 0 {
		t.Fatal("the box-made pair must be served through GetCertificate, so a renewal needs no restart")
	}
	c1, err := got.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || c1 != c2 {
		t.Fatalf("the syslog listener and HTTPS serve different certificates (%p, %p, %v)", c1, c2, err)
	}
	if got.NextProtos != nil || got.MinVersion < tls.VersionTLS12 || got.ClientAuth != tls.NoClientCert {
		t.Errorf("NextProtos=%v MinVersion=%x ClientAuth=%v", got.NextProtos, got.MinVersion, got.ClientAuth)
	}
	if cfg.NextProtos == nil {
		t.Error("cloning must not change the HTTPS configuration")
	}
	lo, _, _, _, err := testTransport(t, options{db: filepath.Join(dir, "w.db"), listen: "127.0.0.1:8443"})
	if err != nil || syslogTLS(lo) != nil {
		t.Fatalf("a loopback box has no certificate: %v", err)
	}
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

// D-214: deps.SyslogTLS reaches logs: with it a TLS source is accepted, without it (a loopback or dev box) it is refused.
func TestWiringLogsTLSSourcesFollowDepsSyslogTLS(t *testing.T) {
	t.Parallel()
	in := logs.Input{Kind: "fortigate", Name: "FW-TLS", SenderIP: "192.168.30.9", Proto: "tls", Port: 6514}
	plain := logsService(*newStack(t).d)
	if _, err := plain.AddSource(t.Context(), "admin@acme.example", in); err == nil || !strings.Contains(err.Error(), "HTTPS certificate") {
		t.Fatalf("a box with no TLS config must refuse proto tls: %v", err)
	}
	withTLS := logsService(*newStackWith(t, func(d *deps) { d.SyslogTLS = &tls.Config{MinVersion: tls.VersionTLS12} }).d)
	if src, err := withTLS.AddSource(t.Context(), "admin@acme.example", in); err != nil || src.Proto != "tls" {
		t.Fatalf("a box with a TLS config must accept proto tls: %+v %v", src, err)
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
	s.setModule("response", true) // #376: the hit is also response's ioc_connection event and an AI's ioc_hit evidence
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
	if err != nil || len(d.BadConnections) != 1 || !d.IOCMatching {
		t.Fatalf("%+v %v matching=%v", d.BadConnections, err, d.IOCMatching)
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
	// #376 (D-335): the same hit is an ioc_connection event of response, through the real bus, with the trigger fields filled
	if n := s.count(`SELECT count(*) FROM resp_events WHERE id = ? AND trigger = 'ioc_connection' AND asset_id = ? AND fields LIKE '%"dest_ip":"185.220.101.47"%' AND fields LIKE '%"src_ip":"192.168.30.1"%' AND fields LIKE '%"confidence":"0.4"%'`, "ioc:"+h.ID, dev.ID); n != 1 {
		t.Fatalf("the hit is not a response event (%d)", n)
	}
	// #376 (D-337): and it is evidence an AI proposal can cite through the wired port: found, so the gate after evidence answers
	body := response.ProposeBody{Trigger: "ioc_connection", ActionID: "blocklist_add", Params: map[string]string{"ip": "185.220.101.47"}, Confidence: 0.5,
		Evidence: []response.ProposedEvidence{{Kind: "ioc_hit", ID: h.ID}}, Why: "A device talked to a listed address."}
	if res, err := s.d.Response.Propose(ctx, body); err != nil || res.Outcome != response.OutcomeSuggestion {
		t.Fatalf("a proposal citing the hit: %+v %v", res, err)
	}
	s.setModule("logs", false)
	_, err = s.d.Response.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_invalid")
	s.setModule("logs", true)
	// response's evidence port, the adapter itself
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
	// M3: a feed that was switched off is not pulled and not pruned, so its listings are stale: they are no hit
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE feeds_source SET enabled = 0 WHERE id = ?`, feedID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := f.Lookup(ctx, "ip", "185.220.101.47"); ok || err != nil {
		t.Fatalf("a listing of a disabled feed is a hit: %v %v", ok, err)
	}
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE feeds_source SET enabled = 1 WHERE id = ?`, feedID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.Lookup(ctx, "ip", "185.220.101.47"); !ok {
		t.Fatal("the listing is not found again when the feed is on")
	}
	s.setModule("feeds", false)
	if f.On() {
		t.Fatal("On with the feeds module off")
	}
	if d, err := svc.Digest(ctx); err != nil || len(d.BadConnections) != 0 || d.IOCMatching {
		t.Fatalf("the digest shows hits, or says it can match, with the feeds module off: %v %+v %v", err, d.BadConnections, d.IOCMatching)
	}
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

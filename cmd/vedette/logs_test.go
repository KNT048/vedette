package main

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"strconv"
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
	if jobs := logsJobs(*s.d); len(jobs) != 2 || jobs[0].Module != "logs" || jobs[0].Name != "purge" || jobs[1].Module != "logs" || jobs[1].Name != "syslog" || jobs[1].Housekeeping {
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
	cfg, _, _, renew, err := transport(options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "box.example"})
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
	lo, _, _, _, err := transport(options{db: filepath.Join(dir, "w.db"), listen: "127.0.0.1:8443"})
	if err != nil || syslogTLS(lo) != nil {
		t.Fatalf("a loopback box has no certificate: %v", err)
	}
}

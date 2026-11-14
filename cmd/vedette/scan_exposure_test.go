package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/surface"
)

// D-229, exposure INV-12: exposure scans with the scan module's runner, which follows that module's switch. Off (the default), the
// answer is 409 module_off and nothing is probed; on, it scans, and only what exposure's own public-address rule allows; switched
// off while a scan runs, the scan stops and answers module_off (SYS-5).
func TestExposureRunnerFollowsTheScanModule(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	toggle := func(on bool) {
		t.Helper()
		var ch modreg.Change
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			if on {
				ch, err = reg.Enable(ctx, tx, "admin@acme.example", "scan", true)
			} else {
				ch, err = reg.Disable(ctx, tx, "admin@acme.example", "scan")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		reg.Publish(ch)
	}
	r := scanRunner(deps{Log: log, DB: db, Reg: reg})
	private := exposure.ScanTarget{ID: "xt-1", Kind: exposure.KindIP, Value: "10.0.0.1", User: "operator@acme.example"}
	wantOff := func(err error) {
		t.Helper()
		var ae *exposure.APIError
		if !errors.As(err, &ae) || ae.HTTP != 409 || ae.Code != "module_off" {
			t.Fatalf("want 409 module_off, got %v", err)
		}
	}
	_, err = r.Scan(ctx, private)
	wantOff(err)
	toggle(true)
	// on: a private address is refused by exposure's rule before anything is dialed
	if _, err := r.Scan(ctx, private); !errors.Is(err, surface.ErrNotPublic) {
		t.Fatalf("scan module on, private IP: %v", err)
	}
	// switched off while a scan runs: it is stopped, and nothing it found is kept
	blocking := &fakeSurface{started: make(chan struct{})}
	r.(*exposureRunner).scan = blocking //nolint:forcetypeassert // scanRunner's own type
	done := make(chan error, 1)
	go func() {
		_, err := r.Scan(ctx, exposure.ScanTarget{ID: "xt-2", Kind: exposure.KindIP, Value: "203.0.113.10"})
		done <- err
	}()
	<-blocking.started
	toggle(false)
	wantOff(<-done)
}

type fakeSurface struct {
	res     surface.Result
	err     error
	domain  string
	ip      netip.Addr
	allowed []string
	started chan struct{} // set: the scan blocks until its context ends
}

func (f *fakeSurface) Domain(ctx context.Context, d string, may func(context.Context, netip.Addr) bool) (surface.Result, error) {
	f.domain = d
	for _, a := range []string{"203.0.113.10", "203.0.113.11"} {
		if may(ctx, netip.MustParseAddr(a)) {
			f.allowed = append(f.allowed, a)
		}
	}
	return f.res, f.err
}

func (f *fakeSurface) IP(ctx context.Context, ip netip.Addr) (surface.Result, error) {
	f.ip = ip
	if f.started != nil {
		close(f.started)
		<-ctx.Done()
		return surface.Result{}, ctx.Err()
	}
	return f.res, f.err
}

// The surface result in exposure's shape, the port-scan question handed to exposure as the person who asked, and the failures of a
// scan as the person reads them.
func TestExposureRunnerResult(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("203.0.113.10")
	f := &fakeSurface{res: surface.Result{
		Hosts:    []surface.Host{{Name: "acme.example", IP: ip, Source: "dns", Addrs: []surface.Addr{{IP: ip, Class: "box"}, {IP: netip.MustParseAddr("2606:4700::5"), Class: "public"}}}},
		Wordlist: surface.WordlistNoAnswer, Unresolved: []string{"old.acme.example", "vpn.acme.example"},
		Ports: []surface.Port{{IP: ip, Port: 443, Service: "https", Product: "FortiGate"}, {IP: ip, Port: 3000, Service: "http"}},
		Admin: []surface.Admin{{URL: "https://acme.example", Product: "FortiGate", IP: ip, Port: 443, Danger: true}, {URL: "http://acme.example:3000", Product: "Grafana", IP: ip, Port: 3000}},
		Certs: []surface.Cert{{Host: "acme.example", Issuer: "R11", NotAfter: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)}},
	}}
	var asked []string
	scope := func(_ context.Context, actor string, a netip.Addr) (bool, error) {
		asked = append(asked, actor+" "+a.String())
		if a.String() == "203.0.113.11" {
			return true, errors.New("the database is gone") // an error never allows a port scan
		}
		return true, nil
	}
	r := &exposureRunner{on: func() bool { return true }, scan: f, scope: scope, log: slog.New(slog.DiscardHandler), running: map[*int]context.CancelCauseFunc{}}
	c, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "xt-1", Kind: exposure.KindDomain, Value: "acme.example", User: "op@acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	if f.domain != "acme.example" || len(c.Hosts) != 1 || !reflect.DeepEqual(c.Hosts[0], exposure.HostRow{Name: "acme.example", IP: "203.0.113.10", Source: "dns",
		IPs: []exposure.HostIP{{IP: "203.0.113.10", Family: "ipv4", Class: "box"}, {IP: "2606:4700::5", Family: "ipv6", Class: "public"}}}) ||
		len(c.NotChecked) != 1 || c.NotChecked[0].Text != exposure.NotWordlistNoAnswer || len(c.Unresolved) != 2 ||
		len(c.Ports) != 2 || c.Ports[0] != (exposure.PortRow{IP: "203.0.113.10", Port: 443, Service: "https", Product: "FortiGate"}) ||
		len(c.AdminPanels) != 2 || c.AdminPanels[0].Risk != "danger" || c.AdminPanels[1].Risk != "warn" ||
		len(c.Certs) != 1 || c.Certs[0] != (exposure.CertRow{Host: "acme.example", Issuer: "R11", ExpiresAt: "2027-01-02T03:04:05Z"}) {
		t.Fatalf("content %+v", c)
	}
	if fmt.Sprint(asked) != "[op@acme.example 203.0.113.10 op@acme.example 203.0.113.11]" || fmt.Sprint(f.allowed) != "[203.0.113.10]" {
		t.Fatalf("scope asked %v, allowed %v", asked, f.allowed)
	}
	if _, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "xt-2", Kind: exposure.KindIP, Value: "203.0.113.10"}); err != nil || f.ip != ip {
		t.Fatalf("IP scan: %v, asked %v", err, f.ip)
	}
	for _, c := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("%w: crt.sh answered 502", surface.ErrCT), "unreachable"},
		{surface.ErrTooLong, "unreachable"},
		{surface.ErrTooManyNames, "too_many"},
	} {
		f.err = c.err
		var ae *exposure.APIError
		if _, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "xt-1", Kind: exposure.KindDomain, Value: "acme.example"}); !errors.As(err, &ae) || ae.Code != c.code {
			t.Fatalf("%v: got %v", c.err, err)
		}
	}
}

// The real scope rule (exposure.IsPublicIPv4) in the real scanner: CGNAT, link-local (cloud metadata), a mapped private address
// and a private one are never dialed, as the box's IP or as the address of a domain's name (which is still listed).
func TestExposureScanNeverProbesNonPublicAddresses(t *testing.T) {
	t.Parallel()
	synctest.Test(t, exposureScanNeverProbesNonPublic) // the wordlist's rate limit runs on the bubble's clock
}

func exposureScanNeverProbesNonPublic(t *testing.T) {
	bad := []string{"100.64.0.1", "169.254.169.254", "::ffff:10.0.0.1", "10.0.0.1"}
	var dials []string
	var mu sync.Mutex
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, addr)
		mu.Unlock()
		return nil, errors.New("refused")
	}
	names := ""
	var res resolverFunc
	m := map[string]netip.Addr{}
	for i, a := range bad {
		n := fmt.Sprintf("h%d.acme.example", i)
		names += n + `\n`
		m[n] = netip.MustParseAddr(a)
	}
	res = func(host string) []netip.Addr {
		if a, ok := m[host]; ok {
			return []netip.Addr{a}
		}
		return nil
	}
	ct := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"name_value":"` + names + `"}]`)), Header: http.Header{}, Request: r}, nil
	})}
	s, err := surface.New(surface.Config{Public: exposure.IsPublicIPv4, Probes: nopProbes{}, Dial: dial, Resolver: res, CT: ct, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range bad {
		if _, err := s.IP(t.Context(), netip.MustParseAddr(a)); !errors.Is(err, surface.ErrNotPublic) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	got, err := s.Domain(t.Context(), "acme.example", func(context.Context, netip.Addr) bool {
		t.Error("a non-public address was offered for a port scan")
		return true
	})
	if err != nil || len(got.Hosts) != len(bad) {
		t.Fatalf("hosts %+v, %v", got.Hosts, err)
	}
	if len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
}

type resolverFunc func(host string) []netip.Addr

func (f resolverFunc) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a := f(strings.TrimSuffix(host, ".")); a != nil {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f resolverFunc) LookupCNAME(_ context.Context, host string) (string, error) {
	if f(strings.TrimSuffix(host, ".")) != nil {
		return host, nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
func (resolverFunc) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, errors.New("no such host")
}
func (resolverFunc) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, errors.New("no such host")
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nopProbes struct{}

func (nopProbes) Record(context.Context, []surface.Probe) error { return nil }

// Review r1 H1: the dns row of a domain scan goes through the adapter into the real scan_probe table (ip NOT NULL, 1 to 253
// characters): its target is the domain, so the row is written and the scan goes on.
func TestExposureDNSProbeRowFitsTheProbeLog(t *testing.T) {
	t.Parallel()
	d := testServices(t)
	p := surface.Probe{ID: "xp-dns", Label: "acme.example", Kind: "dns", Request: "DNS lookups via the box's resolver"}
	if err := (scanProbeLog{d: d}).Record(t.Context(), []surface.Probe{p}); err != nil {
		t.Fatalf("before: %v", err)
	}
	p.Answered, p.Request = true, "5 names listed; "+p.Request
	if err := (scanProbeLog{d: d}).Record(t.Context(), []surface.Probe{p}); err != nil {
		t.Fatalf("after: %v", err)
	}
	rows, err := scanService(d).Probes(t.Context())
	if err != nil || len(rows) != 1 || rows[0].IP != "acme.example" || rows[0].Template != "exposure: dns" || rows[0].Result != "banner" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}
